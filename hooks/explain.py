#!/usr/bin/env python3
"""
Permission Explainer Hook
- 本地规则引擎 + DeepSeek API 加权协商评估风险
- 用中文解释操作含义、风险、后果，三选项交互
- 安全优先：低风险放行，中/高/严重拦截展示说明
"""

import sys
import json
import hashlib
import os
import urllib.request
import urllib.error

# 强制 UTF-8 输入输出，避免 Windows GBK 编码问题
sys.stdin.reconfigure(encoding="utf-8", errors="replace")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".claude", "settings.json")
PLUGIN_DIR = os.path.join(os.path.expanduser("~"), ".claude", "plugins", "permission-explainer")
CACHE_PATH = os.path.join(PLUGIN_DIR, ".analysis_cache.json")
PENDING_PATH = os.path.join(PLUGIN_DIR, ".pending_approvals.json")
TRUSTED_PATH = os.path.join(PLUGIN_DIR, ".trusted_patterns.json")
CACHE_MAX = 500
PENDING_TTL = 120  # 秒，在此时间内再次请求同一操作则放行


# ── 配置 ──────────────────────────────────────────────────

def load_config():
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            s = json.load(f)
        env = s.get("env", {})
        return {
            "base_url": env.get("ANTHROPIC_BASE_URL", "https://api.deepseek.com/anthropic"),
            "api_key": env.get("ANTHROPIC_AUTH_TOKEN", ""),
            "model": env.get("ANTHROPIC_MODEL", "deepseek-v4-pro"),
            "timeout": min(int(env.get("API_TIMEOUT_MS", "15000")) / 1000, 12),
        }
    except Exception:
        return None


def load_cache():
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(cache):
    # 限制缓存条目数量
    if len(cache) > CACHE_MAX:
        keys = list(cache.keys())
        for k in keys[: len(keys) - CACHE_MAX]:
            del cache[k]
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ── 待批准追踪 ─────────────────────────────────────────────
# 机制：高风险操作首次 deny 并展示风险说明，用户确认后重新请求，
# 钩子检测到同一操作在 PENDING_TTL 内再次出现则放行（allow）。

def load_pending():
    try:
        with open(PENDING_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_pending(pending):
    # 清理过期条目
    now = __import__("time").time()
    for k in list(pending.keys()):
        if now - pending[k] > PENDING_TTL:
            del pending[k]
    try:
        os.makedirs(os.path.dirname(PENDING_PATH), exist_ok=True)
        with open(PENDING_PATH, "w", encoding="utf-8") as f:
            json.dump(pending, f, ensure_ascii=False)
    except Exception:
        pass


# ── 信任模式追踪 ─────────────────────────────────────────────
# 用户选择"始终允许"后，同类操作在本会话内自动放行

def load_trusted():
    try:
        with open(TRUSTED_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_trusted(trusted):
    try:
        os.makedirs(os.path.dirname(TRUSTED_PATH), exist_ok=True)
        with open(TRUSTED_PATH, "w", encoding="utf-8") as f:
            json.dump(trusted, f, ensure_ascii=False)
    except Exception:
        pass


# ── DeepSeek API 调用 ─────────────────────────────────────

def call_deepseek(config, prompt):
    url = config["base_url"].rstrip("/") + "/v1/messages"
    body = json.dumps(
        {
            "model": config["model"],
            "max_tokens": 400,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": config["api_key"],
            "anthropic-version": "2023-06-01",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=config["timeout"]) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            content = result.get("content", [])
            for block in content:
                if block.get("type") == "text":
                    return block.get("text", "")
            return None
    except Exception:
        return None


# ── Prompt 构造 ───────────────────────────────────────────

def build_prompt(tool_name, tool_input, cwd):
    input_str = json.dumps(tool_input, ensure_ascii=False)
    if len(input_str) > 1500:
        input_str = input_str[:1500] + "...(truncated)"

    return (
        "You are a security analyst. Analyze this tool call and reply in STRICT JSON (no markdown fences):\n\n"
        f"Tool: {tool_name}\n"
        f"Input: {input_str}\n"
        f"Working dir: {cwd}\n\n"
        'Return ONLY this JSON (all fields in Chinese):\n'
        "{\n"
        '  "explain_cn": "用一句通俗中文解释这个操作（面向非程序员）",\n'
        '  "risk_level": "low|medium|high|critical",\n'
        '  "risk_reason_cn": "风险原因（中文）",\n'
        '  "worst_case_cn": "最坏后果（中文）"\n'
        "}"
    )


# ── 加权协商合并 ───────────────────────────────────────────
# 本地规则和大模型各自独立评估，按协商策略合并

def _merge_risk(local_risk, api_risk):
    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    rev = {0: "low", 1: "medium", 2: "high", 3: "critical"}

    local_score = risk_order.get(local_risk, 1)
    api_score = risk_order.get(api_risk, 1)
    diff = local_score - api_score  # 正数 = 本地更严格

    if diff <= 0:
        # API 认为同等或更危险 → 信任模型发现隐蔽风险
        return api_risk, ""
    elif diff == 1:
        # API 略低一档 → 取平均向上取整（偏向本地）
        avg = (local_score + api_score + 1) // 2
        return rev[avg], ""
    else:
        # diff >= 2：严重分歧 → 折中 + 警告用户
        avg = (local_score + api_score + 1) // 2
        merged = rev[avg]
        warning = f"⚠️ 风险分歧：本地={local_risk}，AI={api_risk}，折中={merged}"
        return merged, warning


# ── 分析入口 ──────────────────────────────────────────────

def analyze_tool(tool_name, tool_input, cwd, config, cache):
    cache_key = hashlib.md5(
        (tool_name + json.dumps(tool_input, sort_keys=True)).encode()
    ).hexdigest()

    if cache_key in cache:
        return cache[cache_key]

    # 始终先跑本地规则
    local = local_analysis(tool_name, tool_input)

    # 插件自身文件操作 → 直接放行，不调 API（避免 API 误判升级）
    if local.get("risk_reason_cn", "") == "插件自身配置文件":
        cache[cache_key] = local
        save_cache(cache)
        return local

    # 无 API 配置则直接用本地结果
    if not config or not config["api_key"]:
        cache[cache_key] = local
        save_cache(cache)
        return local

    # 调用 API 获取独立评估
    prompt = build_prompt(tool_name, tool_input, cwd)
    text = call_deepseek(config, prompt)

    if text is None:
        cache[cache_key] = local
        save_cache(cache)
        return local

    try:
        clean = text.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1]
            if clean.endswith("```"):
                clean = clean[:-3]
        api = json.loads(clean)
    except json.JSONDecodeError:
        cache[cache_key] = local
        save_cache(cache)
        return local

    # 加权协商合并：本地规则与大模型各自独立评估
    local_risk = local.get("risk_level", "medium")
    api_risk = api.get("risk_level", "medium")
    merged_risk, dispute_note = _merge_risk(local_risk, api_risk)

    # API 说人话更自然，优先用 API 文本；本地作为兜底
    result = {
        "explain_cn": api.get("explain_cn", local["explain_cn"]),
        "risk_level": merged_risk,
        "risk_reason_cn": api.get("risk_reason_cn") or local.get("risk_reason_cn", ""),
        "worst_case_cn": api.get("worst_case_cn") or local.get("worst_case_cn", ""),
    }

    if dispute_note:
        result["risk_reason_cn"] = dispute_note + " | " + result["risk_reason_cn"]

    cache[cache_key] = result
    save_cache(cache)
    return result


# ── 本地规则（API 不可用时的降级方案）───────────────────

def local_analysis(tool_name, tool_input):
    """本地规则分析，不依赖 API"""

    # 先根据工具类型设定基础风险
    base = {
        "Read": ("读取文件内容，查看其中的代码或数据", "low", "纯读取操作，不会修改任何内容", "无破坏性后果"),
        "Glob": ("按文件名模式搜索匹配的文件", "low", "仅列出文件名，不读取内容", "无破坏性后果"),
        "Grep": ("在文件内容中搜索匹配的文本行", "low", "仅搜索匹配行，不修改任何文件", "无破坏性后果"),
        "TaskCreate": ("创建一个新的待办任务，记录要完成的工作", "low", "仅记录任务信息", "无破坏性后果"),
        "TaskUpdate": ("更新任务状态或信息", "low", "仅修改任务元数据", "无破坏性后果"),
        "WebFetch": ("从指定网址获取网页内容", "low", "仅读取网页，不修改本地文件", "可能访问到恶意网址"),
        "WebSearch": ("在网络上搜索关键词", "low", "仅搜索，不修改本地文件", "无破坏性后果"),
        "Write": ("创建或完全覆盖一个文件", "medium", "会覆盖已有文件内容，原内容永久丢失", "重要文件被覆盖后无法恢复"),
        "Edit": ("精确替换文件中的某一段文字", "medium", "修改出错可能让代码无法运行", "引入 bug 或破坏程序功能"),
        "Bash": ("在终端执行 Shell 命令", "medium", "可以执行任意系统命令", "取决于具体命令"),
        "PowerShell": ("在 PowerShell 中执行命令", "medium", "可以执行任意 Windows 命令或脚本", "取决于具体命令"),
    }

    info = base.get(
        tool_name,
        (f"执行 {tool_name} 操作", "medium", "不常见操作类型", "未知后果"),
    )

    explain = info[0]
    risk = info[1]
    reason = info[2]
    worst = info[3]

    # Bash / PowerShell: 分析具体命令（插件自身文件直接放行）
    if tool_name in ("Bash", "PowerShell"):
        cmd = str(tool_input.get("command", ""))
        c = cmd.lower()
        # 删除操作：若所有目标路径都在插件目录内 → 直接放行
        if any(x in c for x in ["rm ", "del ", "rmdir ", "rd "]):
            paths = _extract_paths(cmd)
            real_paths = [p for p in paths if "\\" in p or "/" in p]
            if real_paths and all(
                os.path.normpath(p).startswith(os.path.normpath(PLUGIN_DIR))
                for p in real_paths
            ):
                risk, reason, worst = ("low", "插件自身配置文件", "无破坏性后果")
            else:
                risk, reason, worst = _analyze_command(cmd)
        else:
            risk, reason, worst = _analyze_command(cmd)
        explain = f"在终端执行命令: {cmd[:80]}{'...' if len(cmd)>80 else ''}"

    # Write: 分析路径（插件自身文件直接放行，避免循环拦截）
    elif tool_name == "Write":
        path = str(tool_input.get("file_path", ""))
        if os.path.normpath(path).startswith(os.path.normpath(PLUGIN_DIR)):
            risk, reason, worst = ("low", "插件自身配置文件", "无破坏性后果")
        else:
            risk, reason, worst = _analyze_write_path(path)
        explain = f"写入文件: {path}"

    # Edit: 分析路径（插件自身文件直接放行，避免循环拦截）
    elif tool_name == "Edit":
        path = str(tool_input.get("file_path", ""))
        if os.path.normpath(path).startswith(os.path.normpath(PLUGIN_DIR)):
            risk, reason, worst = ("low", "插件自身配置文件", "无破坏性后果")
        else:
            risk, reason, worst = _analyze_edit_path(path)
        explain = f"编辑文件: {path}"

    return {
        "explain_cn": explain,
        "risk_level": risk,
        "risk_reason_cn": reason,
        "worst_case_cn": worst,
    }


# ── 路径 + 文件名 + 操作范围联合打分 ─────────────────────

def _extract_paths(cmd):
    """从 rm/del/rmdir/rd 命令中提取所有目标路径"""
    import re
    paths = []
    # 匹配引号路径: "C:\path" 或 '/path'
    for m in re.finditer(r"""["']([^"']+)["']""", cmd):
        p = m.group(1)
        if not p.startswith("-"):
            paths.append(p)
    # 匹配非引号路径: 跟在 rm/del -flags 后面，不是 - 开头
    parts = cmd.split()
    for i, part in enumerate(parts):
        if part.lower() in ("rm", "del", "rmdir", "rd", "sudo"):
            continue
        if part.startswith("-"):
            continue
        if part in (">", ">>", "|", "&&", "||", ";"):
            break
        # 排除 shell 重定向: 2>/dev/null, >/dev/null, 1>/dev/null 等
        import re as _re2
        if _re2.match(r"^\d*>>?|^>>?", part):
            continue
        # 排除命令关键字
        if part.lower() in ("find", "xargs", "exec", "bash", "python", "cmd", "echo"):
            continue
        # strip 外层引号后比较，避免引号匹配和非引号匹配重复提取
        clean = part.strip('"').strip("'")
        if clean not in paths:
            paths.append(clean)
    return paths


def _score_path_risk(path):
    """返回 (path_score, filename_score, details)
    score: 1=low, 2=medium, 3=high, 4=critical
    """
    p = path.lower().replace("\\", "/")
    filename = os.path.basename(path) if path else ""
    fname = filename.lower()
    dirname = os.path.dirname(path).lower().replace("\\", "/") if path else ""

    # ── 目录评分 ──
    path_score = 2  # 默认中等
    reasons = []

    # critical 目录
    critical_dirs = [
        "c:/windows", "c:/windows/system32", "c:/windows/syswow64",
        "/etc", "/boot", "/sys", "/proc", "/dev",
        "~/.ssh", "/root", "c:/program files", "c:/program files (x86)",
    ]
    # 盘符根目录 (c:/, d:/, ...)
    if dirname in ("c:/", "d:/", "e:/") or dirname == "/":
        path_score = max(path_score, 4)
        reasons.append("磁盘根目录")
    for d in critical_dirs:
        if d in p or d in dirname:
            path_score = max(path_score, 4)
            reasons.append("系统关键目录")
            break

    # high 目录
    if path_score < 4:
        high_dirs = [
            "documents", "我的文档", "/var", "/usr", "/opt",
            "appdata/roaming", "~/.config", "~/.aws", "~/.kube",
            "/etc/nginx", "/etc/apache", "/etc/ssh",
        ]
        for d in high_dirs:
            if d in p or d in dirname:
                path_score = max(path_score, 3)
                reasons.append("用户数据/应用配置目录")
                break

    # low 目录
    low_dirs = [
        "/tmp", "/var/tmp", "appdata/local/temp",
        "node_modules", "__pycache__", ".git/", "dist/", "build/",
        ".cache", "vendor/", "target/",
    ]
    for d in low_dirs:
        if d in p or d in dirname:
            path_score = min(path_score, 1)
            reasons.append("临时/可重建目录")
            break

    # ── 文件名/后缀评分 ──
    filename_score = 2  # 默认中等
    fname_reason = ""

    # critical 文件名
    critical_names = [
        ".env", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts",
        ".pem", ".key", ".pfx", ".p12", ".jks",
        "password", "secret", "credential", "token",
    ]
    for kw in critical_names:
        if kw in fname:
            filename_score = 4
            fname_reason = f"安全凭证/密钥文件: {filename}"
            break

    # high 文件名
    if filename_score < 4:
        high_names = [
            ".docx", ".doc", ".pdf", ".pptx", ".xlsx", ".xls",
            ".sql", ".mdb", ".db", ".sqlite", ".sqlite3",
            "backup", "dump", "export", "production", "prod",
            "论文", "毕业", "合同", "报告", "简历", "档案", "证书",
            "账", "税", "工资", "薪资",
        ]
        for kw in high_names:
            if kw in fname:
                filename_score = 3
                fname_reason = f"重要文档/数据文件: {filename}"
                break

    # low 文件名（可能覆盖 high 判定，此时清除 high 理由避免矛盾）
    low_names = [
        ".tmp", ".log", ".cache", ".pyc", ".pyo", ".class",
        "test", "draft", "temp", "tmp",
        "测试", "临时", "草稿",
    ]
    for kw in low_names:
        if kw in fname:
            filename_score = min(filename_score, 1)
            fname_reason = f"临时/测试文件: {filename}"
            break

    if fname_reason:
        reasons.append(fname_reason)

    return path_score, filename_score, reasons


def _score_delete_risk(paths, cmd):
    """综合打分：目录风险 × 文件名风险 × 操作范围"""
    max_path_score = 2
    max_fname_score = 2
    scope_score = 1
    all_reasons = []

    c = cmd.lower()

    # ── 操作范围评分升级 ──
    # 通配符：可能影响大量未知文件
    if "*" in cmd or "?" in cmd:
        scope_score = max(scope_score, 3)
        all_reasons.append("使用通配符，可能影响大量文件")
    # 递归删除 (Unix -rf 或 Windows /s)
    if "-rf" in c or "-fr" in c or "-r " in c or " -r" in c or " /s " in c or c.endswith(" /s"):
        scope_score = max(scope_score, 3)
        all_reasons.append("递归删除整个目录")
    # 强制模式 (Unix -f 或 Windows /f /q)
    if " -f " in c or c.endswith(" -f") or " /f " in c or c.endswith(" /f") or " /q " in c or c.endswith(" /q"):
        scope_score = max(scope_score, 2)
        all_reasons.append("强制/安静模式，不提示确认")
    # sudo 提权
    if "sudo " in c or "su " in c:
        scope_score = max(scope_score, 4)
        all_reasons.append("使用超级用户权限")

    for path in paths:
        ps, fs, reasons = _score_path_risk(path)
        max_path_score = max(max_path_score, ps)
        max_fname_score = max(max_fname_score, fs)
        for r in reasons:
            if r not in all_reasons:
                all_reasons.append(r)

    # 合并分数：取三者中最高
    combined = max(max_path_score, max_fname_score, scope_score)

    # 确定风险等级和描述
    if combined >= 4:
        risk = "critical"
    elif combined >= 3:
        risk = "high"
    elif combined >= 2:
        risk = "medium"
    else:
        risk = "low"

    path_list = ", ".join(paths[:3])
    if len(paths) > 3:
        path_list += f" 等{len(paths)}个文件"

    reason_detail = "；".join(all_reasons) if all_reasons else "删除文件或目录，被删除的内容可能无法恢复"

    worst_map = {
        "critical": "系统关键文件被删除，电脑可能无法启动或服务崩溃",
        "high": "重要文档或数据永久丢失，且无备份可恢复",
        "medium": "文件被删除后需手动恢复或重建",
        "low": "临时文件丢失，可轻松重建",
    }

    return (risk, f"删除: {path_list} → {reason_detail}", worst_map.get(risk, worst_map["medium"]))


def _analyze_command(cmd):
    c = cmd.lower()

    # ── Critical ──
    if any(x in c for x in ["rm -rf /", "rm -rf ~", "rm -rf .", "rm -rf /*"]):
        return ("critical", "递归删除整个目录，所有文件永久丢失且无法恢复", "整个系统或项目文件被删除，电脑/项目不可用")
    if any(x in c for x in ["> /dev/sda", "dd if=", "mkfs.", "format c:", "format d:", "diskpart", "cleanmgr /sagerun"]):
        return ("critical", "直接操作磁盘设备，会破坏分区表和文件系统", "硬盘数据全部丢失，系统崩溃无法启动")
    if any(x in c for x in ["git push --force", "git push -f"]):
        return ("high", "强制推送覆盖远程仓库历史，团队成员的工作可能丢失", "团队代码仓库被破坏，同事的提交永久丢失")

    # ── High ──
    if any(x in c for x in ["sudo ", "su "]):
        return ("high", "使用超级用户权限执行命令，可修改系统关键配置", "系统配置被错误修改，软件或服务不可用")

    # ── 删除操作：路径 + 文件名 + 操作范围联合打分 ──
    if any(x in c for x in ["rm ", "del ", "rmdir ", "rd "]):
        paths = _extract_paths(cmd)
        if paths:
            risk, reason, worst = _score_delete_risk(paths, cmd)
        else:
            risk, reason, worst = ("high", "删除文件或目录，被删除的内容可能无法恢复", "重要文件被永久删除")
        return (risk, reason, worst)

    if any(x in c for x in ["chmod 777", "chmod -R 777"]):
        return ("high", "赋予所有用户完全读写执行权限，安全风险极高", "任何用户或程序都可修改此文件，系统安全性严重降低")
    if any(x in c for x in ["git reset --hard", "git checkout -- "]):
        return ("high", "丢弃 Git 仓库中未提交的本地更改", "未提交的代码修改全部丢失且不可恢复")
    if "> " in c or ">>" in c:
        return ("high", "重定向输出到文件，会覆盖或追加文件内容", "错误的重定向可能覆盖重要文件")

    # ── Medium ──
    if any(x in c for x in ["pip install", "npm install -g", "gem install", "cargo install"]):
        return ("medium", "在系统级别安装软件包，可能引入恶意代码", "安装的包可能包含安全漏洞或恶意脚本")
    if any(x in c for x in ["docker rm", "docker rmi"]):
        return ("medium", "删除 Docker 容器或镜像", "运行中的容器数据未备份即丢失")
    if any(x in c for x in ["kill ", "pkill ", "taskkill"]):
        return ("medium", "强制终止进程", "正在运行的程序被强制关闭，未保存数据丢失")
    if "shutdown" in c or "reboot" in c:
        return ("high", "关闭或重启电脑", "所有未保存工作丢失，系统重启")

    # ── Low ──
    read_cmds = [
        "ls", "dir", "cat", "type", "echo", "pwd", "whoami", "date",
        "which", "where", "find ", "grep ", "head", "tail", "wc ",
        "sort", "uniq", "diff", "ps", "df", "du", "free", "top",
        "ping", "curl", "wget", "tree", "less", "more", "man",
        "python --version", "node --version", "git status", "git log",
        "git diff", "git branch", "git remote -v",
    ]
    if any(kw in c for kw in read_cmds):
        return ("low", "只读或查看信息类命令，不会修改任何文件", "仅输出信息到终端，无破坏性后果")

    # ── Package managers (low) ──
    pkg_cmds = ["npm ", "pip ", "cargo ", "go ", "yarn ", "pnpm ", "poetry "]
    if any(kw in c for kw in pkg_cmds):
        return ("low", "包管理操作，修改项目依赖", "安装错误版本的包可能导致项目运行异常")

    # ── Git (low) ──
    if "git " in c:
        return ("low", "Git 版本控制操作", "错误操作需手动修复仓库状态")

    return ("medium", "不常见命令，请仔细确认参数含义后再决定", "未知后果，建议确认后执行")


def _analyze_write_path(path):
    ps, fs, reasons = _score_path_risk(path)
    combined = max(ps, fs)
    detail = "；".join(reasons) if reasons else "写入文件将覆盖已有内容"

    if combined >= 4:
        return ("critical", f"写入: {detail}", "系统关键文件损坏或密钥泄露")
    elif combined >= 3:
        return ("high", f"写入: {detail}", "重要文件被覆盖且无法恢复")
    elif combined >= 2:
        return ("medium", f"写入: {detail}", "原文件内容永久丢失")
    else:
        return ("low", f"写入: {detail}", "可安全覆盖")


def _analyze_edit_path(path):
    ps, fs, reasons = _score_path_risk(path)
    combined = max(ps, fs)
    detail = "；".join(reasons) if reasons else "修改文件内容"

    if combined >= 4:
        return ("critical", f"编辑: {detail}", "安全凭证泄露或系统关键文件损坏")
    elif combined >= 3:
        return ("high", f"编辑: {detail}", "重要文件内容异常，可能影响功能")
    elif combined >= 2:
        return ("medium", f"编辑: {detail}", "编辑错误可能引入 bug")
    else:
        return ("low", f"编辑: {detail}", "可安全编辑")


# ── 信任模式 key 计算 ─────────────────────────────────────
# 用户选择"始终允许"后，同类操作在本会话内自动放行
# 同类定义：相同 tool + risk_level + op_category + parent_dir

def _compute_trust_key(tool_name, tool_input, risk_level):
    if tool_name in ("Bash", "PowerShell"):
        cmd = str(tool_input.get("command", ""))
        c = cmd.lower()
        if any(x in c for x in ["rm ", "del ", "rmdir ", "rd "]):
            op_category = "delete"
            paths = _extract_paths(cmd)
            parent = os.path.basename(os.path.dirname(paths[0])) if paths else "unknown"
        elif ">" in c or ">>" in c:
            op_category = "write"
            parent = "unknown"
        else:
            op_category = "execute"
            words = cmd.split()
            parent = words[0] if words else "unknown"
    elif tool_name == "Write":
        path = str(tool_input.get("file_path", ""))
        op_category = "write"
        parent = os.path.basename(os.path.dirname(path)) if path else "unknown"
    elif tool_name == "Edit":
        path = str(tool_input.get("file_path", ""))
        op_category = "edit"
        parent = os.path.basename(os.path.dirname(path)) if path else "unknown"
    else:
        op_category = "other"
        parent = "unknown"

    return hashlib.md5(
        f"{tool_name}|{risk_level}|{op_category}|{parent}".encode()
    ).hexdigest()


# ── 主入口 ────────────────────────────────────────────────

def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                    },
                    "systemMessage": "[权限解释器] 未收到输入数据，请用户自行判断。",
                },
                ensure_ascii=False,
            )
        )
        return 0

    try:
        hook_input = json.loads(raw)
    except json.JSONDecodeError:
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                    },
                    "systemMessage": "[权限解释器] 输入解析失败，请用户自行判断。",
                },
                ensure_ascii=False,
            )
        )
        return 0

    tool_name = hook_input.get("tool_name", "Unknown")
    tool_input = hook_input.get("tool_input", {})
    cwd = hook_input.get("cwd", os.getcwd())
    hook_event_name = hook_input.get("hook_event_name", "PreToolUse")

    config = load_config()
    cache = load_cache()

    result = analyze_tool(tool_name, tool_input, cwd, config, cache)

    risk = result.get("risk_level", "medium")
    explain = result.get("explain_cn", f"执行 {tool_name} 操作")
    reason = result.get("risk_reason_cn", "")
    worst = result.get("worst_case_cn", "")

    emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(risk, "⚪")

    msg = (
        f"--- 权限解释 (中文) ---\n"
        f"{emoji} 风险: {risk.upper()}\n"
        f"做什么: {explain}\n"
        f"为什么: {reason}\n"
        f"最坏情况: {worst}\n"
        f"------------------------"
    )

    # 风险决策（三选项模式）
    # - 低风险 → allow 直接放行
    # - 已信任模式 → allow 自动放行（用户之前选了"始终允许"）
    # - 已在待批准列表 → allow（用户刚选了"确认"）
    # - 其他 → deny + 展示三个选项：确认 / 始终允许 / 拒绝
    import time

    pending = load_pending()
    trusted = load_trusted()

    # 计算 pending key（仅用关键参数，忽略 description 等非核心字段）
    if tool_name in ("Bash", "PowerShell"):
        pending_key = hashlib.md5(
            (tool_name + str(tool_input.get("command", ""))).encode()
        ).hexdigest()
    elif tool_name in ("Write", "Edit"):
        pending_key = hashlib.md5(
            (tool_name + str(tool_input.get("file_path", ""))).encode()
        ).hexdigest()
    else:
        pending_key = hashlib.md5(
            (tool_name + json.dumps(tool_input, sort_keys=True)).encode()
        ).hexdigest()

    trust_key = _compute_trust_key(tool_name, tool_input, risk)

    if risk == "low":
        decision = "allow"
    elif trust_key in trusted:
        decision = "allow"
        msg += "\n⚡ 已自动放行（你已信任此类操作）"
    elif pending_key in pending:
        decision = "allow"
        msg += "\n✅ 已放行（你已确认重新执行）"
        del pending[pending_key]
        save_pending(pending)
    else:
        decision = "deny"
        if risk == "critical":
            msg += "\n🔴 严重风险！"
        elif risk == "high":
            msg += "\n🟠 高风险！"
        else:
            msg += "\n🟡 中风险。"
        msg += f"""
------------------------
📋 你的选择：
  回复 "确认" → 仅此次放行
  回复 "始终允许" → 本次会话内同类操作自动放行
  回复 "拒绝" → 取消操作
[PERMISSION_EXPLAINER_TRUST_KEY:{trust_key}]"""
        pending[pending_key] = time.time()
        save_pending(pending)

    output = {
        "hookSpecificOutput": {
            "hookEventName": hook_event_name,
            "permissionDecision": decision,
        },
        "systemMessage": msg,
    }

    print(json.dumps(output, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
