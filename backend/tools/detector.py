"""攻击检测规则引擎。

输入：归一化的流量事件列表
输出：Finding 列表（攻击类型、严重级别、来源 IP、证据、MITRE 编号等）

设计为「特征匹配 + 行为统计」双路：
- 特征匹配：针对 URL/UA/载荷的恶意签名（SQLi/XSS/遍历/命令注入/扫描器）
- 行为统计：针对时序行为（端口扫描、暴力破解、CC/DDoS）
规则引擎完全离线、确定性，是大模型研判的客观依据。
"""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import unquote

# --------- 特征签名（大小写不敏感） ---------
SIGNATURES = {
    "sql_injection": {
        "name": "SQL 注入",
        "severity": "high",
        "mitre": "T1190",
        "patterns": [
            r"union\s+select", r"\bor\s+1\s*=\s*1\b", r"'\s*or\s*'", r"--\s*$",
            r"information_schema", r"\bsleep\s*\(", r"benchmark\s*\(",
            r"\bselect\b.+\bfrom\b", r"concat\s*\(", r"0x[0-9a-f]{8,}",
            r"xp_cmdshell", r"waitfor\s+delay",
        ],
    },
    "xss": {
        "name": "跨站脚本 (XSS)",
        "severity": "high",
        "mitre": "T1059.007",
        "patterns": [
            r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
            r"<img[^>]+src", r"document\.cookie", r"alert\s*\(", r"<svg",
            r"%3cscript",
        ],
    },
    "path_traversal": {
        "name": "目录遍历 / 文件包含",
        "severity": "high",
        "mitre": "T1083",
        "patterns": [
            r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"/etc/passwd", r"/etc/shadow",
            r"\\windows\\win.ini", r"php://", r"file://", r"/proc/self/environ",
        ],
    },
    "command_injection": {
        "name": "命令注入",
        "severity": "critical",
        "mitre": "T1059",
        "patterns": [
            r";\s*(cat|ls|id|whoami|uname|wget|curl)\b", r"\|\s*(bash|sh|nc)\b",
            r"`[^`]+`", r"\$\([^)]+\)", r"&&\s*(cat|wget|curl)", r"/bin/(ba)?sh",
        ],
    },
    "webshell": {
        "name": "WebShell / 恶意上传",
        "severity": "critical",
        "mitre": "T1505.003",
        "patterns": [
            r"(eval|assert|system|passthru|shell_exec)\s*\(",
            r"\.php\?.*=.*(eval|system)", r"c99\.php", r"r57\.php",
            r"(\.php|\.jsp|\.asp)x?;\.(jpg|png|gif)",
        ],
    },
}

# 已知扫描器/攻击工具的 User-Agent 关键字
SCANNER_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wfuzz",
    "hydra", "acunetix", "nessus", "openvas", "zgrab", "fuzz", "feroxbuster",
    "metasploit", "havij", "appscan", "w3af",
]

# 敏感探测路径（扫描器常访问）
SENSITIVE_PATHS = [
    "/.git", "/.env", "/wp-admin", "/wp-login", "/phpmyadmin", "/admin",
    "/manager/html", "/.svn", "/config", "/backup", "/shell", "/.aws",
    "/actuator", "/console", "/solr", "/druid",
]

# 行为阈值
PORT_SCAN_DISTINCT_PORTS = 15   # 同源访问的不同端口数
PORT_SCAN_WINDOW = 60           # 秒
BRUTE_FORCE_FAILS = 8           # 同源失败登录次数
DDOS_REQ_PER_IP = 100           # 单 IP 请求数
DDOS_TOTAL_REQ = 500            # 总请求数


def _ts_to_epoch(ts):
    """尽力把多种时间戳转成可比较的 float，失败返回 None。"""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts).strip()
    # 纯数字（epoch）
    try:
        return float(s)
    except ValueError:
        pass
    from datetime import datetime
    fmts = [
        "%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ]
    for f in fmts:
        try:
            return datetime.strptime(s.split(".")[0].replace("Z", "+0000") if "T" in s else s, f).timestamp()
        except (ValueError, OverflowError):
            continue
    return None


def _decoded_url(ev: dict) -> str:
    url = str(ev.get("url") or "")
    cur = url
    for _ in range(2):
        try:
            nxt = unquote(cur)
            if nxt == cur:
                break
            cur = nxt
        except Exception:
            break
    return cur


def _mk_finding(type_en, meta, src_ips, evidence, count, dst_ports=None,
                first=None, last=None, extra_desc=""):
    return {
        "type": meta["name"],
        "type_en": type_en,
        "severity": meta["severity"],
        "src_ips": sorted(src_ips)[:20],
        "dst_ports": sorted(set(p for p in (dst_ports or []) if p))[:20],
        "count": count,
        "first_seen": first,
        "last_seen": last,
        "mitre": meta.get("mitre"),
        "description": (meta.get("name", "") + " 行为。" + extra_desc).strip(),
        "evidence": evidence[:5],
    }


def _signature_findings(events: list[dict]) -> list[dict]:
    findings = []
    for type_en, meta in SIGNATURES.items():
        regexes = [re.compile(p, re.IGNORECASE) for p in meta["patterns"]]
        hits = defaultdict(list)   # src_ip -> [raw evidence]
        ports = set()
        times = []
        for ev in events:
            target = " ".join(str(ev.get(f, "")) for f in ("url", "raw"))
            decoded = _decoded_url(ev)
            haystack = (target + " " + decoded).lower()
            if any(r.search(haystack) for r in regexes):
                ip = ev.get("src_ip") or "未知"
                hits[ip].append(ev.get("raw") or ev.get("url") or "")
                if ev.get("dst_port"):
                    ports.add(ev["dst_port"])
                t = _ts_to_epoch(ev.get("timestamp"))
                if t:
                    times.append((t, ev.get("timestamp")))
        if hits:
            total = sum(len(v) for v in hits.values())
            evidence = [e for lst in hits.values() for e in lst if e]
            times.sort()
            findings.append(_mk_finding(
                type_en, meta, set(hits.keys()), evidence, total,
                dst_ports=ports,
                first=times[0][1] if times else None,
                last=times[-1][1] if times else None,
                extra_desc=f"共匹配 {total} 次，涉及 {len(hits)} 个源 IP。",
            ))
    return findings


def _scanner_findings(events: list[dict]) -> list[dict]:
    findings = []
    ua_hits = defaultdict(list)
    path_hits = defaultdict(dict)  # src_ip -> {matched_sensitive_path: event_raw}
    ua_tools = set()
    for ev in events:
        ua = (ev.get("user_agent") or "").lower()
        for tool in SCANNER_UA:
            if tool in ua:
                ua_hits[ev.get("src_ip") or "未知"].append(ev.get("raw") or ua)
                ua_tools.add(tool)
        decoded = _decoded_url(ev).lower()
        path = decoded.split("?")[0]
        for p in SENSITIVE_PATHS:
            if path == p or path.startswith(f"{p}/") or path.startswith(f"{p}."):
                ip = ev.get("src_ip") or "未知"
                if p not in path_hits[ip]:
                    path_hits[ip][p] = ev.get("raw") or decoded

    if ua_hits:
        total = sum(len(v) for v in ua_hits.values())
        findings.append(_mk_finding(
            "scanner_tool",
            {"name": "自动化扫描器/攻击工具", "severity": "high", "mitre": "T1595"},
            set(ua_hits.keys()),
            [e for lst in ua_hits.values() for e in lst],
            total,
            extra_desc=f"检测到工具特征：{', '.join(sorted(ua_tools))}。",
        ))
    # 敏感路径探测：某源 IP 探测了至少 3 个不同敏感路径才判定为扫描
    heavy = {ip: paths for ip, paths in path_hits.items() if len(paths) >= 3}
    if heavy:
        total = sum(len(paths) for paths in heavy.values())
        evidence = [ev for paths in heavy.values() for ev in paths.values()]
        findings.append(_mk_finding(
            "sensitive_path_probe",
            {"name": "敏感路径探测", "severity": "medium", "mitre": "T1595.003"},
            set(heavy.keys()),
            evidence,
            total,
            extra_desc=f"源 IP 探测了 {total} 个不同敏感路径，疑似目录或资产扫描行为。",
        ))
    return findings


def _port_scan_findings(events: list[dict]) -> list[dict]:
    by_src = defaultdict(lambda: {"ports": set(), "times": [], "evidence": []})
    for ev in events:
        src = ev.get("src_ip")
        dport = ev.get("dst_port")
        if not src or not dport:
            continue
        rec = by_src[src]
        rec["ports"].add(dport)
        t = _ts_to_epoch(ev.get("timestamp"))
        if t:
            rec["times"].append(t)
        if len(rec["evidence"]) < 5:
            rec["evidence"].append(ev.get("raw") or f"{src} -> :{dport}")

    findings = []
    offenders = set()
    all_ports = set()
    evidence = []
    first = last = None
    for src, rec in by_src.items():
        if len(rec["ports"]) >= PORT_SCAN_DISTINCT_PORTS:
            # 若有时间，进一步看是否集中在窗口内
            span_ok = True
            if rec["times"]:
                span = max(rec["times"]) - min(rec["times"])
                span_ok = span <= PORT_SCAN_WINDOW * max(1, len(rec["ports"]) / PORT_SCAN_DISTINCT_PORTS)
            if span_ok:
                offenders.add(src)
                all_ports |= rec["ports"]
                evidence.extend(rec["evidence"])
    if offenders:
        findings.append(_mk_finding(
            "port_scan",
            {"name": "端口扫描", "severity": "medium", "mitre": "T1046"},
            offenders, evidence, len(all_ports), dst_ports=all_ports,
            extra_desc=f"源 IP 在短时间内探测了 {len(all_ports)} 个不同端口。",
        ))
    return findings


def _brute_force_findings(events: list[dict]) -> list[dict]:
    login_re = re.compile(r"(login|signin|sign-in|auth|wp-login|admin|session)", re.IGNORECASE)
    by_src = defaultdict(lambda: {"fails": 0, "evidence": [], "times": []})
    auth_ports = {21, 22, 23, 25, 110, 143, 3389, 5900}
    for ev in events:
        url = ev.get("url") or ""
        status = ev.get("status")
        dst_port = ev.get("dst_port")
        is_login = bool(login_re.search(url)) or dst_port in auth_ports
        if not is_login:
            continue
        # 判定失败：明确返回 401/403，或在无 HTTP 状态码的认证端口（SSH/RDP）持续连接
        # 显式排除成功响应（如 status=200/302），绝不将正常登录计为爆破尝试
        if status in (401, 403):
            failed = True
        elif dst_port in auth_ports and status is None:
            failed = True
        else:
            failed = False

        if failed:
            src = ev.get("src_ip") or "未知"
            rec = by_src[src]
            rec["fails"] += 1
            t = _ts_to_epoch(ev.get("timestamp"))
            if t:
                rec["times"].append(t)
            if len(rec["evidence"]) < 5:
                rec["evidence"].append(ev.get("raw") or url)

    findings = []
    offenders = {ip: rec for ip, rec in by_src.items() if rec["fails"] >= BRUTE_FORCE_FAILS}
    if offenders:
        total = sum(r["fails"] for r in offenders.values())
        evidence = [e for r in offenders.values() for e in r["evidence"]]
        findings.append(_mk_finding(
            "brute_force",
            {"name": "暴力破解", "severity": "high", "mitre": "T1110"},
            set(offenders.keys()), evidence, total,
            extra_desc=f"检测到针对登录/认证服务的持续失败尝试，共 {total} 次（已排除成功登录）。",
        ))
    return findings


def _ddos_findings(events: list[dict]) -> list[dict]:
    counts = defaultdict(int)
    evidence_map = defaultdict(list)
    for ev in events:
        src = ev.get("src_ip") or "未知"
        counts[src] += 1
        if len(evidence_map[src]) < 3:
            evidence_map[src].append(ev.get("raw") or ev.get("url") or src)
    total = sum(counts.values())
    heavy = {ip: c for ip, c in counts.items() if c >= DDOS_REQ_PER_IP}
    findings = []
    if heavy or (total >= DDOS_TOTAL_REQ and len(counts) <= 10):
        offenders = set(heavy.keys()) or set(counts.keys())
        evidence = [e for ip in offenders for e in evidence_map[ip]]
        findings.append(_mk_finding(
            "dos_cc",
            {"name": "CC / DDoS（高频请求）", "severity": "high", "mitre": "T1498"},
            offenders, evidence, total,
            extra_desc=f"短时间内观察到异常高的请求量（总计 {total} 条）。",
        ))
    return findings


def detect_attacks(events: list[dict]) -> list[dict]:
    """对事件列表运行全部规则，返回去重后的 findings。"""
    if not events:
        return []
    findings: list[dict] = []
    findings += _signature_findings(events)
    findings += _scanner_findings(events)
    findings += _port_scan_findings(events)
    findings += _brute_force_findings(events)
    findings += _ddos_findings(events)

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (severity_rank.get(f["severity"], 9), -f["count"]))
    return findings
