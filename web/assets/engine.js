/**
 * Sentinel browser-side traffic analysis engine.
 * Pure functions only: no DOM, no network. Logs never leave the page.
 */

export const MAX_EVENTS = 20000;

export const SAMPLE_CATALOG = [
  {
    id: "web_attack_nginx.log",
    name: "Web 攻击组合",
    tag: "WEB ATTACK",
    description: "SQL 注入、XSS、目录遍历、命令注入与扫描器指纹",
    meta: "15 条 · Nginx",
    tone: "critical",
  },
  {
    id: "brute_force_ssh.log",
    name: "登录暴力破解",
    tag: "CREDENTIAL",
    description: "401 失败风暴，末尾混入一次成功登录作为噪声",
    meta: "12 条 · Nginx",
    tone: "warning",
  },
  {
    id: "port_scan_capture.csv",
    name: "端口扫描",
    tag: "RECON",
    description: "5 秒内探测 24 个端口，验证行为窗口检测",
    meta: "26 条 · CSV",
    tone: "scan",
  },
  {
    id: "normal_traffic.log",
    name: "正常流量对照",
    tag: "BASELINE",
    description: "纯正常请求，用于确认规则引擎不会凭空报警",
    meta: "18 条 · Nginx",
    tone: "normal",
  },
];

export const DETECTION_RULES = [
  { name: "SQL 注入", severity: "high", mitre: "T1190", kind: "特征匹配", description: "UNION SELECT、布尔/时间盲注、information_schema 等载荷。" },
  { name: "跨站脚本 XSS", severity: "high", mitre: "T1059.007", kind: "特征匹配", description: "script 标签、事件处理器、javascript: 与 document.cookie 访问。" },
  { name: "目录遍历 / 文件包含", severity: "high", mitre: "T1083", kind: "特征匹配", description: "../ 穿越序列、敏感系统文件与 php://、file:// 协议。" },
  { name: "命令注入", severity: "critical", mitre: "T1059", kind: "特征匹配", description: "管道、分号、反引号与 $() 拼接系统命令。" },
  { name: "WebShell / 恶意上传", severity: "critical", mitre: "T1505.003", kind: "特征匹配", description: "eval/system 等执行函数与双扩展名上传特征。" },
  { name: "扫描器指纹", severity: "high", mitre: "T1595", kind: "特征匹配", description: "sqlmap、nmap、nikto、gobuster 等自动化工具 User-Agent。" },
  { name: "敏感路径探测", severity: "medium", mitre: "T1595.003", kind: "行为统计", description: "同一来源探测 .git、.env、管理后台等 ≥3 个敏感路径。" },
  { name: "端口扫描", severity: "medium", mitre: "T1046", kind: "行为统计", description: "同一来源 60 秒内访问 ≥15 个不同目标端口。" },
  { name: "暴力破解", severity: "high", mitre: "T1110", kind: "行为统计", description: "登录入口 ≥8 次 401/403 失败；成功登录不计入失败。" },
  { name: "CC / DDoS", severity: "high", mitre: "T1498", kind: "行为统计", description: "单来源 60 秒内 ≥100 次请求，或少量来源产生 ≥500 次请求。" },
];

export const DEMO_GEO_MAP = {
  "113.108.182.66": { country: "中国", province: "广东省", city: "广州市", isp: "电信" },
  "221.226.13.45": { country: "中国", province: "江苏省", city: "南京市", isp: "电信" },
  "59.110.23.88": { country: "中国", province: "北京市", city: "北京市", isp: "阿里云" },
  "183.6.51.200": { country: "中国", province: "广东省", city: "深圳市", isp: "联通" },
  "171.12.66.190": { country: "中国", province: "河南省", city: "郑州市", isp: "电信" },
  "120.79.155.33": { country: "中国", province: "广东省", city: "深圳市", isp: "阿里云" },
  "218.92.0.123": { country: "中国", province: "江苏省", city: "镇江市", isp: "电信" },
  "45.155.205.99": { country: "荷兰", province: "北荷兰省", city: "阿姆斯特丹", isp: "Hosting" },
  "193.32.162.10": { country: "俄罗斯", province: "莫斯科州", city: "莫斯科", isp: "Datacenter" },
  "104.21.5.6": { country: "美国", province: "加利福尼亚州", city: "旧金山", isp: "Cloudflare" },
  "1.94.108.77": { country: "中国", province: "四川省", city: "成都市", isp: "移动" },
};

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const RISK_LABEL = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "无明显风险" };
const FORMAT_LABEL = {
  nginx: "Nginx / Apache 访问日志",
  json: "JSON / JSONL",
  csv: "CSV 表格",
  kv: "Key=Value 日志",
  simulated: "模拟端口流量",
  unknown: "未识别格式",
  empty: "空输入",
};

const MAX_EVIDENCE = 5;
const MAX_EVIDENCE_CHARS = 420;
const PORT_SCAN_PORTS = 15;
const PORT_SCAN_WINDOW = 60;
const BRUTE_FORCE_FAILS = 8;
const FLOOD_REQ_PER_IP = 100;
const FLOOD_TOTAL = 500;

const SIGNATURES = {
  sql_injection: {
    name: "SQL 注入",
    severity: "high",
    mitre: "T1190",
    patterns: [
      /\bunion\s+select\b/i,
      /\bor\s+1\s*=\s*1\b/i,
      /'\s*or\s*'/i,
      /--(?:\s|$)/,
      /\binformation_schema\b/i,
      /\bsleep\s*\(/i,
      /\bbenchmark\s*\(/i,
      /\bselect\b[\s\S]{0,80}\bfrom\b/i,
      /\bconcat\s*\(/i,
      /\b0x[0-9a-f]{8,}\b/i,
      /\bxp_cmdshell\b/i,
      /\bwaitfor\s+delay\b/i,
    ],
  },
  xss: {
    name: "跨站脚本 XSS",
    severity: "high",
    mitre: "T1059.007",
    patterns: [
      /<script/i,
      /javascript:/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /<img[^>]+src/i,
      /document\.cookie/i,
      /alert\s*\(/i,
      /<svg/i,
      /%3cscript/i,
    ],
  },
  path_traversal: {
    name: "目录遍历 / 文件包含",
    severity: "high",
    mitre: "T1083",
    patterns: [
      /\.\.\//,
      /\.\.\\/,
      /%2e%2e%2f/i,
      /\/etc\/passwd/i,
      /\/etc\/shadow/i,
      /\\windows\\win\.ini/i,
      /php:\/\//i,
      /file:\/\//i,
      /\/proc\/self\/environ/i,
    ],
  },
  command_injection: {
    name: "命令注入",
    severity: "critical",
    mitre: "T1059",
    patterns: [
      /;\s*(?:cat|ls|id|whoami|uname|wget|curl)\b/i,
      /\|\s*(?:bash|sh|nc)\b/i,
      /`[^`]+`/,
      /\$\([^)]+\)/,
      /&&\s*(?:cat|wget|curl)\b/i,
      /\/bin\/(?:ba)?sh\b/i,
    ],
  },
  webshell: {
    name: "WebShell / 恶意上传",
    severity: "critical",
    mitre: "T1505.003",
    patterns: [
      /(?:eval|assert|system|passthru|shell_exec)\s*\(/i,
      /\.php\?.*=(?:eval|system)/i,
      /\bc99\.php\b/i,
      /\br57\.php\b/i,
      /(?:\.php|\.jsp|\.asp)x?;\.(?:jpg|png|gif)/i,
    ],
  },
};

const SCANNER_UA = [
  "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wfuzz",
  "hydra", "acunetix", "nessus", "openvas", "zgrab", "feroxbuster",
  "metasploit", "havij", "appscan", "w3af", "nuclei", "ffuf", "dirsearch",
  "burpsuite", "zaproxy",
];

const SENSITIVE_PATHS = [
  "/.git", "/.env", "/.svn", "/.aws", "/.ds_store", "/wp-admin",
  "/wp-login", "/phpmyadmin", "/admin", "/manager/html", "/config",
  "/backup", "/shell", "/actuator", "/console", "/solr", "/druid",
  "/server-status", "/debug",
];

const AUTH_PORTS = new Set([21, 22, 23, 25, 110, 143, 3389, 5900]);
const LOGIN_RE = /(?:login|signin|sign-in|auth|wp-login|admin|session)/i;

const ALIASES = {
  source_ip: "src_ip", sourceip: "src_ip", client_ip: "src_ip",
  clientip: "src_ip", remote_addr: "src_ip", remote_ip: "src_ip",
  ip: "src_ip", saddr: "src_ip", src: "src_ip", srcaddr: "src_ip",
  source_address: "src_ip",
  dest_ip: "dst_ip", destination_ip: "dst_ip", daddr: "dst_ip",
  dst: "dst_ip", dstaddr: "dst_ip", server_ip: "dst_ip",
  dest_address: "dst_ip",
  sport: "src_port", source_port: "src_port", spt: "src_port",
  dport: "dst_port", destination_port: "dst_port", dpt: "dst_port",
  port: "dst_port",
  proto: "protocol", request_method: "method", verb: "method",
  http_method: "method", uri: "url", request: "url", request_uri: "url",
  path: "url", http_request: "url",
  useragent: "user_agent", ua: "user_agent", agent: "user_agent",
  http_user_agent: "user_agent",
  status_code: "status", code: "status", response: "status",
  size: "bytes", length: "bytes", len: "bytes",
  bytes_sent: "bytes", body_bytes_sent: "bytes", resp_size: "bytes",
  time: "timestamp", ts: "timestamp", datetime: "timestamp",
  "@timestamp": "timestamp", date: "timestamp", event_time: "timestamp",
  tcp_flags: "flags", tcpflags: "flags",
};

const MONTHS = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

const NGINX_RE = new RegExp(
  '(?<ip>\\d{1,3}(?:\\.\\d{1,3}){3})\\s+\\S+\\s+\\S+\\s+\\[(?<time>[^\\]]+)\\]\\s+' +
  '"(?<method>[A-Z]+)\\s+(?<url>[^"]*?)\\s+HTTP/[\\d.]+"\\s+' +
  '(?<status>\\d{3})\\s+(?<bytes>\\d+|-)' +
  '(?:\\s+"(?<referer>[^"]*)"\\s+"(?<ua>[^"]*)")?'
);

function text(value) {
  return value === null || value === undefined ? "" : String(value);
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function toInt(value) {
  if (value === null || value === undefined || value === "-" || value === "") return null;
  const n = Number.parseInt(String(value).trim(), 10);
  return Number.isFinite(n) ? n : null;
}

export function parseTimestamp(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value <= 0) return null;
    return value > 1e11 ? value / 1000 : value;
  }
  const s = String(value).trim();
  if (!s || s === "-") return null;

  if (/^\d{13}$/.test(s)) return Number(s) / 1000;
  if (/^\d{10}(?:\.\d+)?$/.test(s)) return Number(s);

  const nginx = s.match(
    /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}))?$/
  );
  if (nginx) {
    const [, dd, mon, yyyy, hh, mm, ss, tz] = nginx;
    const month = MONTHS[mon.toLowerCase()];
    if (month === undefined) return null;
    const pad = (n) => String(n).padStart(2, "0");
    const iso = `${yyyy}-${pad(month + 1)}-${pad(dd)}T${hh}:${mm}:${ss}` +
      (tz ? `${tz.slice(0, 3)}:${tz.slice(3)}` : "");
    const ms = Date.parse(iso);
    return Number.isFinite(ms) ? ms / 1000 : null;
  }

  let candidate = s;
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?/.test(candidate)) {
    candidate = candidate.replace(" ", "T");
  }
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/.test(candidate)) {
    if (/[+-]\d{4}$/.test(candidate)) {
      candidate = `${candidate.slice(0, -5)}${candidate.slice(-5, -2)}:${candidate.slice(-2)}`;
    }
    const ms = Date.parse(candidate);
    return Number.isFinite(ms) ? ms / 1000 : null;
  }
  return null;
}

export function formatDateTime(epochSeconds) {
  if (!Number.isFinite(epochSeconds)) return "";
  const d = new Date(epochSeconds * 1000);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function formatClock(epochSeconds, withSeconds = false) {
  const d = new Date(epochSeconds * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return withSeconds
    ? `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
    : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function pathOf(url) {
  const s = text(url).trim();
  if (!s) return "/";
  try {
    const parsed = new URL(s, "http://sentinel.local");
    return parsed.pathname || "/";
  } catch {
    return s.split("?")[0].split("#")[0] || "/";
  }
}

function urlInfo(rawUrl) {
  const s = text(rawUrl).trim();
  if (!s) return {};
  try {
    const absolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(s);
    const parsed = new URL(s, "http://sentinel.local");
    const info = { path: `${parsed.pathname}${parsed.search}${parsed.hash}` };
    if (absolute) {
      info.host = parsed.hostname || null;
      info.port = parsed.port
        ? Number(parsed.port)
        : (parsed.protocol === "https:" ? 443 : 80);
      info.protocol = parsed.protocol.replace(":", "").toUpperCase();
    }
    return info;
  } catch {
    return {};
  }
}

export function normalizeRecord(input) {
  const out = {};
  if (!input || typeof input !== "object") return out;

  for (const [rawKey, rawValue] of Object.entries(input)) {
    if (rawValue === null || rawValue === undefined || rawValue === "" || rawValue === "-") continue;
    const key = ALIASES[text(rawKey).trim().toLowerCase()] || text(rawKey).trim().toLowerCase();
    out[key] = rawValue;
  }

  if (typeof out.url === "string" && /^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+/i.test(out.url)) {
    const parts = out.url.trim().split(/\s+/);
    if (parts.length >= 2) {
      if (!out.method) out.method = parts[0].toUpperCase();
      out.url = parts[1];
    }
  }

  for (const key of ["src_port", "dst_port", "status", "bytes"]) {
    if (key in out) {
      const n = toInt(out[key]);
      if (n === null) delete out[key];
      else out[key] = n;
    }
  }

  if (out.protocol !== undefined) {
    const p = text(out.protocol).trim().toUpperCase();
    out.protocol = p === "6" ? "TCP" : p === "17" ? "UDP" : p === "1" ? "ICMP" : p;
  }

  for (const key of ["src_ip", "dst_ip", "host", "method", "user_agent", "flags", "url"]) {
    if (out[key] !== undefined) out[key] = text(out[key]).trim();
  }
  if (out.method) out.method = out.method.toUpperCase();

  if (out.url) {
    const info = urlInfo(out.url);
    if (info.host && !out.host) out.host = info.host;
    if (info.port && !out.dst_port) out.dst_port = info.port;
    if (info.protocol && !out.protocol) out.protocol = info.protocol;
  }
  if (out.host && /:\d+$/.test(out.host) && !out.dst_port) {
    const port = Number(out.host.split(":").pop());
    if (Number.isFinite(port)) out.dst_port = port;
  }

  const epoch = parseTimestamp(out.timestamp);
  if (epoch !== null) out.epoch = epoch;

  return out;
}

function parseNginx(input) {
  const events = [];
  for (const line of input.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const m = NGINX_RE.exec(line);
    if (!m || !m.groups) continue;
    const g = m.groups;
    const info = urlInfo(g.url);
    events.push({
      timestamp: g.time,
      src_ip: g.ip,
      method: g.method,
      url: g.url,
      host: info.host || null,
      dst_port: info.port || null,
      status: toInt(g.status),
      bytes: toInt(g.bytes),
      user_agent: g.ua || null,
      protocol: "HTTP",
      epoch: parseTimestamp(g.time),
      raw: line.trim(),
    });
  }
  return events;
}

function parseJson(input) {
  let data;
  try {
    data = JSON.parse(input);
  } catch {
    return parseJsonLines(input);
  }
  let list;
  if (Array.isArray(data)) list = data;
  else if (data && typeof data === "object") {
    const nested = data.events || data.data || data.logs || data.records;
    list = Array.isArray(nested) ? nested : [data];
  } else {
    return [];
  }
  const events = [];
  for (const item of list) {
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const event = normalizeRecord(item);
    event.raw = JSON.stringify(item);
    events.push(event);
  }
  return events;
}

function parseJsonLines(input) {
  const events = [];
  for (const line of input.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const item = JSON.parse(trimmed);
      if (item && typeof item === "object" && !Array.isArray(item)) {
        const event = normalizeRecord(item);
        event.raw = trimmed;
        events.push(event);
      }
    } catch {
      // Not JSONL; the caller falls back to another parser.
    }
  }
  return events;
}

function splitCsvLine(line, delimiter) {
  const cells = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === delimiter) {
      cells.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  cells.push(current);
  return cells;
}

function detectDelimiter(line) {
  let best = ",";
  let bestCount = 0;
  for (const delimiter of [",", ";", "\t", "|"]) {
    let count = 0;
    let quoted = false;
    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      if (ch === '"') quoted = !quoted;
      else if (!quoted && ch === delimiter) count += 1;
    }
    if (count > bestCount) {
      best = delimiter;
      bestCount = count;
    }
  }
  return bestCount > 0 ? best : null;
}

function parseCsv(input) {
  const lines = input.split(/\r?\n/).filter((line) => line.trim());
  if (lines.length < 2) return [];
  const headerLine = lines[0].replace(/^\uFEFF/, "");
  const delimiter = detectDelimiter(headerLine);
  if (!delimiter) return [];
  const header = splitCsvLine(headerLine, delimiter).map((h) => h.trim());
  if (!header.length) return [];

  const events = [];
  for (let i = 1; i < lines.length; i += 1) {
    const cells = splitCsvLine(lines[i], delimiter);
    const record = {};
    header.forEach((key, index) => {
      record[key] = cells[index] ?? "";
    });
    const event = normalizeRecord(record);
    event.raw = lines[i].trim();
    events.push(event);
  }
  return events.some((e) => e.src_ip || e.dst_ip || e.url || e.status !== undefined) ? events : [];
}

function parseKeyValue(input) {
  const events = [];
  const pairRe = /([A-Za-z_][\w.-]*)=("[^"]*"|\S+)/g;
  for (const line of input.split(/\r?\n/)) {
    if (!line.trim() || !line.includes("=")) continue;
    const pairs = {};
    let match;
    pairRe.lastIndex = 0;
    while ((match = pairRe.exec(line)) !== null) {
      pairs[match[1]] = match[2].replace(/^"|"$/g, "");
    }
    if (!Object.keys(pairs).length) continue;
    const event = normalizeRecord(pairs);
    event.raw = line.trim();
    events.push(event);
  }
  return events;
}

export function sniffFormat(input) {
  const head = input.trim().split(/\r?\n/).slice(0, 8).join("\n");
  if (!head) return "empty";
  if (/^\s*[\[{]/.test(head)) return "json";
  if (NGINX_RE.test(head.split(/\r?\n/)[0])) return "nginx";
  const firstLine = head.split(/\r?\n/)[0];
  if (detectDelimiter(firstLine) && !firstLine.includes("=")) return "csv";
  if (firstLine.includes("=")) return "kv";
  return "unknown";
}

export function formatLabel(format) {
  return FORMAT_LABEL[format] || format || "未知格式";
}

export function parseLogs(input) {
  const source = text(input);
  if (!source.trim()) {
    return { events: [], format: "empty", truncated: false, formatLabel: FORMAT_LABEL.empty };
  }
  const sniffed = sniffFormat(source);
  const parsers = {
    nginx: parseNginx,
    json: parseJson,
    csv: parseCsv,
    kv: parseKeyValue,
  };
  const order = [sniffed, ...Object.keys(parsers).filter((key) => key !== sniffed && key !== "unknown")];
  for (const name of order) {
    const parser = parsers[name];
    if (!parser) continue;
    try {
      const events = parser(source);
      if (events.length) {
        const truncated = events.length > MAX_EVENTS;
        return {
          events: truncated ? events.slice(0, MAX_EVENTS) : events,
          format: name,
          truncated,
          formatLabel: FORMAT_LABEL[name],
        };
      }
    } catch {
      // Try the next parser.
    }
  }
  return { events: [], format: sniffed, truncated: false, formatLabel: formatLabel(sniffed) };
}

function evidenceOf(event) {
  const raw = event.raw || [
    event.src_ip, event.method, event.url, event.status,
  ].filter(Boolean).join(" ");
  return text(raw).replace(/\s+/g, " ").trim().slice(0, MAX_EVIDENCE_CHARS);
}

function addEvidence(list, event) {
  const value = evidenceOf(event);
  if (value && !list.includes(value) && list.length < MAX_EVIDENCE) list.push(value);
}

function validPort(port) {
  return Number.isFinite(port) && port > 0 && port < 65536;
}

function buildFinding(typeEn, meta, srcIps, evidence, count, extra = {}) {
  return {
    type: meta.name,
    type_en: typeEn,
    severity: meta.severity,
    mitre: meta.mitre || null,
    src_ips: [...new Set(srcIps.filter(Boolean))].sort().slice(0, 20),
    dst_ports: [...new Set((extra.dstPorts || []).filter(validPort))].sort((a, b) => a - b).slice(0, 20),
    count,
    first_seen: extra.first || null,
    last_seen: extra.last || null,
    description: `${meta.name} 行为。${extra.description || ""}`.trim(),
    evidence: evidence.slice(0, MAX_EVIDENCE),
  };
}

function signatureFindings(events) {
  const findings = [];
  for (const [typeEn, rule] of Object.entries(SIGNATURES)) {
    const byIp = new Map();
    const evidence = [];
    const ports = new Set();
    let first = null;
    let last = null;
    let firstEpoch = Infinity;
    let lastEpoch = -Infinity;

    for (const event of events) {
      const url = text(event.url);
      const decoded = safeDecode(url);
      const haystack = `${url} ${decoded} ${text(event.raw)}`.toLowerCase();
      if (!rule.patterns.some((pattern) => pattern.test(haystack))) continue;

      const ip = event.src_ip || "未知";
      if (!byIp.has(ip)) byIp.set(ip, []);
      byIp.get(ip).push(event);
      addEvidence(evidence, event);
      if (validPort(event.dst_port)) ports.add(event.dst_port);
      if (Number.isFinite(event.epoch)) {
        if (event.epoch < firstEpoch) {
          firstEpoch = event.epoch;
          first = event.timestamp || formatDateTime(event.epoch);
        }
        if (event.epoch > lastEpoch) {
          lastEpoch = event.epoch;
          last = event.timestamp || formatDateTime(event.epoch);
        }
      } else {
        if (first === null) first = event.timestamp || null;
        last = event.timestamp || last;
      }
    }

    if (!byIp.size) continue;
    const total = [...byIp.values()].reduce((sum, list) => sum + list.length, 0);
    findings.push(buildFinding(typeEn, rule, [...byIp.keys()], evidence, total, {
      dstPorts: [...ports],
      first,
      last,
      description: `特征命中 ${total} 次，涉及 ${byIp.size} 个来源 IP。`,
    }));
  }
  return findings;
}

function scannerFindings(events) {
  const findings = [];
  const uaHits = new Map();
  const uaTools = new Set();
  const pathHits = new Map();

  for (const event of events) {
    const ua = text(event.user_agent).toLowerCase();
    const ip = event.src_ip || "未知";
    for (const tool of SCANNER_UA) {
      if (!ua.includes(tool)) continue;
      if (!uaHits.has(ip)) uaHits.set(ip, []);
      uaHits.get(ip).push(event);
      uaTools.add(tool);
      break;
    }

    const path = safeDecode(pathOf(event.url)).toLowerCase();
    const matched = SENSITIVE_PATHS.find((sensitive) =>
      path === sensitive ||
      path.startsWith(`${sensitive}/`) ||
      path.startsWith(`${sensitive}.`)
    );
    if (matched) {
      if (!pathHits.has(ip)) pathHits.set(ip, new Map());
      if (!pathHits.get(ip).has(matched)) pathHits.get(ip).set(matched, event);
    }
  }

  if (uaHits.size) {
    const evidence = [];
    for (const list of uaHits.values()) {
      for (const event of list) addEvidence(evidence, event);
    }
    const total = [...uaHits.values()].reduce((sum, list) => sum + list.length, 0);
    findings.push(buildFinding("scanner_tool", {
      name: "自动化扫描器 / 攻击工具",
      severity: "high",
      mitre: "T1595",
    }, [...uaHits.keys()], evidence, total, {
      description: `检测到工具指纹：${[...uaTools].sort().join("、")}。`,
    }));
  }

  const heavy = new Map();
  for (const [ip, paths] of pathHits.entries()) {
    if (paths.size >= 3) heavy.set(ip, paths);
  }
  if (heavy.size) {
    const evidence = [];
    let totalPaths = 0;
    let totalHits = 0;
    for (const paths of heavy.values()) {
      totalPaths += paths.size;
      totalHits += paths.size;
      for (const event of paths.values()) addEvidence(evidence, event);
    }
    findings.push(buildFinding("sensitive_path_probe", {
      name: "敏感路径探测",
      severity: "medium",
      mitre: "T1595.003",
    }, [...heavy.keys()], evidence, totalHits, {
      description: `共探测 ${totalPaths} 个敏感路径，疑似目录或资产扫描。`,
    }));
  }

  return findings;
}

function portScanFindings(events) {
  const byIp = new Map();
  for (const event of events) {
    if (!event.src_ip || !validPort(event.dst_port)) continue;
    if (!byIp.has(event.src_ip)) byIp.set(event.src_ip, []);
    byIp.get(event.src_ip).push(event);
  }

  const offenders = [];
  let allPorts = new Set();
  const evidence = [];
  let first = null;
  let last = null;

  for (const [ip, points] of byIp.entries()) {
    const uniquePorts = new Set(points.map((p) => p.dst_port));
    if (uniquePorts.size < PORT_SCAN_PORTS) continue;

    let windowPoints = null;
    const timed = points
      .filter((p) => Number.isFinite(p.epoch))
      .sort((a, b) => a.epoch - b.epoch);

    if (timed.length >= PORT_SCAN_PORTS) {
      const counts = new Map();
      let left = 0;
      let best = 0;
      let bestLeft = 0;
      let bestRight = 0;
      for (let right = 0; right < timed.length; right += 1) {
        const port = timed[right].dst_port;
        counts.set(port, (counts.get(port) || 0) + 1);
        while (timed[right].epoch - timed[left].epoch > PORT_SCAN_WINDOW) {
          const leftPort = timed[left].dst_port;
          const next = (counts.get(leftPort) || 0) - 1;
          if (next <= 0) counts.delete(leftPort);
          else counts.set(leftPort, next);
          left += 1;
        }
        if (counts.size > best) {
          best = counts.size;
          bestLeft = left;
          bestRight = right;
        }
      }
      if (best >= PORT_SCAN_PORTS) {
        windowPoints = timed.slice(bestLeft, bestRight + 1);
      }
    } else if (uniquePorts.size >= PORT_SCAN_PORTS) {
      windowPoints = points;
    }

    if (!windowPoints) continue;
    offenders.push(ip);
    const ports = new Set(windowPoints.map((p) => p.dst_port));
    allPorts = new Set([...allPorts, ...ports]);
    for (const event of windowPoints.slice(0, MAX_EVIDENCE)) addEvidence(evidence, event);
    if (Number.isFinite(windowPoints[0]?.epoch)) {
      first = formatDateTime(windowPoints[0].epoch);
      last = formatDateTime(windowPoints[windowPoints.length - 1].epoch);
    }
  }

  if (!offenders.length) return [];
  return [buildFinding("port_scan", {
    name: "端口扫描",
    severity: "medium",
    mitre: "T1046",
  }, offenders, evidence, allPorts.size, {
    dstPorts: [...allPorts],
    first,
    last,
    description: `${PORT_SCAN_WINDOW} 秒窗口内探测了 ${allPorts.size} 个不同端口。`,
  })];
}

function bruteForceFindings(events) {
  const groups = new Map();
  for (const event of events) {
    const failed = event.status === 401 || event.status === 403;
    if (!failed) continue;

    const path = pathOf(event.url);
    const authPath = LOGIN_RE.test(path) || AUTH_PORTS.has(event.dst_port);
    if (!authPath) continue;

    const ip = event.src_ip || "未知";
    if (!groups.has(ip)) groups.set(ip, []);
    groups.get(ip).push(event);
  }

  const offenders = [];
  const evidence = [];
  let count = 0;
  const ports = new Set();
  let first = null;
  let last = null;

  for (const [ip, failures] of groups.entries()) {
    if (failures.length < BRUTE_FORCE_FAILS) continue;
    offenders.push(ip);
    count += failures.length;
    for (const event of failures.slice(0, MAX_EVIDENCE)) {
      addEvidence(evidence, event);
      if (validPort(event.dst_port)) ports.add(event.dst_port);
    }
    const times = failures.filter((e) => Number.isFinite(e.epoch)).sort((a, b) => a.epoch - b.epoch);
    if (times.length) {
      first = formatDateTime(times[0].epoch);
      last = formatDateTime(times[times.length - 1].epoch);
    }
  }

  if (!offenders.length) return [];
  return [buildFinding("brute_force", {
    name: "暴力破解",
    severity: "high",
    mitre: "T1110",
  }, offenders, evidence, count, {
    dstPorts: [...ports],
    first,
    last,
    description: `仅统计登录入口的 401/403 失败响应，成功登录与端口探测已排除；共 ${count} 次。`,
  })];
}

function floodFindings(events) {
  const byIp = new Map();
  const evidenceByIp = new Map();
  for (const event of events) {
    const ip = event.src_ip || "未知";
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(event);
    if (!evidenceByIp.has(ip)) evidenceByIp.set(ip, []);
    if (evidenceByIp.get(ip).length < 3) addEvidence(evidenceByIp.get(ip), event);
  }

  const total = events.length;
  const unique = byIp.size;
  const offenders = new Map();

  for (const [ip, list] of byIp.entries()) {
    const timed = list.filter((e) => Number.isFinite(e.epoch)).sort((a, b) => a.epoch - b.epoch);
    let peak = 0;
    let peakWindow = null;
    if (timed.length) {
      let left = 0;
      for (let right = 0; right < timed.length; right += 1) {
        while (timed[right].epoch - timed[left].epoch > 60) left += 1;
        const size = right - left + 1;
        if (size > peak) {
          peak = size;
          peakWindow = timed.slice(left, right + 1);
        }
      }
    }
    const amount = timed.length ? peak : list.length;
    if (amount >= FLOOD_REQ_PER_IP) offenders.set(ip, { amount, points: peakWindow || list });
  }

  if (!offenders.size && total >= FLOOD_TOTAL && unique <= 10) {
    for (const [ip, list] of byIp.entries()) {
      offenders.set(ip, { amount: list.length, points: list });
    }
  }

  if (!offenders.size) return [];
  const evidence = [];
  let count = 0;
  for (const { points } of offenders.values()) {
    count += points.length;
    for (const event of points.slice(0, MAX_EVIDENCE)) addEvidence(evidence, event);
  }
  return [buildFinding("dos_cc", {
    name: "CC / DDoS 高频请求",
    severity: "high",
    mitre: "T1498",
  }, [...offenders.keys()], evidence, count, {
    description: `短时间内观察到异常高的请求量（总计 ${total} 条，${unique} 个来源）。`,
  })];
}

export function detectAttacks(events) {
  if (!Array.isArray(events) || !events.length) return [];
  const findings = [
    ...signatureFindings(events),
    ...scannerFindings(events),
    ...portScanFindings(events),
    ...bruteForceFindings(events),
    ...floodFindings(events),
  ];
  return findings.sort((a, b) => {
    const rank = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
    return rank !== 0 ? rank : b.count - a.count;
  });
}

export function isPrivateIp(ip) {
  const value = text(ip).trim();
  if (!value) return false;
  if (value === "::1" || value.toLowerCase().startsWith("fe80:") || /^f[cd][0-9a-f]{2}:/i.test(value)) {
    return true;
  }
  const match = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  const octets = match.slice(1).map(Number);
  if (octets.some((n) => n > 255)) return false;
  const [a, b] = octets;
  return a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a >= 224;
}

export function geolocateIp(ip) {
  const value = text(ip).trim();
  const base = {
    ip: value || "未知",
    is_private: false,
    country: null,
    province: null,
    city: null,
    isp: null,
    source: "unknown",
    demo: false,
  };
  if (!value || value === "未知") return base;
  if (isPrivateIp(value)) {
    return {
      ...base,
      is_private: true,
      country: "内网 / 保留地址",
      province: "内网",
      source: "private",
    };
  }
  const demo = DEMO_GEO_MAP[value];
  if (demo) {
    return { ...base, ...demo, source: "demo", demo: true };
  }
  return base;
}

export function geolocateMany(ips) {
  const result = {};
  for (const ip of new Set(ips.filter(Boolean))) {
    result[ip] = geolocateIp(ip);
  }
  return result;
}

export function geoLabel(geo) {
  if (!geo) return "未知";
  if (geo.is_private) return "内网 / 保留地址";
  if (geo.source === "pending" || geo.pending) return "等待云端查询…";
  const parts = [geo.country, geo.province, geo.city].filter(Boolean);
  return parts.length ? parts.join(" · ") : "演示库未覆盖";
}

export function buildTimeline(events, findings) {
  const timed = events.filter((event) => Number.isFinite(event.epoch) && event.epoch > 0);
  if (timed.length < 2) return null;
  timed.sort((a, b) => a.epoch - b.epoch);
  const start = timed[0].epoch;
  const end = timed[timed.length - 1].epoch;
  const span = Math.max(end - start, 1);

  const nice = [5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 86400];
  let bucket = nice.find((value) => value >= span / 30) || 86400;
  while (Math.ceil(span / bucket) > 60) {
    bucket *= 2;
  }

  const attackIps = new Set(findings.flatMap((finding) => finding.src_ips || []));
  const buckets = new Map();
  for (const event of timed) {
    const index = Math.floor((event.epoch - start) / bucket);
    if (!buckets.has(index)) buckets.set(index, { total: 0, attack: 0 });
    const rec = buckets.get(index);
    rec.total += 1;
    if (event.src_ip && attackIps.has(event.src_ip)) rec.attack += 1;
  }

  const points = [...buckets.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([index, rec]) => {
      const t = start + index * bucket;
      return {
        t,
        label: bucket < 60 ? formatClock(t, true) : formatClock(t),
        total: rec.total,
        attack: rec.attack,
      };
    });

  return {
    start,
    end,
    span,
    bucket_seconds: bucket,
    bucket_label: bucket < 60 ? `${bucket} 秒` : bucket < 3600 ? `${bucket / 60} 分钟` : `${bucket / 3600} 小时`,
    points,
    max_total: Math.max(...points.map((p) => p.total), 1),
    max_attack: Math.max(...points.map((p) => p.attack), 1),
    timestamped_events: timed.length,
  };
}

function shortTypes(findings) {
  const types = [...new Set(findings.map((f) => f.type))];
  if (types.length <= 3) return types.join("、");
  return `${types.slice(0, 3).join("、")}等 ${types.length} 类`;
}

function typePhrase(findings) {
  const types = [...new Set(findings.map((f) => f.type))];
  const more = types.length > 3;
  const label = more
    ? `${types.slice(0, 3).join("、")}等 ${types.length} 类`
    : types.join("、");
  return `${label}${more ? "" : "等"}`;
}

function riskFor(findings) {
  if (!findings.length) return "无明显风险";
  const top = findings[0]?.severity || "info";
  return RISK_LABEL[top] || "中危";
}

function verdictFor(findings) {
  if (!findings.length) return "未发现明确攻击特征";
  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasHigh = findings.some((f) => f.severity === "high");
  const types = typePhrase(findings);
  if (hasCritical) return `检测到${types}高风险行为，存在明确的攻击迹象。`;
  if (hasHigh) return `检测到${types}可疑攻击行为，建议优先复核。`;
  return `发现${types}异常探测行为，需结合业务基线复核。`;
}

const REMEDIATION = {
  sql_injection: "对数据库访问统一使用参数化查询；在 WAF 上启用 SQL 注入规则并观察误报。",
  xss: "对输出做上下文编码并启用 CSP；为会话 Cookie 设置 HttpOnly 与 SameSite。",
  path_traversal: "对文件路径做白名单与规范化校验；限制 Web 进程访问系统敏感目录。",
  command_injection: "禁止把请求参数拼接进系统命令；使用安全 API 并做严格白名单。",
  webshell: "排查上传目录与近期文件变更；禁止上传目录执行脚本，删除可疑文件。",
  scanner_tool: "在边界临时封禁扫描源 IP；收敛服务指纹并启用 Bot / 速率防护。",
  sensitive_path_probe: "移除或保护 .git、.env、备份文件；管理后台增加强认证与来源限制。",
  port_scan: "收敛公网暴露端口；对扫描源限速或封禁，并检查 IDS 告警。",
  brute_force: "启用登录失败锁定、速率限制与多因素认证；封禁高频失败来源。",
  dos_cc: "启用限流与人机校验；接入 CDN / 抗 D 服务并对异常来源自动封禁。",
};

function recommendationsFor(findings) {
  const recommendations = [];
  for (const finding of findings) {
    const rec = REMEDIATION[finding.type_en];
    if (rec && !recommendations.includes(rec)) recommendations.push(rec);
  }
  if (findings.length) {
    const general = [
      "先复核报告中的证据行，确认是否为业务误报，再执行阻断。",
      "对命中来源 IP 临时封禁或限速，并保留原始日志与报告作为证据。",
      "检查同一时间窗内的认证、数据库与 WAF 日志，确认是否已造成影响。",
    ];
    for (const rec of general) {
      if (recommendations.length >= 6) break;
      if (!recommendations.includes(rec)) recommendations.push(rec);
    }
  } else {
    recommendations.push(
      "保持日志留存与定期审计，关注低频、长期、加密流量中的异常。",
      "收敛公网管理端口，给后台与数据库增加来源限制和强认证。",
      "结合业务基线设置告警阈值，避免只依赖固定特征规则。"
    );
  }
  return recommendations.slice(0, 6);
}

function summaryFor({ findings, events, geo, origins, stats, simulated, live, replay }) {
  const total = events.length;
  const unique = stats.unique_src_ips;
  const format = stats.format_label;
  const prefix = simulated
    ? "本次使用可复现的模拟端口流量，结论仅用于演示分析流程。"
    : replay
      ? "以下为实时回放快照，用于演示增量研判流程。"
      : live
        ? "以下为实时监视中的日志快照。"
        : "";

  if (!findings.length) {
    return `${prefix}共分析 ${total} 条事件、${unique} 个来源 IP（${format}）。规则引擎未命中已知攻击特征或异常行为阈值。` +
      "这不等于绝对安全：规则覆盖有限，建议结合业务基线、资产暴露面和更长时间窗继续复核。";
  }

  const ranked = (Array.isArray(origins) && origins.length ? origins : Object.values(geo))
    .filter((g) => g.province && !g.is_private)
    .sort((a, b) => (b.event_count || 0) - (a.event_count || 0))
    .slice(0, 3);
  const originText = ranked.length
    ? `主要来源：${ranked
      .map((g) => `${g.ip}（${geoLabel(g)}${g.demo ? "，演示" : g.source === "online" ? "，云端情报" : ""}）`)
      .join("；")}。`
    : "攻击源归属地未覆盖。";
  const top = RISK_LABEL[findings[0].severity] || "中危";
  const names = [...new Set(findings.map((f) => f.type))];
  const nameText = names.length > 3
    ? `${names.slice(0, 3).join("、")} 等`
    : names.join("、");
  return `${prefix}在 ${total} 条事件中命中 ${findings.length} 类行为（${nameText}），最高等级为${top}。` +
    `${originText}建议先复核证据，再按处置建议封禁、限速并加固对应入口。`;
}

function randomId() {
  let hex = "";
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const bytes = new Uint8Array(3);
    crypto.getRandomValues(bytes);
    hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  } else {
    hex = Math.random().toString(16).slice(2, 8);
  }
  return hex.toUpperCase();
}

export function buildReport({
  events,
  findings,
  geo,
  timeline,
  format,
  formatLabel: label,
  sourceLabel = "日志分析",
  fileName = "",
  simulated = false,
  truncated = false,
  trace = [],
  live = false,
  replay = false,
  reportId = "",
  alerts = [],
}) {
  const uniqueSources = new Set(events.map((e) => e.src_ip).filter(Boolean));
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
  }

  const attackerIps = [...new Set(findings.flatMap((f) => f.src_ips || []))];
  const attackerSet = new Set(attackerIps);
  const usage = new Map();
  for (const event of events) {
    const ip = event.src_ip;
    if (!ip || !attackerSet.has(ip)) continue;
    const row = usage.get(ip) || {
      event_count: 0,
      first_epoch: null,
      last_epoch: null,
      first_seen: null,
      last_seen: null,
    };
    row.event_count += 1;
    if (Number.isFinite(event.epoch)) {
      if (row.first_epoch === null || event.epoch < row.first_epoch) {
        row.first_epoch = event.epoch;
        row.first_seen = event.timestamp || row.first_seen;
      }
      if (row.last_epoch === null || event.epoch > row.last_epoch) {
        row.last_epoch = event.epoch;
        row.last_seen = event.timestamp || row.last_seen;
      }
    }
    if (!row.first_seen && event.timestamp) row.first_seen = event.timestamp;
    if (event.timestamp) row.last_seen = event.timestamp;
    usage.set(ip, row);
  }

  const findingTypes = new Map();
  for (const finding of findings) {
    for (const ip of finding.src_ips || []) {
      if (!findingTypes.has(ip)) findingTypes.set(ip, []);
      findingTypes.get(ip).push(finding.type);
    }
  }

  const origins = attackerIps
    .map((ip) => {
      const base = geo[ip] || geolocateIp(ip);
      const row = usage.get(ip) || {};
      return {
        ...base,
        event_count: row.event_count || 0,
        first_seen: row.first_seen || null,
        last_seen: row.last_seen || null,
        finding_types: [...new Set(findingTypes.get(ip) || [])].slice(0, 6),
      };
    })
    .sort((a, b) => {
      if (a.is_private !== b.is_private) return a.is_private ? 1 : -1;
      const byEvents = (b.event_count || 0) - (a.event_count || 0);
      return byEvents !== 0 ? byEvents : text(a.ip).localeCompare(text(b.ip));
    });
  const resolved = origins.filter((o) => o.province && !o.is_private).length;
  const demoGeo = origins.filter((o) => o.demo).length;
  const cloudGeo = origins.filter((o) => o.source === "online").length;
  const attackerEvents = events.filter((e) => e.src_ip && attackerIps.includes(e.src_ip)).length;
  const timestamped = events.filter((e) => Number.isFinite(e.epoch)).length;
  const epochs = events.filter((e) => Number.isFinite(e.epoch)).map((e) => e.epoch);
  const start = epochs.length ? Math.min(...epochs) : null;
  const end = epochs.length ? Math.max(...epochs) : null;

  const stats = {
    total_events: events.length,
    unique_src_ips: uniqueSources.size,
    finding_count: findings.length,
    attacker_events: attackerEvents,
    timestamped_events: timestamped,
    geo_resolved: resolved,
    demo_geo: demoGeo,
    cloud_geo: cloudGeo,
    alert_count: Array.isArray(alerts) ? alerts.length : 0,
    severity_counts: severityCounts,
    format: format || "unknown",
    format_label: label || formatLabel(format),
  };

  const limitations = [];
  if (simulated) limitations.push("端口监测使用模拟流量，不代表真实网络状态；云端无法直接抓取网卡流量。");
  limitations.push("IP 归属地只代表网络出口的大致位置，无法定位具体个人，也不能单独作为法律证据。");
  if (demoGeo) limitations.push("部分归属地来自内置演示库，仅覆盖样例 IP；演示数据不可用于真实取证。");
  if (cloudGeo) {
    limitations.push("云端归属地来自第三方 GeoIP（ipwho.is），为城市级估算，VPN、代理、NAT 与 CDN 会降低准确性。");
  }
  limitations.push(
    "规则引擎基于特征与阈值，未知攻击、加密流量和低速长期攻击可能漏检。",
    "时间戳按浏览器所在时区换算并显示，原始日志的时区信息未单独保留。",
    "结论只覆盖已提供日志的时间范围与字段，不能代表资产的全部安全状态。",
  );
  if (live) {
    limitations.push("实时追踪只监视当前选择的日志文件并在浏览器内重新研判；需保持页面打开，日志轮转或文件被替换后应重新选择。");
    if (Array.isArray(alerts) && alerts.length) {
      limitations.push("实时告警只比较页面会话内的相邻快照，首个快照仅作基线不触发告警；刷新页面或重新选择文件后告警历史会清空。");
    }
  }
  if (replay) limitations.push("当前为内置攻击样例的时间回放，仅用于演示实时分析流程，不代表真实网络状态。");
  if (truncated) limitations.push(`单次最多分析 ${MAX_EVENTS} 条事件，超出部分未参与本次研判。`);
  if (!timestamped) limitations.push("日志缺少可解析时间戳，端口扫描、暴破和 CC 规则退化为全量计数。");

  const report = {
    report_id: reportId || `SNT-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${randomId()}`,
    generated_at: formatDateTime(Date.now() / 1000),
    engine: replay
      ? "Sentinel Rule Engine 2.0 · 浏览器实时回放"
      : live
        ? "Sentinel Rule Engine 2.0 · 浏览器实时"
        : "Sentinel Rule Engine 2.0 · 浏览器端",
    data_mode: sourceLabel,
    file_name: fileName,
    simulated,
    live: Boolean(live),
    replay: Boolean(replay),
    truncated,
    verdict: verdictFor(findings),
    risk_level: riskFor(findings),
    attack_detected: findings.length > 0,
    summary: summaryFor({
      findings,
      events,
      geo,
      origins,
      stats,
      simulated,
      live,
      replay,
    }),
    time_range: {
      start: start !== null ? formatDateTime(start) : (events[0]?.timestamp || null),
      end: end !== null ? formatDateTime(end) : (events[events.length - 1]?.timestamp || null),
    },
    findings,
    attacker_origins: origins,
    alerts: Array.isArray(alerts) ? alerts : [],
    recommendations: recommendationsFor(findings),
    stats,
    timeline,
    trace,
    limitations,
  };

  return report;
}

function mulberry32(seed) {
  let value = seed >>> 0;
  return () => {
    value += 0x6D2B79F5;
    let t = value;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function simulatePortCapture(port, duration = 15, host = "demo.local") {
  const target = validPort(port) ? port : 80;
  const seconds = Math.min(Math.max(Number(duration) || 15, 5), 60);
  const rand = mulberry32(20260615 + target);
  const events = [];
  const end = Date.now() / 1000;
  const start = end - seconds;
  let cursor = start;

  const push = (event) => {
    const epoch = Math.min(cursor, end);
    events.push({
      ...event,
      timestamp: formatDateTime(epoch),
      epoch,
      dst_ip: "10.0.0.10",
    });
  };

  const benignIp = "59.110.23.88";
  const benignUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36";
  const benignPaths = ["/", "/index.html", "/api/v1/products", "/static/app.js", "/static/app.css"];
  for (let i = 0; i < 15; i += 1) {
    const path = benignPaths[Math.floor(rand() * benignPaths.length)];
    push({
      src_ip: benignIp,
      src_port: 20000 + Math.floor(rand() * 40000),
      dst_port: target,
      protocol: "HTTP",
      method: "GET",
      url: path,
      status: 200,
      bytes: 200 + Math.floor(rand() * 3800),
      user_agent: benignUa,
      host,
      raw: `${benignIp} - - "GET ${path} HTTP/1.1" 200 ${200 + Math.floor(rand() * 3800)} "-" "${benignUa}"`,
    });
    cursor += 0.15 + rand() * 0.35;
  }

  const scannerIp = "221.226.13.45";
  const ports = [];
  while (ports.length < 24) {
    const candidate = 1 + Math.floor(rand() * 1023);
    if (!ports.includes(candidate)) ports.push(candidate);
  }
  for (const targetPort of ports) {
    push({
      src_ip: scannerIp,
      src_port: 40000 + Math.floor(rand() * 20000),
      dst_port: targetPort,
      protocol: "TCP",
      flags: "S",
      bytes: 60,
      raw: `${scannerIp}.${40000 + Math.floor(rand() * 20000)} > 10.0.0.10.${targetPort}: Flags [S]`,
    });
    cursor += 0.08;
  }

  const payloads = [
    ["GET", "/product?id=1' UNION SELECT username,password FROM users--", 200, "113.108.182.66", "sqlmap/1.7.2#stable (http://sqlmap.org)"],
    ["GET", "/search?q=<script>alert(document.cookie)</script>", 200, "45.155.205.99", "Mozilla/5.0 (X11; Linux x86_64)"],
    ["GET", "/comment?text=<img src=x onerror=alert(1)>", 200, "45.155.205.99", "Mozilla/5.0 (X11; Linux x86_64)"],
    ["GET", "/download?file=../../../../etc/passwd", 404, "45.155.205.99", "Mozilla/5.0 (X11; Linux x86_64)"],
    ["GET", "/api/ping?host=127.0.0.1;cat /etc/passwd", 500, "45.155.205.99", "Mozilla/5.0 (X11; Linux x86_64)"],
    ["GET", "/.env", 404, "193.32.162.10", "python-requests/2.31.0"],
    ["GET", "/.git/config", 404, "193.32.162.10", "python-requests/2.31.0"],
    ["GET", "/wp-login.php", 403, "193.32.162.10", "python-requests/2.31.0"],
  ];
  for (const [method, path, status, ip, ua] of payloads) {
    push({
      src_ip: ip,
      src_port: 20000 + Math.floor(rand() * 40000),
      dst_port: target,
      protocol: "HTTP",
      method,
      url: path,
      status,
      bytes: 150 + Math.floor(rand() * 700),
      user_agent: ua,
      host,
      raw: `${ip} - - "${method} ${path} HTTP/1.1" ${status} - "-" "${ua}"`,
    });
    cursor += 0.2 + rand() * 0.4;
  }

  const bruteIp = "171.12.66.190";
  for (let i = 0; i < 12; i += 1) {
    const success = i === 11;
    push({
      src_ip: bruteIp,
      src_port: 20000 + Math.floor(rand() * 40000),
      dst_port: target,
      protocol: "HTTP",
      method: "POST",
      url: "/admin/login",
      status: success ? 200 : 401,
      bytes: success ? 980 : 120,
      user_agent: "python-requests/2.31.0",
      host,
      raw: `${bruteIp} - - "POST /admin/login HTTP/1.1" ${success ? 200 : 401} - "-" "python-requests/2.31.0"`,
    });
    cursor += 0.35;
  }

  events.sort((a, b) => a.epoch - b.epoch);
  return events;
}
