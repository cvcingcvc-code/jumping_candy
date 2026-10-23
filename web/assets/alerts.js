const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const ALERT_KIND_LABELS = {
  new_finding: "新攻击类型",
  new_attacker: "新攻击源",
};

function rank(severity) {
  return SEVERITY_RANK[severity] ?? 9;
}

function key(finding) {
  return finding?.type_en || finding?.type || "";
}

function unique(values) {
  return [...new Set((values || []).filter(Boolean))];
}

function summarizeIps(ips, max = 3) {
  const list = unique(ips);
  if (!list.length) return "来源未记录";
  if (list.length <= max) return list.join("、");
  return `${list.slice(0, max).join("、")} 等 ${list.length} 个来源`;
}

export function deriveAlerts(previous, current) {
  if (!previous || !current) return [];

  const previousTypes = new Map((previous.findings || []).map((finding) => [key(finding), finding]));
  const previousIps = new Set(previous.attackerIps || []);
  const counts = current.counts instanceof Map ? current.counts : new Map();
  const at = Number.isFinite(current.at) ? current.at : Date.now();
  const alerts = [];

  for (const finding of current.findings || []) {
    if (previousTypes.has(key(finding))) continue;
    const ips = unique(finding.src_ips);
    alerts.push({
      id: `${at}-finding-${key(finding)}`,
      kind: "new_finding",
      severity: finding.severity || "info",
      title: `新增${finding.type || "攻击行为"}`,
      detail: `${finding.count || 0} 次命中 · ${summarizeIps(ips)}`,
      finding_type: key(finding),
      ips: ips.slice(0, 6),
      count: finding.count || 0,
      at,
    });
  }

  for (const ip of current.attackerIps || []) {
    if (previousIps.has(ip)) continue;
    const knownHits = (current.findings || []).filter(
      (finding) => previousTypes.has(key(finding)) && (finding.src_ips || []).includes(ip)
    );
    if (!knownHits.length) continue;
    const top = [...knownHits].sort((a, b) => rank(a.severity) - rank(b.severity))[0];
    const eventCount = counts.get(ip) || 0;
    alerts.push({
      id: `${at}-attacker-${ip}`,
      kind: "new_attacker",
      severity: top.severity || "info",
      title: `新攻击源 ${ip}`,
      detail: `${knownHits.slice(0, 2).map((finding) => finding.type).join("、") || "已知攻击"} · ${eventCount} 条事件`,
      finding_type: key(top),
      ips: [ip],
      count: eventCount,
      at,
    });
  }

  return alerts.sort((a, b) => rank(a.severity) - rank(b.severity) || a.title.localeCompare(b.title));
}
