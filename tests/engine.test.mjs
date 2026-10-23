import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  MAX_EVENTS,
  SAMPLE_CATALOG,
  DETECTION_RULES,
  parseLogs,
  detectAttacks,
  geolocateIp,
  geolocateMany,
  geoLabel,
  buildTimeline,
  buildReport,
  simulatePortCapture,
} from "../web/assets/engine.js";

const here = dirname(fileURLToPath(import.meta.url));
const sample = (name) => readFileSync(join(here, "..", "web", "data", "samples", name), "utf8");
const analyze = (text) => {
  const parsed = parseLogs(text);
  const findings = detectAttacks(parsed.events);
  const attackerIps = [...new Set(findings.flatMap((finding) => finding.src_ips))];
  const geo = geolocateMany(attackerIps);
  const timeline = buildTimeline(parsed.events, findings);
  const report = buildReport({
    events: parsed.events,
    findings,
    geo,
    timeline,
    format: parsed.format,
    formatLabel: parsed.formatLabel,
    sourceLabel: "测试",
    fileName: "sample",
  });
  return { parsed, findings, geo, timeline, report };
};
const finding = (findings, type) => findings.find((item) => item.type === type);

test("sample catalog and rule list stay aligned with the UI", () => {
  assert.equal(SAMPLE_CATALOG.length, 4);
  assert.equal(DETECTION_RULES.length, 10);
  assert.equal(MAX_EVENTS, 20000);
  const tones = SAMPLE_CATALOG.map((item) => item.tone);
  assert.deepEqual(tones, ["critical", "warning", "scan", "normal"]);
});

test("web attack sample detects SQLi, XSS, traversal, command injection, scanner and probing", () => {
  const { parsed, findings, report } = analyze(sample("web_attack_nginx.log"));
  assert.equal(parsed.format, "nginx");
  assert.equal(parsed.events.length, 15);

  const names = findings.map((item) => item.type);
  assert.ok(names.includes("SQL 注入"));
  assert.ok(names.includes("跨站脚本 XSS"));
  assert.ok(names.includes("目录遍历 / 文件包含"));
  assert.ok(names.includes("命令注入"));
  assert.ok(names.includes("自动化扫描器 / 攻击工具"));
  assert.ok(names.includes("敏感路径探测"));
  assert.equal(finding(findings, "SQL 注入").count, 3);
  assert.equal(finding(findings, "跨站脚本 XSS").count, 2);

  for (const item of findings) {
    assert.ok(item.src_ips.length > 0, `${item.type} should expose attacker IPs`);
    assert.ok(item.evidence.length > 0, `${item.type} should retain evidence lines`);
    assert.ok(item.evidence.every((line) => line.length <= 420));
    assert.ok(["critical", "high", "medium", "low", "info"].includes(item.severity));
  }

  assert.equal(report.risk_level, "严重");
  assert.equal(report.stats.total_events, 15);
  assert.equal(report.stats.unique_src_ips, 4);
  assert.equal(report.stats.demo_geo, 3);
  assert.ok(report.attacker_origins.every((origin) => origin.demo === true));
  assert.ok(report.timeline);
  assert.equal(report.timeline.timestamped_events, 15);
  assert.ok(!report.verdict.includes("类 等"));
  assert.match(report.summary, /在 15 条事件中命中 6 类行为/);
  assert.ok(report.recommendations.length > 0 && report.recommendations.length <= 6);
});

test("successful login is excluded from brute-force counting", () => {
  const { parsed, findings } = analyze(sample("brute_force_ssh.log"));
  assert.equal(parsed.events.length, 12);
  const brute = finding(findings, "暴力破解");
  assert.ok(brute, "expected a brute-force finding");
  assert.equal(brute.count, 10);
  assert.equal(brute.severity, "high");
  assert.deepEqual(brute.src_ips, ["171.12.66.190"]);
  assert.ok(brute.evidence.every((line) => !line.includes(" 200 ")));
  assert.equal(findings.length, 1);
});

test("port scan sample is detected without a brute-force false positive", () => {
  const { parsed, findings } = analyze(sample("port_scan_capture.csv"));
  assert.equal(parsed.format, "csv");
  assert.equal(parsed.events.length, 25);
  assert.equal(parsed.events.filter((event) => event.src_ip === "221.226.13.45").length, 24);

  const scan = finding(findings, "端口扫描");
  assert.ok(scan);
  assert.equal(scan.count, 24);
  assert.equal(scan.severity, "medium");
  assert.deepEqual(scan.src_ips, ["221.226.13.45"]);
  assert.equal(finding(findings, "暴力破解"), undefined);
  assert.equal(findings.length, 1);
});

test("normal traffic raises no findings", () => {
  const { parsed, findings, report } = analyze(sample("normal_traffic.log"));
  assert.equal(parsed.events.length, 18);
  assert.equal(findings.length, 0);
  assert.equal(report.risk_level, "无明显风险");
  assert.equal(report.attack_detected, false);
  assert.equal(report.verdict, "未发现明确攻击特征");
  assert.equal(report.stats.geo_resolved, 0);
  assert.equal(report.attacker_origins.length, 0);
  assert.equal(report.recommendations.length, 3);
});

test("JSON array, JSONL and key=value inputs are normalized", () => {
  const json = JSON.stringify([
    { timestamp: "2026-06-15T10:00:00+08:00", src_ip: "10.0.0.5", dst_port: 443, status: 200, url: "/" },
    { timestamp: "2026-06-15T10:00:05+08:00", src_ip: "10.0.0.5", dst_port: 443, status: 401, url: "/login" },
  ]);
  const parsedJson = parseLogs(json);
  assert.equal(parsedJson.format, "json");
  assert.equal(parsedJson.events.length, 2);
  assert.equal(parsedJson.events[1].status, 401);
  assert.ok(Number.isFinite(parsedJson.events[0].epoch));

  const jsonl = [
    JSON.stringify({ src_ip: "1.2.3.4", dst_port: "22", status: "401", url: "/admin/login", method: "post" }),
    JSON.stringify({ src_ip: "1.2.3.4", dst_port: "22", status: "200", url: "/admin/login" }),
  ].join("\n");
  const parsedJsonl = parseLogs(jsonl);
  assert.equal(parsedJsonl.format, "json");
  assert.equal(parsedJsonl.events.length, 2);
  assert.equal(parsedJsonl.events[0].dst_port, 22);
  assert.equal(parsedJsonl.events[0].method, "POST");

  const kv = [
    'src_ip=198.51.100.9 dst_port=3389 status=401 url=/admin/login user_agent="python-requests/2.31.0"',
    "src_ip=198.51.100.9 dst_port=3389 status=200 url=/admin/login",
  ].join("\n");
  const parsedKv = parseLogs(kv);
  assert.equal(parsedKv.format, "kv");
  assert.equal(parsedKv.events.length, 2);
  assert.equal(parsedKv.events[0].src_ip, "198.51.100.9");
  assert.equal(parsedKv.events[0].dst_port, 3389);
});

test("CSV parser handles quoted fields and timestamps", () => {
  const csv = [
    "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,flags,bytes",
    '2026-06-15T03:05:01,203.0.113.7,10.0.0.10,51001,22,TCP,S,60',
    '2026-06-15T03:05:02,203.0.113.7,10.0.0.10,51002,443,TCP,"PA, ACK",512',
  ].join("\n");
  const parsed = parseLogs(csv);
  assert.equal(parsed.format, "csv");
  assert.equal(parsed.events.length, 2);
  assert.equal(parsed.events[1].flags, "PA, ACK");
  assert.equal(parsed.events[1].bytes, 512);
  assert.ok(Number.isFinite(parsed.events[0].epoch));
});

test("signature detection decodes URL-encoded payloads", () => {
  const line = '1.2.3.4 - - [15/Jun/2026:10:00:00 +0800] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 100 "-" "Mozilla/5.0"';
  const parsed = parseLogs(line);
  assert.equal(parsed.events.length, 1);
  const findings = detectAttacks(parsed.events);
  assert.ok(findings.some((item) => item.type === "跨站脚本 XSS"));
});

test("geolocation is explicit about demo, private and unknown sources", () => {
  const demo = geolocateIp("113.108.182.66");
  assert.equal(demo.source, "demo");
  assert.equal(demo.demo, true);
  assert.match(geoLabel(demo), /广东省/);

  const privateIp = geolocateIp("192.168.1.10");
  assert.equal(privateIp.is_private, true);
  assert.equal(privateIp.source, "private");
  assert.equal(privateIp.demo, false);
  assert.equal(geoLabel(privateIp), "内网 / 保留地址");

  const unknown = geolocateIp("203.0.113.5");
  assert.equal(unknown.source, "unknown");
  assert.equal(unknown.demo, false);
  assert.equal(geoLabel(unknown), "演示库未覆盖");
  assert.equal(geoLabel({ source: "pending", pending: true }), "等待云端查询…");
});

test("attacker origins carry event volume, time window and finding types", () => {
  const { report } = analyze(sample("web_attack_nginx.log"));
  assert.ok(report.attacker_origins.length >= 3);
  for (const origin of report.attacker_origins) {
    assert.ok(origin.event_count > 0, `${origin.ip} should carry event count`);
    assert.ok(origin.finding_types.length > 0, `${origin.ip} should expose finding types`);
    assert.ok(origin.first_seen, `${origin.ip} should have first seen`);
    assert.ok(origin.last_seen, `${origin.ip} should have last seen`);
  }
  const sorted = [...report.attacker_origins].sort((a, b) => b.event_count - a.event_count);
  assert.deepEqual(
    report.attacker_origins.map((origin) => origin.ip),
    sorted.map((origin) => origin.ip)
  );
});

test("online provenance is counted and disclosed", () => {
  const { parsed, findings, geo, timeline } = analyze(sample("brute_force_ssh.log"));
  const enriched = {
    ...geo,
    "171.12.66.190": {
      ip: "171.12.66.190",
      country: "中国",
      province: "河南省",
      city: "郑州市",
      isp: "Chinanet",
      org: "Chinanet Henan",
      asn: "AS4134",
      network_kind: "broadband",
      source: "online",
      demo: false,
      provider: "ipwho.is",
      confidence: "城市级估算",
    },
  };
  const report = buildReport({
    events: parsed.events,
    findings,
    geo: enriched,
    timeline,
    format: parsed.format,
    formatLabel: parsed.formatLabel,
  });
  assert.equal(report.stats.cloud_geo, 1);
  assert.equal(report.stats.demo_geo, 0);
  assert.equal(report.attacker_origins[0].source, "online");
  assert.ok(report.limitations.some((item) => item.includes("ipwho.is")));
  assert.ok(!report.limitations.some((item) => item.includes("内置演示库")));
});

test("live and replay reports flag their mode and keep explicit limitations", () => {
  const { parsed, findings, geo, timeline } = analyze(sample("brute_force_ssh.log"));
  const common = {
    events: parsed.events,
    findings,
    geo,
    timeline,
    format: parsed.format,
    formatLabel: parsed.formatLabel,
    sourceLabel: "实时监视 · access.log",
    fileName: "access.log",
    live: true,
  };

  const live = buildReport({ ...common, reportId: "SNT-20261023-ABC123" });
  assert.equal(live.report_id, "SNT-20261023-ABC123");
  assert.equal(live.live, true);
  assert.equal(live.replay, false);
  assert.match(live.engine, /浏览器实时/);
  assert.ok(live.summary.startsWith("以下为实时监视中的日志快照。"));
  assert.ok(live.limitations.some((item) => item.includes("实时追踪")));

  const replay = buildReport({ ...common, replay: true });
  assert.equal(replay.replay, true);
  assert.match(replay.engine, /回放/);
  assert.ok(replay.summary.startsWith("以下为实时回放快照"));
  assert.ok(replay.limitations.some((item) => item.includes("回放")));
});

test("live reports carry session alerts and disclose their scope", () => {
  const { parsed, findings, geo, timeline } = analyze(sample("web_attack_nginx.log"));
  const alerts = [
    {
      id: "1-finding-sqli",
      kind: "new_finding",
      severity: "critical",
      title: "新增SQL 注入",
      detail: "2 次命中 · 8.8.8.8",
      finding_type: "sqli",
      ips: ["8.8.8.8"],
      count: 2,
      at: 1,
    },
  ];
  const common = {
    events: parsed.events,
    findings,
    geo,
    timeline,
    format: parsed.format,
    formatLabel: parsed.formatLabel,
    sourceLabel: "实时监视 · access.log",
    fileName: "access.log",
    live: true,
  };

  const withAlerts = buildReport({ ...common, alerts });
  assert.deepEqual(withAlerts.alerts, alerts);
  assert.equal(withAlerts.stats.alert_count, 1);
  assert.ok(withAlerts.limitations.some((item) => item.includes("实时告警只比较")));

  const withoutAlerts = buildReport({ ...common });
  assert.equal(withAlerts.alerts[0].severity, "critical");
  assert.deepEqual(withoutAlerts.alerts, []);
  assert.equal(withoutAlerts.stats.alert_count, 0);
  assert.ok(!withoutAlerts.limitations.some((item) => item.includes("实时告警只比较")));
});

test("timeline aggregates events into readable buckets", () => {
  const { parsed, findings } = analyze(sample("web_attack_nginx.log"));
  const timeline = buildTimeline(parsed.events, findings);
  assert.ok(timeline.points.length >= 2 && timeline.points.length <= 60);
  assert.equal(timeline.points.reduce((sum, point) => sum + point.total, 0), 15);
  assert.ok(timeline.points.every((point) => point.attack <= point.total));
  assert.equal(timeline.bucket_seconds, 15);
  assert.equal(buildTimeline([], []), null);
});

test("report carries trace, limitations and truncation context", () => {
  const { parsed, findings, geo, timeline } = analyze(sample("brute_force_ssh.log"));
  const report = buildReport({
    events: parsed.events,
    findings,
    geo,
    timeline,
    format: parsed.format,
    formatLabel: parsed.formatLabel,
    sourceLabel: "示例日志",
    fileName: "brute_force_ssh.log",
    trace: [{ label: "数据源", detail: "示例日志" }],
    truncated: true,
  });
  assert.match(report.report_id, /^SNT-\d{8}-[0-9A-F]{6}$/);
  assert.equal(report.data_mode, "示例日志");
  assert.equal(report.file_name, "brute_force_ssh.log");
  assert.equal(report.truncated, true);
  assert.ok(report.trace.length === 1);
  assert.ok(report.limitations.some((item) => item.includes("20000")));
  assert.ok(report.limitations.some((item) => item.includes("归属地")));
  assert.ok(report.limitations.some((item) => item.includes("时区")));
  assert.match(report.time_range.start, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
});

test("simulated port capture is reproducible and exercises the full pipeline", () => {
  const first = simulatePortCapture(80, 15, "demo.local");
  const second = simulatePortCapture(80, 15, "demo.local");
  assert.equal(first.length, 59);
  assert.deepEqual(
    first.map((event) => [event.src_ip, event.dst_port, event.status]),
    second.map((event) => [event.src_ip, event.dst_port, event.status])
  );

  const findings = detectAttacks(first);
  const scan = finding(findings, "端口扫描");
  const brute = finding(findings, "暴力破解");
  assert.ok(scan && scan.count === 24);
  assert.ok(brute && brute.count === 11);
  assert.ok(findings.some((item) => item.type === "SQL 注入"));
  assert.ok(findings.some((item) => item.type === "命令注入"));

  const timeline = buildTimeline(first, findings);
  const report = buildReport({
    events: first,
    findings,
    geo: geolocateMany([...new Set(findings.flatMap((item) => item.src_ips))]),
    timeline,
    format: "simulated",
    formatLabel: "模拟端口流量",
    sourceLabel: "端口模拟 · :80 / 15s",
    simulated: true,
  });
  assert.equal(report.simulated, true);
  assert.ok(report.summary.startsWith("本次使用可复现的模拟端口流量"));
  assert.ok(report.limitations[0].includes("模拟流量"));
});
