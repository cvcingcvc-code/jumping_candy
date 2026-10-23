import { test } from "node:test";
import assert from "node:assert/strict";

import { ALERT_KIND_LABELS, deriveAlerts } from "../web/assets/alerts.js";

const AT = 1_700_000_000_000;

const finding = (type, typeEn, severity, count, ips) => ({
  type,
  type_en: typeEn,
  severity,
  count,
  src_ips: ips,
});

const snapshot = (findings, attackerIps, counts = []) => ({
  findings,
  attackerIps,
  counts: new Map(counts),
  at: AT,
});

test("alert derivation needs both sides of the diff", () => {
  const current = snapshot([finding("SQL 注入", "sqli", "critical", 2, ["8.8.8.8"])], ["8.8.8.8"]);
  assert.deepEqual(deriveAlerts(null, current), []);
  assert.deepEqual(deriveAlerts(current, null), []);
  assert.deepEqual(deriveAlerts({}, {}), []);
});

test("an identical snapshot produces no alerts, so the first one stays a baseline", () => {
  const base = snapshot([finding("SQL 注入", "sqli", "critical", 2, ["8.8.8.8"])], ["8.8.8.8"], [
    ["8.8.8.8", 5],
  ]);
  assert.deepEqual(deriveAlerts(base, snapshot(base.findings, base.attackerIps, base.counts)), []);
});

test("a new attack type raises one alert with count and sources", () => {
  const previous = snapshot([finding("SQL 注入", "sqli", "critical", 2, ["8.8.8.8"])], ["8.8.8.8"]);
  const current = snapshot(
    [
      finding("SQL 注入", "sqli", "critical", 3, ["8.8.8.8"]),
      finding("XSS 跨站脚本", "xss", "high", 4, ["1.1.1.1", "2.2.2.2"]),
    ],
    ["8.8.8.8", "1.1.1.1", "2.2.2.2"]
  );

  const alerts = deriveAlerts(previous, current);
  assert.equal(alerts.length, 1);
  const [alert] = alerts;
  assert.equal(alert.kind, "new_finding");
  assert.equal(alert.finding_type, "xss");
  assert.equal(alert.severity, "high");
  assert.equal(alert.title, "新增XSS 跨站脚本");
  assert.match(alert.detail, /4 次命中/);
  assert.match(alert.detail, /1\.1\.1\.1、2\.2\.2\.2/);
  assert.deepEqual(alert.ips, ["1.1.1.1", "2.2.2.2"]);
  assert.equal(alert.at, AT);
});

test("a new source hitting a known attack type raises a source alert", () => {
  const sqli = finding("SQL 注入", "sqli", "critical", 5, ["8.8.8.8", "9.9.9.9"]);
  const previous = snapshot([sqli], ["8.8.8.8"]);
  const current = snapshot(
    [finding("SQL 注入", "sqli", "critical", 5, ["8.8.8.8", "9.9.9.9"])],
    ["8.8.8.8", "9.9.9.9"],
    [["9.9.9.9", 12]]
  );

  const alerts = deriveAlerts(previous, current);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].kind, "new_attacker");
  assert.equal(alerts[0].title, "新攻击源 9.9.9.9");
  assert.equal(alerts[0].finding_type, "sqli");
  assert.equal(alerts[0].severity, "critical");
  assert.equal(alerts[0].count, 12);
  assert.match(alerts[0].detail, /12 条事件/);
});

test("a source that only appears under a brand new type is not alerted twice", () => {
  const previous = snapshot([finding("SQL 注入", "sqli", "critical", 2, ["8.8.8.8"])], ["8.8.8.8"]);
  const current = snapshot(
    [
      finding("SQL 注入", "sqli", "critical", 2, ["8.8.8.8"]),
      finding("目录遍历", "traversal", "medium", 1, ["3.3.3.3"]),
    ],
    ["8.8.8.8", "3.3.3.3"],
    [["3.3.3.3", 1]]
  );

  const alerts = deriveAlerts(previous, current);
  assert.deepEqual(alerts.map((alert) => alert.kind), ["new_finding"]);
  assert.equal(alerts[0].finding_type, "traversal");
});

test("rule label changes keep the same alert identity", () => {
  const previous = snapshot([finding("SQL 注入", "sqli", "critical", 2, ["8.8.8.8"])], ["8.8.8.8"]);
  const current = snapshot([finding("SQL 注入攻击", "sqli", "critical", 4, ["8.8.8.8"])], ["8.8.8.8"]);
  assert.deepEqual(deriveAlerts(previous, current), []);
});

test("alerts are ordered by severity and stay readable when timestamps differ", () => {
  const previous = snapshot([], []);
  const current = snapshot(
    [
      finding("信息收集", "recon", "info", 1, ["4.4.4.4"]),
      finding("CC 攻击", "cc", "medium", 9, ["5.5.5.5"]),
      finding("暴力破解", "brute_force", "high", 20, ["6.6.6.6"]),
      finding("远程命令执行", "rce", "critical", 2, ["7.7.7.7"]),
    ],
    ["4.4.4.4", "5.5.5.5", "6.6.6.6", "7.7.7.7"]
  );

  const alerts = deriveAlerts(previous, current);
  assert.deepEqual(alerts.map((alert) => alert.severity), ["critical", "high", "medium", "info"]);
  assert.ok(alerts.every((alert) => alert.id.startsWith(`${AT}-`)));
  assert.ok(new Set(alerts.map((alert) => alert.id)).size === alerts.length);
});

test("unknown severity and missing sources degrade to explicit defaults", () => {
  const previous = snapshot([], []);
  const current = snapshot([finding("自定义行为", "custom", "weird", 0, [])], []);

  const [alert] = deriveAlerts(previous, current);
  assert.equal(alert.severity, "weird");
  assert.match(alert.detail, /0 次命中 · 来源未记录/);
  assert.deepEqual(alert.ips, []);
});

test("many sources are summarized instead of flooding the alert", () => {
  const previous = snapshot([], []);
  const ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"];
  const current = snapshot([finding("端口扫描", "port_scan", "medium", 30, [...ips, ...ips])], ips);

  const [alert] = deriveAlerts(previous, current);
  assert.match(alert.detail, /1\.1\.1\.1、2\.2\.2\.2、3\.3\.3\.3 等 5 个来源/);
  assert.deepEqual(alert.ips, ips);
});

test("alert kinds have chinese labels for the ui", () => {
  assert.deepEqual(ALERT_KIND_LABELS, { new_finding: "新攻击类型", new_attacker: "新攻击源" });
});
