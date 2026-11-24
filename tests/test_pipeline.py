"""核心流程单元测试（离线，无需 DeepSeek key 即可运行）。

运行：  . .venv/bin/activate && python -m pytest tests/ -v
或：    python tests/test_pipeline.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.tools import detector, geoip, parser, reporter  # noqa: E402


def test_parse_nginx():
    log = '1.2.3.4 - - [15/Jun/2026:10:21:07 +0800] "GET /a?id=1 HTTP/1.1" 200 100 "-" "curl/8"'
    events, fmt = parser.parse_logs(log)
    assert fmt == "nginx"
    assert events[0]["src_ip"] == "1.2.3.4"
    assert events[0]["status"] == 200


def test_parse_csv():
    csv = "timestamp,src_ip,dst_port,protocol\n2026-01-01T00:00:00,9.9.9.9,22,TCP"
    events, fmt = parser.parse_logs(csv)
    assert fmt == "csv"
    assert events[0]["src_ip"] == "9.9.9.9"
    assert events[0]["dst_port"] == 22


def test_detect_sql_injection():
    log = '1.1.1.1 - - [15/Jun/2026:10:00:00 +0800] "GET /p?id=1 UNION SELECT password FROM users-- HTTP/1.1" 200 1 "-" "x"'
    events, _ = parser.parse_logs(log)
    findings = detector.detect_attacks(events)
    types = {f["type_en"] for f in findings}
    assert "sql_injection" in types


def test_detect_port_scan():
    rows = ["timestamp,src_ip,dst_port,protocol,flags"]
    for p in range(1, 30):
        rows.append(f"2026-06-15T03:05:0{p % 10},5.5.5.5,{p},TCP,S")
    events, _ = parser.parse_logs("\n".join(rows))
    findings = detector.detect_attacks(events)
    assert any(f["type_en"] == "port_scan" for f in findings)


def test_detect_brute_force():
    lines = []
    for i in range(10):
        lines.append(f'7.7.7.7 - - [15/Jun/2026:02:11:0{i} +0800] "POST /admin/login HTTP/1.1" 401 1 "-" "x"')
    events, _ = parser.parse_logs("\n".join(lines))
    findings = detector.detect_attacks(events)
    assert any(f["type_en"] == "brute_force" for f in findings)


def test_brute_force_ignores_successful_login():
    """验证成功的登录请求 (200 OK) 不会被误判为暴力破解。"""
    lines = []
    for i in range(10):
        lines.append(f'7.7.7.7 - - [15/Jun/2026:02:11:0{i} +0800] "POST /admin/login HTTP/1.1" 200 1024 "-" "x"')
    events, _ = parser.parse_logs("\n".join(lines))
    findings = detector.detect_attacks(events)
    assert not any(f["type_en"] == "brute_force" for f in findings)


def test_sensitive_path_probe_requires_distinct_paths():
    """多次访问同一个后台管理页面不触发敏感路径扫描，需访问至少 3 个不同敏感路径。"""
    # 同一路径重复 5 次
    single_path = [
        '8.8.8.8 - - [15/Jun/2026:10:00:00 +0800] "GET /admin/dashboard HTTP/1.1" 200 500 "-" "user"'
        for _ in range(5)
    ]
    events, _ = parser.parse_logs("\n".join(single_path))
    findings = detector.detect_attacks(events)
    assert not any(f["type_en"] == "sensitive_path_probe" for f in findings)

    # 探测 3 个不同敏感路径
    probe_paths = [
        '8.8.8.8 - - [15/Jun/2026:10:00:01 +0800] "GET /.git/config HTTP/1.1" 404 100 "-" "scanner"',
        '8.8.8.8 - - [15/Jun/2026:10:00:02 +0800] "GET /.env HTTP/1.1" 404 100 "-" "scanner"',
        '8.8.8.8 - - [15/Jun/2026:10:00:03 +0800] "GET /phpmyadmin HTTP/1.1" 404 100 "-" "scanner"',
    ]
    events2, _ = parser.parse_logs("\n".join(probe_paths))
    findings2 = detector.detect_attacks(events2)
    assert any(f["type_en"] == "sensitive_path_probe" for f in findings2)


def test_double_url_decode_detection():
    """测试经过双重 URL 编码的攻击载荷被正确解码检出。"""
    log = '1.1.1.1 - - [15/Jun/2026:10:00:00 +0800] "GET /api?cmd=%253bcat%2520%252fetc%252fpasswd HTTP/1.1" 200 1 "-" "x"'
    events, _ = parser.parse_logs(log)
    findings = detector.detect_attacks(events)
    types = {f["type_en"] for f in findings}
    assert "command_injection" in types


def test_simulated_traffic_clear_labeling():
    """验证模拟抓包流量在报告中被打上清晰的演练标识，且包含溯源局限性免责说明。"""
    events = [{"src_ip": "1.1.1.1", "timestamp": "2026-06-15T10:00:00"}]
    findings = [{"type": "SQL 注入", "type_en": "sql_injection", "severity": "high", "src_ips": ["1.1.1.1"], "count": 1}]
    geo = {"1.1.1.1": {"ip": "1.1.1.1", "country": "中国", "province": "广东", "city": "广州"}}
    report = reporter.build_report(events, findings, geo, capture_meta={"simulated": True, "used_backend": "simulate"})

    assert report["is_simulated"] is True
    assert "模拟演练" in report["verdict"]
    assert "模拟" in report["summary"]
    assert "免责" in report.get("disclaimer", "") or "说明" in report.get("disclaimer", "")


def test_geolocate_private_and_demo():
    g = geoip.geolocate_ip("10.0.0.1")
    assert g["is_private"] is True
    g2 = geoip.geolocate_ip("113.108.182.66")  # 在内置演示映射中
    assert g2["province"] == "广东省"


def test_build_report_offline():
    log = '1.1.1.1 - - [15/Jun/2026:10:00:00 +0800] "GET /p?id=1 UNION SELECT a FROM b-- HTTP/1.1" 200 1 "-" "sqlmap"'
    events, _ = parser.parse_logs(log)
    findings = detector.detect_attacks(events)
    geo = geoip.geolocate_many([ip for f in findings for ip in f["src_ips"]])
    report = reporter.build_report(events, findings, geo)
    assert report["attack_detected"] is True
    assert report["risk_level"] in {"严重", "高危", "中危", "低危"}
    assert report["recommendations"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
