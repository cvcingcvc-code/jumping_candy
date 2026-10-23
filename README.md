# 哨兵 Sentinel · 网络安全流量分析智能体

一个基于 **DeepSeek + LangGraph** 的网络安全智能体：用户上传**结构化流量日志**或指定**待监测端口**，
智能体自动完成 **攻击检测 → 攻击类型判定 → 攻击者 IP 溯源（至少到省份）→ 生成安全分析报告**。

> 🔒 安全设计：智能体**只分析结构化文本流量日志**，**拒绝直接解析 PCAP 二进制包 / 可执行文件**，
> 从源头规避「文件可能携带恶意载荷」的风险。需要分析 PCAP 时，请先用 `tshark`/`tcpdump` 转成结构化文本。

---

## ☁️ 云端演示版（纯浏览器，无需后端）

`web/` 是可直接部署到任意静态托管（含 Qoder Sites）的浏览器端版本，不需要 Python、FastAPI 或 DeepSeek Key：

- 日志解析、10 类规则检测、IP 溯源、时间线与安全报告**全部在浏览器内完成**，原始日志不上传。
- 支持 Nginx / Apache、CSV、JSON / JSONL、key=value 四类输入，内置 4 组样例。
- **实时监视**：选择本地访问日志后每 2 秒检查变化，只读取你主动选择的文件并在浏览器内重新研判；可暂停、继续、立即刷新、停止，日志被截断或替换时会自动重置。页面关闭即停止，需保持页面打开。
- **实时回放**：用内置攻击样例每 2 秒追加 2 行，演示增量研判；不读取网卡，也不代表真实流量。
- **实时告警中心**：比较相邻快照，只在出现**新攻击类型**或**已知类型的新攻击源**时告警，首个快照作为基线；未读提示条 + 会话内告警历史（最多 50 条），可标记已读、跳转查看，并写入 JSON / Markdown 报告与摘要。刷新页面、重新选择文件或日志轮转后历史清空（页面内已注明）。
- **可选云端来源情报**：开启后仅将**公网攻击源 IP** 发送到 `ipwho.is`，补充国家/省份/城市、ASN/机构与网络类型；内网地址与内置演示 IP 不会被发送。结果缓存在浏览器 7 天，可随时关闭开关。
- 端口监测使用**固定种子的模拟流量**（页面内明确标注），演示抓包后的完整检测链路。
- 单文件上限 10MB，单次最多分析 20,000 条事件；超出部分会截断并在报告中标注。
- 归属地用于研判参考：云端结果为城市级估算，VPN / 代理 / NAT / CDN 会降低准确性，不可用于取证。

本地预览与测试：

```bash
python -m http.server 4173 --directory web   # http://127.0.0.1:4173
node --test tests/engine.test.mjs tests/intel.test.mjs tests/alerts.test.mjs
```

静态文件位于 `web/`（`index.html`、`assets/`、`data/samples/`、`favicon.svg`），无构建步骤。

---

## ✨ 功能特性

| 能力 | 说明 |
| --- | --- |
| 多种输入 | 粘贴日志 / 上传日志文件 / 选择本地文件实时监视 / 指定端口（自动抓包） |
| 实时增量 | 每 2 秒检查所选日志变化，暂停、恢复、立即刷新、停止；日志轮转自动重置 |
| 实时告警 | 相邻快照差分识别新攻击类型与新攻击源，未读提示 + 会话内历史，随报告导出 |
| 来源情报 | 本地演示归属地 + 可选 ipwho.is 公网 IP 城市级情报（含 ASN / 机构 / 网络类型） |
| 攻击检测 | SQL 注入、XSS、目录遍历、命令注入、WebShell、端口扫描、暴力破解、CC/DDoS、扫描器指纹等 |
| 攻击溯源 | 攻击者 IP 定位到**省份级**归属地（ip2region 离线库 / 在线 API / 内置演示映射）|
| 安全报告 | 含研判结论、风险等级、时间范围、攻击明细（含 MITRE ATT&CK）、溯源、处置建议，可下载 JSON |
| 智能研判 | DeepSeek 大模型撰写专业研判与建议；**未配置 key 时自动降级为离线规则模式**，功能依旧完整 |
| 抓包双轨 | 真实抓包（scapy / tcpdump，需本机权限）+ 模拟流量（沙箱/演示）|
| 记忆上下文 | 基于 LangGraph checkpointer，按会话维护多轮上下文 |

---

## 🏗️ 架构

```
前端（原生 HTML+JS 单页）
  对话交互 · 文件上传 · 端口输入 · 报告渲染/下载
        │  REST (/api/*)
        ▼
后端（FastAPI）
        │
        ▼
智能体核心（LangGraph 工作流）
  START → triage(意图分流)
            ├─(port)→ capture(抓包) ─┐
            ├─(log) → parse(解析)  ──┤
            │                        ▼
            │                     detect(检测) → geolocate(溯源) → report(报告) → END
            └─(chat)→ respond(对话) → END

  ├─ 提示词/指令     backend/agent/prompts.py
  ├─ 大模型(DeepSeek) backend/agent/llm.py
  ├─ 记忆/上下文      backend/agent/memory.py（checkpointer）
  └─ 工具插件         backend/tools/{capture,parser,detector,geoip,reporter}.py
```

### 目录结构
```
backend/
  main.py            FastAPI 入口与路由（/api/health,/samples,/upload,/analyze）
  config.py          配置（.env）
  schemas.py         Pydantic 数据模型
  agent/
    graph.py         LangGraph 工作流（核心编排）
    state.py         工作流状态
    prompts.py       提示词/指令
    llm.py           DeepSeek 封装（含离线降级）
    memory.py        记忆/上下文（checkpointer）
  tools/
    capture.py       抓包（scapy/tcpdump/模拟）
    parser.py        日志解析归一化（Nginx/CSV/JSON/KV）
    detector.py      攻击检测规则引擎
    geoip.py         IP 溯源（省份级，多源回退）
    reporter.py      报告生成
  data/
    samples/         内置示例日志
    geoip/           内置演示 IP 映射 / ip2region xdb 位置
frontend/            index.html · style.css · app.js
web/                 云端静态演示版（浏览器端引擎 + UI + 样例）
scripts/             本机真实抓包脚本（Windows）
tests/               单元测试（Python 后端 + 浏览器端引擎）
```

---

## 🚀 快速开始

### Windows（推荐）
1. 确保已安装 **Python 3.10+**（安装时勾选 *Add Python to PATH*）。
2. 在项目文件夹里**双击 `run.bat`**，或在终端执行：
   ```bat
   .\run.bat
   ```
   首次运行会自动建虚拟环境、装依赖、生成 `.env` 并启动，随后自动打开 http://localhost:8000 。
   - 也可用 PowerShell：`.\run.ps1`（若提示禁止运行：先执行 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`）。

### Linux / macOS（或 Windows Git Bash）
```bash
./run.sh
# 浏览器打开 http://localhost:8000
```

或手动：
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # 按需填写 DEEPSEEK_API_KEY
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### 配置 DeepSeek（可选但推荐）
在 `.env` 中填入：
```
DEEPSEEK_API_KEY=sk-xxxxxxxx
```
未配置也能完整运行——研判与建议改用内置规则模板（离线模式）。

### 配置 IP 溯源（生产环境）
- **离线（推荐）**：下载 [ip2region.xdb](https://github.com/lionsoul2014/ip2region) 并设置 `IP2REGION_XDB_PATH`，再 `pip install ip2region`。
- **在线**：保持 `GEOIP_ONLINE_ENABLED=true`，需放通 `ip-api.com` 的出网访问。
- 二者皆无时，使用内置演示映射（覆盖示例数据）。

### 在 Windows 本机真实抓包

云端/沙箱环境抓不到你电脑的网卡流量，但你可以在**自己的电脑**上用 `scripts/` 目录下的脚本抓取真实流量，
产出**结构化 CSV 文本**（不生成 .pcap 二进制），再粘贴/上传到网页里分析：

```bat
cd scripts
capture_traffic.bat        REM 双击运行，或在终端执行
```

- 装了 **Wireshark**（自带 tshark）：脚本会列出网卡供你选择，**以管理员身份运行**可真实抓包，
  直接输出 HTTP 方法/URL/UA 等字段，能检测 SQLi/XSS 等应用层攻击。
- 没装 Wireshark：自动降级为「网络连接快照」模式，用系统自带的 `Get-NetTCPConnection` 轮询记录
  所有 TCP 连接（无需安装任何工具、无需管理员权限），可用于检测端口扫描、异常外联等行为。

参数：`.\capture_traffic.ps1 -Duration 60 -Interface "WLAN"`（默认抓 30 秒）。
抓完会在当前目录生成 `traffic_capture_*.csv`，把内容粘贴进网页「流量日志」框，或直接上传该文件即可。

### 真实抓包（生产环境）
在你自己的服务器/电脑上：`pip install scapy`，设置 `CAPTURE_BACKEND=scapy`（或 `tcpdump`），
并以足够权限运行（抓包通常需要 root / CAP_NET_RAW）。云端沙箱无网卡权限，会自动回退到**模拟流量**演示完整流程。

---

## 🧪 测试
```bash
. .venv/bin/activate
python tests/test_pipeline.py      # 或 python -m pytest tests/ -v
node --test tests/engine.test.mjs tests/intel.test.mjs tests/alerts.test.mjs  # 云端静态版检测引擎、来源情报与告警差分
```

---

## 📡 API 速览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查与运行模式 |
| GET | `/api/samples` | 列出内置示例日志 |
| POST | `/api/upload` | 上传结构化文本日志（拒绝 pcap/二进制）|
| POST | `/api/analyze` | 核心分析（mode = `log` / `port` / `chat`）|

`/api/analyze` 请求示例：
```json
{ "mode": "log", "thread_id": "u1", "log_content": "113.108.182.66 - - [..] \"GET /p?id=1 UNION SELECT..\" 200 .." }
{ "mode": "port", "thread_id": "u1", "port": 80, "duration": 15 }
```

---

## ⚠️ 合规声明
本工具仅用于**防御性**安全分析与教学。请仅在获得授权的资产上使用，溯源结果（尤其在线/离线库）存在误差，
仅供研判参考，不构成法律证据。
