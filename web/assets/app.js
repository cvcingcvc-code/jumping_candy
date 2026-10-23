import {
  DETECTION_RULES,
  SAMPLE_CATALOG,
  parseLogs,
  detectAttacks,
  geolocateMany,
  geoLabel,
  buildTimeline,
  buildReport,
  simulatePortCapture,
  formatLabel,
} from "./engine.js";
import {
  CLOUD_GEO,
  NETWORK_KIND_LABELS,
  fetchCloudGeo,
  isLookupableIp,
  readGeoCache,
  writeGeoCache,
} from "./intel.js";

const $ = (selector, root = document) => root.querySelector(selector);
const NS = "http://www.w3.org/2000/svg";

const ALLOWED_SUFFIXES = [".log", ".txt", ".csv", ".json", ".jsonl", ".ndjson"];
const BLOCKED_SUFFIXES = [".pcap", ".pcapng", ".cap", ".exe", ".bin", ".dll", ".sh", ".dmp"];
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const LIVE_POLL_MS = 2000;
const LIVE_REPLAY_STEP = 2;
const LIVE_SAMPLE_ID = "web_attack_nginx.log";

const RISK_CLASS = {
  "严重": "critical",
  "高危": "high",
  "中危": "medium",
  "低危": "low",
  "无明显风险": "none",
};

const SEVERITY_TEXT = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "提示",
};

const SOURCE_TEXT = {
  demo: "演示库",
  private: "内网",
  unknown: "未覆盖",
  online: "云端情报",
  pending: "查询中",
};

const CLOCK_FORMAT = new Intl.DateTimeFormat("zh-CN", {
  hour12: false,
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

const ICONS = {
  download: '<path d="M9 2.5v8m0 0 3-3m-3 3-3-3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/><path d="M3 11.5v2A1.5 1.5 0 0 0 4.5 15h9a1.5 1.5 0 0 0 1.5-1.5v-2" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>',
  copy: '<rect x="6" y="6" width="8" height="9" rx="1.3" stroke="currentColor" stroke-width="1.2"/><path d="M4 11V4.8c0-.7.6-1.3 1.3-1.3H11" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>',
  chevron: '<path d="m5 7 4 4 4-4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>',
  lock: '<rect x="3.2" y="7" width="9.6" height="6.4" rx="1.4" stroke="currentColor" stroke-width="1.1"/><path d="M5.4 7V5.4a2.6 2.6 0 0 1 5.2 0V7" stroke="currentColor" stroke-width="1.1"/>',
  shield: '<path d="M9 2.8 14.5 5v4.2c0 3-2.2 5.4-5.5 6.6-3.3-1.2-5.5-3.6-5.5-6.6V5L9 2.8Z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="m6.6 9 1.6 1.6 3.2-3.2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>',
  file: '<path d="M5 2.8h5l3 3V15H5z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M10 2.8V6h3" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>',
  clock: '<circle cx="9" cy="9" r="6" stroke="currentColor" stroke-width="1.2"/><path d="M9 5.5V9l2.2 1.4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>',
  arrow: '<path d="M3.5 9h10m0 0L9.8 5.3M13.5 9l-3.7 3.7" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>',
  refresh: '<path d="M14.5 9a5.5 5.5 0 1 1-1.6-3.9M14.5 3.5V6h-2.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>',
};

const state = {
  tab: "sample",
  sampleId: SAMPLE_CATALOG[0].id,
  sampleText: "",
  sampleLoading: false,
  pasteText: "",
  upload: null,
  port: 80,
  duration: 15,
  host: "demo.local",
  busy: false,
  report: null,
  live: {
    mode: null,
    handle: null,
    fileMeta: null,
    text: "",
    picking: false,
    refreshing: false,
    paused: false,
    replayDone: false,
    replayLines: [],
    replayIndex: 0,
    timer: null,
    lastSignature: "",
    lastSize: 0,
    reportId: "",
    latestReport: null,
    snapshot: null,
    changeCount: 0,
    refreshSeq: 0,
    controller: null,
    geoEnabled: true,
    error: "",
    lastRefreshAt: null,
    replayLoading: false,
  },
};

const sampleCache = new Map();
let sampleToken = 0;
let toastTimer = null;

const els = {
  tabsContainer: $("#sourceTabs"),
  tabs: [...document.querySelectorAll(".source-tab")],
  panes: [...document.querySelectorAll(".source-pane")],
  samples: $("#samplesList"),
  sampleMeta: $("#sampleMeta"),
  samplePreview: $("#samplePreview"),
  samplePreviewBody: $("#samplePreviewBody"),
  logInput: $("#logInput"),
  logCount: $("#logCount"),
  clearPaste: $("#clearPaste"),
  fileInput: $("#fileInput"),
  dropzone: $("#dropzone"),
  uploadInfo: $("#uploadInfo"),
  portInput: $("#portInput"),
  durationInput: $("#durationInput"),
  hostInput: $("#hostInput"),
  livePickBtn: $("#livePickBtn"),
  livePickTitle: $("#livePickTitle"),
  livePickSub: $("#livePickSub"),
  livePickAction: $("#livePickAction"),
  liveStatus: $("#liveStatus"),
  liveReplayBtn: $("#liveReplayBtn"),
  geoLookupToggle: $("#geoLookupToggle"),
  tabLive: $("#tab-live"),
  analyzeBtn: $("#analyzeBtn"),
  resetBtn: $("#resetBtn"),
  sourceHint: $("#sourceHint"),
  workspace: $("#workspaceContent"),
  methodBtn: $("#methodBtn"),
  methodDialog: $("#methodDialog"),
  methodClose: $("#methodClose"),
  methodContent: $("#methodContent"),
  toast: $("#toast"),
};

function init() {
  state.live.geoEnabled = Boolean(els.geoLookupToggle?.checked);
  renderSampleList();
  bindTabs();
  bindSourceInputs();
  bindLiveInputs();
  bindActions();
  renderMethod();
  renderEmpty();
  updateSampleSelection();
  updateLivePicker();
  updateAnalyzeState();
  loadSample(state.sampleId);
  window.addEventListener("beforeunload", () => {
    clearInterval(state.live.timer);
    state.live.controller?.abort();
  });
}

function clockTime(ms = Date.now()) {
  return CLOCK_FORMAT.format(new Date(ms));
}

function node(tag, className = "", textContent = null) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (textContent !== null && textContent !== undefined) element.textContent = String(textContent);
  return element;
}

function icon(name, className = "btn-icon") {
  const span = document.createElement("span");
  span.className = className;
  span.innerHTML = `<svg viewBox="0 0 18 18" fill="none" aria-hidden="true">${ICONS[name] || ""}</svg>`;
  return span;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

function pause(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function lineCount(text) {
  return text.split(/\r?\n/).filter((line) => line.trim()).length;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function showToast(message, type = "info") {
  els.toast.textContent = message;
  els.toast.className = `toast is-visible toast-${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    els.toast.className = "toast";
  }, 3600);
}

// ---------------------------------------------------------------- tabs
function bindTabs() {
  els.tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      setTab(tab.dataset.tab);
      if (tab.dataset.tab === "sample" && !state.sampleText && !state.sampleLoading) {
        loadSample(state.sampleId);
      }
    });
  });

  els.tabsContainer.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const current = els.tabs.findIndex((tab) => tab.dataset.tab === state.tab);
    let next = current;
    if (event.key === "ArrowRight") next = (current + 1) % els.tabs.length;
    if (event.key === "ArrowLeft") next = (current - 1 + els.tabs.length) % els.tabs.length;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = els.tabs.length - 1;
    setTab(els.tabs[next].dataset.tab, true);
    if (els.tabs[next].dataset.tab === "sample" && !state.sampleText && !state.sampleLoading) {
      loadSample(state.sampleId);
    }
  });
}

function setTab(name, focus = false) {
  state.tab = name;
  els.tabs.forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
    if (active && focus) tab.focus();
  });
  els.panes.forEach((pane) => {
    pane.hidden = pane.dataset.pane !== name;
  });
  updateAnalyzeState();
  if (name === "live") {
    if (state.live.latestReport) {
      renderReport(state.live.latestReport, { preserve: false, scroll: false });
    } else {
      renderLiveIdle(state.live.error, Boolean(state.live.error));
    }
  }
}

// ---------------------------------------------------------------- samples
function renderSampleList() {
  els.samples.replaceChildren();
  for (const sample of SAMPLE_CATALOG) {
    const button = node("button", "sample-card");
    button.type = "button";
    button.dataset.sample = sample.id;
    button.setAttribute("aria-pressed", "false");

    const top = node("span", "sample-top");
    top.append(
      node("span", `sample-tag tone-${sample.tone}`, sample.tag),
      node("span", "sample-state", "载入")
    );
    button.append(
      top,
      node("span", "sample-name", sample.name),
      node("span", "sample-desc", sample.description),
      node("span", "sample-file", `${sample.meta} · ${sample.id}`)
    );
    button.addEventListener("click", () => selectSample(sample.id));
    els.samples.append(button);
  }
}

function updateSampleSelection() {
  for (const button of els.samples.querySelectorAll(".sample-card")) {
    const active = button.dataset.sample === state.sampleId;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
    const stateLabel = button.querySelector(".sample-state");
    if (stateLabel) stateLabel.textContent = active ? "已载入" : "载入";
  }
}

function selectSample(id) {
  if (state.busy) return;
  state.sampleId = id;
  state.sampleText = "";
  updateSampleSelection();
  setTab("sample");
  els.sampleMeta.textContent = "正在载入样例…";
  els.samplePreview.hidden = true;
  loadSample(id);
}

async function loadSample(id) {
  const token = ++sampleToken;
  state.sampleLoading = true;
  updateAnalyzeState();
  els.sampleMeta.textContent = "正在载入样例…";
  try {
    let content = sampleCache.get(id);
    if (!content) {
      const response = await fetch(`/data/samples/${encodeURIComponent(id)}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      content = await response.text();
      sampleCache.set(id, content);
    }
    if (token !== sampleToken) return;

    state.sampleText = content;
    const parsed = parseLogs(content);
    const lines = lineCount(content);
    els.sampleMeta.textContent = `${lines} 行原始日志 · ${parsed.events.length} 条归一化事件 · ${parsed.formatLabel}`;
    els.samplePreviewBody.textContent = content.split(/\r?\n/).filter((line) => line.trim()).slice(0, 3).join("\n");
    els.samplePreview.hidden = false;
    els.samplePreview.open = false;
  } catch (error) {
    if (token !== sampleToken) return;
    state.sampleText = "";
    els.sampleMeta.textContent = "样例载入失败，请检查网络后重试。";
    els.samplePreview.hidden = true;
    showToast(`样例载入失败：${error.message}`, "error");
  } finally {
    if (token === sampleToken) {
      state.sampleLoading = false;
      updateAnalyzeState();
    }
  }
}

// ---------------------------------------------------------------- source inputs
function bindSourceInputs() {
  els.logInput.addEventListener("input", () => {
    state.pasteText = els.logInput.value;
    updateLogCount();
    updateAnalyzeState();
  });
  els.clearPaste.addEventListener("click", () => {
    els.logInput.value = "";
    state.pasteText = "";
    updateLogCount();
    updateAnalyzeState();
    els.logInput.focus();
  });

  els.fileInput.addEventListener("change", () => {
    const file = els.fileInput.files?.[0];
    if (file) handleFile(file);
  });

  els.dropzone.tabIndex = 0;
  els.dropzone.setAttribute("role", "button");
  els.dropzone.setAttribute("aria-label", "选择或拖拽日志文件");
  els.dropzone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      els.fileInput.click();
    }
  });
  ["dragover", "dragenter"].forEach((name) => {
    els.dropzone.addEventListener(name, (event) => {
      event.preventDefault();
      els.dropzone.classList.add("is-drag");
    });
  });
  ["dragleave", "drop"].forEach((name) => {
    els.dropzone.addEventListener(name, () => els.dropzone.classList.remove("is-drag"));
  });
  els.dropzone.addEventListener("drop", (event) => {
    event.preventDefault();
    const file = event.dataTransfer?.files?.[0];
    if (file) handleFile(file);
  });

  els.portInput.addEventListener("input", updatePortState);
  els.durationInput.addEventListener("change", updatePortState);
  els.hostInput.addEventListener("input", updatePortState);
}

function updateLogCount() {
  const chars = state.pasteText.length;
  const lines = state.pasteText ? lineCount(state.pasteText) : 0;
  els.logCount.textContent = `${chars.toLocaleString("zh-CN")} 字符 · ${lines.toLocaleString("zh-CN")} 行`;
}

function updatePortState() {
  state.port = Number.parseInt(els.portInput.value, 10);
  state.duration = Number.parseInt(els.durationInput.value, 10) || 15;
  state.host = els.hostInput.value.trim() || "demo.local";
  updateAnalyzeState();
}

// ---------------------------------------------------------------- live watch
function bindLiveInputs() {
  els.livePickBtn.addEventListener("click", pickLiveFile);
  els.liveReplayBtn.addEventListener("click", startLiveReplay);
  els.geoLookupToggle.addEventListener("change", onGeoLookupChange);
}

function geoStorage() {
  try {
    const probe = "__sentinel_storage_probe__";
    window.localStorage.setItem(probe, "1");
    window.localStorage.removeItem(probe);
    return window.localStorage;
  } catch {
    return null;
  }
}

function wait(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function decodeLogBuffer(buffer) {
  const utf8 = new TextDecoder("utf-8").decode(buffer);
  if (!utf8.includes("\uFFFD")) return utf8;
  try {
    const gb18030 = new TextDecoder("gb18030").decode(buffer);
    return gb18030.includes("\uFFFD") ? utf8 : gb18030;
  } catch {
    return utf8;
  }
}

function validateLiveFile(file) {
  const suffix = file.name.toLowerCase().match(/\.[^.]+$/)?.[0] || "";
  if (BLOCKED_SUFFIXES.includes(suffix)) {
    throw new UserError("不接收 PCAP、二进制或可执行文件。请改用结构化文本日志。");
  }
  if (!ALLOWED_SUFFIXES.includes(suffix)) {
    throw new UserError(`实时监视仅支持 ${ALLOWED_SUFFIXES.join(" / ")} 文本日志。`);
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    throw new UserError("文件超过 10MB 上限，请截取时间窗或拆分后再监视。");
  }
  if (file.size === 0) {
    throw new UserError("文件为空，暂无可监视的内容。");
  }
}

async function readLiveText(file) {
  const text = decodeLogBuffer(await file.arrayBuffer());
  if (text.includes("\u0000")) throw new UserError("文件包含二进制内容，已停止读取。");
  if (!text.trim()) throw new UserError("当前文件没有可解析的文本内容。");
  return text;
}

async function pickLiveFile() {
  if (state.live.picking) return;
  if (typeof window.showOpenFilePicker !== "function") {
    showToast("当前浏览器不支持持续读取本地文件，已切换到上传模式分析单次快照。实时回放仍可使用。", "info");
    setTab("upload");
    return;
  }
  state.live.picking = true;
  updateAnalyzeState();
  try {
    const handles = await window.showOpenFilePicker({
      multiple: false,
      excludeAcceptAllOption: false,
      types: [{
        description: "文本流量日志",
        accept: {
          "text/plain": [".log", ".txt", ".csv", ".json", ".jsonl", ".ndjson"],
          "text/csv": [".csv"],
          "application/json": [".json", ".jsonl", ".ndjson"],
        },
      }],
    });
    const handle = handles?.[0];
    if (handle) await startFileWatch(handle);
  } catch (error) {
    if (error?.name === "AbortError") return;
    const message = error instanceof UserError
      ? error.message
      : `无法打开文件：${error?.message || "未知错误"}`;
    showToast(message, "error");
  } finally {
    state.live.picking = false;
    updateAnalyzeState();
  }
}

function beginLiveSession(mode) {
  clearInterval(state.live.timer);
  state.live.timer = null;
  state.live.controller?.abort();
  state.live.controller = null;
  state.live.refreshSeq += 1;
  state.live.mode = mode;
  state.live.handle = null;
  state.live.fileMeta = null;
  state.live.text = "";
  state.live.paused = false;
  state.live.replayDone = false;
  state.live.replayLines = [];
  state.live.replayIndex = 0;
  state.live.lastSignature = "";
  state.live.lastSize = 0;
  state.live.reportId = "";
  state.live.latestReport = null;
  state.live.snapshot = null;
  state.live.changeCount = 0;
  state.live.error = "";
  state.live.lastRefreshAt = null;
}

async function startFileWatch(handle) {
  const file = await handle.getFile();
  validateLiveFile(file);
  const text = await readLiveText(file);

  beginLiveSession("file");
  state.live.handle = handle;
  state.live.fileMeta = { name: file.name, size: file.size, lastModified: file.lastModified };
  state.live.text = text;
  state.live.lastSignature = `${file.size}:${file.lastModified}`;
  state.live.lastSize = file.size;
  state.live.changeCount = 1;

  updateLivePicker();
  startLiveTimer();
  analyzeLiveSnapshot({ reason: "initial" });
  setTab("live");
  showToast(`已开始监视 ${file.name}，每 2 秒检查一次；原始日志未上传。`, "success");
}

function startLiveTimer() {
  clearInterval(state.live.timer);
  state.live.timer = setInterval(liveTick, LIVE_POLL_MS);
}

function liveTick() {
  if (!state.live.mode || state.live.paused) return;
  if (state.live.mode === "replay") {
    if (!state.live.replayDone) advanceReplay();
    return;
  }
  void pollLiveFile();
}

async function pollLiveFile({ force = false } = {}) {
  if (state.live.mode !== "file" || state.live.paused || !state.live.handle) return;
  const handle = state.live.handle;
  const seq = state.live.refreshSeq;
  try {
    const file = await handle.getFile();
    if (seq !== state.live.refreshSeq) return;
    if (file.size > MAX_UPLOAD_BYTES) throw new UserError("日志超过 10MB 上限，已暂停监视。");
    const signature = `${file.size}:${file.lastModified}`;
    if (!force && signature === state.live.lastSignature) return;
    const text = await readLiveText(file);
    if (seq !== state.live.refreshSeq) return;
    if (text === state.live.text) {
      state.live.lastSignature = signature;
      state.live.lastSize = file.size;
      if (force) showToast("日志暂无变化，当前报告已是最新。", "info");
      return;
    }

    const previous = state.live.text;
    const rotated = Boolean(previous) && (
      file.size < state.live.lastSize ||
      !text.startsWith(previous.slice(0, Math.min(previous.length, 240)))
    );
    if (rotated) {
      state.live.reportId = "";
      state.live.snapshot = null;
      state.live.changeCount = 0;
      state.live.lastRefreshAt = null;
      showToast("检测到日志被截断或替换，已按新文件重新研判。", "info");
    }

    state.live.handle = handle;
    state.live.fileMeta = { name: file.name, size: file.size, lastModified: file.lastModified };
    state.live.text = text;
    state.live.lastSignature = signature;
    state.live.lastSize = file.size;
    state.live.changeCount += 1;
    updateLivePicker();
    analyzeLiveSnapshot({ reason: force ? "manual" : "poll" });
    if (force) showToast("已读取最新日志并更新研判。", "success");
  } catch (error) {
    if (seq !== state.live.refreshSeq) return;
    if (error?.name === "AbortError") return;
    const message = error instanceof UserError
      ? error.message
      : "读取日志失败：文件可能已被移动、删除，或浏览器权限被撤销。";
    pauseLiveWithError(message);
  }
}

function analyzeLiveSnapshot({ reason = "poll" } = {}) {
  if (!state.live.mode || !state.live.text.trim()) return;
  const seq = state.live.refreshSeq + 1;
  state.live.refreshSeq = seq;
  state.live.controller?.abort();
  state.live.controller = null;

  try {
    const parsed = parseLogs(state.live.text);
    if (!parsed.events.length) {
      pauseLiveWithError("未能从当前文件中解析出流量事件。请确认日志格式，或更换文件。");
      return;
    }
    const findings = detectAttacks(parsed.events);
    const attackerIps = [...new Set(findings.flatMap((finding) => finding.src_ips || []))];
    const baseGeo = geolocateMany(attackerIps);
    const timeline = buildTimeline(parsed.events, findings);
    const attackerSet = new Set(attackerIps);
    const counts = new Map();
    for (const event of parsed.events) {
      if (event.src_ip && attackerSet.has(event.src_ip)) {
        counts.set(event.src_ip, (counts.get(event.src_ip) || 0) + 1);
      }
    }

    const snapshot = { parsed, findings, attackerIps, baseGeo, timeline, counts, seq, at: Date.now() };
    state.live.snapshot = snapshot;
    state.live.lastRefreshAt = snapshot.at;
    state.live.error = "";
    const allowPending = state.live.geoEnabled && state.live.mode === "file" && !state.live.paused;
    const { candidates } = publishLiveReport(snapshot, { pending: allowPending });
    if (allowPending && candidates.length) {
      void enrichLiveGeo(snapshot, candidates, seq);
    }
  } catch (error) {
    console.error(error);
    pauseLiveWithError(`实时研判出错：${error?.message || "未知错误"}`);
  }
}

function liveGeoView(snapshot, { pending = false } = {}) {
  const cache = state.live.mode === "file" ? readGeoCache(geoStorage()) : {};
  const geo = {};
  const potential = [];

  for (const ip of snapshot.attackerIps) {
    const base = snapshot.baseGeo[ip] || { ip, source: "unknown" };
    if (cache[ip]) {
      geo[ip] = cache[ip];
      continue;
    }
    const canLookup = pending &&
      state.live.mode === "file" &&
      isLookupableIp(ip) &&
      base.source !== "demo" &&
      base.source !== "private";
    if (canLookup) {
      potential.push(ip);
    } else {
      geo[ip] = base;
    }
  }

  potential.sort((a, b) => (snapshot.counts.get(b) || 0) - (snapshot.counts.get(a) || 0));
  const candidates = potential.slice(0, CLOUD_GEO.maxPerRefresh);
  for (const ip of potential) {
    geo[ip] = candidates.includes(ip)
      ? { ...snapshot.baseGeo[ip], source: "pending", pending: true }
      : snapshot.baseGeo[ip];
  }
  return { geo, candidates };
}

function composeLiveReport(snapshot, geo) {
  const replay = state.live.mode === "replay";
  const file = state.live.fileMeta;
  const sourceLabel = replay
    ? "实时回放 · Web 攻击组合"
    : `实时监视 · ${file?.name || "本地日志"}`;
  const totalHits = snapshot.findings.reduce((sum, finding) => sum + finding.count, 0);
  const resolved = Object.values(geo).filter((item) => item.province && !item.is_private).length;
  const cloudCount = Object.values(geo).filter((item) => item.source === "online").length;

  const report = buildReport({
    events: snapshot.parsed.events,
    findings: snapshot.findings,
    geo,
    timeline: snapshot.timeline,
    format: snapshot.parsed.format,
    formatLabel: snapshot.parsed.formatLabel,
    sourceLabel,
    fileName: file?.name || "",
    truncated: snapshot.parsed.truncated,
    live: true,
    replay,
    reportId: state.live.reportId,
    trace: [
      { label: "数据源", detail: `${sourceLabel} · 第 ${state.live.changeCount} 次快照` },
      {
        label: replay ? "回放解析" : "日志读取",
        detail: `${snapshot.parsed.formatLabel} · ${snapshot.parsed.events.length} 条${snapshot.parsed.truncated ? " · 已截断" : ""}`,
      },
      { label: "规则检测", detail: `${snapshot.findings.length} 类 · ${totalHits} 次命中` },
      {
        label: "来源情报",
        detail: snapshot.attackerIps.length
          ? `${resolved}/${snapshot.attackerIps.length} 已定位 · ${cloudCount} 个云端`
          : "暂无攻击源需溯源",
      },
    ],
  });
  if (!state.live.reportId) state.live.reportId = report.report_id;
  return report;
}

function publishLiveReport(snapshot, { pending = false } = {}) {
  const { geo, candidates } = liveGeoView(snapshot, { pending });
  const report = composeLiveReport(snapshot, geo);
  state.live.latestReport = report;
  if (state.tab === "live") {
    renderReport(report, { preserve: true, scroll: false });
  }
  updateLivePicker();
  updateLiveStatus();
  updateAnalyzeState();
  return { report, candidates };
}

async function enrichLiveGeo(snapshot, candidates, seq) {
  const controller = new AbortController();
  state.live.controller = controller;
  const cache = readGeoCache(geoStorage()) || {};
  let failed = 0;

  try {
    for (let index = 0; index < candidates.length; index += 1) {
      if (seq !== state.live.refreshSeq || state.live.paused || state.live.mode !== "file") return;
      if (index > 0) {
        try {
          await wait(CLOUD_GEO.requestGapMs, controller.signal);
        } catch {
          return;
        }
      }
      try {
        const entry = await fetchCloudGeo(candidates[index], { signal: controller.signal });
        if (seq !== state.live.refreshSeq) return;
        cache[candidates[index]] = entry;
        writeGeoCache(geoStorage(), cache);
      } catch (error) {
        if (error?.name === "AbortError") return;
        failed += 1;
      }
    }
    if (seq !== state.live.refreshSeq || state.live.mode !== "file") return;
    publishLiveReport(snapshot, { pending: false });
    if (failed) {
      showToast(`${failed} 个 IP 情报查询失败，已保留本地研判结果。`, "info");
    }
  } finally {
    if (state.live.controller === controller) state.live.controller = null;
  }
}

function onGeoLookupChange() {
  state.live.geoEnabled = els.geoLookupToggle.checked;
  if (state.live.mode !== "file" || !state.live.snapshot) return;
  if (!state.live.geoEnabled) {
    state.live.controller?.abort();
    state.live.controller = null;
    state.live.refreshSeq += 1;
    publishLiveReport(state.live.snapshot, { pending: false });
    showToast("已关闭云端情报，后续只使用本地归属地和已缓存的查询结果。", "info");
    return;
  }
  if (state.live.paused) {
    showToast("已开启云端情报，恢复监视后会补查公网攻击源 IP。", "info");
    return;
  }
  analyzeLiveSnapshot({ reason: "manual" });
  showToast("已开启云端情报：仅发送公网攻击源 IP 到 ipwho.is。", "info");
}

function advanceReplay(initial = false) {
  if (state.live.mode !== "replay" || state.live.paused || state.live.replayDone) return;
  const lines = state.live.replayLines;
  const nextIndex = Math.min(state.live.replayIndex + LIVE_REPLAY_STEP, lines.length);
  const chunk = lines.slice(state.live.replayIndex, nextIndex);
  if (!chunk.length) {
    finishReplay();
    return;
  }
  state.live.text = [state.live.text, ...chunk].filter(Boolean).join("\n");
  state.live.replayIndex = nextIndex;
  state.live.changeCount += 1;
  state.live.fileMeta = {
    name: LIVE_SAMPLE_ID,
    size: state.live.text.length,
    lastModified: Date.now(),
  };
  updateLivePicker();
  analyzeLiveSnapshot({ reason: initial ? "initial" : "replay" });
  if (nextIndex >= lines.length) finishReplay();
}

function finishReplay() {
  state.live.replayDone = true;
  state.live.lastRefreshAt = Date.now();
  updateLivePicker();
  updateLiveStatus();
  updateAnalyzeState();
  if (state.tab === "live" && state.live.latestReport) {
    renderReport(state.live.latestReport, { preserve: true, scroll: false });
  }
  showToast(`实时回放完成：${state.live.replayIndex} 行日志已全部研判。`, "success");
}

async function startLiveReplay() {
  if (state.live.replayLoading) return;
  state.live.replayLoading = true;
  updateAnalyzeState();
  try {
    let text = sampleCache.get(LIVE_SAMPLE_ID);
    if (!text) {
      const response = await fetch(`/data/samples/${encodeURIComponent(LIVE_SAMPLE_ID)}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      text = await response.text();
      sampleCache.set(LIVE_SAMPLE_ID, text);
    }
    const lines = text.split(/\r?\n/).filter((line) => line.trim());
    if (!lines.length) throw new Error("样例内容为空");

    beginLiveSession("replay");
    state.live.replayLines = lines;
    state.live.replayIndex = 0;
    state.live.fileMeta = { name: LIVE_SAMPLE_ID, size: 0, lastModified: Date.now() };
    updateLivePicker();
    startLiveTimer();
    advanceReplay(true);
    setTab("live");
    showToast("实时回放已开始：每 2 秒追加日志，观察规则命中与来源画像的变化。", "info");
  } catch (error) {
    showToast(`回放准备失败：${error?.message || "未知错误"}`, "error");
  } finally {
    state.live.replayLoading = false;
    updateAnalyzeState();
  }
}

function pauseLive() {
  if (!state.live.mode || state.live.paused) return;
  state.live.paused = true;
  state.live.controller?.abort();
  state.live.controller = null;
  state.live.refreshSeq += 1;
  updateLivePicker();
  updateLiveStatus();
  updateAnalyzeState();
  if (state.tab === "live" && state.live.latestReport) {
    renderReport(state.live.latestReport, { preserve: true, scroll: false });
  }
  showToast("已暂停监视，最后一份报告仍保留。", "info");
}

function resumeLive() {
  if (!state.live.mode || !state.live.paused || state.live.error) return;
  state.live.paused = false;
  state.live.error = "";
  updateLivePicker();
  updateLiveStatus();
  updateAnalyzeState();
  if (state.live.mode === "replay" && !state.live.replayDone) {
    advanceReplay();
  } else if (state.live.snapshot) {
    analyzeLiveSnapshot({ reason: "resume" });
  }
  showToast("已恢复监视。", "success");
}

function pauseLiveWithError(message) {
  state.live.paused = true;
  state.live.error = message;
  state.live.controller?.abort();
  state.live.controller = null;
  state.live.refreshSeq += 1;
  updateLivePicker();
  updateLiveStatus();
  updateAnalyzeState();
  if (state.tab === "live") {
    if (state.live.latestReport) {
      renderReport(state.live.latestReport, { preserve: true, scroll: false });
    } else {
      renderLiveIdle(message, true);
    }
  }
  showToast(message, "error");
}

function stopLive({ silent = false, keepReport = true } = {}) {
  const hadSession = Boolean(state.live.mode);
  clearInterval(state.live.timer);
  state.live.timer = null;
  state.live.controller?.abort();
  state.live.controller = null;
  state.live.refreshSeq += 1;
  state.live.mode = null;
  state.live.handle = null;
  state.live.fileMeta = null;
  state.live.text = "";
  state.live.paused = false;
  state.live.replayDone = false;
  state.live.replayLines = [];
  state.live.replayIndex = 0;
  state.live.snapshot = null;
  state.live.error = "";
  state.live.picking = false;
  state.live.refreshing = false;
  if (!keepReport) {
    state.live.latestReport = null;
    state.live.reportId = "";
    state.live.changeCount = 0;
    state.live.lastRefreshAt = null;
    state.live.lastSignature = "";
    state.live.lastSize = 0;
  }
  updateLivePicker();
  updateLiveStatus();
  updateAnalyzeState();
  if (state.tab === "live") {
    if (state.live.latestReport) {
      renderReport(state.live.latestReport, { preserve: true, scroll: false });
    } else {
      renderLiveIdle();
    }
  }
  if (hadSession && !silent) {
    showToast("已停止实时监视，最后一份报告仍保留。", "info");
  }
}

async function manualRefreshLive() {
  if (!state.live.mode || state.live.refreshing) return;
  state.live.refreshing = true;
  updateAnalyzeState();
  try {
    if (state.live.mode === "file") {
      await pollLiveFile({ force: true });
    } else if (!state.live.replayDone) {
      analyzeLiveSnapshot({ reason: "manual" });
    } else {
      showToast("回放已结束，可点击“重新回放”再次体验。", "info");
    }
  } finally {
    state.live.refreshing = false;
    updateAnalyzeState();
  }
}

function livePrimaryAction() {
  if (state.busy || state.live.picking || state.live.refreshing) return;
  if (!state.live.mode) {
    pickLiveFile();
    return;
  }
  if (state.live.error) {
    pickLiveFile();
    return;
  }
  if (state.live.replayDone) {
    startLiveReplay();
    return;
  }
  if (state.live.paused) {
    resumeLive();
    return;
  }
  manualRefreshLive();
}

function updateLivePicker() {
  if (!els.livePickBtn) return;
  const live = state.live;
  els.livePickBtn.classList.toggle("is-live", Boolean(live.mode));
  els.geoLookupToggle.disabled = live.mode === "replay";
  els.geoLookupToggle.title = live.mode === "replay"
    ? "回放使用内置演示归属地，不发起云端查询"
    : "仅发送公网攻击源 IP 到 ipwho.is";
  syncLiveChrome();

  if (live.mode === "file") {
    els.livePickTitle.textContent = live.fileMeta?.name || "已选择日志文件";
    els.livePickSub.textContent = `${formatBytes(live.fileMeta?.size || 0)} · 每 2 秒检查变化 · ${live.paused ? "已暂停" : "监视中"}`;
    els.livePickAction.textContent = "更换";
    return;
  }
  if (live.mode === "replay") {
    els.livePickTitle.textContent = "Web 攻击组合 · 实时回放";
    els.livePickSub.textContent = `${live.replayIndex}/${live.replayLines.length} 行 · ${
      live.replayDone ? "回放完成" : live.paused ? "已暂停" : "每 2 秒推进"
    }`;
    els.livePickAction.textContent = "更换";
    return;
  }
  els.livePickTitle.textContent = "选择访问日志文件";
  els.livePickSub.textContent = typeof window.showOpenFilePicker === "function"
    ? "读取新增内容并自动研判，文件正文不上传"
    : "当前浏览器不支持持续读取，可使用上传或示例回放";
  els.livePickAction.textContent = "选择";
}

function syncLiveChrome() {
  const active = Boolean(state.live.mode && !state.live.paused);
  els.tabLive?.classList.toggle("is-live", active);
}

function liveActionButton(label, onClick, danger = false) {
  const button = node("button", `live-btn${danger ? " is-danger" : ""}`, label);
  button.type = "button";
  button.addEventListener("click", onClick);
  return button;
}

function updateLiveStatus() {
  syncLiveChrome();
  const box = els.liveStatus;
  if (!box) return;
  if (!state.live.mode) {
    box.hidden = true;
    box.replaceChildren();
    return;
  }

  const isError = Boolean(state.live.error);
  box.hidden = false;
  box.className = `live-status${isError ? " is-error" : state.live.paused ? " is-paused" : " is-active"}`;
  box.replaceChildren();

  const report = state.live.latestReport;
  const actions = node("div", "live-status-actions");
  let title = "";
  let detail = "";

  if (isError) {
    title = "监视中断";
    detail = state.live.error;
    actions.append(
      liveActionButton("重新选择", pickLiveFile),
      liveActionButton("停止", () => stopLive(), true)
    );
  } else if (state.live.mode === "replay") {
    title = state.live.replayDone ? "回放完成" : state.live.paused ? "回放已暂停" : "实时回放中";
    detail = `${state.live.replayIndex}/${state.live.replayLines.length} 行 · ${
      report ? `${report.stats.total_events} 条事件 · ${report.stats.finding_count} 类命中` : "等待首个快照"
    } · ${state.live.lastRefreshAt ? clockTime(state.live.lastRefreshAt) : "—"}`;
    if (state.live.replayDone) {
      actions.append(
        liveActionButton("重新回放", startLiveReplay),
        liveActionButton("停止", () => stopLive(), true)
      );
    } else if (state.live.paused) {
      actions.append(
        liveActionButton("继续回放", resumeLive),
        liveActionButton("停止", () => stopLive(), true)
      );
    } else {
      actions.append(
        liveActionButton("立即研判", manualRefreshLive),
        liveActionButton("暂停回放", pauseLive),
        liveActionButton("停止", () => stopLive(), true)
      );
    }
  } else {
    title = state.live.paused ? "监视已暂停" : "实时监视中";
    detail = `${report ? `${report.stats.total_events} 条事件 · ${report.stats.finding_count} 类命中` : "等待首个快照"} · ${
      formatBytes(state.live.fileMeta?.size || 0)
    } · ${state.live.lastRefreshAt ? clockTime(state.live.lastRefreshAt) : "—"}`;
    if (state.live.paused) {
      actions.append(
        liveActionButton("继续监视", resumeLive),
        liveActionButton("停止", () => stopLive(), true)
      );
    } else {
      actions.append(
        liveActionButton("立即刷新", manualRefreshLive),
        liveActionButton("暂停", pauseLive),
        liveActionButton("停止", () => stopLive(), true)
      );
    }
  }

  const head = node("div", "live-status-head");
  const copy = node("div", "live-status-copy");
  copy.append(
    node("strong", "live-status-title", title),
    node("span", "live-status-detail", detail)
  );
  head.append(node("span", "live-status-dot"), copy, actions);
  box.append(head);
}

async function handleFile(file) {
  const suffixMatch = file.name.toLowerCase().match(/\.[^.]+$/);
  const suffix = suffixMatch ? suffixMatch[0] : "";
  if (BLOCKED_SUFFIXES.includes(suffix)) {
    showToast("出于安全考虑，不接收 PCAP、二进制或可执行文件。请先转换为结构化文本。", "error");
    els.fileInput.value = "";
    return;
  }
  if (!ALLOWED_SUFFIXES.includes(suffix)) {
    showToast(`仅支持 ${ALLOWED_SUFFIXES.join(" / ")} 文本日志。`, "error");
    els.fileInput.value = "";
    return;
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    showToast("文件超过 10MB 上限，请截取时间窗或拆分后重试。", "error");
    els.fileInput.value = "";
    return;
  }
  try {
    const text = await file.text();
    if (text.includes("\u0000")) {
      showToast("文件包含二进制内容，已拒绝解析。", "error");
      els.fileInput.value = "";
      return;
    }
    if (!text.trim()) {
      showToast("文件为空，没有可分析的内容。", "error");
      els.fileInput.value = "";
      return;
    }
    state.upload = { name: file.name, size: file.size, text, lines: lineCount(text) };
    renderUploadInfo();
    els.dropzone.classList.add("has-file");
    setTab("upload");
    updateAnalyzeState();
    showToast("文件已载入浏览器，原始内容未上传。", "success");
  } catch {
    showToast("读取文件失败，请重试。", "error");
    els.fileInput.value = "";
  }
}

function renderUploadInfo() {
  els.uploadInfo.replaceChildren();
  if (!state.upload) {
    els.uploadInfo.hidden = true;
    return;
  }
  const fileIcon = icon("file", "upload-icon");
  const copy = node("div", "upload-copy");
  copy.append(
    node("strong", "upload-name", state.upload.name),
    node("span", "upload-meta", `${formatBytes(state.upload.size)} · ${state.upload.lines} 行 · 已读取到浏览器`)
  );
  const remove = node("button", "text-btn", "移除");
  remove.type = "button";
  remove.addEventListener("click", () => {
    state.upload = null;
    els.fileInput.value = "";
    els.dropzone.classList.remove("has-file");
    renderUploadInfo();
    updateAnalyzeState();
  });
  const row = node("div", "upload-row");
  row.append(fileIcon, copy, remove);
  els.uploadInfo.append(row);
  els.uploadInfo.hidden = false;
}

// ---------------------------------------------------------------- actions
function bindActions() {
  els.analyzeBtn.addEventListener("click", runAnalysis);
  els.resetBtn.addEventListener("click", resetAll);
  els.methodBtn.addEventListener("click", openMethod);
  els.methodClose.addEventListener("click", () => els.methodDialog.close());
  els.methodDialog.addEventListener("click", (event) => {
    if (event.target === els.methodDialog) els.methodDialog.close();
  });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      if (els.methodDialog.open) return;
      event.preventDefault();
      const liveReady = state.tab === "live" && !state.live.picking && !state.live.refreshing;
      if (!state.busy && (canAnalyze() || liveReady)) runAnalysis();
    }
  });
}

function canAnalyze() {
  if (state.busy) return false;
  if (state.tab === "sample") return !state.sampleLoading && state.sampleText.trim().length > 0;
  if (state.tab === "paste") return state.pasteText.trim().length > 0;
  if (state.tab === "upload") return Boolean(state.upload?.text);
  if (state.tab === "live") return Boolean(state.live.mode && state.live.text.trim());
  if (state.tab === "port") {
    return Number.isInteger(state.port) && state.port >= 1 && state.port <= 65535;
  }
  return false;
}

function updateAnalyzeState() {
  const isLive = state.tab === "live";
  const ready = canAnalyze();
  let disabled = state.busy || !ready;
  let label = state.busy ? "分析中" : "运行分析";
  let busy = state.busy;

  if (isLive) {
    const liveBusy = state.live.picking || state.live.refreshing || state.live.replayLoading;
    disabled = state.busy || liveBusy;
    busy = state.busy || liveBusy;
    if (state.live.picking) label = "打开文件…";
    else if (state.live.replayLoading) label = "准备回放…";
    else if (!state.live.mode) label = "开始实时监视";
    else if (state.live.error) label = "重新选择文件";
    else if (state.live.replayDone) label = "重新回放";
    else if (state.live.paused) label = state.live.mode === "replay" ? "继续回放" : "继续监视";
    else label = state.live.refreshing ? "研判中" : "刷新研判";
  }

  els.analyzeBtn.disabled = disabled;
  els.analyzeBtn.classList.toggle("is-busy", busy);
  els.analyzeBtn.setAttribute("aria-busy", String(busy));
  els.analyzeBtn.querySelector(".btn-label").textContent = label;
  els.resetBtn.disabled = state.busy;
  updateSourceHint();
}

function updateSourceHint() {
  if (state.busy) {
    els.sourceHint.textContent = "正在分析…";
    return;
  }
  if (state.sampleLoading) {
    els.sourceHint.textContent = "正在载入样例…";
    return;
  }
  if (state.tab === "port" && !(Number.isInteger(state.port) && state.port >= 1 && state.port <= 65535)) {
    els.sourceHint.textContent = "端口需在 1–65535 之间";
    return;
  }
  const hints = {
    sample: state.sampleText ? "样例已载入，可以开始分析" : "从内置样例开始",
    paste: state.pasteText ? "日志已就绪" : "粘贴任意支持格式",
    upload: state.upload ? "文件已就绪" : "上传结构化文本",
    live: state.live.mode
      ? state.live.paused
        ? "监视已暂停，报告保留"
        : state.live.mode === "replay"
          ? "实时回放中，每 2 秒推进"
          : "实时监视中，每 2 秒检查"
      : "读取你选择的本地日志",
    port: "云端模拟端口监测",
  };
  els.sourceHint.textContent = hints[state.tab] || "";
}

async function runAnalysis() {
  if (state.tab === "live") {
    livePrimaryAction();
    return;
  }
  if (state.busy || !canAnalyze()) {
    showToast("请先提供可分析的流量数据。", "error");
    return;
  }

  const tab = state.tab;
  state.busy = true;
  updateAnalyzeState();
  const simulated = tab === "port";
  renderProgress(simulated);

  try {
    let events = [];
    let format = "";
    let label = "";
    let sourceLabel = "";
    let fileName = "";
    let truncated = false;
    let text = "";

    markStep(0, "active");
    await pause(140);

    if (simulated) {
      sourceLabel = `端口模拟 · :${state.port} / ${state.duration}s`;
      events = simulatePortCapture(state.port, state.duration, state.host);
      format = "simulated";
      label = formatLabel("simulated");
      markStep(0, "done", `生成 ${events.length} 条模拟流量`);
    } else {
      if (tab === "sample") {
        sourceLabel = `示例日志 · ${state.sampleId}`;
        fileName = state.sampleId;
        text = state.sampleText;
      } else if (tab === "paste") {
        sourceLabel = "粘贴日志";
        text = state.pasteText;
      } else {
        sourceLabel = `上传文件 · ${state.upload.name}`;
        fileName = state.upload.name;
        text = state.upload.text;
      }
      const parsed = parseLogs(text);
      if (!parsed.events.length) {
        throw new UserError("未能从输入中解析出流量事件。请确认日志为 Nginx/Apache、CSV、JSON 或 key=value 格式。");
      }
      events = parsed.events;
      format = parsed.format;
      label = parsed.formatLabel;
      truncated = parsed.truncated;
      markStep(0, "done", `${label} · ${events.length} 条事件`);
    }

    markStep(1, "active");
    await pause(170);
    const findings = detectAttacks(events);
    const totalHits = findings.reduce((sum, finding) => sum + finding.count, 0);
    markStep(1, "done", findings.length ? `命中 ${findings.length} 类规则` : "未命中已知规则");

    markStep(2, "active");
    await pause(150);
    const attackerIps = [...new Set(findings.flatMap((finding) => finding.src_ips))];
    const geo = geolocateMany(attackerIps);
    const resolved = Object.values(geo).filter((item) => item.province && !item.is_private).length;
    markStep(2, "done", attackerIps.length ? `${resolved}/${attackerIps.length} 个攻击源已定位` : "无需溯源");

    markStep(3, "active");
    await pause(150);
    const timeline = buildTimeline(events, findings);
    const trace = [
      { label: "数据源", detail: sourceLabel },
      {
        label: simulated ? "流量生成" : "日志解析",
        detail: simulated ? `模拟流量 · ${events.length} 条` : `${label} · ${events.length} 条`,
      },
      { label: "规则检测", detail: `${findings.length} 类 · ${totalHits} 次命中` },
      {
        label: "IP 溯源",
        detail: attackerIps.length ? `${resolved}/${attackerIps.length} 个攻击源已定位` : "无攻击源需溯源",
      },
    ];
    const report = buildReport({
      events,
      findings,
      geo,
      timeline,
      format,
      formatLabel: label,
      sourceLabel,
      fileName,
      simulated,
      truncated,
      trace,
    });
    markStep(3, "done", "报告已生成");

    await pause(220);
    renderReport(report);
    showToast("分析完成，报告已在本地生成。", "success");
  } catch (error) {
    console.error(error);
    const message = error instanceof UserError
      ? error.message
      : `分析过程出错：${error.message || "未知错误"}`;
    renderEmpty(message, true);
    showToast(message, "error");
  } finally {
    state.busy = false;
    updateAnalyzeState();
  }
}

class UserError extends Error {}

async function resetAll() {
  if (state.busy) return;
  if (state.live.mode || state.live.latestReport) {
    stopLive({ silent: true, keepReport: false });
  }
  state.pasteText = "";
  els.logInput.value = "";
  updateLogCount();
  state.upload = null;
  els.fileInput.value = "";
  els.dropzone.classList.remove("has-file");
  renderUploadInfo();
  state.port = 80;
  els.portInput.value = "80";
  state.duration = 15;
  els.durationInput.value = "15";
  state.host = "demo.local";
  els.hostInput.value = "demo.local";
  state.sampleId = SAMPLE_CATALOG[0].id;
  state.sampleText = "";
  state.report = null;
  updateSampleSelection();
  setTab("sample");
  renderEmpty();
  await loadSample(state.sampleId);
  showToast("已重置输入与结果。", "info");
}

async function runDemo() {
  if (state.busy) return;
  state.sampleId = "web_attack_nginx.log";
  state.sampleText = "";
  updateSampleSelection();
  setTab("sample");
  await loadSample(state.sampleId);
  if (state.sampleText) await runAnalysis();
}

// ---------------------------------------------------------------- progress
function renderProgress(simulated) {
  const firstLabel = simulated ? "生成模拟流量" : "解析流量";
  els.workspace.innerHTML = `
    <section class="progress-card" aria-busy="true">
      <div class="progress-head">
        <div class="eyebrow">ANALYSIS IN PROGRESS</div>
        <h1>正在分析流量…</h1>
        <p>解析、检测、溯源与报告生成都在浏览器内完成。原始日志没有离开本机。</p>
      </div>
      <ol class="progress-list">
        ${[
          [firstLabel, "等待中"],
          ["规则检测", "等待中"],
          ["IP 溯源", "等待中"],
          ["生成报告", "等待中"],
        ].map(([label, detail], index) => `
          <li class="progress-step" data-step="${index}">
            <span class="step-marker">${String(index + 1).padStart(2, "0")}</span>
            <span class="step-copy"><strong class="step-name">${label}</strong><span class="step-detail">${detail}</span></span>
            <span class="step-state">等待</span>
          </li>`).join("")}
      </ol>
      <div class="progress-foot"><span class="pulse-dot"></span>本地执行 · 0 网络请求</div>
    </section>`;
}

function markStep(index, status, detail) {
  const step = $(`.progress-step[data-step="${index}"]`, els.workspace);
  if (!step) return;
  step.classList.toggle("is-active", status === "active");
  step.classList.toggle("is-done", status === "done");
  const detailEl = $(".step-detail", step);
  if (detail) detailEl.textContent = detail;
  const stateEl = $(".step-state", step);
  if (stateEl) stateEl.textContent = status === "active" ? "执行中" : status === "done" ? "完成" : "等待";
}

// ---------------------------------------------------------------- empty state
function renderEmpty(message = "", isError = false) {
  const capabilities = DETECTION_RULES
    .map((rule) => `<span class="capability">${escapeHtml(rule.name)}</span>`)
    .join("");
  els.workspace.innerHTML = `
    <section class="empty-state">
      <div class="empty-copy">
        <div class="eyebrow">SENTINEL / TRAFFIC FORENSICS</div>
        <h1>把原始流量，<br />整理成可执行的研判。</h1>
        <p class="empty-lead">在浏览器内完成日志解析、规则检测、IP 溯源与报告生成。原始日志不会上传到任何服务器。</p>
        ${message ? `<div class="alert ${isError ? "alert-error" : "alert-info"}">${escapeHtml(message)}</div>` : ""}
        <div class="flow">
          <div class="flow-item">
            <span class="flow-num">01</span>
            <div><strong>载入数据</strong><span>示例、粘贴或上传</span></div>
          </div>
          <div class="flow-item">
            <span class="flow-num">02</span>
            <div><strong>规则检测</strong><span>特征匹配 + 行为窗口</span></div>
          </div>
          <div class="flow-item">
            <span class="flow-num">03</span>
            <div><strong>证据报告</strong><span>溯源、时间线与处置建议</span></div>
          </div>
        </div>
        <div class="empty-actions">
          <button id="demoBtn" class="primary-btn" type="button">
            <span>运行示例分析</span>
            <span class="btn-icon"><svg viewBox="0 0 18 18" fill="none" aria-hidden="true">${ICONS.arrow}</svg></span>
          </button>
          <button id="emptyMethodBtn" class="ghost-btn" type="button">方法与边界</button>
        </div>
        <div class="capabilities">
          <span class="cap-label">检测能力</span>
          ${capabilities}
        </div>
        <p class="empty-note">内置归属地库仅覆盖样例 IP；真实公网 IP 可在“实时”模式按需查询云端情报。</p>
      </div>
      <div class="empty-visual" aria-hidden="true">
        <div class="radar">
          <span class="radar-line-h"></span>
          <span class="radar-line-v"></span>
          <span class="radar-sweep"></span>
          <span class="radar-core"></span>
          <span class="blip b1"></span>
          <span class="blip b2"></span>
          <span class="blip b3"></span>
          <span class="radar-caption">LOCAL ENGINE / READY</span>
        </div>
        <div class="visual-stats">
          <div><b>10</b><span>检测规则</span></div>
          <div><b>4</b><span>日志格式</span></div>
          <div><b>0</b><span>日志上传</span></div>
        </div>
      </div>
    </section>`;
  $("#demoBtn", els.workspace)?.addEventListener("click", runDemo);
  $("#emptyMethodBtn", els.workspace)?.addEventListener("click", openMethod);
}

function renderLiveIdle(message = "", isError = false) {
  const formats = ["Nginx / Apache", "CSV", "JSON / JSONL", "key=value"]
    .map((item) => `<span class="capability">${escapeHtml(item)}</span>`)
    .join("");
  els.workspace.innerHTML = `
    <section class="empty-state live-empty">
      <div class="empty-copy">
        <div class="eyebrow">LIVE / LOCAL FILE WATCH</div>
        <h1>让日志继续增长，<br />异常一出现就被看见。</h1>
        <p class="empty-lead">选择一个本地访问日志。哨兵每 2 秒检查文件变化，在浏览器内重新解析、检测并生成快照报告；文件正文不会上传。</p>
        ${message ? `<div class="alert ${isError ? "alert-error" : "alert-info"}">${escapeHtml(message)}</div>` : ""}
        <div class="flow">
          <div class="flow-item">
            <span class="flow-num">01</span>
            <div><strong>选择日志</strong><span>本地读取，不上传正文</span></div>
          </div>
          <div class="flow-item">
            <span class="flow-num">02</span>
            <div><strong>自动快照</strong><span>每 2 秒检查一次变化</span></div>
          </div>
          <div class="flow-item">
            <span class="flow-num">03</span>
            <div><strong>来源画像</strong><span>可选云端 IP 情报</span></div>
          </div>
        </div>
        <div class="empty-actions">
          <button id="liveEmptyPick" class="primary-btn" type="button">
            <span>${isError ? "重新选择文件" : "选择日志文件"}</span>
            <span class="btn-icon"><svg viewBox="0 0 18 18" fill="none" aria-hidden="true">${ICONS.arrow}</svg></span>
          </button>
          <button id="liveEmptyReplay" class="ghost-btn" type="button">用攻击样例体验实时</button>
          <button id="liveEmptyMethod" class="ghost-btn" type="button">方法与边界</button>
        </div>
        <div class="capabilities">
          <span class="cap-label">支持格式</span>
          ${formats}
        </div>
        <p class="empty-note">需要保持页面打开；日志轮转、文件被替换或权限撤销后需重新选择。开启云端情报时只发送公网攻击源 IP。</p>
      </div>
      <div class="empty-visual" aria-hidden="true">
        <div class="radar">
          <span class="radar-line-h"></span>
          <span class="radar-line-v"></span>
          <span class="radar-sweep"></span>
          <span class="radar-core"></span>
          <span class="blip b1"></span>
          <span class="blip b2"></span>
          <span class="blip b3"></span>
          <span class="radar-caption">LIVE WATCH / READY</span>
        </div>
        <div class="visual-stats">
          <div><b>2s</b><span>检查间隔</span></div>
          <div><b>0</b><span>日志上传</span></div>
          <div><b>10</b><span>检测规则</span></div>
        </div>
      </div>
    </section>`;
  $("#liveEmptyPick", els.workspace)?.addEventListener("click", pickLiveFile);
  $("#liveEmptyReplay", els.workspace)?.addEventListener("click", startLiveReplay);
  $("#liveEmptyMethod", els.workspace)?.addEventListener("click", openMethod);
}

// ---------------------------------------------------------------- report
function renderReport(report, options = {}) {
  const preserve = Boolean(options.preserve);
  const openKeys = preserve
    ? new Set([...els.workspace.querySelectorAll(".finding.is-open")].map((item) => item.dataset.findingKey))
    : new Set();
  const activeFinding = document.activeElement?.closest?.(".finding")?.dataset.findingKey || "";
  const previousScroll = preserve ? window.scrollY : 0;

  state.report = report;
  const riskKey = RISK_CLASS[report.risk_level] || "none";
  const root = node("article", `report risk-${riskKey}`);
  root.setAttribute("aria-labelledby", "reportVerdict");

  const hero = node("header", "report-hero");
  const heroTop = node("div", "hero-top");
  const kicker = node("div", "report-kicker");
  kicker.append(
    node("span", "eyebrow", report.live ? "LIVE ANALYSIS / SNAPSHOT" : "ANALYSIS REPORT"),
    node("span", "report-id", report.report_id)
  );
  heroTop.append(kicker, node("span", `risk-badge risk-${riskKey}`, report.risk_level));

  hero.append(heroTop);
  if (report.live) hero.append(renderLiveStrip(report));
  hero.append(
    node("h1", "report-verdict", report.verdict),
    node("p", "report-summary", report.summary)
  );

  const meta = node("div", "report-meta");
  const metaItems = [
    [report.live ? "快照时间" : "生成时间", report.generated_at],
    ["数据源", report.data_mode],
    ["研判引擎", report.engine],
    ["时间范围", `${report.time_range.start || "—"} → ${report.time_range.end || "—"}`],
  ];
  for (const [label, value] of metaItems) {
    const item = node("div", "meta-item");
    item.append(node("span", "meta-label", label), node("span", "meta-value", value));
    meta.append(item);
  }
  hero.append(meta);

  const actions = node("div", "report-actions");
  actions.append(
    actionButton("json", "导出 JSON", "download"),
    actionButton("markdown", "导出 Markdown", "download"),
    actionButton("copy", "复制摘要", "copy")
  );
  hero.append(actions);
  root.append(hero);

  const attackerCount = report.attacker_origins.length;
  const kpis = [
    {
      label: "流量事件",
      value: report.stats.total_events.toLocaleString("zh-CN"),
      note: `${report.stats.timestamped_events.toLocaleString("zh-CN")} 条含可解析时间戳`,
    },
    {
      label: "来源 IP",
      value: report.stats.unique_src_ips.toLocaleString("zh-CN"),
      note: `${report.stats.attacker_events.toLocaleString("zh-CN")} 条来自攻击源`,
    },
    {
      label: "命中类型",
      value: report.stats.finding_count,
      note: report.stats.finding_count ? "按严重度排序" : "未命中已知特征",
    },
    {
      label: "溯源覆盖",
      value: attackerCount ? `${report.stats.geo_resolved}/${attackerCount}` : "—",
      note: attackerCount
        ? (report.stats.cloud_geo
          ? `${report.stats.cloud_geo} 个云端情报${report.stats.demo_geo ? ` · ${report.stats.demo_geo} 演示` : ""}`
          : report.stats.demo_geo ? `${report.stats.demo_geo} 个来自演示库` : "演示库未覆盖")
        : "无攻击源需溯源",
    },
  ];
  const kpiGrid = node("section", "kpi-grid");
  for (const kpi of kpis) {
    const card = node("div", "kpi");
    card.append(
      node("span", "kpi-label", kpi.label),
      node("strong", "kpi-value", kpi.value),
      node("span", "kpi-note", kpi.note)
    );
    kpiGrid.append(card);
  }
  root.append(kpiGrid);

  const reportGrid = node("div", "report-grid");
  reportGrid.append(renderTimelineCard(report), renderSeverityCard(report));
  root.append(reportGrid);

  root.append(renderFindings(report, openKeys));
  root.append(renderOrigins(report));

  const recommendationCard = node("section", "card recommendations-card");
  const recHead = node("div", "card-head");
  recHead.append(
    node("h3", "", "处置与加固建议"),
    node("span", "card-meta", `${report.recommendations.length} 条`)
  );
  recommendationCard.append(recHead);
  const list = node("ol", "rec-list");
  report.recommendations.forEach((item) => list.append(node("li", "", item)));
  recommendationCard.append(list);
  root.append(recommendationCard);

  root.append(renderMethodTrace(report));
  root.append(renderReportFooter());

  els.workspace.replaceChildren(root);
  bindReportActions(root, report);

  if (preserve) {
    requestAnimationFrame(() => window.scrollTo({ top: previousScroll, behavior: "auto" }));
    if (activeFinding) {
      const target = [...root.querySelectorAll(".finding")]
        .find((item) => item.dataset.findingKey === activeFinding);
      target?.querySelector(".finding-head")?.focus({ preventScroll: true });
    }
  } else if (options.scroll !== false && !report.live && window.matchMedia("(max-width: 980px)").matches) {
    root.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function renderLiveStrip(report) {
  const strip = node("div", "report-live-strip");
  const active = Boolean(state.live.mode && !state.live.paused && !state.live.replayDone);
  if (!active) strip.classList.add("is-idle");

  let label = "实时快照";
  if (state.live.mode === "replay") {
    label = state.live.replayDone
      ? `回放完成 · ${state.live.replayIndex}/${state.live.replayLines.length} 行`
      : state.live.paused
        ? "回放已暂停 · 报告为暂停前快照"
        : `实时回放中 · ${state.live.replayIndex}/${state.live.replayLines.length} 行`;
  } else if (state.live.mode === "file") {
    label = state.live.paused ? "监视已暂停 · 报告为暂停前快照" : "实时监视中 · 每 2 秒检查变化";
  } else {
    label = "实时快照 · 监视已停止";
  }

  strip.append(
    node("span", "live-pulse"),
    node("span", "live-strip-text", label),
    node("span", "live-strip-mode", report.replay ? "内置回放 · 浏览器内" : "本地文件 · 浏览器内"),
    node("span", "live-strip-meta", state.live.lastRefreshAt ? `快照 ${clockTime(state.live.lastRefreshAt)}` : "")
  );
  return strip;
}

function actionButton(action, label, iconName) {
  const button = node("button", "ghost-btn small");
  button.type = "button";
  button.dataset.action = action;
  button.append(icon(iconName, "btn-icon"), node("span", "", label));
  return button;
}

function bindReportActions(root, report) {
  root.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.dataset.action;
      if (action === "json") downloadJson(report);
      if (action === "markdown") downloadMarkdown(report);
      if (action === "copy") copySummary(report);
    });
  });
}

function renderTimelineCard(report) {
  const card = node("section", "card timeline-card");
  const head = node("div", "card-head");
  head.append(
    node("h3", "", "事件时间线"),
    node("span", "card-meta", report.timeline ? `按 ${report.timeline.bucket_label}聚合` : "缺少时间戳")
  );
  card.append(head);

  if (!report.timeline) {
    card.append(node("p", "card-empty", "日志中没有足够的可解析时间戳，未生成时间线。"));
    return card;
  }

  card.append(renderTimelineChart(report.timeline));
  const legend = node("div", "chart-legend");
  const totalLegend = node("span", "");
  totalLegend.append(node("i", "legend-line legend-total"), document.createTextNode("全部事件"));
  const attackLegend = node("span", "");
  attackLegend.append(node("i", "legend-line legend-attack"), document.createTextNode("攻击源相关事件"));
  legend.append(totalLegend, attackLegend);
  card.append(legend);
  card.append(renderTimelineTable(report.timeline));
  return card;
}

function svgNode(tag, attrs = {}) {
  const element = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    element.setAttribute(key, String(value));
  }
  return element;
}

function niceChartScale(peak) {
  const value = Math.max(Number(peak) || 1, 1);
  const candidates = [
    1, 2, 5, 10, 20, 25, 50, 100, 125, 150, 200, 250, 300,
    500, 1000, 2000, 5000, 10000, 20000, 50000,
  ];
  const target = value / 3;
  const step = candidates.find((item) => item >= target) || Math.ceil(target / 10000) * 10000;
  const max = Math.ceil(value / step) * step;
  const ticks = [];
  for (let tick = max; tick >= 0; tick -= step) ticks.push(tick);
  return { max, ticks };
}

function renderTimelineChart(timeline) {
  const width = 760;
  const height = 180;
  const pad = { left: 38, right: 14, top: 16, bottom: 30 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const points = timeline.points;
  const scale = niceChartScale(timeline.max_total);
  const max = scale.max;
  const x = (index) => points.length === 1
    ? pad.left + plotW / 2
    : pad.left + (index / (points.length - 1)) * plotW;
  const y = (value) => pad.top + plotH - (value / max) * plotH;
  const baseY = pad.top + plotH;

  const svg = svgNode("svg", {
    viewBox: `0 0 ${width} ${height}`,
    class: "timeline-svg",
    role: "img",
    "aria-label": `事件时间线，共 ${points.length} 个时间桶，峰值 ${timeline.max_total} 条事件。`,
    preserveAspectRatio: "xMidYMid meet",
  });
  const title = svgNode("title");
  title.textContent = `事件时间线：峰值 ${timeline.max_total} 条事件`;
  svg.append(title);

  const defs = svgNode("defs");
  const gradient = svgNode("linearGradient", {
    id: "timelineFill",
    x1: "0", y1: "0", x2: "0", y2: "1",
  });
  gradient.append(
    svgNode("stop", { offset: "0%", "stop-color": "#c6f56a", "stop-opacity": "0.26" }),
    svgNode("stop", { offset: "100%", "stop-color": "#c6f56a", "stop-opacity": "0" })
  );
  defs.append(gradient);
  svg.append(defs);

  for (const tick of scale.ticks) {
    const gy = y(tick);
    if (tick > 0) {
      svg.append(svgNode("line", {
        x1: pad.left, y1: gy, x2: width - pad.right, y2: gy,
        class: "chart-grid",
      }));
    }
    const text = svgNode("text", {
      x: pad.left - 8, y: gy + 3,
      class: "chart-axis", "text-anchor": "end",
    });
    text.textContent = String(tick);
    svg.append(text);
  }

  const coords = points.map((point, index) => ({ x: x(index), y: y(point.total) }));
  const area = `M ${coords[0].x} ${baseY} ` +
    coords.map((coord) => `L ${coord.x} ${coord.y}`).join(" ") +
    ` L ${coords[coords.length - 1].x} ${baseY} Z`;
  svg.append(svgNode("path", { d: area, fill: "url(#timelineFill)" }));

  const totalPath = coords.map((coord, index) =>
    `${index === 0 ? "M" : "L"} ${coord.x} ${coord.y}`).join(" ");
  svg.append(svgNode("path", { d: totalPath, class: "chart-line-total" }));

  if (points.some((point) => point.attack > 0)) {
    const attackPath = points.map((point, index) => {
      const px = x(index);
      const py = y(point.attack);
      return `${index === 0 ? "M" : "L"} ${px} ${py}`;
    }).join(" ");
    svg.append(svgNode("path", { d: attackPath, class: "chart-line-attack" }));
    points.forEach((point, index) => {
      if (point.attack <= 0) return;
      const circle = svgNode("circle", {
        cx: x(index), cy: y(point.attack), r: 2.8, class: "chart-dot-attack",
      });
      const pointTitle = svgNode("title");
      pointTitle.textContent = `${point.label} · 事件 ${point.total} · 攻击源 ${point.attack}`;
      circle.append(pointTitle);
      svg.append(circle);
    });
  }

  const labelIndexes = [...new Set([
    0,
    Math.round((points.length - 1) * 0.25),
    Math.round((points.length - 1) * 0.5),
    Math.round((points.length - 1) * 0.75),
    points.length - 1,
  ])];
  for (const index of labelIndexes) {
    const text = svgNode("text", {
      x: x(index), y: height - 8,
      class: "chart-axis",
      "text-anchor": index === 0 ? "start" : index === points.length - 1 ? "end" : "middle",
    });
    text.textContent = points[index].label;
    svg.append(text);
  }

  svg.append(svgNode("line", {
    x1: pad.left, y1: baseY, x2: width - pad.right, y2: baseY, class: "chart-axis-line",
  }));

  return svg;
}

function renderTimelineTable(timeline) {
  const details = node("details", "chart-data");
  const summary = document.createElement("summary");
  summary.textContent = "查看时间线数据";
  details.append(summary);
  const scroll = node("div", "table-scroll");
  const table = node("table");
  const thead = node("thead");
  const headRow = node("tr");
  ["时间", "事件数", "攻击源相关"].forEach((label) => headRow.append(node("th", "", label)));
  thead.append(headRow);
  const tbody = node("tbody");
  for (const point of timeline.points) {
    const row = node("tr");
    row.append(
      node("td", "", point.label),
      node("td", "", point.total),
      node("td", "", point.attack)
    );
    tbody.append(row);
  }
  table.append(thead, tbody);
  scroll.append(table);
  details.append(scroll);
  return details;
}

function renderSeverityCard(report) {
  const card = node("section", "card severity-card");
  const head = node("div", "card-head");
  head.append(
    node("h3", "", "严重度分布"),
    node("span", "card-meta", `${report.stats.finding_count} 类发现`)
  );
  card.append(head);

  const order = ["critical", "high", "medium", "low"];
  const counts = report.stats.severity_counts;
  const total = order.reduce((sum, key) => sum + (counts[key] || 0), 0);
  const bar = node("div", "severity-bar");
  if (!total) {
    const segment = node("span", "sev-segment sev-none");
    segment.style.flexGrow = "1";
    bar.append(segment);
  } else {
    for (const key of order) {
      const count = counts[key] || 0;
      if (!count) continue;
      const segment = node("span", `sev-segment sev-${key}`);
      segment.style.flexGrow = String(count);
      segment.title = `${SEVERITY_TEXT[key]} · ${count} 类`;
      bar.append(segment);
    }
  }
  card.append(bar);

  const legend = node("div", "severity-legend");
  for (const key of order) {
    const item = node("div", "severity-item");
    const dot = node("i", `sev-dot sev-${key}`);
    item.append(dot, node("span", "", SEVERITY_TEXT[key]), node("b", "", counts[key] || 0));
    legend.append(item);
  }
  card.append(legend);
  card.append(node("p", "card-note", "按发现类型计数，不等同于受影响事件数。"));
  return card;
}

function renderFindings(report, openKeys = new Set()) {
  const card = node("section", "card findings-card");
  const head = node("div", "card-head");
  head.append(
    node("h3", "", "检测发现"),
    node("span", "card-meta", report.findings.length ? `${report.findings.length} 类 · 按严重度排序` : "无命中")
  );
  card.append(head);

  if (!report.findings.length) {
    const empty = node("div", "no-findings");
    empty.append(
      icon("shield", "no-findings-icon"),
      node("h4", "", "未命中已知攻击特征"),
      node("p", "", "规则引擎没有发现 SQL 注入、XSS、扫描、暴破、CC 等已知行为。请结合业务基线与更长时间窗继续复核。")
    );
    card.append(empty);
    return card;
  }

  report.findings.forEach((finding, index) => {
    const key = finding.type_en || finding.type;
    const isOpen = openKeys.has(key);
    const article = node("article", `finding sev-${finding.severity}`);
    article.dataset.findingKey = key;
    const headButton = node("button", "finding-head");
    headButton.type = "button";
    headButton.setAttribute("aria-expanded", String(isOpen));
    const bodyId = `finding-body-${index}`;
    headButton.setAttribute("aria-controls", bodyId);

    const title = node("span", "finding-title");
    title.append(
      node("span", `sev-pill sev-${finding.severity}`, SEVERITY_TEXT[finding.severity] || finding.severity),
      node("strong", "finding-name", finding.type)
    );
    if (finding.mitre) title.append(node("code", "mitre", finding.mitre));

    const meta = node("span", "finding-meta");
    const portText = finding.dst_ports.length ? ` · ${finding.dst_ports.length} 个端口` : "";
    meta.textContent = `${finding.count} 次 · ${finding.src_ips.length} 个来源${portText}`;

    headButton.append(title, meta, icon("chevron", "chevron"));

    const body = node("div", "finding-body");
    body.id = bodyId;
    body.hidden = !isOpen;
    if (isOpen) article.classList.add("is-open");
    body.append(node("p", "finding-desc", finding.description));

    const facts = node("div", "finding-facts");
    const factItems = [
      ["首次出现", finding.first_seen || "未知"],
      ["末次出现", finding.last_seen || "未知"],
      ["目标端口", finding.dst_ports.length ? finding.dst_ports.join(" / ") : "—"],
      ["ATT&CK", finding.mitre || "—"],
    ];
    for (const [label, value] of factItems) {
      const fact = node("div", "fact");
      fact.append(node("span", "fact-label", label), node("span", "fact-value", value));
      facts.append(fact);
    }
    body.append(facts);

    const evidence = node("div", "evidence");
    evidence.append(node("span", "evidence-label", "证据原文"));
    if (finding.evidence.length) {
      for (const line of finding.evidence) {
        evidence.append(node("pre", "evidence-line", line));
      }
    } else {
      evidence.append(node("p", "muted", "数据字段不足，未保留原始证据行。"));
    }
    body.append(evidence);

    headButton.addEventListener("click", () => {
      const expanded = headButton.getAttribute("aria-expanded") === "true";
      headButton.setAttribute("aria-expanded", String(!expanded));
      body.hidden = expanded;
      article.classList.toggle("is-open", !expanded);
    });

    article.append(headButton, body);
    card.append(article);
  });

  return card;
}

function renderOrigins(report) {
  const card = node("section", "card origins-card");
  const head = node("div", "card-head");
  const coverage = [];
  if (report.stats.cloud_geo) coverage.push(`${report.stats.cloud_geo} 个云端情报`);
  if (report.stats.demo_geo) coverage.push(`${report.stats.demo_geo} 个演示`);
  if (!coverage.length) coverage.push("待补充情报");
  head.append(
    node("h3", "", "攻击源画像"),
    node("span", "card-meta", report.attacker_origins.length ? coverage.join(" · ") : "无攻击源")
  );
  card.append(head);

  if (!report.attacker_origins.length) {
    card.append(node("p", "card-empty", "本次分析没有需要溯源的攻击源 IP。"));
    return card;
  }

  const scroll = node("div", "table-scroll");
  const table = node("table", "origins-table");
  const thead = node("thead");
  const headRow = node("tr");
  ["IP / 命中", "归属地", "网络画像", "事件", "来源"].forEach((label) => headRow.append(node("th", "", label)));
  thead.append(headRow);
  const tbody = node("tbody");

  for (const origin of report.attacker_origins) {
    const row = node("tr");

    const ip = node("td", "origin-ip-cell");
    ip.append(node("code", "", origin.ip || "未知"));
    if (origin.finding_types?.length) {
      const types = node("span", "origin-types");
      types.textContent = origin.finding_types.slice(0, 2).join(" · ");
      if (origin.finding_types.length > 2) types.textContent += ` +${origin.finding_types.length - 2}`;
      types.title = origin.finding_types.join(" / ");
      ip.append(types);
    }

    const location = node("td", "origin-location");
    location.append(node("span", "", geoLabel(origin)));
    if (origin.timezone) location.append(node("span", "origin-sub", origin.timezone));

    const network = node("td", "origin-network");
    if (origin.network_kind && NETWORK_KIND_LABELS[origin.network_kind]) {
      network.append(node("span", `net-badge net-${origin.network_kind}`, NETWORK_KIND_LABELS[origin.network_kind]));
    }
    const networkDetail = [origin.asn, origin.org || origin.isp].filter(Boolean).join(" · ");
    if (networkDetail) network.append(node("span", "origin-sub", networkDetail));
    if (!network.childNodes.length) network.textContent = "—";

    const events = node("td", "origin-events");
    events.append(node("strong", "", origin.event_count || 0), node("span", "origin-sub", "条"));
    if (origin.first_seen) {
      events.title = `首次 ${origin.first_seen} · 末次 ${origin.last_seen || "未知"}`;
    }

    const source = node("td", "origin-source");
    const badge = node("span", `source-badge source-${origin.source || "unknown"}`, SOURCE_TEXT[origin.source] || origin.source || "未知");
    if (origin.source === "online") {
      badge.title = `${CLOUD_GEO.label} · ${origin.provider || CLOUD_GEO.id} · ${origin.confidence || "城市级估算"}`;
    }
    if (origin.demo) badge.title = "内置演示归属地，不可用于取证";
    if (origin.source === "pending") badge.title = `正在向 ${CLOUD_GEO.id} 查询公网 IP 归属地`;
    source.append(badge);
    if (origin.source === "online" && origin.provider) {
      source.append(node("span", "origin-sub", origin.provider));
    }

    row.append(ip, location, network, events, source);
    tbody.append(row);
  }

  table.append(thead, tbody);
  scroll.append(table);
  card.append(scroll);

  const notes = [];
  if (report.stats.cloud_geo) {
    notes.push(`云端归属地来自 ${CLOUD_GEO.id} 的城市级估算；仅发送公网攻击源 IP。VPN、代理、NAT 与 CDN 会降低准确性。`);
  }
  if (report.stats.demo_geo) {
    notes.push(`其中 ${report.stats.demo_geo} 个归属地来自内置演示库，仅用于展示溯源流程，不可用于真实取证。`);
  }
  if (!notes.length && report.attacker_origins.some((origin) => !origin.is_private)) {
    notes.push("内置演示库未覆盖该 IP；可在“实时”模式开启云端情报，或接入自有 GeoIP 库。");
  }
  if (notes.length) card.append(node("p", "card-note", notes.join(" ")));
  return card;
}

function renderMethodTrace(report) {
  const card = node("section", "card method-card");
  const head = node("div", "card-head");
  head.append(
    node("h3", "", "分析轨迹与研判边界"),
    node("span", "card-meta", "LOCAL / EXPLAINABLE")
  );
  card.append(head);

  if (report.trace.length) {
    const trace = node("div", "trace-grid");
    report.trace.forEach((item, index) => {
      const entry = node("div", "trace-item");
      entry.append(
        node("span", "trace-index", String(index + 1).padStart(2, "0")),
        node("div", "trace-copy")
      );
      entry.lastChild.append(
        node("span", "trace-label", item.label),
        node("span", "trace-detail", item.detail)
      );
      trace.append(entry);
    });
    card.append(trace);
  }

  const limitations = node("div", "limitations");
  limitations.append(node("h4", "", "已知边界"));
  const list = node("ul", "limit-list");
  report.limitations.forEach((item) => list.append(node("li", "", item)));
  limitations.append(list);
  card.append(limitations);

  const privacy = node("div", "privacy-strip");
  const privacyText = report.stats.cloud_geo
    ? "解析、检测与报告生成在浏览器内完成，原始日志未上传。云端情报仅接收公网攻击源 IP。"
    : "解析、检测、溯源与报告生成全部在浏览器内完成，原始日志未上传。";
  privacy.append(icon("lock", "btn-icon"), node("span", "", privacyText));
  card.append(privacy);
  return card;
}

function renderReportFooter() {
  const footer = node("footer", "report-footer");
  footer.append(
    node("span", "", "Sentinel · 防御性安全分析演示"),
    node("span", "", "报告仅供研判参考，不构成法律证据。")
  );
  return footer;
}

// ---------------------------------------------------------------- method dialog
function openMethod() {
  if (!els.methodDialog.open) els.methodDialog.showModal();
}

function renderMethod() {
  const intro = node("p", "dialog-lead",
    "哨兵在浏览器内完成日志解析、规则检测、来源画像与报告生成。页面不加载第三方脚本、字体或分析 SDK；实时模式只读取你主动选择的本地日志。");

  const ruleSection = node("section", "dialog-section");
  ruleSection.append(node("h3", "", "检测规则"));
  const rules = node("div", "method-rules");
  for (const rule of DETECTION_RULES) {
    const row = node("div", "method-rule");
    const top = node("div", "method-rule-top");
    top.append(
      node("strong", "", rule.name),
      node("span", `sev-pill sev-${rule.severity}`, SEVERITY_TEXT[rule.severity] || rule.severity),
      node("code", "mitre", rule.mitre),
      node("span", "method-kind", rule.kind)
    );
    row.append(top, node("p", "", rule.description));
    rules.append(row);
  }
  ruleSection.append(rules);

  const dataSection = node("section", "dialog-section");
  dataSection.append(node("h3", "", "数据如何处理"));
  const dataList = node("ul", "dialog-list");
  [
    "日志在浏览器内存中解析，不写入服务器，也不进入任何第三方大模型。",
    "规则检测、报告生成与导出全部本地执行，本项目没有后端分析接口。",
    "实时模式可选择性开启云端 IP 情报：仅在生成快照后，把命中的公网攻击源 IP 发送到 ipwho.is，用于查询归属地与 ASN；不发送日志正文、URL、请求头或 Cookie。",
    "关闭云端情报后，溯源只使用内置演示归属地；已查询结果最多缓存在浏览器 localStorage 中 7 天。",
  ].forEach((item) => dataList.append(node("li", "", item)));
  dataSection.append(dataList);

  const formatSection = node("section", "dialog-section");
  formatSection.append(node("h3", "", "支持的输入"));
  const chips = node("div", "dialog-chips");
  ["Nginx / Apache combined", "CSV", "JSON / JSONL", "key=value 日志", "本地日志实时监视", "端口模拟流量"].forEach((item) => {
    chips.append(node("span", "capability", item));
  });
  formatSection.append(chips);

  const limitsSection = node("section", "dialog-section");
  limitsSection.append(node("h3", "", "研判边界"));
  const limits = node("ul", "dialog-list");
  [
    "内置归属地库仅覆盖演示 IP；真实公网 IP 默认显示“未覆盖”，可在实时模式按需查询第三方云端情报。",
    "IP 归属地只代表网络出口的大致位置，VPN、代理、NAT 与 CDN 会降低准确性，不能定位个人或作为法律证据。",
    "规则引擎擅长已知特征与高频行为，未知攻击、加密流量与低速长期攻击可能漏检。",
    `单次最多分析 ${(20000).toLocaleString("zh-CN")} 条事件；超出部分会提示截断。`,
    "实时模式只监视当前选择的文本文件，需保持页面打开；日志轮转、文件被替换或浏览器撤销权限后需重新选择。",
    "云端无法抓取网卡流量，端口监测使用固定种子的模拟数据演示完整链路。",
    "本工具仅用于防御性分析与教学，请只在获得授权的资产上使用。",
  ].forEach((item) => limits.append(node("li", "", item)));
  limitsSection.append(limits);

  els.methodContent.replaceChildren(intro, ruleSection, dataSection, formatSection, limitsSection);
}

// ---------------------------------------------------------------- export and clipboard
function downloadJson(report) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json;charset=utf-8" });
  downloadBlob(blob, `${report.report_id}.json`);
}

function downloadMarkdown(report) {
  const lines = [];
  lines.push("# Sentinel 安全分析报告", "");
  lines.push(`**报告编号：** ${report.report_id}`);
  lines.push(`**生成时间：** ${report.generated_at}`);
  lines.push(`**数据源：** ${report.data_mode}`);
  lines.push(`**模式：** ${report.replay ? "内置样例实时回放" : report.live ? "本地日志实时快照" : "单次分析"}`);
  lines.push(`**风险等级：** ${report.risk_level}`);
  lines.push(`**研判引擎：** ${report.engine}`);
  lines.push(`**时间范围：** ${report.time_range.start || "—"} → ${report.time_range.end || "—"}`, "");
  lines.push("## 研判结论", "", report.verdict, "", report.summary, "");
  lines.push("## 概览", "");
  lines.push(`- 流量事件：${report.stats.total_events}`);
  lines.push(`- 来源 IP：${report.stats.unique_src_ips}`);
  lines.push(`- 命中类型：${report.stats.finding_count}`);
  lines.push(`- 溯源覆盖：${report.stats.geo_resolved}/${report.attacker_origins.length}`);
  if (report.stats.cloud_geo) lines.push(`- 云端情报：${report.stats.cloud_geo} 个（${CLOUD_GEO.id}）`);
  if (report.stats.demo_geo) lines.push(`- 演示归属地：${report.stats.demo_geo} 个`);
  lines.push("");

  if (report.findings.length) {
    lines.push("## 攻击发现", "");
    lines.push("| 类型 | 等级 | 次数 | 来源 IP | ATT&CK |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const finding of report.findings) {
      lines.push(`| ${md(finding.type)} | ${SEVERITY_TEXT[finding.severity]} | ${finding.count} | ${md(finding.src_ips.join(", "))} | ${finding.mitre || "—"} |`);
    }
    lines.push("");
    for (const finding of report.findings) {
      lines.push(`### ${finding.type}`, "", finding.description, "");
      if (finding.evidence.length) {
        lines.push("证据：", "", "````text", finding.evidence.join("\n"), "````", "");
      }
    }
  } else {
    lines.push("## 攻击发现", "", "未命中已知攻击特征。", "");
  }

  if (report.attacker_origins.length) {
    lines.push("## 攻击源画像", "");
    lines.push("| IP | 事件 | 归属地 | 网络画像 | 来源 |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const origin of report.attacker_origins) {
      const network = [
        origin.network_kind ? NETWORK_KIND_LABELS[origin.network_kind] : "",
        origin.asn,
        origin.org || origin.isp,
      ].filter(Boolean).join(" · ");
      lines.push(`| ${origin.ip} | ${origin.event_count || 0} | ${md(geoLabel(origin))} | ${md(network || "—")} | ${SOURCE_TEXT[origin.source] || origin.source} |`);
    }
    lines.push("");
  }

  lines.push("## 处置与加固建议", "");
  report.recommendations.forEach((item, index) => lines.push(`${index + 1}. ${item}`));
  lines.push("", "## 研判边界", "");
  report.limitations.forEach((item) => lines.push(`- ${item}`));
  lines.push("", "---", "", "Sentinel · 防御性安全分析演示 · 报告仅供研判参考，不构成法律证据。");

  const blob = new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" });
  downloadBlob(blob, `${report.report_id}.md`);
}

function md(value) {
  return String(value ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copySummary(report) {
  const summary = [
    report.verdict,
    `风险等级：${report.risk_level}`,
    report.summary,
    `报告编号：${report.report_id}`,
  ].join("\n\n");
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(summary);
    } else {
      throw new Error("clipboard unavailable");
    }
    showToast("摘要已复制。", "success");
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = summary;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    try {
      document.execCommand("copy");
      showToast("摘要已复制。", "success");
    } catch {
      showToast("复制失败，请手动选择文本。", "error");
    }
    textarea.remove();
  }
}

init();
