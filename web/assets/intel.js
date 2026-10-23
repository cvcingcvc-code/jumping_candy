import { isPrivateIp } from "./engine.js";

export const CLOUD_GEO = {
  id: "ipwho.is",
  label: "云端 IP 情报",
  endpoint: "https://ipwho.is/",
  ttlMs: 7 * 24 * 60 * 60 * 1000,
  maxPerRefresh: 8,
  requestGapMs: 320,
};

export const NETWORK_KIND_LABELS = {
  hosting: "云 / IDC",
  mobile: "移动网络",
  education: "教育网",
  broadband: "宽带 / ISP",
  unknown: "网络未分类",
};

const HOSTING_PATTERNS = [
  /\baws\b/i, /amazon/i, /google/i, /microsoft/i, /azure/i,
  /alibaba|aliyun|阿里云/i, /tencent|腾讯云/i, /huawei|华为云/i,
  /oracle/i, /digitalocean/i, /linode/i, /akamai/i, /cloudflare/i,
  /ovh/i, /vultr/i, /hetzner/i, /leaseweb/i, /choopa/i, /m247/i,
  /hosting/i, /host(?:ing)?\s+(?:provider|network|service)/i,
  /data\s*cent(?:er|re)/i, /colocation/i, /\bidc\b/i,
  /contabo/i, /rackspace/i, /equinix/i, /gcore/i, /scaleway/i,
  /upcloud/i, /kamatera/i, /psychz/i, /server/i,
];

const MOBILE_PATTERNS = [
  /mobile/i, /cellular/i, /\bcmcc\b/i, /china\s+mobile/i, /中国移动/i,
  /wireless/i, /\b(?:4g|5g)\b/i,
];

const EDUCATION_PATTERNS = [
  /university/i, /college/i, /education/i, /ac\.cn/i, /教育网/i, /科研/i,
];

const BROADBAND_PATTERNS = [
  /telecom/i, /chinanet/i, /unicom/i, /china\s+unicom/i, /联通/i, /电信/i,
  /broadband/i, /fiber/i, /comcast/i, /verizon/i, /at&t/i, /charter/i,
  /spectrum/i, /\bcable\b/i, /\bdsl\b/i, /\bisp\b/i,
];

function text(value) {
  return typeof value === "string" ? value.trim() : "";
}

function clip(value, max = 160) {
  return text(value).slice(0, max) || null;
}

export function inferNetworkKind(...parts) {
  const haystack = parts.filter(Boolean).join(" ");
  if (!haystack) return "unknown";
  if (EDUCATION_PATTERNS.some((pattern) => pattern.test(haystack))) return "education";
  if (HOSTING_PATTERNS.some((pattern) => pattern.test(haystack))) return "hosting";
  if (MOBILE_PATTERNS.some((pattern) => pattern.test(haystack))) return "mobile";
  if (BROADBAND_PATTERNS.some((pattern) => pattern.test(haystack))) return "broadband";
  return "unknown";
}

export function isLookupableIp(ip) {
  const value = text(ip);
  if (!value || isPrivateIp(value)) return null;
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return null;
  if (value.split(".").some((part) => Number(part) > 255)) return null;
  return value;
}

export function normalizeIpWhoPayload(ip, payload, now = Date.now()) {
  const target = isLookupableIp(ip);
  if (!target) throw new Error("not_lookupable");
  if (!payload || typeof payload !== "object" || payload.success !== true) {
    throw new Error("lookup_failed");
  }
  if (text(payload.ip) && text(payload.ip) !== target) throw new Error("ip_mismatch");

  const country = clip(payload.country, 80);
  const province = clip(payload.region, 80);
  const city = clip(payload.city, 80);
  if (!country && !province && !city) throw new Error("empty_location");

  const connection = payload.connection && typeof payload.connection === "object"
    ? payload.connection
    : {};
  const isp = clip(connection.org || connection.isp, 160);
  const asnNumber = Number(connection.asn);
  const asn = Number.isFinite(asnNumber) && asnNumber > 0 ? `AS${asnNumber}` : null;

  return {
    ip: target,
    is_private: false,
    country,
    province,
    city,
    isp,
    org: clip(connection.org, 160),
    asn,
    network_kind: inferNetworkKind(connection.org, connection.isp),
    timezone: clip(payload.timezone?.id, 80),
    latitude: Number.isFinite(Number(payload.latitude)) ? Number(payload.latitude) : null,
    longitude: Number.isFinite(Number(payload.longitude)) ? Number(payload.longitude) : null,
    source: "online",
    demo: false,
    provider: CLOUD_GEO.id,
    confidence: "城市级估算",
    fetched_at: now,
  };
}

export function isFreshCloudGeo(entry, now = Date.now()) {
  return Boolean(
    entry &&
    entry.source === "online" &&
    Number.isFinite(entry.fetched_at) &&
    now - entry.fetched_at >= 0 &&
    now - entry.fetched_at < CLOUD_GEO.ttlMs
  );
}

export function readGeoCache(storage) {
  if (!storage) return {};
  try {
    const parsed = JSON.parse(storage.getItem("sentinel.cloudGeo.v1") || "{}");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const now = Date.now();
    const entries = {};
    for (const [ip, entry] of Object.entries(parsed)) {
      if (isLookupableIp(ip) && isFreshCloudGeo(entry, now)) entries[ip] = entry;
    }
    return entries;
  } catch {
    return {};
  }
}

export function writeGeoCache(storage, entries, limit = 120) {
  if (!storage) return;
  try {
    const now = Date.now();
    const fresh = Object.entries(entries)
      .filter(([ip, entry]) => isLookupableIp(ip) && isFreshCloudGeo(entry, now))
      .sort((a, b) => b[1].fetched_at - a[1].fetched_at)
      .slice(0, limit);
    storage.setItem("sentinel.cloudGeo.v1", JSON.stringify(Object.fromEntries(fresh)));
  } catch {
    // Storage can be unavailable in private or quota-limited contexts.
  }
}

export async function fetchCloudGeo(ip, { fetchImpl = fetch, signal, now = Date.now() } = {}) {
  const target = isLookupableIp(ip);
  if (!target) throw new Error("not_lookupable");
  const response = await fetchImpl(`${CLOUD_GEO.endpoint}${encodeURIComponent(target)}?lang=zh-CN`, {
    method: "GET",
    mode: "cors",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    cache: "no-store",
    signal,
  });
  if (!response.ok) throw new Error(`http_${response.status}`);
  const payload = await response.json();
  return normalizeIpWhoPayload(target, payload, now);
}
