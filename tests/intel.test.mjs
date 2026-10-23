import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CLOUD_GEO,
  NETWORK_KIND_LABELS,
  inferNetworkKind,
  isLookupableIp,
  normalizeIpWhoPayload,
  isFreshCloudGeo,
  readGeoCache,
  writeGeoCache,
  fetchCloudGeo,
} from "../web/assets/intel.js";

function memoryStorage() {
  const entries = new Map();
  return {
    getItem: (key) => (entries.has(key) ? entries.get(key) : null),
    setItem: (key, value) => entries.set(key, String(value)),
    removeItem: (key) => entries.delete(key),
  };
}

const payloadFor = (ip, overrides = {}) => ({
  success: true,
  ip,
  country: "荷兰",
  region: "北荷兰省",
  city: "阿姆斯特丹",
  connection: {
    asn: 12345,
    org: "Hosting B.V.",
    isp: "Hosting Network",
  },
  timezone: { id: "Europe/Amsterdam" },
  latitude: "52.37",
  longitude: "4.89",
  ...overrides,
});

test("only public IPv4 sources leave the browser for lookup", () => {
  assert.equal(isLookupableIp("45.155.205.99"), "45.155.205.99");
  assert.equal(isLookupableIp("8.8.8.8"), "8.8.8.8");
  assert.equal(isLookupableIp("192.168.1.10"), null);
  assert.equal(isLookupableIp("127.0.0.1"), null);
  assert.equal(isLookupableIp("100.64.0.9"), null);
  assert.equal(isLookupableIp("2001:4860:4860::8888"), null);
  assert.equal(isLookupableIp("999.1.1.1"), null);
  assert.equal(isLookupableIp(""), null);
});

test("ipwho.is payloads are normalized with ASN and network kind", () => {
  const entry = normalizeIpWhoPayload("45.155.205.99", payloadFor("45.155.205.99"), 1000);
  assert.equal(entry.ip, "45.155.205.99");
  assert.equal(entry.country, "荷兰");
  assert.equal(entry.province, "北荷兰省");
  assert.equal(entry.city, "阿姆斯特丹");
  assert.equal(entry.asn, "AS12345");
  assert.equal(entry.org, "Hosting B.V.");
  assert.equal(entry.network_kind, "hosting");
  assert.equal(NETWORK_KIND_LABELS.hosting, "云 / IDC");
  assert.equal(entry.timezone, "Europe/Amsterdam");
  assert.equal(entry.source, "online");
  assert.equal(entry.demo, false);
  assert.equal(entry.provider, "ipwho.is");
  assert.equal(entry.fetched_at, 1000);
  assert.equal(entry.latitude, 52.37);

  assert.throws(() => normalizeIpWhoPayload("8.8.8.8", { success: false }), /lookup_failed/);
  assert.throws(
    () => normalizeIpWhoPayload("8.8.8.8", payloadFor("1.1.1.1")),
    /ip_mismatch/
  );
  assert.throws(
    () => normalizeIpWhoPayload("8.8.8.8", payloadFor("8.8.8.8", { country: "", region: "", city: "" })),
    /empty_location/
  );
  assert.throws(() => normalizeIpWhoPayload("10.0.0.1", payloadFor("10.0.0.1")), /not_lookupable/);
});

test("network kinds are inferred from organization text", () => {
  assert.equal(inferNetworkKind("China Mobile Communications"), "mobile");
  assert.equal(inferNetworkKind("CERNET Education Network"), "education");
  assert.equal(inferNetworkKind("Chinanet Henan Telecom"), "broadband");
  assert.equal(inferNetworkKind("DigitalOcean LLC"), "hosting");
  assert.equal(inferNetworkKind(""), "unknown");
});

test("cloud cache keeps only fresh online entries and respects its limit", () => {
  const storage = memoryStorage();
  const now = Date.now();
  const first = normalizeIpWhoPayload("8.8.8.8", payloadFor("8.8.8.8"), now - 1000);
  const second = normalizeIpWhoPayload("1.1.1.1", payloadFor("1.1.1.1"), now);
  const stale = { ...first, ip: "9.9.9.9", fetched_at: now - CLOUD_GEO.ttlMs - 1000 };
  const privateEntry = { source: "online", fetched_at: now };

  assert.equal(isFreshCloudGeo(first, now), true);
  assert.equal(isFreshCloudGeo(stale, now), false);
  assert.equal(isFreshCloudGeo({ source: "demo", fetched_at: now }, now), false);

  writeGeoCache(storage, {
    "8.8.8.8": first,
    "1.1.1.1": second,
    "9.9.9.9": stale,
    "192.168.1.1": privateEntry,
  });
  const cached = readGeoCache(storage);
  assert.deepEqual(Object.keys(cached).sort(), ["1.1.1.1", "8.8.8.8"]);
  assert.equal(cached["1.1.1.1"].city, "阿姆斯特丹");

  writeGeoCache(storage, { "8.8.8.8": first, "1.1.1.1": second }, 1);
  assert.deepEqual(Object.keys(readGeoCache(storage)), ["1.1.1.1"]);
  assert.deepEqual(readGeoCache(memoryStorage()), {});
  assert.deepEqual(readGeoCache(null), {});
});

test("cloud lookup uses a credential-free CORS request and surfaces failures", async () => {
  let seen = null;
  const fetchImpl = async (url, init) => {
    seen = { url, init };
    return { ok: true, json: async () => payloadFor("8.8.8.8") };
  };
  const entry = await fetchCloudGeo("8.8.8.8", { fetchImpl, now: 123 });
  assert.match(seen.url, /^https:\/\/ipwho\.is\/8\.8\.8\.8\?lang=zh-CN$/);
  assert.equal(seen.init.method, "GET");
  assert.equal(seen.init.mode, "cors");
  assert.equal(seen.init.credentials, "omit");
  assert.equal(seen.init.referrerPolicy, "no-referrer");
  assert.equal(seen.init.cache, "no-store");
  assert.equal(entry.source, "online");
  assert.equal(entry.fetched_at, 123);

  await assert.rejects(
    () => fetchCloudGeo("8.8.8.8", { fetchImpl: async () => ({ ok: false, status: 429 }) }),
    /http_429/
  );
  await assert.rejects(() => fetchCloudGeo("10.1.1.1", { fetchImpl }), /not_lookupable/);
});
