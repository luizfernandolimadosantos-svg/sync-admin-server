import { getStore } from "@netlify/blobs";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const COOKIE = "sync_admin";
const SESSION_TTL = 60 * 60 * 1000;
const PIN_TTL = 5 * 60 * 1000;
const json = (data, status = 200, extra = {}) => Response.json(data, {
  status,
  headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...extra }
});
const validId = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const validSessionId = value => typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
const VALID_THEMES = new Set(["hellsing-red", "midnight-blue", "void-violet", "emerald"]);
const sha = value => createHash("sha256").update(value).digest("hex");
const deviceKey = id => `device-${id}`;
const sessionKey = id => `session-${id}`;
const sessionSecret = () => process.env.SYNC_SESSION_SECRET || "";
const pinDigest = pin => createHmac("sha256", sessionSecret()).update(pin).digest("hex");

function equal(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
function makeCookie() {
  const exp = Date.now() + SESSION_TTL;
  const payload = `${exp}.${randomBytes(18).toString("hex")}`;
  const encoded = Buffer.from(payload).toString("base64url");
  const sig = createHmac("sha256", sessionSecret()).update(encoded).digest("hex");
  return `${COOKIE}=${encoded}.${sig}; Path=/api; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`;
}
function hasAdminSession(request) {
  const secret = sessionSecret();
  if (secret.length < 32) return false;
  const raw = request.headers.get("cookie") || "";
  const match = raw.split(";").map(x => x.trim()).find(x => x.startsWith(`${COOKIE}=`));
  if (!match) return false;
  const value = match.slice(COOKIE.length + 1);
  const dot = value.lastIndexOf(".");
  if (dot < 1) return false;
  const encoded = value.slice(0, dot), signature = value.slice(dot + 1);
  const expected = createHmac("sha256", secret).update(encoded).digest("hex");
  if (!equal(signature, expected)) return false;
  try {
    const [exp] = Buffer.from(encoded, "base64url").toString().split(".");
    return Number.isSafeInteger(Number(exp)) && Number(exp) > Date.now();
  } catch { return false; }
}
async function readJson(request) {
  const raw = await request.text();
  if (raw.length > 50000) return { error: "Payload too large" };
  try { return JSON.parse(raw || "{}"); }
  catch { return { error: "Invalid JSON" }; }
}
function safeReport(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const allowedVerdicts = new Set(["clean", "suspicious", "detected"]);
  const allowedSeverity = new Set(["info", "suspicious", "detected"]);
  if (!allowedVerdicts.has(input.verdict) || !Array.isArray(input.findings) || input.findings.length > 100) return null;
  const findings = [];
  for (const item of input.findings) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return null;
    if (typeof item.category !== "string" || item.category.length > 64 ||
        typeof item.rule !== "string" || item.rule.length > 120 ||
        !allowedSeverity.has(item.severity)) return null;
    findings.push({ category: item.category, rule: item.rule, severity: item.severity });
  }
  const counts = {};
  if (input.counts && typeof input.counts === "object" && !Array.isArray(input.counts)) {
    for (const key of ["processes", "files", "rules", "findings"]) {
      const value = input.counts[key];
      if (Number.isSafeInteger(value) && value >= 0 && value <= 1000000) counts[key] = value;
    }
  }
  const summary = typeof input.summary === "string" ? input.summary.slice(0, 500) : "";
  return { verdict: input.verdict, summary, counts, findings,
    completedAt: Number.isSafeInteger(input.completedAt) ? input.completedAt : Date.now() };
}
function normalizeRules(input) {
  if (!Array.isArray(input) || input.length > 100) return null;
  const seen = new Set(), rules = [];
  for (const item of input) {
    if (!item || typeof item !== "object") return null;
    const name = typeof item.name === "string" ? item.name.trim().slice(0, 80) : "";
    const category = typeof item.category === "string" ? item.category.trim().slice(0, 48) : "";
    const filename = typeof item.filename === "string" ? item.filename.trim() : "";
    const digest = typeof item.sha256 === "string" ? item.sha256.toLowerCase() : "";
    const severity = item.severity;
    if (!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$/.test(name) || !/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,47}$/.test(category) ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(filename) ||
        !/^[a-f0-9]{64}$/.test(digest) || !["suspicious", "detected"].includes(severity)) return null;
    const key = `${filename.toLowerCase()}|${digest}`;
    if (seen.has(key)) continue;
    seen.add(key);
    rules.push({ id: sha(`${key}|${name}`).slice(0, 16), name, category, filename,
      sha256: digest, severity });
  }
  return rules;
}
function normalizeSettings(input) {
  if (!input || typeof input !== "object") return null;
  const theme = VALID_THEMES.has(input.theme) ? input.theme : "hellsing-red";
  const banner = typeof input.banner === "string"
    ? input.banner.replace(/[^A-Za-z0-9 .,!?_-]/g, " ").replace(/\s+/g, " ").trim().slice(0, 100)
    : "";
  return { theme, banner, updatedAt: Date.now() };
}
function safeHttpsUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password ? url.toString() : "";
  } catch { return ""; }
}
async function getDevice(db, device, token) {
  if (!validId(device) || !validId(token)) return { error: json({ error: "Invalid device credentials" }, 400) };
  const record = await db.get(deviceKey(device), { type: "json" });
  if (!record || !equal(record.tokenHash, sha(token))) return { error: json({ error: "Device credential mismatch" }, 403) };
  return { record };
}
async function loginAllowed(db, request) {
  const ip = request.headers.get("x-nf-client-connection-ip") || "unknown";
  const key = `login-${sha(ip)}`;
  const now = Date.now();
  const prior = await db.get(key, { type: "json" });
  const entry = prior && now - prior.startedAt < 15 * 60 * 1000
    ? prior : { startedAt: now, attempts: 0 };
  entry.attempts++;
  await db.setJSON(key, entry);
  return entry.attempts <= 8;
}

export default async function handler(request) {
  try {
    const route = new URL(request.url).pathname.split("/").filter(Boolean).pop();
    const db = getStore({ name: "sync-devices", consistency: "strong" });
    const releases = getStore({ name: "sync-releases", consistency: "strong" });

    if (request.method === "GET" && route === "release-download") {
      const release = await db.get("release-meta", { type: "json" });
      if (!release) return json({ error: "No scanner release is published" }, 404);
      if (release.mode === "external" && release.url) return Response.redirect(release.url, 302);
      const file = await releases.get("current.exe", { type: "blob" });
      if (!file) return json({ error: "Published scanner file is unavailable" }, 404);
      return new Response(file, { status: 200, headers: {
        "Content-Type": "application/octet-stream", "Content-Disposition": "attachment; filename=SYNCScanner.exe",
        "Content-Length": String(file.size), "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"
      }});
    }
    if (request.method === "GET" && route === "release-info") {
      const release = await db.get("release-meta", { type: "json" });
      if (!release) return json({ release: null });
      return json({ release: { mode: release.mode, version: release.version,
        sha256: release.sha256 || "", size: release.size || null,
        publishedAt: release.publishedAt, downloadPath: "/api/release-download" } });
    }
    if (request.method !== "POST") return json({ error: "POST required" }, 405);

    if (route === "release-upload") {
      if (!hasAdminSession(request)) return json({ error: "Admin authentication required" }, 401);
      const form = await request.formData();
      const file = form.get("file"), version = String(form.get("version") || "").trim();
      if (!file || typeof file.arrayBuffer !== "function" || !/^\d+(?:\.\d+){0,3}[A-Za-z0-9._-]{0,16}$/.test(version))
        return json({ error: "Choose an .exe and enter a valid version" }, 400);
      if (!file.name?.toLowerCase().endsWith(".exe")) return json({ error: "Only .exe files are accepted" }, 400);
      if (file.size < 2 || file.size > 4 * 1024 * 1024)
        return json({ error: "Direct upload is limited to 4 MiB. Use an HTTPS release link for larger files." }, 413);
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) return json({ error: "The selected file is not a Windows PE executable" }, 400);
      const digest = createHash("sha256").update(bytes).digest("hex");
      const meta = { mode: "blob", version, sha256: digest, size: bytes.byteLength, fileName: "SYNCScanner.exe", publishedAt: Date.now() };
      await releases.set("current.exe", bytes, { metadata: {
        version: meta.version, sha256: meta.sha256, size: String(meta.size),
        fileName: meta.fileName, publishedAt: String(meta.publishedAt)
      }});
      await db.setJSON("release-meta", meta);
      return json({ release: meta });
    }

    const body = await readJson(request);
    if (body.error) return json({ error: body.error }, body.error === "Payload too large" ? 413 : 400);

    if (["request", "status", "report"].includes(route) && sessionSecret().length < 32)
      return json({ error: "Session signing secret is not configured" }, 503);

    if (route === "login") {
      const password = process.env.SYNC_ADMIN_PASSWORD || "";
      if (!password || sessionSecret().length < 32)
        return json({ error: "Admin environment is not configured" }, 503);
      if (!await loginAllowed(db, request)) return json({ error: "Too many attempts; wait 15 minutes" }, 429);
      if (!equal(body.password, password)) return json({ error: "Invalid credentials" }, 401);
      return json({ ok: true }, 200, { "Set-Cookie": makeCookie() });
    }
    if (route === "logout")
      return json({ ok: true }, 200, { "Set-Cookie": `${COOKIE}=; Path=/api; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });

    // A scanner only reports presence or sends results after the user confirms consent locally.
    if (route === "request") {
      const { device, token, consent } = body;
      if (!validId(device) || !validId(token) || consent !== true)
        return json({ error: "Valid device credentials and explicit consent are required" }, 400);
      let record = await db.get(deviceKey(device), { type: "json" });
      if (record && !equal(record.tokenHash, sha(token))) return json({ error: "Device credential mismatch" }, 403);
      if (record?.status === "locked") return json({ error: "This device is blocked" }, 403);
      const now = Date.now();
      if (!record) record = { device, tokenHash: sha(token), status: "pending", firstSeen: now };
      const sessionId = randomBytes(16).toString("hex");
      const pin = String(randomBytes(4).readUInt32BE(0) % 900000 + 100000);
      const expiresAt = now + PIN_TTL;
      await db.setJSON(sessionKey(sessionId), {
        sessionId, device, pinHash: pinDigest(pin), status: "pending",
        createdAt: now, expiresAt, lastSeen: now, report: null
      });
      record.lastSeen = now;
      record.activeSession = sessionId;
      await db.setJSON(deviceKey(device), record);
      return json({ sessionId, pin, status: "pending", expiresAt });
    }

    if (route === "status" || route === "report") {
      const { device, token, sessionId } = body;
      const auth = await getDevice(db, device, token);
      if (auth.error) return auth.error;
      if (!validSessionId(sessionId)) return json({ error: "Invalid session" }, 400);
      const session = await db.get(sessionKey(sessionId), { type: "json" });
      if (!session || session.device !== device) return json({ error: "Unknown session" }, 404);
      const now = Date.now();
      if (auth.record.status === "locked" && ["pending", "approved"].includes(session.status))
        session.status = "denied";
      if (["pending", "approved"].includes(session.status) && session.expiresAt <= now) session.status = "expired";
      session.lastSeen = now;
      auth.record.lastSeen = now;
      await db.setJSON(sessionKey(sessionId), session);
      await db.setJSON(deviceKey(device), auth.record);
      if (route === "status") {
        const settings = await db.get("scanner-settings", { type: "json" }) || { theme: "hellsing-red", banner: "" };
        return json({ status: session.status, expiresAt: session.expiresAt,
          config: { theme: settings.theme, banner: settings.banner } });
      }
      if (session.status !== "approved") return json({ error: "This scan session is not approved" }, 403);
      if (auth.record.status === "locked") return json({ error: "This device is blocked" }, 403);
      if (body.consent !== true) return json({ error: "Explicit report consent is required" }, 400);
      const report = safeReport(body.report);
      if (!report) return json({ error: "Invalid report format" }, 400);
      session.status = "complete";
      session.completedAt = now;
      session.report = report;
      auth.record.reportAt = now;
      auth.record.latestVerdict = report.verdict;
      auth.record.latestReport = report;
      auth.record.lastSeen = now;
      await db.setJSON(sessionKey(sessionId), session);
      await db.setJSON(deviceKey(device), auth.record);
      return json({ status: session.status, received: true });
    }

    if (route === "scanner-rules") {
      const { device, token, sessionId } = body;
      const auth = await getDevice(db, device, token);
      if (auth.error) return auth.error;
      if (auth.record.status === "locked" || !validSessionId(sessionId)) return json({ error: "Invalid or blocked session" }, 403);
      const session = await db.get(sessionKey(sessionId), { type: "json" });
      if (!session || session.device !== device || session.status !== "approved" || session.expiresAt <= Date.now())
        return json({ error: "Approved scan session required" }, 403);
      const ruleSet = await db.get("scanner-rules", { type: "json" }) || { version: 1, rules: [] };
      return json(ruleSet);
    }

    if (!hasAdminSession(request)) return json({ error: "Admin authentication required" }, 401);

    if (route === "list") {
      const [deviceData, sessionData] = await Promise.all([
        db.list({ prefix: "device-", paginate: false }),
        db.list({ prefix: "session-", paginate: false })
      ]);
      const devices = [];
      const sessions = [];
      for (const item of deviceData.blobs || []) {
        const record = await db.get(item.key, { type: "json" });
        if (record) devices.push({ device: record.device, status: record.status || "pending",
          firstSeen: record.firstSeen, lastSeen: record.lastSeen,
          hasReport: !!record.latestReport, reportAt: record.reportAt || null,
          verdict: record.latestVerdict || null,
          findingCount: record.latestReport?.findings?.length || 0,
          activeSession: record.activeSession || null });
      }
      for (const item of sessionData.blobs || []) {
        const record = await db.get(item.key, { type: "json" });
        if (record) sessions.push({ sessionId: record.sessionId, device: record.device,
          status: record.status, createdAt: record.createdAt, expiresAt: record.expiresAt,
          lastSeen: record.lastSeen, completedAt: record.completedAt || null,
          verdict: record.report?.verdict || null });
      }
      devices.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
      sessions.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      const [release, settings, ruleSet] = await Promise.all([
        db.get("release-meta", { type: "json" }),
        db.get("scanner-settings", { type: "json" }),
        db.get("scanner-rules", { type: "json" })
      ]);
      return json({ devices: devices.slice(0, 500), sessions: sessions.slice(0, 500),
        release: release || null,
        settings: settings || { theme: "hellsing-red", banner: "" },
        rules: ruleSet || { version: 1, rules: [] } });
    }
    if (route === "release-link") {
      const url = safeHttpsUrl(body.url);
      const version = typeof body.version === "string" ? body.version.trim() : "";
      const expectedHash = typeof body.sha256 === "string" ? body.sha256.toLowerCase().trim() : "";
      if (!url || !/^\d+(?:\.\d+){0,3}[A-Za-z0-9._-]{0,16}$/.test(version) || !/^[a-f0-9]{64}$/.test(expectedHash))
        return json({ error: "Enter a valid version, HTTPS link, and 64-character SHA-256" }, 400);
      const release = { mode: "external", version, url, sha256: expectedHash, publishedAt: Date.now() };
      await db.setJSON("release-meta", release);
      return json({ release: { mode: release.mode, version, sha256: expectedHash, publishedAt: release.publishedAt } });
    }
    if (route === "release-remove") {
      await releases.delete("current.exe");
      await db.delete("release-meta");
      return json({ ok: true });
    }
    if (route === "rules-save") {
      const rules = normalizeRules(body.rules);
      if (!rules) return json({ error: "Rules must be exact SHA-256 matches with a plain filename; max 100" }, 400);
      const previous = await db.get("scanner-rules", { type: "json" });
      const ruleSet = { version: (previous?.version || 0) + 1, rules, updatedAt: Date.now() };
      await db.setJSON("scanner-rules", ruleSet);
      return json(ruleSet);
    }
    if (route === "settings-save") {
      const settings = normalizeSettings(body.settings);
      if (!settings) return json({ error: "Invalid scanner settings" }, 400);
      await db.setJSON("scanner-settings", settings);
      return json({ settings });
    }
    if (route === "approve") {
      if (typeof body.pin !== "string" || !/^\d{6}$/.test(body.pin)) return json({ error: "Enter the six-digit scanner PIN" }, 400);
      const result = await db.list({ prefix: "session-", paginate: false });
      for (const item of result.blobs || []) {
        const session = await db.get(item.key, { type: "json" });
        if (!session || session.status !== "pending") continue;
        if (session.expiresAt <= Date.now()) { session.status = "expired"; await db.setJSON(item.key, session); continue; }
        if (!equal(session.pinHash, pinDigest(body.pin))) continue;
        const device = await db.get(deviceKey(session.device), { type: "json" });
        if (!device || device.status === "locked") return json({ error: "Device is blocked" }, 403);
        session.status = "approved";
        session.approvedAt = Date.now();
        session.expiresAt = Date.now() + 60 * 60 * 1000;
        device.status = "unlocked";
        device.lastSeen = Date.now();
        await db.setJSON(item.key, session);
        await db.setJSON(deviceKey(session.device), device);
        return json({ ok: true, device: session.device, sessionId: session.sessionId });
      }
      return json({ error: "PIN not found, already used, or expired" }, 404);
    }
    if (route === "deny") {
      if (!validSessionId(body.sessionId)) return json({ error: "Invalid session" }, 400);
      const session = await db.get(sessionKey(body.sessionId), { type: "json" });
      if (!session) return json({ error: "Unknown session" }, 404);
      if (session.status !== "pending") return json({ error: "Only pending sessions can be denied" }, 409);
      session.status = "denied";
      session.deniedAt = Date.now();
      await db.setJSON(sessionKey(body.sessionId), session);
      return json({ ok: true });
    }
    if (route === "decision") {
      if (!validId(body.device) || !["locked", "unlocked"].includes(body.status)) return json({ error: "Invalid decision" }, 400);
      const record = await db.get(deviceKey(body.device), { type: "json" });
      if (!record) return json({ error: "Unknown device" }, 404);
      record.status = body.status;
      await db.setJSON(deviceKey(body.device), record);
      if (body.status === "locked") {
        const sessions = await db.list({ prefix: "session-", paginate: false });
        for (const item of sessions.blobs || []) {
          const session = await db.get(item.key, { type: "json" });
          if (session?.device === body.device && ["pending", "approved"].includes(session.status)) {
            session.status = "denied";
            session.deniedAt = Date.now();
            await db.setJSON(item.key, session);
          }
        }
      }
      return json({ ok: true, status: record.status });
    }
    if (route === "view") {
      if (!validId(body.device)) return json({ error: "Invalid device" }, 400);
      const record = await db.get(deviceKey(body.device), { type: "json" });
      if (!record) return json({ error: "Unknown device" }, 404);
      return json({ report: record.latestReport || null, reportAt: record.reportAt || null });
    }
    return json({ error: "Unknown route" }, 404);
  } catch (error) {
    console.error("SYNC API failure", error?.message);
    return json({ error: "Server error" }, 500);
  }
}
