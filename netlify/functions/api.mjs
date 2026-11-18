import { getStore } from "@netlify/blobs";
import { createHash, timingSafeEqual } from "node:crypto";

const json = (data, status = 200) => Response.json(data, {
  status,
  headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
});
const validId = x => typeof x === "string" && /^[a-f0-9]{64}$/.test(x);
const validToken = x => typeof x === "string" && /^[a-f0-9]{64}$/.test(x);
const hash = x => createHash("sha256").update(x).digest("hex");
function equal(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
const key = id => "device-" + id;

export default async function handler(request, context) {
  try {
    if (request.method !== "POST") return json({ error: "POST required" }, 405);
    const route = new URL(request.url).pathname.split("/").filter(Boolean).pop();
    const raw = await request.text();
    if (raw.length > 50000) return json({ error: "Payload too large" }, 413);
    let body;
    try { body = JSON.parse(raw || "{}"); }
    catch { return json({ error: "Invalid JSON" }, 400); }

    // Functions v2: Netlify provides Blobs credentials automatically.
    const db = getStore({ name: "sync-devices", consistency: "strong" });

    if (route === "hello" || route === "report") {
      const { device, token } = body;
      if (!validId(device) || !validToken(token))
        return json({ error: "Invalid device or token" }, 400);
      let record = await db.get(key(device), { type: "json" });
      const tokenHash = hash(token);
      if (record && !equal(record.tokenHash, tokenHash))
        return json({ error: "Device credential mismatch" }, 403);
      const now = Date.now();
      if (!record) record = {
        device, tokenHash, status: "pending",
        firstSeen: now, lastSeen: now, report: null
      };
      record.lastSeen = now;
      if (route === "report") {
        if (body.consent !== true || typeof body.report !== "string" ||
            body.report.length > 36000)
          return json({ error: "Explicit consent required; max 36000 chars" }, 400);
        record.report = body.report;
        record.reportAt = now;
      }
      await db.setJSON(key(device), record);
      return json({ status: record.status, reportReceived: route === "report" });
    }

    const secret = process.env.SYNC_ADMIN_TOKEN;
    const auth = request.headers.get("authorization") || "";
    if (!secret || secret.length < 12 || !equal(auth, `Bearer ${secret}`))
      return json({ error: "Admin authentication required" }, 401);

    if (route === "list") {
      const result = await db.list({ prefix: "device-", paginate: false });
      const records = [];
      for (const blob of result.blobs || []) {
        const item = await db.get(blob.key, { type: "json" });
        if (item) records.push({
          device: item.device, status: item.status,
          firstSeen: item.firstSeen, lastSeen: item.lastSeen,
          hasReport: typeof item.report === "string",
          reportAt: item.reportAt || null
        });
      }
      records.sort((a, b) => b.lastSeen - a.lastSeen);
      return json({ devices: records.slice(0, 500) });
    }

    if (route === "decision") {
      if (!validId(body.device) || !["locked", "unlocked"].includes(body.status))
        return json({ error: "Invalid decision" }, 400);
      const record = await db.get(key(body.device), { type: "json" });
      if (!record) return json({ error: "Unknown device" }, 404);
      record.status = body.status;
      await db.setJSON(key(body.device), record);
      return json({ ok: true, status: record.status });
    }

    if (route === "view") {
      if (!validId(body.device)) return json({ error: "Invalid device" }, 400);
      const record = await db.get(key(body.device), { type: "json" });
      if (!record) return json({ error: "Unknown device" }, 404);
      return json({ report: record.report || "", reportAt: record.reportAt || null });
    }

    return json({ error: "Unknown route" }, 404);
  } catch (error) {
    console.error("SYNC API failure", error?.message);
    return json({ error: "Server error" }, 500);
  }
}
