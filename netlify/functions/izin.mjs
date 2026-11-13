import { getStore } from "@netlify/blobs";
import { createHmac, timingSafeEqual } from "node:crypto";

const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json" } });

const tokenFor = (pw) => createHmac("sha256", pw).update("izin-owner").digest("hex");

function isOwner(req) {
  const pw = process.env.OWNER_PASSWORD;
  if (!pw) return false;
  const t = (req.headers.get("authorization") || "").replace("Bearer ", "");
  const a = Buffer.from(t), b = Buffer.from(tokenFor(pw));
  return a.length === b.length && timingSafeEqual(a, b);
}

export default async (req) => {
  const store = getStore("izin");

  if (req.method === "GET") {
    const { blobs } = await store.list();
    const items = (await Promise.all(blobs.map((b) => store.get(b.key, { type: "json" })))).filter(Boolean);
    items.sort((x, y) => y.ts - x.ts);
    return json({ items, owner: isOwner(req) });
  }

  if (req.method !== "POST") return json({ error: "method" }, 405);
  let b;
  try { b = await req.json(); } catch { return json({ error: "bad" }, 400); }

  if (b.aksi === "login") {
    const pw = process.env.OWNER_PASSWORD;
    if (!pw) return json({ error: "OWNER_PASSWORD belum diset di Netlify" }, 500);
    const x = Buffer.from(String(b.pass || "")), y = Buffer.from(pw);
    if (x.length !== y.length || !timingSafeEqual(x, y)) return json({ error: "Password owner salah." }, 401);
    return json({ token: tokenFor(pw) });
  }

  if (b.aksi === "kirim") {
    const t = (v, n) => String(v || "").trim().slice(0, n);
    const d = { admin: t(b.admin, 40), ic: t(b.ic, 40), rank: t(b.rank, 40), hari: Math.min(parseInt(b.hari, 10) || 0, 60), alasan: t(b.alasan, 500) };
    if (!d.admin || !d.ic || !d.rank || d.hari < 1 || !d.alasan) return json({ error: "Lengkapi semua kolom." }, 400);
    const id = Date.now() + "-" + Math.random().toString(36).slice(2, 7);
    await store.setJSON(id, { id, ...d, status: "pending", ts: Date.now() });
    return json({ ok: true });
  }

  if (b.aksi === "putusan") {
    if (!isOwner(req)) return json({ error: "Hanya Owner." }, 403);
    if (!["ok", "no", "pending"].includes(b.status)) return json({ error: "bad" }, 400);
    const cur = await store.get(String(b.id), { type: "json" });
    if (!cur) return json({ error: "tidak ada" }, 404);
    cur.status = b.status;
    await store.setJSON(cur.id, cur);
    return json({ ok: true });
  }

  return json({ error: "aksi" }, 400);
};

export const config = { path: "/api/izin" };
