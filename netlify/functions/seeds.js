// Public content proxy for widgets (Status seed).
// Reads owner/repo/path from query, fetches GitHub Contents API, and returns parsed JSON.
// Auth priority: (1) session cookie (bs_sess) if present, (2) SEEDS_GITHUB_TOKEN env (optional), (3) unauthenticated.
// CORS enabled; short CDN cache.

const crypto = require("crypto");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Netlify-CDN-Cache-Control": "public, max-age=0, s-maxage=60, stale-while-revalidate=30",
};

function getCookie(name, cookieHeader = "") {
  const m = (`; ${cookieHeader}`).match(new RegExp(`;\\s*${name}=([^;]*)`));
  return m ? m[1] : "";
}
function b64uToBuf(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Buffer.from(s, "base64"); }
function key(secret) { return crypto.createHash("sha256").update(String(secret)).digest(); }
function decrypt(cookieVal, secret) {
  if (!cookieVal || !cookieVal.startsWith("v1.")) return null;
  const buf = b64uToBuf(cookieVal.slice(3));
  if (buf.length < 12 + 16) return null;
  const iv = buf.subarray(0, 12), tag = buf.subarray(buf.length - 16), ct = buf.subarray(12, buf.length - 16);
  const d = crypto.createDecipheriv("aes-256-gcm", key(secret), iv); d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString("utf8"));
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS, body: "" };
  if (event.httpMethod !== "GET") return { statusCode: 405, headers: CORS, body: "Method Not Allowed" };

  const qp = new URLSearchParams(event.rawQuery || event.rawQueryString || "");
  const owner = qp.get("owner");
  const repo = qp.get("repo");
  // default path points at status file if not provided
  const reqPath = qp.get("path") || "pods/status/content/status.json";
  const ref = qp.get("ref");

  if (!owner || !repo) {
    return {
      statusCode: 400, headers: { ...CORS, "Content-Type": "application/json" },
      body: JSON.stringify({ ok: false, error: "bad_request", need: ["owner", "repo"] }),
    };
  }

  // choose auth
  let auth = null;
  const sess = getCookie("bs_sess", event.headers?.cookie || "");
  if (sess && process.env.SESSION_SECRET) {
    try { const p = decrypt(sess, process.env.SESSION_SECRET); if (p?.tok) auth = `token ${p.tok}`; } catch {}
  }
  if (!auth && process.env.SEEDS_GITHUB_TOKEN) {
    auth = `token ${process.env.SEEDS_GITHUB_TOKEN}`;
  }

  const encPath = reqPath.split("/").map(encodeURIComponent).join("/");
  const url = new URL(`https://api.github.com/repos/${owner}/${repo}/contents/${encPath}`);
  if (ref) url.searchParams.set("ref", ref);

  const gh = await fetch(url.toString(), {
    headers: {
      "User-Agent": "beanstalk-seeds-proxy",
      "Accept": "application/vnd.github+json",
      ...(auth ? { "Authorization": auth } : {}),
    },
  });

  if (gh.status === 404) {
    return { statusCode: 404, headers: { ...CORS, "Content-Type": "application/json" }, body: JSON.stringify({ ok: false, error: "not_found", owner, repo, path: reqPath }) };
  }
  if (!gh.ok) {
    const t = await gh.text().catch(() => "");
    return { statusCode: 502, headers: { ...CORS, "Content-Type": "application/json" }, body: JSON.stringify({ ok: false, error: "github_error", status: gh.status, body: t.slice(0, 500) }) };
  }

  const data = await gh.json();
  if (data.type !== "file" || data.encoding !== "base64" || typeof data.content !== "string") {
    return { statusCode: 200, headers: { ...CORS, "Content-Type": "application/json" }, body: JSON.stringify({ ok: true, kind: data.type || "unknown" }) };
  }
  let json = null;
  try { json = JSON.parse(Buffer.from(data.content, "base64").toString("utf8")); } catch { /* leave null */ }

  return {
    statusCode: 200,
    headers: { ...CORS, "Content-Type": "application/json" },
    body: JSON.stringify({ ok: true, kind: "status", owner, repo, path: data.path, ref: ref || null, json }),
  };
};