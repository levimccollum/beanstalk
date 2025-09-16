// GitHub proxy (read-only "whoami" test).
// Decrypts HttpOnly `bs_sess`, validates expiry, then calls GitHub /user.
// Returns minimal identity info. No secrets exposed to the client.

const crypto = require("crypto");

const okCors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function getCookie(name, cookieHeader = "") {
  const m = (`; ${cookieHeader}`).match(new RegExp(`;\\s*${name}=([^;]*)`));
  return m ? m[1] : "";
}

function base64urlToBuffer(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function deriveKey(secret) {
  return crypto.createHash("sha256").update(String(secret)).digest(); // 32 bytes
}

function decryptSession(cookieVal, secret) {
  // cookie format: "v1.<base64url(iv|ct|tag)>"
  if (!cookieVal || !cookieVal.startsWith("v1.")) return null;
  const raw = cookieVal.slice(3);
  const buf = base64urlToBuffer(raw);
  if (buf.length < 12 + 16) return null; // iv(12) + tag(16) + ct(>=0)
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ct = buf.subarray(12, buf.length - 16);

  const key = deriveKey(secret);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  return JSON.parse(pt); // { v, iat, exp, scope, tok }
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: okCors, body: "" };
  }
  if (event.httpMethod !== "GET") {
    return { statusCode: 405, headers: okCors, body: "Method Not Allowed" };
  }

  try {
    const sessionSecret = process.env.SESSION_SECRET;
    if (!sessionSecret) {
      return {
        statusCode: 500,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify({ ok: false, error: "missing_env", need: ["SESSION_SECRET"] }),
      };
    }

    const cookie = event.headers?.cookie || "";
    const cookieVal = getCookie("bs_sess", cookie);
    if (!cookieVal) {
      return {
        statusCode: 401,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify({ ok: false, error: "unauthenticated", hint: "no session cookie" }),
      };
    }

    let payload;
    try {
      payload = decryptSession(cookieVal, sessionSecret);
    } catch {
      return {
        statusCode: 401,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify({ ok: false, error: "bad_session" }),
      };
    }

    if (!payload || !payload.tok) {
      return {
        statusCode: 401,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify({ ok: false, error: "no_token" }),
      };
    }

    if (payload.exp && Date.now() > payload.exp) {
      return {
        statusCode: 401,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify({ ok: false, error: "session_expired" }),
      };
    }

    // Call GitHub /user (read identity)
    const gh = await fetch("https://api.github.com/user", {
      headers: {
        "User-Agent": "beanstalk-proxy",
        "Accept": "application/vnd.github+json",
        "Authorization": `token ${payload.tok}`, // GitHub REST v3
      },
    });

    if (gh.status === 401) {
      return {
        statusCode: 401,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify({ ok: false, error: "github_unauthorized" }),
      };
    }

    if (!gh.ok) {
      const text = await gh.text().catch(() => "");
      return {
        statusCode: 502,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify({ ok: false, error: "github_error", status: gh.status, body: text.slice(0, 500) }),
      };
    }

    const user = await gh.json();
    // Return minimal, safe fields
    return {
      statusCode: 200,
      headers: { ...okCors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
      body: JSON.stringify({
        ok: true,
        proxy: "github",
        scope: payload.scope || null,
        user: {
          login: user.login,
          id: user.id,
          name: user.name,
          avatar_url: user.avatar_url,
          html_url: user.html_url,
        },
      }),
    };
  } catch (e) {
    return {
      statusCode: 500,
      headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({ ok: false, error: "internal_error" }),
    };
  }
};