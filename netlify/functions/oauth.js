// OAuth exchange (GitHub) for Beanstalk — no secrets in the browser.
// Routes:
//   /.netlify/functions/oauth/start     → redirect to GitHub authorize
//   /.netlify/functions/oauth/callback  → exchange code→token, set HttpOnly cookie, redirect to ORIGIN
//   /.netlify/functions/oauth/logout    → clear cookie, redirect to ORIGIN
//
// Netlify ENV required:
//   GITHUB_CLIENT_ID
//   GITHUB_CLIENT_SECRET
//   SESSION_SECRET              (random ≥32 chars)
//   ORIGIN                      (e.g., https://<yoursite>.netlify.app  — use subdomain first)
//   GITHUB_SCOPES               (default: "public_repo read:user")

const crypto = require("crypto");
const ONE_WEEK = 60 * 60 * 24 * 7;

const ok = (body, headers = {}) => ({
  statusCode: 200,
  headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  body: JSON.stringify(body),
});

const redirect = (location, setCookies = []) => {
  const res = {
    statusCode: 302,
    headers: {
      Location: location,
      "Cache-Control": "no-store",
    },
  };

  if (Array.isArray(setCookies) && setCookies.length > 1) {
    res.multiValueHeaders = { "Set-Cookie": setCookies };
  } else if (Array.isArray(setCookies) && setCookies.length === 1) {
    res.headers["Set-Cookie"] = setCookies[0];
  }
  return res;
};

function b64u(buf) {
  return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function b64uPad(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return s; }
function deriveKey(secret) { return crypto.createHash("sha256").update(String(secret)).digest(); }
function encrypt(plaintext, secret) {
  const key = deriveKey(secret); const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]); const tag = c.getAuthTag();
  return b64u(Buffer.concat([iv, ct, tag]));
}
function cookieHeader(name, value, { maxAge, httpOnly = true, secure = true, path = "/", sameSite = "Lax" } = {}) {
  let c = `${name}=${value || ""}; Path=${path}; SameSite=${sameSite}`;
  if (httpOnly) c += "; HttpOnly"; if (secure) c += "; Secure";
  if (typeof maxAge === "number") c += `; Max-Age=${maxAge}`; return c;
}
function getCookie(name, cookieHeader = "") {
  const m = (`; ${cookieHeader}`).match(new RegExp(`;\\s*${name}=([^;]*)`)); return m ? m[1] : "";
}
function computeOrigin(event) {
  const env = process.env.ORIGIN; if (env) return env.replace(/\/+$/,"");
  const proto = event.headers?.["x-forwarded-proto"] || "https"; const host = event.headers?.host || "";
  return `${proto}://${host}`;
}

exports.handler = async (event) => {
  const path = event.path || "";
  const origin = computeOrigin(event);
  const callbackUrl = `${origin}/.netlify/functions/oauth/callback`;
  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  const sessionSecret = process.env.SESSION_SECRET;
  const scopes = process.env.GITHUB_SCOPES || "public_repo read:user";

  if (path.endsWith("/start")) {
    if (!clientId || !clientSecret || !sessionSecret) {
      return ok({ ok:false, error:"missing_env", need:["GITHUB_CLIENT_ID","GITHUB_CLIENT_SECRET","SESSION_SECRET"] });
    }
    const state = b64u(crypto.randomBytes(16));
    const setState = cookieHeader("bs_state", state, { maxAge: 600 });
    const auth = new URL("https://github.com/login/oauth/authorize");
    auth.searchParams.set("client_id", clientId);
    auth.searchParams.set("scope", scopes);
    auth.searchParams.set("redirect_uri", callbackUrl);
    auth.searchParams.set("state", state);
    return redirect(auth.toString(), [setState]);
  }

  if (path.endsWith("/callback")) {
    const qp = new URLSearchParams(event.rawQuery || event.rawQueryString || "");
    const code = qp.get("code"); const state = qp.get("state");
    const cookieState = getCookie("bs_state", event.headers?.cookie || "");
    if (!code || !state || !cookieState || state !== cookieState) {
      const clear = cookieHeader("bs_state","",{maxAge:0}); return ok({ ok:false, error:"invalid_state_or_code" }, { "Set-Cookie": clear });
    }
    const ghRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Accept":"application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: callbackUrl }),
    });
    if (!ghRes.ok) return ok({ ok:false, error:"exchange_failed", details: await ghRes.text() });
    const json = await ghRes.json();
    if (!json.access_token) return ok({ ok:false, error:"no_access_token", details: json });

    const payload = JSON.stringify({ v:1, iat:Date.now(), exp:Date.now()+ONE_WEEK*1000, scope: json.scope || scopes, tok: json.access_token });
    const enc = encrypt(payload, sessionSecret);
    const sess = cookieHeader("bs_sess", `v1.${enc}`, { maxAge: ONE_WEEK });
    const clearState = cookieHeader("bs_state","",{maxAge:0});
    return redirect(`${origin}/?authed=1`, [sess, clearState]);
  }

  if (path.endsWith("/logout")) {
    const clear = cookieHeader("bs_sess","",{maxAge:0}); return redirect(`${origin}/?logged_out=1`, [clear]);
  }

  return ok({ ok:true, routes:{ start:"/.netlify/functions/oauth/start", callback:"/.netlify/functions/oauth/callback", logout:"/.netlify/functions/oauth/logout" }});
};