// GitHub proxy: whoami + read-only Contents API
// Decrypts HttpOnly `bs_sess`, validates expiry, then either:
//  - op=whoami (default): GET /user
//  - op=contents (or if owner/repo/path present): GET /repos/:owner/:repo/contents/:path[?ref=...]

const crypto = require("crypto");

const okCors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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
  if (event.httpMethod !== "GET" && event.httpMethod !== "POST") {
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

    // WRITE: commit-to-main via Contents API (POST)
    if (event.httpMethod === "POST") {
      let body = {};
      try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }
      const owner = body.owner;
      const repo = body.repo;
      const reqPath = body.path;
      const text = body.text; // plain text to commit
      const message = body.message || `beanstalk: update ${reqPath}`;
      const branch = body.branch || "main"; // commit-to-main by default
      const sha = body.sha; // optional, required by GitHub when updating existing file

      if (!owner || !repo || !reqPath || typeof text !== "string") {
        return {
          statusCode: 400,
          headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
          body: JSON.stringify({ ok:false, error:"bad_request", need:["owner","repo","path","text"] }),
        };
      }

      const encPath = reqPath.split("/").map(encodeURIComponent).join("/");
      const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encPath}`;
      const payloadGit = {
        message,
        content: Buffer.from(text, "utf8").toString("base64"),
        branch,
        ...(sha ? { sha } : {}),
      };

      const gh = await fetch(url, {
        method: "PUT",
        headers: {
          "User-Agent": "beanstalk-proxy",
          "Accept": "application/vnd.github+json",
          "Authorization": `token ${payload.tok}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payloadGit),
      });

      if (!gh.ok) {
        const textResp = await gh.text().catch(() => "");
        return {
          statusCode: gh.status,
          headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
          body: JSON.stringify({ ok:false, error:"github_error", status: gh.status, body: textResp.slice(0, 800) }),
        };
      }

      const resJson = await gh.json();
      return {
        statusCode: 200,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
        body: JSON.stringify({
          ok: true,
          proxy: "github",
          kind: "write",
          path: resJson.content?.path || reqPath,
          branch,
          commit: resJson.commit?.sha || null,
          content: {
            sha: resJson.content?.sha || null,
            size: resJson.content?.size || null,
          }
        }),
      };
    }

    const qp = new URLSearchParams(event.rawQuery || event.rawQueryString || "");
    const owner = qp.get("owner");
    const repo = qp.get("repo");
    const reqPath = qp.get("path"); // e.g., pods/status/content/status.json
    const ref = qp.get("ref");      // optional branch name or sha
    const op = qp.get("op") || (owner && repo && reqPath ? "contents" : "whoami");

    // List repositories the signed-in user can access (uses session token)
    if (op === "repos") {
      // token presence already validated above, but keep a guard
      if (!payload.tok) {
        return {
          statusCode: 401,
          headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
          body: JSON.stringify({ ok: false, error: "unauthenticated" })
        };
      }

      const gh = await fetch("https://api.github.com/user/repos?per_page=100&sort=updated", {
        headers: {
          "User-Agent": "beanstalk-proxy",
          "Accept": "application/vnd.github+json",
          "Authorization": `token ${payload.tok}`,
        },
      });

      if (!gh.ok) {
        const bodyTxt = await gh.text().catch(() => "");
        return {
          statusCode: 502,
          headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
          body: JSON.stringify({ ok: false, error: "github_error", status: gh.status, body: bodyTxt.slice(0, 500) })
        };
      }

      const data = await gh.json();
      const repos = Array.isArray(data) ? data.map(r => ({
        id: r.id,
        name: r.name,
        full_name: r.full_name,
        private: !!r.private,
        owner: r.owner && r.owner.login ? r.owner.login : null
      })) : [];

      return {
        statusCode: 200,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
        body: JSON.stringify({ ok: true, proxy: "github", kind: "repos", repos })
      };
    }

    if (op === "contents" && owner && repo && reqPath) {
      // Build Contents API URL
      const encPath = reqPath.split("/").map(encodeURIComponent).join("/");
      const url = new URL(`https://api.github.com/repos/${owner}/${repo}/contents/${encPath}`);
      if (ref) url.searchParams.set("ref", ref);

      const gh = await fetch(url.toString(), {
        headers: {
          "User-Agent": "beanstalk-proxy",
          "Accept": "application/vnd.github+json",
          "Authorization": `token ${payload.tok}`,
        },
      });

      if (gh.status === 404) {
        return {
          statusCode: 404,
          headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
          body: JSON.stringify({ ok: false, error: "not_found", owner, repo, path: reqPath, ref: ref || null }),
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

      const data = await gh.json();

      if (Array.isArray(data)) {
        // Directory listing
        return {
          statusCode: 200,
          headers: { ...okCors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
          body: JSON.stringify({
            ok: true,
            proxy: "github",
            kind: "dir",
            owner,
            repo,
            path: reqPath,
            ref: ref || null,
            items: data.map(it => ({ path: it.path, type: it.type, size: it.size, sha: it.sha, name: it.name }))
          }),
        };
      }

      // Single file
      if (data.type === "file" && data.encoding === "base64" && typeof data.content === "string") {
        const text = Buffer.from(data.content, "base64").toString("utf8");
        return {
          statusCode: 200,
          headers: { ...okCors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
          body: JSON.stringify({
            ok: true,
            proxy: "github",
            kind: "file",
            owner,
            repo,
            path: data.path,
            sha: data.sha,
            size: data.size,
            encoding: data.encoding,
            text,
          }),
        };
      }

      // Fallback: unknown shape
      return {
        statusCode: 200,
        headers: { ...okCors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
        body: JSON.stringify({ ok: true, proxy: "github", kind: data.type || "unknown", data }),
      };
    }

    // Default: whoami
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