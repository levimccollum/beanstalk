// GitHub proxy (scaffold). Do NOT call GitHub yet.
// Behavior:
// - OPTIONS → 204 (CORS preflight)
// - GET without "bs_sess" cookie → 401 JSON (unauthenticated)
// - GET with "bs_sess" cookie → 200 JSON (proxy alive; placeholder)

const okCors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

exports.handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: okCors, body: "" };
  }

  if (event.httpMethod !== "GET") {
    return { statusCode: 405, headers: okCors, body: "Method Not Allowed" };
  }

  const cookie = event.headers?.cookie || "";
  const hasSession = /(^|;\\s*)bs_sess=/.test(cookie);

  if (!hasSession) {
    return {
      statusCode: 401,
      headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        ok: false,
        error: "unauthenticated",
        hint: "OAuth not set up yet. Next step will set session via oauth.js",
      }),
    };
  }

  // Placeholder success (when a cookie is present). Real GitHub calls come later.
  return {
    statusCode: 200,
    headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify({
      ok: true,
      proxy: "github",
      note: "Session detected. Real GitHub API wiring comes next.",
    }),
  };
};