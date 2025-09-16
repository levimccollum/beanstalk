// Public environment checklist for Beanstalk setup (no secrets revealed).
// Visit: /.netlify/functions/envcheck

function computeOrigin(event) {
  const envOrigin = process.env.ORIGIN;
  if (envOrigin) return envOrigin.replace(/\/+$/, "");
  const proto = event.headers?.["x-forwarded-proto"] || "https";
  const host = event.headers?.host || "";
  return `${proto}://${host}`;
}

exports.handler = async (event) => {
  const origin = computeOrigin(event);
  const callbackUrl = `${origin}/.netlify/functions/oauth/callback`;

  const required = [
    "GITHUB_CLIENT_ID",
    "GITHUB_CLIENT_SECRET",
    "SESSION_SECRET",
    "ORIGIN",
    "GITHUB_SCOPES"
  ];

  const missing = required.filter((k) => !process.env[k]);
  const ok = missing.length === 0;

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    },
    body: JSON.stringify({
      ok,
      missing,
      origin,
      callbackUrl,
      docs: {
        startOAuth: "/.netlify/functions/oauth/start",
        logout: "/.netlify/functions/oauth/logout"
      },
      notes: [
        "Create a GitHub OAuth App using the callbackUrl above.",
        "Add the missing variables in Netlify → Site settings → Environment variables.",
        "Never commit credentials to the repo; use env vars only."
      ]
    })
  };
};