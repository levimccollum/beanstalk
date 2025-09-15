// Minimal health check for Netlify Functions
const okCors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: okCors, body: "" };
  }
  if (event.httpMethod !== "GET") {
    return { statusCode: 405, headers: okCors, body: "Method Not Allowed" };
  }

  const payload = {
    ok: true,
    name: "beanstalk-health",
    time: new Date().toISOString(),
    url: event.rawUrl || "",
    method: event.httpMethod,
  };

  return {
    statusCode: 200,
    headers: { ...okCors, "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(payload),
  };
};