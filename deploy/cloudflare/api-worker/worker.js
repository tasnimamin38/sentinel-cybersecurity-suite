const ALLOWED_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
];
const EDGE_HEALTH_PATH = "/__sentinel/edge-health";
const EXPECTED_API_HOST = "sentinel-staging-api-q2nk.onrender.com";

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

function validateApiOrigin(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError("API origin is not configured.");
  }

  const parsed = new URL(value);
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname !== EXPECTED_API_HOST ||
    parsed.port !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    throw new TypeError("API origin is not an approved HTTPS origin.");
  }

  return parsed.origin;
}

export default {
  async fetch(request, env) {
    const requestUrl = new URL(request.url);

    if (requestUrl.pathname === EDGE_HEALTH_PATH) {
      if (request.method !== "GET") {
        return new Response("Method Not Allowed", {
          status: 405,
          headers: { allow: "GET", "cache-control": "no-store" },
        });
      }
      return jsonResponse({
        status: "ok",
        service: "sentinel-api-edge-proxy",
        upstreamConfigured: true,
      });
    }

    if (!ALLOWED_METHODS.has(request.method)) {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: {
          allow: "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
          "cache-control": "no-store",
        },
      });
    }

    let apiOrigin;
    try {
      apiOrigin = validateApiOrigin(env?.SENTINEL_API_ORIGIN);
    } catch {
      return jsonResponse({ detail: "SENTINEL API upstream is not configured." }, 503);
    }

    const upstreamUrl = new URL(
      requestUrl.pathname + requestUrl.search,
      apiOrigin,
    );

    // The destination is fixed to the verified Render API host. Never use
    // request-supplied host, scheme, forwarding or URL parameters as an upstream.
    if (upstreamUrl.origin !== apiOrigin) {
      return jsonResponse({ detail: "Invalid upstream destination." }, 400);
    }

    const headers = new Headers(request.headers);
    for (const name of HOP_BY_HOP_HEADERS) headers.delete(name);
    headers.set("x-forwarded-host", requestUrl.host);
    headers.set("x-forwarded-proto", "https");

    const init = {
      method: request.method,
      headers,
      redirect: "manual",
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
      // Required by Node's Fetch implementation in unit tests; accepted by Workers.
      init.duplex = "half";
    }

    try {
      return await fetch(new Request(upstreamUrl.toString(), init));
    } catch {
      return jsonResponse({ detail: "SENTINEL API upstream is unavailable." }, 502);
    }
  },
};
