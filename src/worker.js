/**
 * Cloudflare Worker — HTTP Basic Auth gate for the weather-updates static site.
 *
 * Every request is challenged with HTTP Basic Auth before the static asset is
 * served. Credentials are checked with a timing-safe comparison to prevent
 * timing-oracle attacks.
 *
 * Configuration (Cloudflare secrets — never committed to the repo):
 *   BASIC_USER   Username (set via: wrangler secret put BASIC_USER)
 *   PASSWORD     Password (set via: wrangler secret put PASSWORD)
 *
 * The MkDocs static site is served via the ASSETS binding defined in
 * wrangler.toml. On auth success every request is forwarded to ASSETS.
 */

import { Buffer } from "node:buffer";

const encoder = new TextEncoder();

/**
 * Timing-safe string comparison. Avoids leaking secret length through early
 * exit when lengths differ by comparing against self and negating.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  if (aBytes.byteLength !== bBytes.byteLength) {
    return !crypto.subtle.timingSafeEqual(aBytes, aBytes);
  }
  return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

/** Response sent when credentials are missing or wrong. */
function unauthorizedResponse() {
  return new Response("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Weather Updates", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
}

export default {
  /**
   * @param {Request} request
   * @param {{ BASIC_USER: string, PASSWORD: string, ASSETS: { fetch: Function } }} env
   * @returns {Promise<Response>}
   */
  async fetch(request, env) {
    const authorization = request.headers.get("Authorization");

    if (!authorization) {
      return unauthorizedResponse();
    }

    const [scheme, encoded] = authorization.split(" ");
    if (scheme !== "Basic" || !encoded) {
      return new Response("Malformed authorization header.", { status: 400 });
    }

    const credentials = Buffer.from(encoded, "base64").toString("utf-8");
    const separatorIndex = credentials.indexOf(":");
    const user = credentials.substring(0, separatorIndex);
    const pass = credentials.substring(separatorIndex + 1);

    const expectedUser = env.BASIC_USER ?? "agrovision";
    const expectedPass = env.PASSWORD;

    if (!expectedPass) {
      // Password secret not configured — fail closed, never open.
      return new Response("Service misconfigured.", { status: 503 });
    }

    if (!timingSafeEqual(expectedUser, user) || !timingSafeEqual(expectedPass, pass)) {
      return unauthorizedResponse();
    }

    // Auth passed — fetch the static asset and mark it private so Cloudflare's
    // edge cache never stores it (which would bypass auth on subsequent requests).
    const assetResponse = await env.ASSETS.fetch(request);
    const response = new Response(assetResponse.body, assetResponse);
    response.headers.set("Cache-Control", "private, no-store");
    return response;
  },
};
