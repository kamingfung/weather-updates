/**
 * Cloudflare Worker — HTTP Basic Auth gate for the weather-updates static site.
 *
 * Files are stored in Workers KV (SITE_ASSETS binding) and served directly
 * by this Worker. Every request passes through the auth gate — there is no
 * CDN layer that can bypass it, unlike the ASSETS binding approach.
 *
 * Secrets (set via: wrangler secret put <NAME>):
 *   BASIC_USER   Username shown in browser dialog
 *   PASSWORD     Password
 *
 * MIME types are inferred from file extension. HTML files are served with
 * Cache-Control: private, no-store so browsers do not cache them.
 */

import { Buffer } from "node:buffer";

const encoder = new TextEncoder();

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css":  "text/css",
  ".js":   "application/javascript",
  ".json": "application/json",
  ".png":  "image/png",
  ".jpg":  "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif":  "image/gif",
  ".svg":  "image/svg+xml",
  ".ico":  "image/x-icon",
  ".woff": "font/woff",
  ".woff2":"font/woff2",
  ".gz":   "application/gzip",
  ".xml":  "application/xml",
  ".map":  "application/json",
};

function mimeType(path) {
  const ext = path.match(/\.[^.]+$/)?.[0]?.toLowerCase() ?? "";
  return MIME_TYPES[ext] ?? "application/octet-stream";
}

function timingSafeEqual(a, b) {
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  if (aBytes.byteLength !== bBytes.byteLength) {
    return !crypto.subtle.timingSafeEqual(aBytes, aBytes);
  }
  return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

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
  async fetch(request, env) {
    // ── Auth gate ────────────────────────────────────────────────────────
    const authorization = request.headers.get("Authorization");
    if (!authorization) return unauthorizedResponse();

    const [scheme, encoded] = authorization.split(" ");
    if (scheme !== "Basic" || !encoded) {
      return new Response("Malformed authorization header.", { status: 400 });
    }

    const credentials = Buffer.from(encoded, "base64").toString("utf-8");
    const sep  = credentials.indexOf(":");
    const user = credentials.substring(0, sep);
    const pass = credentials.substring(sep + 1);

    const expectedUser = env.BASIC_USER ?? "agrovision";
    const expectedPass = env.PASSWORD;

    if (!expectedPass) {
      return new Response("Service misconfigured.", { status: 503 });
    }
    if (!timingSafeEqual(expectedUser, user) || !timingSafeEqual(expectedPass, pass)) {
      return unauthorizedResponse();
    }

    // ── Serve from KV ────────────────────────────────────────────────────
    const url      = new URL(request.url);
    let   pathname = decodeURIComponent(url.pathname);

    // Normalise directory paths to index.html
    if (pathname.endsWith("/")) pathname += "index.html";
    else if (!pathname.includes(".")) pathname += "/index.html";

    // KV keys are stored without leading slash
    const key = pathname.replace(/^\//, "");

    const value = await env.SITE_ASSETS.get(key, { type: "stream" });

    if (value === null) {
      // Diagnostic: return what key was attempted so we can debug KV misses.
      const notFound = await env.SITE_ASSETS.get("404.html", { type: "stream" });
      return new Response(notFound ?? "Not Found", {
        status: 404,
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    const isHtml = pathname.endsWith(".html");
    return new Response(value, {
      status: 200,
      headers: {
        "Content-Type":  mimeType(pathname),
        // HTML: never cache (contains nav state). Assets: short cache ok.
        "Cache-Control": isHtml ? "private, no-store" : "private, max-age=300",
      },
    });
  },
};
