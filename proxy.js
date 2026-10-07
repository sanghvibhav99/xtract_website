import { NextResponse } from "next/server";
import {
  COOKIE_NAME,
  verifySessionValue
} from "./lib/session";

/*
 * ============================================================
 * XTRACT ARCHIVE BOT PROTECTION
 * ============================================================
 *
 * Protected resource:
 *
 *     /data/*
 *
 * This layer is intentionally strict.
 *
 * It is designed to reject:
 *   - Codex
 *   - Claude Code
 *   - Gemini / Gemini CLI
 *   - Antigravity
 *   - Cursor
 *   - Copilot
 *   - OpenAI crawlers
 *   - Claude / Anthropic crawlers
 *   - Python requests
 *   - curl / wget
 *   - axios / fetch / undici
 *   - Scrapy
 *   - generic HTTP clients
 *   - requests with obviously forged/non-browser headers
 *
 * IMPORTANT:
 * User-Agent detection is NOT sufficient by itself.
 * A scraper can impersonate Chrome.
 *
 * Therefore this also checks:
 *   - browser Fetch Metadata headers
 *   - Accept headers
 *   - Referer
 *   - Turnstile session
 *   - request method
 *   - suspicious automation headers
 *
 * ============================================================
 */


/*
 * ------------------------------------------------------------
 * 1. KNOWN AI / AUTOMATION IDENTIFIERS
 * ------------------------------------------------------------
 */

const BLOCKED_USER_AGENTS = [
  // OpenAI / Codex
  "codex",
  "openai",
  "gptbot",
  "chatgpt-user",
  "chatgpt",

  // Anthropic / Claude
  "claude",
  "anthropic",

  // Google / Gemini
  "gemini",
  "google-extended",
  "googleother",

  // Antigravity / AI IDEs / coding agents
  "antigravity",
  "cursor",
  "copilot",
  "github-copilot",
  "windsurf",
  "codeium",
  "tabnine",
  "cline",
  "roo-code",
  "roocode",
  "continue",

  // AI / search crawlers
  "perplexitybot",
  "bytespider",
  "ccbot",
  "amazonbot",
  "meta-externalagent",
  "facebookexternalhit",
  "imagesiftbot",
  "ai2bot",
  "diffbot",

  // Generic crawlers
  "crawler",
  "spider",
  "scraper",
  "bot/",
  "bot-",

  // Programmatic Python clients
  "python-requests",
  "python-urllib",
  "urllib3",
  "httpx",
  "aiohttp",

  // Node / JS HTTP clients
  "axios",
  "node-fetch",
  "undici",
  "got/",
  "superagent",

  // CLI HTTP clients
  "curl/",
  "wget/",
  "httpie",

  // Other HTTP clients
  "java/",
  "okhttp",
  "apache-httpclient",
  "libwww-perl",
  "go-http-client",
  "php/",
  "ruby",

  // Scraping frameworks
  "scrapy",
  "selenium",
  "playwright",
  "puppeteer",
  "headlesschrome",
  "phantomjs"
];


/*
 * ------------------------------------------------------------
 * 2. SUSPICIOUS AUTOMATION HEADERS
 * ------------------------------------------------------------
 *
 * These are headers commonly associated with automation,
 * proxies, scraping libraries, or programmatic requests.
 *
 * We do NOT trust normal browser headers such as
 * X-Forwarded-For because infrastructure can add them.
 * ------------------------------------------------------------
 */

const SUSPICIOUS_HEADERS = [
  "x-requested-with",
  "x-automation",
  "x-scraper",
  "x-crawler",
  "x-bot",
  "x-spider",
  "x-playwright",
  "x-puppeteer",
  "x-selenium"
];


/*
 * ------------------------------------------------------------
 * 3. KNOWN AUTOMATION HEADER VALUES
 * ------------------------------------------------------------
 */

const AUTOMATION_HEADER_VALUES = [
  "selenium",
  "playwright",
  "puppeteer",
  "webdriver",
  "automation",
  "scraper",
  "crawler",
  "bot"
];


/*
 * ------------------------------------------------------------
 * Utility: reject request
 * ------------------------------------------------------------
 */

function forbidden(reason = "Forbidden") {
  return new NextResponse(reason, {
    status: 403,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow, noarchive"
    }
  });
}


/*
 * ------------------------------------------------------------
 * Utility: inspect User-Agent
 * ------------------------------------------------------------
 */

function hasBlockedUserAgent(request) {
  const ua = (
    request.headers.get("user-agent") || ""
  ).toLowerCase();

  if (!ua) {
    return true;
  }

  return BLOCKED_USER_AGENTS.some(
    token => ua.includes(token)
  );
}


/*
 * ------------------------------------------------------------
 * Utility: inspect suspicious custom headers
 * ------------------------------------------------------------
 */

function hasSuspiciousHeaders(request) {
  for (const headerName of SUSPICIOUS_HEADERS) {
    if (request.headers.has(headerName)) {
      return true;
    }
  }

  /*
   * Check all headers for explicit automation values.
   *
   * This intentionally ignores normal infrastructure headers.
   */

  for (const [name, value] of request.headers.entries()) {
    const lowerName = name.toLowerCase();
    const lowerValue = value.toLowerCase();

    /*
     * Don't inspect harmless browser / infrastructure headers
     * for generic words like "bot".
     */

    if (
      lowerName === "user-agent" ||
      lowerName === "cookie" ||
      lowerName === "accept" ||
      lowerName === "accept-language" ||
      lowerName === "accept-encoding" ||
      lowerName === "cache-control" ||
      lowerName === "connection" ||
      lowerName === "host" ||
      lowerName === "referer" ||
      lowerName === "origin" ||
      lowerName.startsWith("sec-") ||
      lowerName.startsWith("x-vercel-") ||
      lowerName.startsWith("x-forwarded-")
    ) {
      continue;
    }

    if (
      AUTOMATION_HEADER_VALUES.some(
        token => lowerValue.includes(token)
      )
    ) {
      return true;
    }
  }

  return false;
}


/*
 * ------------------------------------------------------------
 * Utility: browser Fetch Metadata
 * ------------------------------------------------------------
 *
 * Modern Chrome / Chromium browsers normally send these.
 *
 * For an image loaded from your own page:
 *
 *   Sec-Fetch-Dest: image
 *   Sec-Fetch-Mode: no-cors
 *   Sec-Fetch-Site: same-origin
 *
 * This makes raw HTTP scraping harder.
 * ------------------------------------------------------------
 */

function hasInvalidFetchMetadata(request) {
  const destination =
    request.headers.get("sec-fetch-dest");

  const mode =
    request.headers.get("sec-fetch-mode");

  const site =
    request.headers.get("sec-fetch-site");

  /*
   * If these headers exist, make sure they are sensible.
   */

  if (destination && destination !== "image") {
    return true;
  }

  if (
    mode &&
    mode !== "no-cors" &&
    mode !== "cors" &&
    mode !== "same-origin"
  ) {
    return true;
  }

  if (
    site &&
    site !== "same-origin" &&
    site !== "same-site" &&
    site !== "none"
  ) {
    return true;
  }

  return false;
}


/*
 * ------------------------------------------------------------
 * Utility: inspect Accept header
 * ------------------------------------------------------------
 */

function hasInvalidAcceptHeader(request) {
  const accept =
    request.headers.get("accept") || "";

  /*
   * A real browser requesting an image normally accepts
   * image formats or */
   /*
   * A request explicitly advertising only JSON/text is
   * suspicious for an image endpoint.
   */

  const lower = accept.toLowerCase();

  if (
    lower &&
    !lower.includes("image/") &&
    !lower.includes("*/*")
  ) {
    return true;
  }

  return false;
}


/*
 * ------------------------------------------------------------
 * Utility: inspect Referer
 * ------------------------------------------------------------
 */

function hasBadReferer(request) {
  const referer =
    request.headers.get("referer");

  /*
   * Directly opening an image URL may have no Referer.
   *
   * We allow that here because otherwise legitimate users
   * opening an image in a new tab could be blocked.
   *
   * If a Referer exists, however, it must point back to
   * this site.
   */

  if (!referer) {
    return false;
  }

  try {
    const url = new URL(referer);

    const requestUrl =
      new URL(request.url);

    if (url.hostname !== requestUrl.hostname) {
      return true;
    }

    /*
     * Only allow HTTPS in production.
     */

    if (
      requestUrl.protocol === "https:" &&
      url.protocol !== "https:"
    ) {
      return true;
    }

    return false;
  } catch {
    return true;
  }
}


/*
 * ------------------------------------------------------------
 * Utility: suspicious browser fingerprint
 * ------------------------------------------------------------
 */

function hasSuspiciousBrowserProfile(request) {
  const ua =
    request.headers.get("user-agent") || "";

  const acceptLanguage =
    request.headers.get("accept-language");

  const acceptEncoding =
    request.headers.get("accept-encoding");

  /*
   * A request claiming to be Chrome but carrying essentially
   * no normal browser negotiation headers is suspicious.
   */

  if (
    /chrome|chromium|edg|firefox|safari/i.test(ua)
  ) {
    if (!acceptLanguage) {
      return true;
    }

    if (!acceptEncoding) {
      return true;
    }
  }

  return false;
}


/*
 * ------------------------------------------------------------
 * Utility: request method
 * ------------------------------------------------------------
 */

function hasInvalidMethod(request) {
  return request.method !== "GET";
}


/*
 * ------------------------------------------------------------
 * MAIN PROXY
 * ------------------------------------------------------------
 */

export async function proxy(request) {

  /*
   * ----------------------------------------------------------
   * STEP 1
   * Only GET requests are valid for /data/*
   * ----------------------------------------------------------
   */

  if (hasInvalidMethod(request)) {
    return forbidden();
  }


  /*
   * ----------------------------------------------------------
   * STEP 2
   * Kill known AI agents / crawlers / HTTP clients.
   * ----------------------------------------------------------
   */

  if (hasBlockedUserAgent(request)) {
    return forbidden();
  }


  /*
   * ----------------------------------------------------------
   * STEP 3
   * Kill explicit automation headers.
   * ----------------------------------------------------------
   */

  if (hasSuspiciousHeaders(request)) {
    return forbidden();
  }


  /*
   * ----------------------------------------------------------
   * STEP 4
   * Validate browser Fetch Metadata.
   * ----------------------------------------------------------
   */

  if (hasInvalidFetchMetadata(request)) {
    return forbidden();
  }


  /*
   * ----------------------------------------------------------
   * STEP 5
   * Validate image Accept header.
   * ----------------------------------------------------------
   */

  if (hasInvalidAcceptHeader(request)) {
    return forbidden();
  }


  /*
   * ----------------------------------------------------------
   * STEP 6
   * Validate Referer when one is supplied.
   * ----------------------------------------------------------
   */

  if (hasBadReferer(request)) {
    return forbidden();
  }


  /*
   * ----------------------------------------------------------
   * STEP 7
   * Reject suspicious "Chrome" requests with obviously
   * incomplete browser negotiation.
   * ----------------------------------------------------------
   */

  if (hasSuspiciousBrowserProfile(request)) {
    return forbidden();
  }


  /*
   * ----------------------------------------------------------
   * STEP 8
   * REQUIRE VALID TURNSTILE SESSION.
   *
   * This is the important part.
   *
   * Even if somebody spoofs Chrome headers, they still need
   * your signed xtract_verified session cookie.
   * ----------------------------------------------------------
   */

  const session =
    request.cookies.get(COOKIE_NAME)?.value;

  const valid =
    await verifySessionValue(session);

  if (!valid) {
    return forbidden();
  }


  /*
   * ----------------------------------------------------------
   * STEP 9
   * Everything passed.
   *
   * Allow Next.js/Vercel to serve the image.
   * ----------------------------------------------------------
   */

  return NextResponse.next();
}


/*
 * ------------------------------------------------------------
 * MATCH ONLY THE IMAGE/DATA DIRECTORY
 * ------------------------------------------------------------
 */

export const config = {
  matcher: [
    "/data/:path*"
  ]
};