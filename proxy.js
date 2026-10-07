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
 * Protected resources:
 *
 *   /group/*
 *   /data/*
 *
 * Blocks known AI agents, chatbots, crawlers, HTTP clients,
 * scraping frameworks, and obviously automated requests.
 *
 * A valid 5-minute Turnstile session is still required.
 * ============================================================
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

  // AI IDEs / coding agents
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

  // Python HTTP clients
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

  // Scraping / browser automation
  "scrapy",
  "selenium",
  "playwright",
  "puppeteer",
  "headlesschrome",
  "phantomjs"
];

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

function hasSuspiciousHeaders(request) {
  for (const headerName of SUSPICIOUS_HEADERS) {
    if (request.headers.has(headerName)) {
      return true;
    }
  }

  for (const [name, value] of request.headers.entries()) {
    const lowerName = name.toLowerCase();
    const lowerValue = value.toLowerCase();

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

function hasInvalidFetchMetadata(request) {
  const destination =
    request.headers.get("sec-fetch-dest");

  const mode =
    request.headers.get("sec-fetch-mode");

  const site =
    request.headers.get("sec-fetch-site");

  /*
   * Group pages are documents.
   * Image requests are images.
   */
  if (
    destination &&
    destination !== "image" &&
    destination !== "document" &&
    destination !== "empty"
  ) {
    return true;
  }

  if (
    mode &&
    mode !== "no-cors" &&
    mode !== "cors" &&
    mode !== "same-origin" &&
    mode !== "navigate"
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

function hasInvalidAcceptHeader(request) {
  const accept =
    request.headers.get("accept") || "";

  if (!accept) {
    return false;
  }

  const lower = accept.toLowerCase();

  /*
   * Allow both:
   *
   * Group pages:
   *   text/html
   *
   * Images:
   *   image/*
   *
   * Browsers:
   *   */
  if (
    !lower.includes("image/") &&
    !lower.includes("text/html") &&
    !lower.includes("*/*")
  ) {
    return true;
  }

  return false;
}

function hasBadReferer(request) {
  const referer =
    request.headers.get("referer");

  /*
   * No Referer is allowed.
   * This permits users to open an image directly.
   */

  if (!referer) {
    return false;
  }

  try {
    const url = new URL(referer);
    const requestUrl = new URL(request.url);

    if (url.hostname !== requestUrl.hostname) {
      return true;
    }

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

function hasSuspiciousBrowserProfile(request) {
  const ua =
    request.headers.get("user-agent") || "";

  const acceptLanguage =
    request.headers.get("accept-language");

  const acceptEncoding =
    request.headers.get("accept-encoding");

  /*
   * Browser-like User-Agent but missing normal
   * browser negotiation headers.
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

function hasInvalidMethod(request) {
  return request.method !== "GET";
}

export async function proxy(request) {
  const pathname = request.nextUrl.pathname;

  /*
   * Only protect archive groups and their images.
   */
  const isProtected =
    pathname.startsWith("/group/") ||
    pathname.startsWith("/data/");

  if (!isProtected) {
    return NextResponse.next();
  }

  /*
   * 1. Only GET requests.
   */
  if (hasInvalidMethod(request)) {
    return forbidden();
  }

  /*
   * 2. Block known AI / chatbot / crawler User-Agents.
   */
  if (hasBlockedUserAgent(request)) {
    return forbidden();
  }

  /*
   * 3. Block explicit automation headers.
   */
  if (hasSuspiciousHeaders(request)) {
    return forbidden();
  }

  /*
   * 4. Validate browser Fetch Metadata.
   */
  if (hasInvalidFetchMetadata(request)) {
    return forbidden();
  }

  /*
   * 5. Validate Accept header.
   */
  if (hasInvalidAcceptHeader(request)) {
    return forbidden();
  }

  /*
   * 6. Validate Referer when supplied.
   */
  if (hasBadReferer(request)) {
    return forbidden();
  }

  /*
   * 7. Validate browser profile.
   */
  if (hasSuspiciousBrowserProfile(request)) {
    return forbidden();
  }

  /*
   * 8. Require valid 5-minute Turnstile session.
   */
  const session =
    request.cookies.get(COOKIE_NAME)?.value;

  const valid =
    await verifySessionValue(session);

  if (!valid) {
    return forbidden();
  }

  /*
   * 9. Everything passed.
   */
  return NextResponse.next();
}

export const config = {
  matcher: [
    "/group/:path*",
    "/data/:path*"
  ]
};