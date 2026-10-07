const COOKIE_NAME = "xtract_verified";
const SESSION_DURATION = 5 * 60; // 5 minutes

function base64urlEncode(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);

  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function getKey() {
  const secret = process.env.SESSION_SECRET;

  if (!secret) {
    throw new Error("SESSION_SECRET is not configured");
  }

  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign", "verify"]
  );
}

export async function createSessionValue() {
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = String(timestamp);

  const key = await getKey();

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );

  return `${timestamp}.${base64urlEncode(new Uint8Array(signature))}`;
}

export async function verifySessionValue(value) {
  if (!value || !value.includes(".")) {
    return false;
  }

  const [timestampString, signatureString] = value.split(".");

  const timestamp = Number(timestampString);

  if (!Number.isFinite(timestamp)) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);

  if (now - timestamp < 0 || now - timestamp > SESSION_DURATION) {
    return false;
  }

  try {
    const key = await getKey();

    return await crypto.subtle.verify(
      "HMAC",
      key,
      base64urlDecode(signatureString),
      new TextEncoder().encode(timestampString)
    );
  } catch {
    return false;
  }
}

export { COOKIE_NAME, SESSION_DURATION };