"use strict";

export const DEFAULT_SERVER_URL = "http://127.0.0.1:8765";

export function isAllowedLocalServer(urlStr) {
  try {
    const parsed = new URL((urlStr || "").trim());
    return (
      parsed.protocol === "http:" &&
      (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost")
    );
  } catch (e) {
    return false;
  }
}

export function normalizeServerOrigin(urlStr) {
  const parsed = new URL(urlStr.trim());
  return parsed.origin;
}

export function isPrivateOrLocalHostname(hostname) {
  const h = (hostname || "").toLowerCase().replace(/\.+$/, "").replace(/^\[|\]$/g, "");
  if (!h || h === "localhost" || h.endsWith(".localhost")) {
    return true;
  }
  if (!h.includes(".") && !h.includes(":")) {
    return true;
  }
  if (h.includes(":")) {
    return (
      h === "::1" ||
      h === "::" ||
      h.startsWith("fc") ||
      h.startsWith("fd") ||
      h.startsWith("fe80") ||
      h.startsWith("::ffff:")
    );
  }
  const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (ipv4Match) {
    const a = Number(ipv4Match[1]);
    const b = Number(ipv4Match[2]);
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
  }
  return false;
}

export function getSafePublicReferer(urlStr, items) {
  if (!urlStr || !Array.isArray(items)) {
    return undefined;
  }
  const hasUrlItem = items.some((it) => /^https?:\/\//i.test((it || "").trim()));
  if (!hasUrlItem) {
    return undefined;
  }
  try {
    const parsed = new URL(urlStr.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return undefined;
    }
    if (isPrivateOrLocalHostname(parsed.hostname)) {
      return undefined;
    }
    return parsed.href;
  } catch (e) {
    return undefined;
  }
}
