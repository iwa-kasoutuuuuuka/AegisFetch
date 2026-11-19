"use strict";

const DEFAULT_SERVER_URL = "http://127.0.0.1:8765";
let badgeTimer = null;

function isAllowedLocalServer(urlStr) {
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

function isPrivateOrLocalHostname(hostname) {
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

function getSafePublicReferer(urlStr, items) {
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

function flashBadge(text, color) {
  if (badgeTimer) {
    clearTimeout(badgeTimer);
  }
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setBadgeText({ text });
  badgeTimer = setTimeout(() => {
    chrome.action.setBadgeText({ text: "" });
    badgeTimer = null;
  }, 4000);
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "aegisfetch-download-selection",
      title: "🛡️ AegisFetch で取得: \"%s\"",
      contexts: ["selection"]
    });
    chrome.contextMenus.create({
      id: "aegisfetch-download-link",
      title: "🛡️ このリンクを AegisFetch でダウンロード",
      contexts: ["link"]
    });
  });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  const stored = await chrome.storage.local.get(["serverUrl", "apiToken", "outputDir"]);
  const rawServer = stored.serverUrl || DEFAULT_SERVER_URL;
  if (!isAllowedLocalServer(rawServer)) {
    flashBadge("ERR", "#ef4444");
    return;
  }
  const serverUrl = new URL(rawServer).origin;
  const apiToken = (stored.apiToken || "").trim();
  const outputDir = (stored.outputDir || "").trim();

  if (!apiToken) {
    flashBadge("KEY", "#f59e0b");
    return;
  }

  let items = [];
  if (info.menuItemId === "aegisfetch-download-selection" && info.selectionText) {
    items = info.selectionText
      .split(/[\r\n,\t]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  } else if (info.menuItemId === "aegisfetch-download-link" && info.linkUrl) {
    items = [info.linkUrl.trim()];
  }

  if (items.length === 0) {
    return;
  }

  const pageReferer = getSafePublicReferer(info.pageUrl, items);

  try {
    const resp = await fetch(`${serverUrl}/api/start`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Aegis-Token": apiToken
      },
      body: JSON.stringify({
        items,
        page_referer: pageReferer,
        output_dir: outputDir || undefined
      })
    });

    if (resp.status === 200) {
      const data = await resp.json();
      if (data && data.success) {
        flashBadge("OK", "#10b981");
        return;
      }
    } else if (resp.status === 403) {
      let errData = {};
      try {
        errData = await resp.json();
      } catch (_) {}
      if (errData && errData.error_code === "invalid_token") {
        flashBadge("KEY", "#f59e0b");
      } else {
        flashBadge("BLK", "#ef4444");
      }
      return;
    }
    flashBadge("ERR", "#ef4444");
  } catch (e) {
    flashBadge("ERR", "#ef4444");
  }
});
