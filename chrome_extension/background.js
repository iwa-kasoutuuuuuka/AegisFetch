"use strict";

const DEFAULT_SERVER_URL = "http://127.0.0.1:8765";

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

function flashBadge(text, color) {
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setBadgeText({ text });
  setTimeout(() => {
    chrome.action.setBadgeText({ text: "" });
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

  const pageReferer =
    info.pageUrl && (info.pageUrl.startsWith("http://") || info.pageUrl.startsWith("https://"))
      ? info.pageUrl
      : undefined;

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
      flashBadge("KEY", "#f59e0b");
      return;
    }
    flashBadge("ERR", "#ef4444");
  } catch (e) {
    flashBadge("ERR", "#ef4444");
  }
});
