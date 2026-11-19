"use strict";

import { DEFAULT_SERVER_URL, isAllowedLocalServer, getSafePublicReferer } from "./shared.js";

let badgeTimer = null;

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
  const stored = await chrome.storage.local.get([
    "serverUrl",
    "apiToken",
    "outputDir",
    "concurrency",
    "locale",
    "checkUpdates"
  ]);
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
        output_dir: outputDir || undefined,
        concurrency: Number(stored.concurrency || 1),
        locale: stored.locale || "ja-jp",
        check_updates: Boolean(stored.checkUpdates)
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
