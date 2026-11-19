"use strict";

import {
  DEFAULT_SERVER_URL,
  isAllowedLocalServer,
  normalizeServerOrigin,
  getSafePublicReferer
} from "./shared.js";

let currentSettings = {
  serverUrl: DEFAULT_SERVER_URL,
  apiToken: "",
  outputDir: "",
  concurrency: 1,
  locale: "ja-jp",
  checkUpdates: false
};
let activePageUrl = "";
let activeTabId = null;
let pollTimer = null;
let isSubmitting = false;

async function loadSettings() {
  const stored = await chrome.storage.local.get([
    "serverUrl",
    "apiToken",
    "outputDir",
    "concurrency",
    "locale",
    "checkUpdates"
  ]);
  currentSettings = {
    serverUrl: stored.serverUrl && isAllowedLocalServer(stored.serverUrl)
      ? normalizeServerOrigin(stored.serverUrl)
      : DEFAULT_SERVER_URL,
    apiToken: (stored.apiToken || "").trim(),
    outputDir: (stored.outputDir || "").trim(),
    concurrency: Number(stored.concurrency || 1),
    locale: stored.locale || "ja-jp",
    checkUpdates: Boolean(stored.checkUpdates)
  };

  document.getElementById("inputServerUrl").value = currentSettings.serverUrl;
  document.getElementById("inputToken").value = currentSettings.apiToken;
  document.getElementById("inputOutputDir").value = currentSettings.outputDir;
  document.getElementById("selectConcurrency").value = String(currentSettings.concurrency);
  document.getElementById("selectLocale").value = currentSettings.locale;
  document.getElementById("chkUpdates").checked = currentSettings.checkUpdates;
}

async function apiFetch(path, options = {}) {
  if (!isAllowedLocalServer(currentSettings.serverUrl)) {
    throw new Error("サーバーURLは 127.0.0.1 または localhost のみ許可されています。");
  }

  const headers = Object.assign({}, options.headers || {});
  if (currentSettings.apiToken) {
    headers["X-Aegis-Token"] = currentSettings.apiToken;
  }
  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  return fetch(`${currentSettings.serverUrl}${path}`, {
    method: options.method || "GET",
    headers,
    body: options.body
  });
}

function setStatusBadge(mode, text) {
  const badge = document.getElementById("statusBadge");
  badge.classList.remove("online", "auth", "offline");
  badge.classList.add(mode);
  badge.textContent = text;
}

function showSettingsNotice(msg) {
  const el = document.getElementById("settingsNotice");
  if (!msg) {
    el.classList.add("hidden");
    el.textContent = "";
    return;
  }
  el.textContent = msg;
  el.classList.remove("hidden");
}

async function checkServerHealth() {
  try {
    const resp = await apiFetch("/api/health");
    if (resp.status === 200) {
      const data = await resp.json();
      setStatusBadge("online", `Online v${data.version || ""}`.trim());
      showSettingsNotice("");
      return true;
    }
    if (resp.status === 403) {
      let errData = {};
      try {
        errData = await resp.json();
      } catch (_) {}
      if (!errData.error_code || errData.error_code === "invalid_token") {
        setStatusBadge("auth", "トークン未設定/不一致");
        document.getElementById("settingsPanel").classList.remove("hidden");
        showSettingsNotice("Web UI 右上の「🔑 拡張トークンをコピー」からトークンを設定してください。");
      } else {
        setStatusBadge("offline", "接続拒否 (403)");
        showSettingsNotice(errData.message || "ローカルブリッジへの接続が拒否されました。");
      }
      return false;
    }
    setStatusBadge("offline", `Error ${resp.status}`);
    return false;
  } catch (e) {
    setStatusBadge("offline", "Offline (Web UI未起動)");
    document.getElementById("jobStatusText").textContent =
      "AegisFetch Web UI (aegisfetch-ui) を起動してください";
    return false;
  }
}

function renderPdfList(items) {
  const container = document.getElementById("pdfListContainer");
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  document.getElementById("scanCount").textContent = `${items.length} 件検出`;
  const btnSend = document.getElementById("btnSendSelected");

  if (!items || items.length === 0) {
    const emptyDiv = document.createElement("div");
    emptyDiv.className = "pdf-empty";
    emptyDiv.textContent = "このページ内にPDFリンクが見つかりませんでした。「型番・URL送信」タブから型番指定もできます。";
    container.appendChild(emptyDiv);
    btnSend.disabled = true;
    return;
  }

  for (const item of items) {
    const label = document.createElement("label");
    label.className = "pdf-row";

    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = true;
    cb.dataset.url = item.url;
    cb.addEventListener("change", updateSendSelectedState);

    const meta = document.createElement("div");
    meta.className = "pdf-meta";

    const title = document.createElement("div");
    title.className = "pdf-title";
    title.textContent = item.label || item.url.split("/").pop() || "PDF Document";

    const urlDiv = document.createElement("div");
    urlDiv.className = "pdf-url";
    urlDiv.textContent = item.url;

    meta.appendChild(title);
    meta.appendChild(urlDiv);
    label.appendChild(cb);
    label.appendChild(meta);
    container.appendChild(label);
  }

  updateSendSelectedState();
}

function updateSendSelectedState() {
  const checkedCount = document.querySelectorAll('#pdfListContainer input[type="checkbox"]:checked').length;
  const btnSend = document.getElementById("btnSendSelected");
  btnSend.disabled = checkedCount === 0;
  btnSend.textContent = checkedCount > 0
    ? `🚀 選択したPDFをダウンロード (${checkedCount}件)`
    : "🚀 選択したPDFをダウンロード";
}

function injectedPageScanner() {
  const selection = (window.getSelection() ? window.getSelection().toString() : "").trim();
  const seen = new Set();
  const results = [];

  const addCandidate = (rawUrl, textLabel) => {
    const trimmed = (rawUrl || "").trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.toLowerCase().startsWith("javascript:")) {
      return;
    }
    let absUrl;
    try {
      absUrl = new URL(trimmed, window.location.href).href;
    } catch (e) {
      return;
    }
    if (!absUrl.startsWith("http://") && !absUrl.startsWith("https://")) {
      return;
    }
    const lower = absUrl.toLowerCase();
    const labelLower = (textLabel || "").toLowerCase();
    const isPdfUrl = lower.includes(".pdf") || lower.includes("publications.balluff.com/pdfengine/pdf");
    const isDatasheetText =
      (labelLower.includes("datasheet") || labelLower.includes("データシート") || labelLower.includes("カタログ")) &&
      !absUrl.split("#")[0].endsWith("/");

    if ((isPdfUrl || isDatasheetText) && !seen.has(absUrl)) {
      seen.add(absUrl);
      const cleanLabel = (textLabel || "").replace(/\s+/g, " ").trim();
      const fallbackName = absUrl.split("?")[0].split("/").pop() || "datasheet.pdf";
      results.push({
        url: absUrl,
        label: cleanLabel || fallbackName
      });
    }
  };

  document.querySelectorAll("a[href]").forEach((a) => {
    addCandidate(a.getAttribute("href"), a.textContent || a.getAttribute("title") || "");
  });
  document.querySelectorAll("iframe[src], embed[src]").forEach((el) => {
    addCandidate(el.getAttribute("src"), el.getAttribute("title") || "Embedded PDF");
  });
  document.querySelectorAll("object[data]").forEach((el) => {
    addCandidate(el.getAttribute("data"), el.getAttribute("title") || "Embedded PDF");
  });

  return { selection, results };
}

async function injectedFetchPdfBase64(targetUrl) {
  const resp = await fetch(targetUrl, { credentials: "include" });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }
  const buf = await resp.arrayBuffer();
  const bytes = new Uint8Array(buf);
  if (bytes.length < 512) {
    throw new Error("Payload too small");
  }
  // Check %PDF magic bytes
  if (bytes[0] !== 0x25 || bytes[1] !== 0x50 || bytes[2] !== 0x44 || bytes[3] !== 0x46) {
    throw new Error("Not a valid PDF (HTML/login page returned)");
  }
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return {
    b64: btoa(binary),
    size: bytes.length
  };
}

async function scanActiveTab() {
  const container = document.getElementById("pdfListContainer");
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs && tabs[0];
    if (!tab || !tab.id || !tab.url || (!tab.url.startsWith("http://") && !tab.url.startsWith("https://"))) {
      activePageUrl = "";
      activeTabId = null;
      while (container.firstChild) container.removeChild(container.firstChild);
      const div = document.createElement("div");
      div.className = "pdf-empty";
      div.textContent = "HTTP/HTTPS の Web ページを開いた状態でスキャンしてください。";
      container.appendChild(div);
      document.getElementById("scanCount").textContent = "0 件検出";
      document.getElementById("btnSendSelected").disabled = true;
      return;
    }

    activePageUrl = tab.url;
    activeTabId = tab.id;
    const execRes = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: injectedPageScanner
    });

    const payload = execRes && execRes[0] && execRes[0].result ? execRes[0].result : { selection: "", results: [] };
    if (payload.selection) {
      const quickBox = document.getElementById("quickItemsInput");
      if (!quickBox.value.trim()) {
        quickBox.value = payload.selection;
      }
    }
    renderPdfList(payload.results || []);
  } catch (e) {
    while (container.firstChild) container.removeChild(container.firstChild);
    const div = document.createElement("div");
    div.className = "pdf-empty";
    div.textContent = `スキャンに失敗しました: ${e.message || e}`;
    container.appendChild(div);
  }
}

async function sendViaBrowserAuthSession(urls) {
  const statusEl = document.getElementById("jobStatusText");
  const barEl = document.getElementById("jobProgressBar");
  const btnSelected = document.getElementById("btnSendSelected");
  const btnQuick = document.getElementById("btnSendQuick");

  if (!activeTabId || !urls || urls.length === 0 || isSubmitting) {
    return;
  }

  isSubmitting = true;
  if (btnSelected) btnSelected.disabled = true;
  if (btnQuick) btnQuick.disabled = true;

  let okCount = 0;
  let failCount = 0;

  try {
    for (let i = 0; i < urls.length; i++) {
      const u = urls[i];
      const pct = Math.round(((i) / urls.length) * 100);
      barEl.style.width = `${Math.max(5, pct)}%`;
      statusEl.textContent = `認証セッション取得中 ${i + 1}/${urls.length}...`;

      try {
        const execRes = await chrome.scripting.executeScript({
          target: { tabId: activeTabId },
          func: injectedFetchPdfBase64,
          args: [u]
        });
        const fetched = execRes && execRes[0] ? execRes[0].result : null;
        if (!fetched || !fetched.b64) {
          throw new Error("ブラウザ側でPDFを取得できませんでした");
        }
        const rawName = u.split("?")[0].split("/").pop() || `document_${i + 1}.pdf`;
        const resp = await apiFetch("/api/save-browser-pdf", {
          method: "POST",
          body: JSON.stringify({
            filename: rawName,
            content_b64: fetched.b64,
            output_dir: currentSettings.outputDir || undefined
          })
        });
        const data = await resp.json();
        if (!resp.ok || !data.success) {
          throw new Error(data.message || `HTTP ${resp.status}`);
        }
        okCount++;
      } catch (err) {
        failCount++;
      }
    }
    barEl.style.width = "100%";
    statusEl.textContent = `ブラウザ認証完了: 成功 ${okCount} / 失敗 ${failCount}`;
  } finally {
    isSubmitting = false;
    if (btnQuick) btnQuick.disabled = false;
    if (btnSelected) updateSendSelectedState();
  }
}

async function sendDownloadJob(items, pageReferer) {
  const statusEl = document.getElementById("jobStatusText");
  const barEl = document.getElementById("jobProgressBar");
  const btnSelected = document.getElementById("btnSendSelected");
  const btnQuick = document.getElementById("btnSendQuick");

  if (!items || items.length === 0 || isSubmitting) {
    return;
  }

  isSubmitting = true;
  if (btnSelected) btnSelected.disabled = true;
  if (btnQuick) btnQuick.disabled = true;

  statusEl.textContent = `送信中 (${items.length}件)...`;
  barEl.style.width = "5%";

  try {
    const safeReferer = getSafePublicReferer(pageReferer, items);
    const payload = {
      items,
      page_referer: safeReferer,
      output_dir: currentSettings.outputDir || undefined,
      concurrency: currentSettings.concurrency,
      locale: currentSettings.locale,
      check_updates: currentSettings.checkUpdates
    };

    const resp = await apiFetch("/api/start", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    let data = {};
    try {
      data = await resp.json();
    } catch (_) {}

    if (resp.status === 403) {
      if (data.error_code === "invalid_token") {
        setStatusBadge("auth", "認証エラー (403)");
        document.getElementById("settingsPanel").classList.remove("hidden");
        showSettingsNotice("トークンが無効です。Web UI から最新のトークンをコピーしてください。");
        statusEl.textContent = "認証エラー: トークンを確認してください";
      } else {
        statusEl.textContent = `エラー: ${data.message || "リクエストが拒否されました"}`;
      }
      barEl.style.width = "0%";
      return;
    }

    if (!resp.ok || !data.success) {
      statusEl.textContent = `エラー: ${data.message || "送信失敗"}`;
      barEl.style.width = "0%";
      return;
    }

    const jobId = data.job_id;
    if (pollTimer) clearInterval(pollTimer);
    pollJobProgress(jobId);
    pollTimer = setInterval(() => pollJobProgress(jobId), 800);
  } catch (e) {
    statusEl.textContent = "通信エラー: Web UI が起動していません";
    barEl.style.width = "0%";
    setStatusBadge("offline", "Offline");
  } finally {
    isSubmitting = false;
    if (btnQuick) btnQuick.disabled = false;
    if (btnSelected) updateSendSelectedState();
  }
}

async function pollJobProgress(jobId) {
  const statusEl = document.getElementById("jobStatusText");
  const barEl = document.getElementById("jobProgressBar");
  try {
    const resp = await apiFetch(`/api/job?job_id=${encodeURIComponent(jobId)}`);
    if (!resp.ok) {
      clearInterval(pollTimer);
      return;
    }
    const job = await resp.json();
    if (!job.success) {
      clearInterval(pollTimer);
      return;
    }

    const pct = job.percent || 0;
    barEl.style.width = `${pct}%`;

    if (job.status === "running") {
      statusEl.textContent = `取得中 ${job.completed_items}/${job.total_items} (${pct}%)`;
    } else {
      clearInterval(pollTimer);
      statusEl.textContent = `完了: 成功 ${job.success_count} / 失敗 ${job.failed_count}`;
    }
  } catch (e) {
    clearInterval(pollTimer);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  await checkServerHealth();
  await scanActiveTab();

  document.getElementById("btnToggleSettings").addEventListener("click", () => {
    document.getElementById("settingsPanel").classList.toggle("hidden");
  });

  document.getElementById("btnToggleTokenVis").addEventListener("click", () => {
    const inp = document.getElementById("inputToken");
    inp.type = inp.type === "password" ? "text" : "password";
  });

  document.getElementById("btnSaveSettings").addEventListener("click", async () => {
    const rawUrl = document.getElementById("inputServerUrl").value.trim() || DEFAULT_SERVER_URL;
    if (!isAllowedLocalServer(rawUrl)) {
      showSettingsNotice("セキュリティ保護のため http://127.0.0.1 または http://localhost のみ設定可能です。");
      return;
    }
    const normalizedUrl = normalizeServerOrigin(rawUrl);

    currentSettings = {
      serverUrl: normalizedUrl,
      apiToken: document.getElementById("inputToken").value.trim(),
      outputDir: document.getElementById("inputOutputDir").value.trim(),
      concurrency: Number(document.getElementById("selectConcurrency").value || 1),
      locale: document.getElementById("selectLocale").value || "ja-jp",
      checkUpdates: document.getElementById("chkUpdates").checked
    };
    await chrome.storage.local.set(currentSettings);
    const ok = await checkServerHealth();
    if (ok) {
      document.getElementById("settingsPanel").classList.add("hidden");
    }
  });

  const tabScan = document.getElementById("tabScan");
  const tabQuick = document.getElementById("tabQuick");
  const paneScan = document.getElementById("paneScan");
  const paneQuick = document.getElementById("paneQuick");

  tabScan.addEventListener("click", () => {
    tabScan.classList.add("active");
    tabQuick.classList.remove("active");
    paneScan.classList.remove("hidden");
    paneQuick.classList.add("hidden");
  });

  tabQuick.addEventListener("click", () => {
    tabQuick.classList.add("active");
    tabScan.classList.remove("active");
    paneQuick.classList.remove("hidden");
    paneScan.classList.add("hidden");
  });

  document.getElementById("btnScanPage").addEventListener("click", scanActiveTab);

  document.getElementById("btnSelectAll").addEventListener("click", () => {
    document.querySelectorAll('#pdfListContainer input[type="checkbox"]').forEach((cb) => {
      cb.checked = true;
    });
    updateSendSelectedState();
  });

  document.getElementById("btnDeselectAll").addEventListener("click", () => {
    document.querySelectorAll('#pdfListContainer input[type="checkbox"]').forEach((cb) => {
      cb.checked = false;
    });
    updateSendSelectedState();
  });

  document.getElementById("btnSendSelected").addEventListener("click", () => {
    const urls = Array.from(document.querySelectorAll('#pdfListContainer input[type="checkbox"]:checked'))
      .map((cb) => cb.dataset.url)
      .filter(Boolean);
    if (document.getElementById("chkBrowserAuthMode").checked) {
      sendViaBrowserAuthSession(urls);
    } else {
      sendDownloadJob(urls, activePageUrl);
    }
  });

  document.getElementById("btnSendQuick").addEventListener("click", () => {
    const raw = document.getElementById("quickItemsInput").value;
    const items = raw
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s && !s.startsWith("#"));
    sendDownloadJob(items, activePageUrl);
  });

  document.getElementById("btnOpenWebUi").addEventListener("click", () => {
    if (isAllowedLocalServer(currentSettings.serverUrl)) {
      chrome.tabs.create({ url: currentSettings.serverUrl });
    }
  });
});
