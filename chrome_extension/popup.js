"use strict";

const DEFAULT_SERVER_URL = "http://127.0.0.1:8765";

let currentSettings = {
  serverUrl: DEFAULT_SERVER_URL,
  apiToken: "",
  outputDir: ""
};
let activePageUrl = "";
let pollTimer = null;
let isSubmitting = false;

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

function normalizeServerOrigin(urlStr) {
  const parsed = new URL(urlStr.trim());
  return parsed.origin;
}

async function loadSettings() {
  const stored = await chrome.storage.local.get(["serverUrl", "apiToken", "outputDir"]);
  currentSettings = {
    serverUrl: stored.serverUrl && isAllowedLocalServer(stored.serverUrl)
      ? normalizeServerOrigin(stored.serverUrl)
      : DEFAULT_SERVER_URL,
    apiToken: (stored.apiToken || "").trim(),
    outputDir: (stored.outputDir || "").trim()
  };

  document.getElementById("inputServerUrl").value = currentSettings.serverUrl;
  document.getElementById("inputToken").value = currentSettings.apiToken;
  document.getElementById("inputOutputDir").value = currentSettings.outputDir;
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

async function scanActiveTab() {
  const container = document.getElementById("pdfListContainer");
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs && tabs[0];
    if (!tab || !tab.id || !tab.url || (!tab.url.startsWith("http://") && !tab.url.startsWith("https://"))) {
      activePageUrl = "";
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
      output_dir: currentSettings.outputDir || undefined
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
    currentSettings = {
      serverUrl: normalizeServerOrigin(rawUrl),
      apiToken: document.getElementById("inputToken").value.trim(),
      outputDir: document.getElementById("inputOutputDir").value.trim()
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
    sendDownloadJob(urls, activePageUrl);
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
