"use strict";

const EXTENSION_TOKEN = window.__AEGIS_EXTENSION_TOKEN__ || "";
let activeJobId = null;
let activeJobStatus = null;
let pollTimer = null;
let jobsSyncTimer = null;
let lastFailedItems = [];
let lastJobResults = [];

function copyExtensionToken() {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(EXTENSION_TOKEN).then(() => {
      alert("拡張機能連携用トークンをクリップボードにコピーしました！\nChrome拡張の設定画面に貼り付けてください。");
    }).catch(() => {
      window.prompt("AegisFetch 拡張機能トークン (コピーしてください):", EXTENSION_TOKEN);
    });
  } else {
    window.prompt("AegisFetch 拡張機能トークン (コピーしてください):", EXTENSION_TOKEN);
  }
}

const SETTINGS_KEYS = [
  "outputDir", "proxiesInput", "proxyModeSelect", "concurrencySelect",
  "localeSelect", "minDelay", "maxDelay", "fallbackDirectCheck",
  "autoLocaleFallbackCheck", "genericSearchCheck", "checkUpdatesCheck"
];

function saveUiSettings() {
  try {
    const data = {};
    for (const id of SETTINGS_KEYS) {
      const el = document.getElementById(id);
      if (!el) continue;
      data[id] = (el.type === "checkbox") ? el.checked : el.value;
    }
    localStorage.setItem("aegisfetch_ui_settings_v1", JSON.stringify(data));
  } catch (e) {}
}

function restoreUiSettings() {
  try {
    const raw = localStorage.getItem("aegisfetch_ui_settings_v1");
    if (!raw) return;
    const data = JSON.parse(raw);
    for (const id of SETTINGS_KEYS) {
      const el = document.getElementById(id);
      if (!el || !(id in data)) continue;
      if (el.type === "checkbox") el.checked = Boolean(data[id]);
      else if (data[id] !== undefined && data[id] !== null) el.value = data[id];
    }
  } catch (e) {}
}

function updateItemCount() {
  const raw = document.getElementById("itemsInput").value;
  const count = raw.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith("#")).length;
  document.getElementById("itemCountLabel").textContent = count + " 件";
}

async function handleBomFileSelect(file) {
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) {
    alert("ファイルサイズが大きすぎます (上限 5MB)");
    return;
  }
  const reader = new FileReader();
  reader.onload = async () => {
    const b64 = reader.result.split(",")[1];
    try {
      const resp = await fetch("/api/parse-file", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({filename: file.name, content_b64: b64})
      });
      const data = await resp.json();
      if (!data.success) {
        alert("ファイル解析エラー: " + data.message);
        return;
      }
      const ta = document.getElementById("itemsInput");
      const existing = ta.value.trim();
      const loaded = (data.items || []).join("\n");
      ta.value = existing ? (existing + "\n" + loaded) : loaded;
      updateItemCount();
      alert(`「${file.name}」から ${data.items.length} 件の型番/URLを読み込みました！`);
    } catch (e) {
      alert("通信エラー: " + e);
    }
  };
  reader.readAsDataURL(file);
}

function loadSampleList() {
  document.getElementById("itemsInput").value = [
    "BES0002(BES G06EB-NOC40F-S49G)",
    "BES0003(BES G06EB-NSC40F-S49G)",
    "AM6-CN-3H"
  ].join("\n");
  updateItemCount();
}

function getConfiguredProxies() {
  const raw = document.getElementById("proxiesInput").value;
  return raw.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith("#"));
}

function updateProxyCountBadge() {
  const list = getConfiguredProxies();
  const badge = document.getElementById("headerProxyBadge");
  badge.textContent = list.length > 0 ? `Proxy: ACTIVE (${list.length} IPs)` : "Proxy: DIRECT";
}

async function harvestFreeProxies(verifyLive) {
  const btn = document.getElementById("btnHarvestProxies");
  btn.disabled = true;
  btn.textContent = "⏳ 収集＆生存テスト中(約4秒)...";
  try {
    const resp = await fetch("/api/free-proxies", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({verify_live: verifyLive, count: 12})
    });
    const data = await resp.json();
    if (!data.success) {
      alert("無料プロキシ取得エラー: " + (data.message || ""));
      return;
    }
    document.getElementById("proxiesInput").value = (data.working_proxies || []).join("\n");
    updateProxyCountBadge();
    alert(`公開リスト(${data.fetched_total}件)から高速応答プロキシ ${data.working_proxies.length} 件をセットしました！`);
  } catch (e) {
    alert("通信エラー: " + e);
  } finally {
    btn.disabled = false;
    btn.textContent = "⚡ 無料プロキシ取得＆テスト";
  }
}

async function loadPresetProxies() {
  const resp = await fetch("/api/free-proxies", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({preset_only: true})
  });
  const data = await resp.json();
  if (data.working_proxies) {
    document.getElementById("proxiesInput").value = data.working_proxies.join("\n");
    updateProxyCountBadge();
  }
}

function clearProxies() {
  document.getElementById("proxiesInput").value = "";
  updateProxyCountBadge();
}

async function extractLinksFromPage() {
  const urlInput = document.getElementById("extractUrlInput");
  const url = urlInput.value.trim();
  if (!url) { alert("抽出元のWebページURLを入力してください。"); return; }
  const btn = document.getElementById("btnExtract");
  btn.disabled = true;
  btn.textContent = "解析中...";
  try {
    const resp = await fetch("/api/extract", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url})
    });
    const data = await resp.json();
    if (!data.success) { alert("抽出エラー: " + (data.message || "")); return; }
    if (data.pdf_links.length === 0) { alert("PDFリンクが見つかりませんでした。"); return; }
    const ta = document.getElementById("itemsInput");
    const existing = ta.value.trim();
    const newUrls = data.pdf_links.map(x => x.url).join("\n");
    ta.value = existing ? (existing + "\n" + newUrls) : newUrls;
    updateItemCount();
    urlInput.value = "";
    alert(data.pdf_links.length + " 件のPDFリンクを追加しました！");
  } catch (e) {
    alert("通信エラー: " + e);
  } finally {
    btn.disabled = false;
    btn.textContent = "ページ解析";
  }
}

function attachToJob(jobId) {
  if (!jobId) return;
  activeJobId = jobId;
  if (pollTimer) clearInterval(pollTimer);
  pollJobStatus();
  pollTimer = setInterval(pollJobStatus, 700);
}

async function launchJobWithItems(items) {
  const proxies = getConfiguredProxies();
  const proxy_rotation_mode = document.getElementById("proxyModeSelect").value;
  const fallback_to_direct = document.getElementById("fallbackDirectCheck").checked;
  const output_dir = document.getElementById("outputDir").value.trim();
  const locale = document.getElementById("localeSelect").value;
  const concurrency = parseInt(document.getElementById("concurrencySelect").value, 10) || 1;
  const auto_fallback_locales = document.getElementById("autoLocaleFallbackCheck").checked;
  const enable_generic_search = document.getElementById("genericSearchCheck").checked;
  const check_updates = document.getElementById("checkUpdatesCheck").checked;
  const min_delay = parseFloat(document.getElementById("minDelay").value) || 0.6;
  const max_delay = parseFloat(document.getElementById("maxDelay").value) || 1.5;

  document.getElementById("btnStart").disabled = true;
  document.getElementById("btnRetryFailed").disabled = true;
  document.getElementById("btnCancel").disabled = false;
  lastFailedItems = [];

  try {
    const resp = await fetch("/api/start", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        items, proxies, proxy_rotation_mode, fallback_to_direct,
        output_dir, locale, concurrency, auto_fallback_locales,
        enable_generic_search, check_updates, min_delay, max_delay
      })
    });
    const data = await resp.json();
    if (!data.success) {
      alert("開始エラー: " + data.message);
      document.getElementById("btnStart").disabled = false;
      document.getElementById("btnCancel").disabled = true;
      return;
    }
    attachToJob(data.job_id);
    syncRecentJobs();
  } catch (e) {
    alert("リクエスト失敗: " + e);
    document.getElementById("btnStart").disabled = false;
    document.getElementById("btnCancel").disabled = true;
  }
}

function startDownloadJob() {
  const rawText = document.getElementById("itemsInput").value;
  const items = rawText.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith("#"));
  if (items.length === 0) { alert("型番またはURLを1件以上入力してください。"); return; }
  launchJobWithItems(items);
}

function retryFailedItems() {
  if (lastFailedItems.length === 0) return;
  document.getElementById("itemsInput").value = lastFailedItems.join("\n");
  updateItemCount();
  launchJobWithItems(lastFailedItems);
}

async function cancelCurrentJob() {
  if (!activeJobId) return;
  await fetch("/api/cancel", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({job_id: activeJobId})
  });
}

async function pollJobStatus() {
  if (!activeJobId) return;
  try {
    const resp = await fetch("/api/job?job_id=" + encodeURIComponent(activeJobId));
    const job = await resp.json();
    if (!job.success) return;

    activeJobStatus = job.status;
    document.getElementById("jobStatusBadge").textContent = job.status.toUpperCase();
    document.getElementById("statTotal").textContent = job.total_items;
    document.getElementById("statSuccess").textContent = job.success_count;
    document.getElementById("statSkipped").textContent = job.skipped_count;
    document.getElementById("statFailed").textContent = job.failed_count;

    const pct = job.percent || 0;
    document.getElementById("progressBar").style.width = pct + "%";
    document.getElementById("progressPercent").textContent = `${pct}% (${job.completed_items}/${job.total_items})`;

    if (job.last_proxy) {
      document.getElementById("activeProxyText").textContent = `直近の通信経路 (IP): ${job.last_proxy}`;
    }

    const results = job.results || [];
    lastJobResults = results;
    renderLogs(results);

    if (job.status === "running") {
      document.getElementById("btnStart").disabled = true;
      document.getElementById("btnCancel").disabled = false;
      document.getElementById("currentItemText").textContent = "処理中: " + (job.current_item || "...");
    } else {
      document.getElementById("currentItemText").textContent = `完了 (${job.status})`;
      document.getElementById("btnStart").disabled = false;
      document.getElementById("btnCancel").disabled = true;
      document.getElementById("btnExportCsv").disabled = (results.length === 0);
      lastFailedItems = results.filter(r => !r.success).map(r => r.input);
      document.getElementById("btnRetryFailed").disabled = (lastFailedItems.length === 0);
      clearInterval(pollTimer);
      pollTimer = null;
      refreshFileList();
    }
  } catch (e) {
    console.error(e);
  }
}

async function syncRecentJobs() {
  try {
    const resp = await fetch("/api/jobs");
    const data = await resp.json();
    if (!data.success || !Array.isArray(data.jobs)) return;

    const sel = document.getElementById("recentJobSelect");
    if (sel) {
      while (sel.firstChild) sel.removeChild(sel.firstChild);
      if (data.jobs.length === 0) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "ジョブ履歴なし";
        sel.appendChild(opt);
      } else {
        for (const j of data.jobs) {
          const opt = document.createElement("option");
          opt.value = j.job_id;
          const srcTag = j.source === "extension" ? "[拡張]" : "[WebUI]";
          opt.textContent = `${srcTag} ${j.job_id} (${j.status}: ${j.success_count}/${j.total_items}) ${j.started_at || ""}`;
          if (j.job_id === activeJobId) opt.selected = true;
          sel.appendChild(opt);
        }
      }
    }

    // Auto-attach to a running job launched by the Chrome/Edge extension when UI is idle
    const runningJob = data.jobs.find(j => j.status === "running");
    if (runningJob && runningJob.job_id !== activeJobId && activeJobStatus !== "running") {
      attachToJob(runningJob.job_id);
    } else if (!activeJobId && data.jobs.length > 0) {
      attachToJob(data.jobs[0].job_id);
    }
  } catch (e) {}
}

function renderLogs(results) {
  const container = document.getElementById("logList");
  while (container.firstChild) container.removeChild(container.firstChild);
  const rev = [...results].reverse();
  for (const r of rev) {
    const row = document.createElement("div");
    row.className = "log-item";

    const left = document.createElement("div");
    left.style.overflow = "hidden";
    left.style.textOverflow = "ellipsis";
    left.style.whiteSpace = "nowrap";
    const srcLabel = r.source && r.source !== "direct_url" ? ` (${r.source})` : "";
    left.textContent = `[#${r.index}] ${r.input}${srcLabel} -> ${r.filename || r.error || ""}`;

    const rightWrap = document.createElement("div");
    rightWrap.style.display = "flex";
    rightWrap.style.alignItems = "center";

    if (r.proxy_used && r.proxy_used !== "SKIPPED" && r.proxy_used !== "UP-TO-DATE") {
      const pTag = document.createElement("span");
      pTag.className = "tag tag-proxy";
      pTag.textContent = r.proxy_used;
      rightWrap.appendChild(pTag);
    }

    const right = document.createElement("span");
    if (r.skipped) {
      right.className = "tag tag-skip";
      right.textContent = r.proxy_used === "UP-TO-DATE" ? "最新(SKIP)" : `SKIP (${r.size_kb} KB)`;
    } else if (r.updated) {
      right.className = "tag tag-upd";
      right.textContent = `UPDATED (${r.size_kb} KB)`;
    } else if (r.success) {
      right.className = "tag tag-ok";
      right.textContent = `OK (${r.size_kb} KB)`;
    } else {
      right.className = "tag tag-fail";
      right.textContent = "FAILED";
    }

    rightWrap.appendChild(right);
    row.appendChild(left);
    row.appendChild(rightWrap);
    container.appendChild(row);
  }
}

async function refreshFileList() {
  const outDir = document.getElementById("outputDir").value.trim();
  try {
    const resp = await fetch("/api/files?dir=" + encodeURIComponent(outDir));
    const data = await resp.json();
    const tbody = document.getElementById("fileTableBody");
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    if (!data.success) return;

    document.getElementById("fileCountLabel").textContent = data.files.length;
    for (const f of data.files) {
      const tr = document.createElement("tr");
      const tdName = document.createElement("td");
      const a = document.createElement("a");
      a.className = "file-link";
      a.href = `/files/${encodeURIComponent(f.name)}?dir=${encodeURIComponent(data.directory)}`;
      a.target = "_blank";
      a.textContent = "📄 " + f.name;
      tdName.appendChild(a);

      const tdSize = document.createElement("td");
      tdSize.textContent = f.size_kb + " KB";

      const tdDate = document.createElement("td");
      tdDate.textContent = f.modified;

      const tdValid = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = "tag tag-ok";
      badge.textContent = "Verified PDF";
      tdValid.appendChild(badge);

      tr.appendChild(tdName);
      tr.appendChild(tdSize);
      tr.appendChild(tdDate);
      tr.appendChild(tdValid);
      tbody.appendChild(tr);
    }
  } catch (e) {
    console.error(e);
  }
}

function exportResultsCsv() {
  if (!lastJobResults || lastJobResults.length === 0) return;
  const headers = ["No", "Input", "Filename", "Status", "SizeKB", "Source", "ProxyUsed", "URL", "Error", "Time"];
  const esc = (v) => {
    let s = String(v === null || v === undefined ? "" : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  };
  const rows = [headers.join(",")];
  for (const r of lastJobResults) {
    const st = r.skipped ? "SKIPPED" : (r.updated ? "UPDATED" : (r.success ? "OK" : "FAILED"));
    rows.push([
      esc(r.index), esc(r.input), esc(r.filename), esc(st),
      esc(r.size_kb), esc(r.source), esc(r.proxy_used), esc(r.url), esc(r.error), esc(r.timestamp)
    ].join(","));
  }
  const blob = new Blob(["\uFEFF" + rows.join("\r\n")], {type: "text/csv;charset=utf-8;"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "aegisfetch_report.csv";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function downloadAllZip() {
  const outDir = document.getElementById("outputDir").value.trim();
  window.open("/api/download-zip?dir=" + encodeURIComponent(outDir), "_blank");
}

function mergeAllPdfs() {
  const outDir = document.getElementById("outputDir").value.trim();
  window.open("/api/merge-pdf?dir=" + encodeURIComponent(outDir), "_blank");
}

async function openOutputFolder() {
  const outDir = document.getElementById("outputDir").value.trim();
  await fetch("/api/open-folder", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({output_dir: outDir})
  });
}

window.addEventListener("DOMContentLoaded", () => {
  for (const id of SETTINGS_KEYS) {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", saveUiSettings);
    if (el && (el.tagName === "TEXTAREA" || el.tagName === "INPUT")) {
      el.addEventListener("input", saveUiSettings);
    }
  }

  document.getElementById("itemsInput").addEventListener("input", updateItemCount);

  const dropZone = document.getElementById("dropZone");
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleBomFileSelect(e.dataTransfer.files[0]);
    }
  });

  const jobSelect = document.getElementById("recentJobSelect");
  if (jobSelect) {
    jobSelect.addEventListener("change", () => {
      if (jobSelect.value) attachToJob(jobSelect.value);
    });
  }

  restoreUiSettings();
  refreshFileList();
  updateProxyCountBadge();
  updateItemCount();
  syncRecentJobs();
  jobsSyncTimer = setInterval(syncRecentJobs, 2500);
});
