"""
AegisFetch Web UI Dashboard (v2.1.0)
====================================
Interactive browser-based GUI for AegisFetch with Multi-Proxy Rotation & Free Proxy Harvester.
Allows users to:
- Paste part numbers (e.g., BALLUFF order codes) or URLs
- Configure a list of proxies for automatic 1-request-per-IP rotation
- Harvest & live-test free public proxies with 1 click
- Extract PDFs from product pages & monitor real-time download progress

Security:
- Bound strictly to 127.0.0.1 by default
- Enforces all AegisFetch SSRF, Open-Redirect, and Path Traversal guardrails
"""

import os
import sys
import uuid
import time
import json
import threading
import webbrowser
import argparse
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote, parse_qs
from typing import Dict, Any, List, Optional

from aegisfetch import AegisFetch, __version__
from extractors import CatalogExtractor
from proxy_manager import fetch_and_test_free_proxies, DEFAULT_FREE_PROXIES, mask_proxy_credentials
from security import (
    validate_url,
    validate_output_directory,
    sanitize_filename,
    secure_output_path,
    SecurityValidationError,
)

DEFAULT_PORT = 8765
DEFAULT_HOST = "127.0.0.1"
DEFAULT_DOWNLOAD_DIR = os.path.abspath(os.environ.get("AEGISFETCH_DOWNLOAD_DIR", "./downloads"))

_UI_JOBS_LOCK = threading.Lock()
_UI_JOBS: Dict[str, Dict[str, Any]] = {}


def _run_ui_download_job(
    job_id: str,
    raw_items: List[str],
    target_dir: str,
    min_delay: float,
    max_delay: float,
    verify_pdf: bool,
    locale: str = "ja-jp",
    proxies: Optional[List[str]] = None,
    proxy_rotation_mode: str = "round_robin",
    fallback_to_direct: bool = True,
):
    """Background worker for Web UI batch downloads with proxy rotation & cancellation support."""
    try:
        fetcher = AegisFetch(
            output_dir=target_dir,
            min_delay=min_delay,
            max_delay=max_delay,
            proxies=proxies,
            proxy_rotation_mode=proxy_rotation_mode,
            fallback_to_direct=fallback_to_direct,
            verify_pdf=verify_pdf,
            quiet=True
        )

        for idx, raw_line in enumerate(raw_items, 1):
            with _UI_JOBS_LOCK:
                if _UI_JOBS[job_id].get("cancel_requested"):
                    _UI_JOBS[job_id]["status"] = "cancelled"
                    _UI_JOBS[job_id]["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    return
                _UI_JOBS[job_id]["current_item"] = raw_line

            item = raw_line.strip()
            try:
                if item.lower().startswith(("http://", "https://")):
                    safe_u = validate_url(item)
                    fname = sanitize_filename(safe_u.split("?")[0].split("/")[-1])
                    if verify_pdf and not fname.lower().endswith(".pdf"):
                        fname += ".pdf"
                    res = fetcher.download_file(url=safe_u, filename=fname)
                    resolved_url = safe_u
                else:
                    # Resolve Part Number (e.g. BES0002) using direct or current session
                    resolved = CatalogExtractor.resolve_balluff_part(
                        item,
                        locale=locale,
                        session=None
                    )
                    resolved_url = resolved["url"]
                    res = fetcher.download_file(
                        url=resolved["url"],
                        filename=resolved["filename"],
                        referer=resolved["referer"]
                    )

                entry = {
                    "index": idx,
                    "input": item,
                    "url": resolved_url,
                    "filename": os.path.basename(res.save_path),
                    "saved_path": res.save_path,
                    "success": res.success,
                    "skipped": res.skipped,
                    "size_kb": round(res.size_bytes / 1024, 2),
                    "proxy_used": res.proxy_used or "DIRECT",
                    "error": res.error_msg,
                    "timestamp": time.strftime("%H:%M:%S")
                }
            except Exception as e:
                entry = {
                    "index": idx,
                    "input": item,
                    "url": None,
                    "filename": None,
                    "saved_path": None,
                    "success": False,
                    "skipped": False,
                    "size_kb": 0,
                    "proxy_used": mask_proxy_credentials(fetcher.current_proxy),
                    "error": str(e),
                    "timestamp": time.strftime("%H:%M:%S")
                }

            with _UI_JOBS_LOCK:
                job = _UI_JOBS[job_id]
                job["completed_items"] = idx
                job["last_proxy"] = entry["proxy_used"]
                job["results"].append(entry)
                if entry["skipped"]:
                    job["skipped_count"] += 1
                    job["success_count"] += 1
                elif entry["success"]:
                    job["success_count"] += 1
                else:
                    job["failed_count"] += 1

    finally:
        with _UI_JOBS_LOCK:
            if job_id in _UI_JOBS and _UI_JOBS[job_id]["status"] == "running":
                _UI_JOBS[job_id]["status"] = "completed"
                _UI_JOBS[job_id]["current_item"] = None
                _UI_JOBS[job_id]["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AegisFetch Web UI - Resilient Catalog Downloader &amp; Proxy Rotator</title>
  <style>
    :root {
      --bg-dark: #0b0f19;
      --bg-card: #131b2e;
      --bg-input: #0e1424;
      --border: #233252;
      --cyan: #00f2fe;
      --blue: #4facfe;
      --purple: #a855f7;
      --green: #10b981;
      --amber: #f59e0b;
      --red: #ef4444;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
      background: radial-gradient(circle at 50% 0%, #162238 0%, var(--bg-dark) 75%);
      color: var(--text-main);
      min-height: 100vh;
      padding-bottom: 40px;
    }
    header {
      border-bottom: 1px solid var(--border);
      background: rgba(11, 15, 25, 0.85);
      backdrop-filter: blur(10px);
      position: sticky;
      top: 0;
      z-index: 100;
      padding: 14px 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .brand img {
      width: 42px;
      height: 42px;
      filter: drop-shadow(0 0 8px rgba(0, 242, 254, 0.4));
    }
    .brand-title h1 {
      font-size: 1.25rem;
      font-weight: 700;
      background: linear-gradient(90deg, var(--cyan), var(--blue));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand-title p {
      font-size: 0.78rem;
      color: var(--text-muted);
    }
    .badge-group {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    .badge {
      font-size: 0.75rem;
      padding: 4px 10px;
      border-radius: 999px;
      background: rgba(0, 242, 254, 0.1);
      border: 1px solid rgba(0, 242, 254, 0.3);
      color: var(--cyan);
    }
    .badge-purple {
      background: rgba(168, 85, 247, 0.12);
      border: 1px solid rgba(168, 85, 247, 0.4);
      color: #d8b4fe;
    }
    .container {
      max-width: 1280px;
      margin: 22px auto;
      padding: 0 20px;
      display: grid;
      grid-template-columns: 1.08fr 0.92fr;
      gap: 22px;
    }
    @media (max-width: 980px) {
      .container { grid-template-columns: 1fr; }
    }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.35);
    }
    .card-full {
      grid-column: 1 / -1;
    }
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 14px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      flex-wrap: wrap;
      gap: 8px;
    }
    .card-header h2 {
      font-size: 1.02rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    label {
      display: block;
      font-size: 0.81rem;
      color: var(--text-muted);
      margin-bottom: 5px;
      font-weight: 500;
    }
    textarea, input[type="text"], input[type="number"], select {
      width: 100%;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text-main);
      padding: 9px 12px;
      font-size: 0.85rem;
      font-family: 'Consolas', 'Monaco', monospace;
      transition: border-color 0.2s;
    }
    textarea:focus, input:focus, select:focus {
      outline: none;
      border-color: var(--cyan);
      box-shadow: 0 0 0 2px rgba(0, 242, 254, 0.15);
    }
    textarea {
      min-height: 145px;
      resize: vertical;
      line-height: 1.45;
    }
    .proxy-section {
      margin-top: 16px;
      padding: 14px;
      background: rgba(14, 20, 36, 0.65);
      border: 1px solid rgba(168, 85, 247, 0.3);
      border-radius: 10px;
    }
    .proxy-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
      flex-wrap: wrap;
      gap: 8px;
    }
    .proxy-header h3 {
      font-size: 0.9rem;
      color: #e9d5ff;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .form-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-top: 12px;
    }
    .btn-row {
      display: flex;
      gap: 10px;
      margin-top: 16px;
      flex-wrap: wrap;
    }
    button {
      cursor: pointer;
      border: none;
      border-radius: 8px;
      padding: 9px 16px;
      font-size: 0.85rem;
      font-weight: 600;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--cyan), var(--blue));
      color: #06101e;
      box-shadow: 0 4px 14px rgba(0, 242, 254, 0.25);
    }
    .btn-primary:hover:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(0, 242, 254, 0.4);
    }
    .btn-purple {
      background: linear-gradient(135deg, #9333ea, #6366f1);
      color: #ffffff;
      padding: 5px 11px;
      font-size: 0.76rem;
    }
    .btn-purple:hover:not(:disabled) {
      filter: brightness(1.15);
    }
    .btn-secondary {
      background: #1e293b;
      color: var(--text-main);
      border: 1px solid var(--border);
    }
    .btn-secondary:hover:not(:disabled) {
      background: #283548;
      border-color: var(--blue);
    }
    .btn-danger {
      background: rgba(239, 68, 68, 0.15);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.4);
    }
    .btn-danger:hover:not(:disabled) {
      background: rgba(239, 68, 68, 0.3);
    }
    button:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .progress-box {
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 14px;
    }
    .progress-bar-bg {
      width: 100%;
      height: 12px;
      background: #1e293b;
      border-radius: 999px;
      overflow: hidden;
      margin: 10px 0;
    }
    .progress-bar-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, var(--cyan), var(--green));
      transition: width 0.3s ease;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-top: 12px;
    }
    .stat-card {
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 8px;
      padding: 10px;
      text-align: center;
    }
    .stat-card .num {
      font-size: 1.3rem;
      font-weight: 700;
    }
    .stat-card .lbl {
      font-size: 0.72rem;
      color: var(--text-muted);
      margin-top: 2px;
    }
    .log-list {
      max-height: 410px;
      overflow-y: auto;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      font-family: 'Consolas', monospace;
      font-size: 0.79rem;
    }
    .log-item {
      padding: 6px 8px;
      border-bottom: 1px solid rgba(255,255,255,0.04);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
    }
    .log-item:last-child { border-bottom: none; }
    .tag {
      padding: 2px 7px;
      border-radius: 4px;
      font-size: 0.71rem;
      font-weight: 700;
      white-space: nowrap;
    }
    .tag-ok { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .tag-skip { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .tag-fail { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .tag-proxy { background: rgba(168, 85, 247, 0.2); color: #d8b4fe; margin-right: 4px; }
    .file-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    .file-table th, .file-table td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .file-table th {
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.78rem;
    }
    .file-link {
      color: var(--cyan);
      text-decoration: none;
      font-weight: 500;
    }
    .file-link:hover { text-decoration: underline; }
    .extractor-box {
      display: flex;
      gap: 8px;
      margin-top: 6px;
    }
    .checkbox-row {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 8px;
      font-size: 0.8rem;
      color: var(--text-main);
    }
    .checkbox-row input { width: auto; }
  </style>
</head>
<body>

<header>
  <div class="brand">
    <img src="/assets/icon.svg" alt="AegisFetch" />
    <div class="brand-title">
      <h1>AegisFetch Web Console v2.1</h1>
      <p>Anti-403 WAF-Evading Catalog Downloader &amp; Multi-Proxy IP Rotator</p>
    </div>
  </div>
  <div class="badge-group">
    <span class="badge">TLS Fingerprint: Chrome124 / Safari</span>
    <span class="badge badge-purple" id="headerProxyBadge">Proxy Rotation: Ready</span>
    <span class="badge">SSRF Guard: ACTIVE</span>
  </div>
</header>

<div class="container">
  <!-- Left Card: Input, Proxy Rotation & Controls -->
  <div class="card">
    <div class="card-header">
      <h2>📥 カタログ一括ダウンロード設定</h2>
      <button class="btn-secondary" style="padding:4px 10px; font-size:0.75rem;" onclick="loadSampleList()">サンプル型番を挿入</button>
    </div>

    <label for="itemsInput">型番リスト（例: BES0002）または PDFのURL を1行ずつ入力:</label>
    <textarea id="itemsInput" placeholder="BES0002(BES G06EB-NOC40F-S49G)&#10;BES0003(BES G06EB-NSC40F-S49G)&#10;https://example.com/datasheet.pdf"></textarea>

    <div style="margin-top: 12px;">
      <label for="extractUrlInput">🔍 WebページからPDFリンクを自動抽出して上のリストに追加:</label>
      <div class="extractor-box">
        <input type="text" id="extractUrlInput" placeholder="https://www.balluff.com/ja-jp/products/BES0002" />
        <button class="btn-secondary" id="btnExtract" onclick="extractLinksFromPage()" style="white-space:nowrap;">ページ解析</button>
      </div>
    </div>

    <!-- Proxy Rotation Box -->
    <div class="proxy-section">
      <div class="proxy-header">
        <h3>🌐 プロキシ自動ローテーション (1件ごとに別IPへ切替)</h3>
        <div style="display:flex; gap:6px;">
          <button class="btn-purple" id="btnHarvestProxies" onclick="harvestFreeProxies(true)">
            ⚡ 無料プロキシを自動取得＆生存テスト
          </button>
          <button class="btn-secondary" style="padding:5px 9px; font-size:0.74rem;" onclick="loadPresetProxies()">
            📋 プリセット挿入
          </button>
          <button class="btn-secondary" style="padding:5px 9px; font-size:0.74rem;" onclick="clearProxies()">
            クリア
          </button>
        </div>
      </div>

      <label for="proxiesInput">プロキシリスト (1行に1つ `http://IP:PORT` または `socks5://IP:PORT` / 空欄なら直接通信):</label>
      <textarea id="proxiesInput" style="min-height: 95px; font-size:0.8rem;" placeholder="http://176.111.37.5:39811&#10;http://91.134.141.4:3128&#10;socks5://208.102.51.6:58208" oninput="updateProxyCountBadge()"></textarea>

      <div class="form-grid" style="margin-top:8px;">
        <div>
          <label for="proxyModeSelect">IPローテーション順序:</label>
          <select id="proxyModeSelect">
            <option value="round_robin" selected>順番に切り替え (Round-Robin: 1件ごとに次へ)</option>
            <option value="random">ランダムに切り替え (Random)</option>
          </select>
        </div>
        <div style="display:flex; align-items:flex-end;">
          <label class="checkbox-row" style="margin-bottom:6px; cursor:pointer;">
            <input type="checkbox" id="fallbackDirectCheck" checked />
            <span>プロキシ不通時は直接通信(Direct)で救済する</span>
          </label>
        </div>
      </div>
    </div>

    <div class="form-grid">
      <div>
        <label for="outputDir">保存先フォルダ (Output Dir):</label>
        <input type="text" id="outputDir" value="__DEFAULT_DIR__" />
      </div>
      <div>
        <label for="localeSelect">BALLUFF 言語・地域設定:</label>
        <select id="localeSelect">
          <option value="ja-jp" selected>日本語 (ja-jp)</option>
          <option value="en-us">English (en-us)</option>
          <option value="de-de">Deutsch (de-de)</option>
        </select>
      </div>
      <div>
        <label for="minDelay">最小待機 ジッター (秒):</label>
        <input type="number" id="minDelay" value="0.8" step="0.2" min="0.2" />
      </div>
      <div>
        <label for="maxDelay">最大待機 ジッター (秒):</label>
        <input type="number" id="maxDelay" value="1.8" step="0.2" min="0.5" />
      </div>
    </div>

    <div class="btn-row">
      <button class="btn-primary" id="btnStart" onclick="startDownloadJob()">
        🚀 ダウンロード開始
      </button>
      <button class="btn-danger" id="btnCancel" onclick="cancelCurrentJob()" disabled>
        ⏹ 停止
      </button>
      <button class="btn-secondary" onclick="openOutputFolder()">
        📂 保存先フォルダを開く
      </button>
    </div>
  </div>

  <!-- Right Card: Live Progress & Logs -->
  <div class="card">
    <div class="card-header">
      <h2>📊 リアルタイム実行ステータス</h2>
      <span id="jobStatusBadge" class="badge">待機中 (IDLE)</span>
    </div>

    <div class="progress-box">
      <div style="display:flex; justify-content:space-between; font-size:0.84rem; gap:10px;">
        <span id="currentItemText" style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">ジョブ開始待機中...</span>
        <span id="progressPercent" style="white-space:nowrap;">0% (0/0)</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" id="progressBar"></div>
      </div>
      <div style="font-size:0.76rem; color:#d8b4fe; margin-top:4px;" id="activeProxyText">
        現在の通信経路: DIRECT (標準回線)
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="num" id="statTotal" style="color:var(--text-main);">0</div>
          <div class="lbl">総件数</div>
        </div>
        <div class="stat-card">
          <div class="num" id="statSuccess" style="color:var(--green);">0</div>
          <div class="lbl">成功 (OK)</div>
        </div>
        <div class="stat-card">
          <div class="num" id="statSkipped" style="color:var(--amber);">0</div>
          <div class="lbl">スキップ (既存)</div>
        </div>
        <div class="stat-card">
          <div class="num" id="statFailed" style="color:var(--red);">0</div>
          <div class="lbl">失敗</div>
        </div>
      </div>
    </div>

    <label>実行ログ (1件ごとの使用プロキシIP ＆ 結果):</label>
    <div class="log-list" id="logList">
      <div style="color:var(--text-muted); text-align:center; padding: 30px 0;">
        左側のフォームに型番またはURLを入力して「ダウンロード開始」を押してください。
      </div>
    </div>
  </div>

  <!-- Bottom Full Card: Downloaded Files -->
  <div class="card card-full">
    <div class="card-header">
      <h2>📁 ダウンロード済みカタログ一覧 (<span id="fileCountLabel">0</span> ファイル)</h2>
      <button class="btn-secondary" style="padding:6px 12px; font-size:0.8rem;" onclick="refreshFileList()">🔄 一覧を更新</button>
    </div>
    <div style="max-height: 340px; overflow-y: auto;">
      <table class="file-table">
        <thead>
          <tr>
            <th>ファイル名 (クリックでブラウザ表示)</th>
            <th>サイズ</th>
            <th>更新日時</th>
            <th>検証ステータス</th>
          </tr>
        </thead>
        <tbody id="fileTableBody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
  let activeJobId = null;
  let pollTimer = null;

  function loadSampleList() {
    document.getElementById('itemsInput').value = [
      "BES0002(BES G06EB-NOC40F-S49G)",
      "BES0003(BES G06EB-NSC40F-S49G)",
      "BES0004(BES G06EB-POC40F-S49G)",
      "BES0005(BES G06EB-PSC40F-S49G)"
    ].join("\\n");
  }

  function getConfiguredProxies() {
    const raw = document.getElementById('proxiesInput').value;
    return raw.split(/\\r?\\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
  }

  function updateProxyCountBadge() {
    const list = getConfiguredProxies();
    const badge = document.getElementById('headerProxyBadge');
    if (list.length > 0) {
      badge.textContent = `Proxy Rotation: ACTIVE (${list.length} IPs)`;
    } else {
      badge.textContent = 'Proxy Rotation: DIRECT';
    }
  }

  async function harvestFreeProxies(verifyLive) {
    const btn = document.getElementById('btnHarvestProxies');
    btn.disabled = true;
    btn.textContent = "⏳ 公開プロキシ収集＆生存テスト中(約4秒)...";
    try {
      const resp = await fetch('/api/free-proxies', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({verify_live: verifyLive, count: 12})
      });
      const data = await resp.json();
      if (!data.success) {
        alert("無料プロキシ取得エラー: " + (data.message || ""));
        return;
      }
      const ta = document.getElementById('proxiesInput');
      ta.value = (data.working_proxies || []).join("\\n");
      updateProxyCountBadge();
      alert(`公開リスト(${data.fetched_total}件)から高速に応答する無料プロキシ ${data.working_proxies.length} 件を抽出し、セットしました！`);
    } catch (e) {
      alert("通信エラー: " + e);
    } finally {
      btn.disabled = false;
      btn.textContent = "⚡ 無料プロキシを自動取得＆生存テスト";
    }
  }

  async function loadPresetProxies() {
    const resp = await fetch('/api/free-proxies', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({preset_only: true})
    });
    const data = await resp.json();
    if (data.working_proxies) {
      document.getElementById('proxiesInput').value = data.working_proxies.join("\\n");
      updateProxyCountBadge();
    }
  }

  function clearProxies() {
    document.getElementById('proxiesInput').value = "";
    updateProxyCountBadge();
  }

  async function extractLinksFromPage() {
    const urlInput = document.getElementById('extractUrlInput');
    const url = urlInput.value.trim();
    if (!url) {
      alert("抽出元のWebページURLを入力してください。");
      return;
    }
    const btn = document.getElementById('btnExtract');
    btn.disabled = true;
    btn.textContent = "解析中...";
    try {
      const resp = await fetch('/api/extract', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url})
      });
      const data = await resp.json();
      if (!data.success) {
        alert("抽出エラー: " + (data.message || "不明なエラー"));
        return;
      }
      if (data.pdf_links.length === 0) {
        alert("このページからはPDFリンクが見つかりませんでした。");
        return;
      }
      const ta = document.getElementById('itemsInput');
      const existing = ta.value.trim();
      const newUrls = data.pdf_links.map(x => x.url).join("\\n");
      ta.value = existing ? (existing + "\\n" + newUrls) : newUrls;
      urlInput.value = "";
      alert(data.pdf_links.length + " 件のPDFリンクを抽出し、リストに追加しました！");
    } catch (e) {
      alert("通信エラー: " + e);
    } finally {
      btn.disabled = false;
      btn.textContent = "ページ解析";
    }
  }

  async function startDownloadJob() {
    const rawText = document.getElementById('itemsInput').value;
    const items = rawText.split(/\\r?\\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
    if (items.length === 0) {
      alert("型番またはURLを1件以上入力してください。");
      return;
    }
    const proxies = getConfiguredProxies();
    const proxy_rotation_mode = document.getElementById('proxyModeSelect').value;
    const fallback_to_direct = document.getElementById('fallbackDirectCheck').checked;
    const output_dir = document.getElementById('outputDir').value.trim();
    const locale = document.getElementById('localeSelect').value;
    const min_delay = parseFloat(document.getElementById('minDelay').value) || 0.8;
    const max_delay = parseFloat(document.getElementById('maxDelay').value) || 1.8;

    document.getElementById('btnStart').disabled = true;
    document.getElementById('btnCancel').disabled = false;

    try {
      const resp = await fetch('/api/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          items,
          proxies,
          proxy_rotation_mode,
          fallback_to_direct,
          output_dir,
          locale,
          min_delay,
          max_delay
        })
      });
      const data = await resp.json();
      if (!data.success) {
        alert("開始エラー: " + data.message);
        document.getElementById('btnStart').disabled = false;
        document.getElementById('btnCancel').disabled = true;
        return;
      }
      activeJobId = data.job_id;
      if (pollTimer) clearInterval(pollTimer);
      pollJobStatus();
      pollTimer = setInterval(pollJobStatus, 800);
    } catch (e) {
      alert("リクエスト失敗: " + e);
      document.getElementById('btnStart').disabled = false;
      document.getElementById('btnCancel').disabled = true;
    }
  }

  async function cancelCurrentJob() {
    if (!activeJobId) return;
    await fetch('/api/cancel', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({job_id: activeJobId})
    });
  }

  async function pollJobStatus() {
    if (!activeJobId) return;
    try {
      const resp = await fetch('/api/job?job_id=' + encodeURIComponent(activeJobId));
      const job = await resp.json();
      if (!job.success) return;

      document.getElementById('jobStatusBadge').textContent = job.status.toUpperCase();
      document.getElementById('statTotal').textContent = job.total_items;
      document.getElementById('statSuccess').textContent = job.success_count;
      document.getElementById('statSkipped').textContent = job.skipped_count;
      document.getElementById('statFailed').textContent = job.failed_count;

      const pct = job.percent || 0;
      document.getElementById('progressBar').style.width = pct + '%';
      document.getElementById('progressPercent').textContent = `${pct}% (${job.completed_items}/${job.total_items})`;

      if (job.last_proxy) {
        document.getElementById('activeProxyText').textContent = `直近の通信経路 (IP): ${job.last_proxy}`;
      }

      if (job.status === 'running') {
        document.getElementById('currentItemText').textContent = "処理中: " + (job.current_item || "...");
      } else {
        document.getElementById('currentItemText').textContent = `完了 (${job.status})`;
        document.getElementById('btnStart').disabled = false;
        document.getElementById('btnCancel').disabled = true;
        clearInterval(pollTimer);
        refreshFileList();
      }

      renderLogs(job.results || []);
    } catch (e) {
      console.error(e);
    }
  }

  function renderLogs(results) {
    const container = document.getElementById('logList');
    container.innerHTML = '';
    const rev = [...results].reverse();
    for (const r of rev) {
      const row = document.createElement('div');
      row.className = 'log-item';

      const left = document.createElement('div');
      left.style.overflow = 'hidden';
      left.style.textOverflow = 'ellipsis';
      left.style.whiteSpace = 'nowrap';
      left.textContent = `[#${r.index}] ${r.input} -> ${r.filename || r.error || ''}`;

      const rightWrap = document.createElement('div');
      rightWrap.style.display = 'flex';
      rightWrap.style.alignItems = 'center';

      if (r.proxy_used && r.proxy_used !== 'SKIPPED') {
        const pTag = document.createElement('span');
        pTag.className = 'tag tag-proxy';
        pTag.textContent = r.proxy_used;
        rightWrap.appendChild(pTag);
      }

      const right = document.createElement('span');
      if (r.skipped) {
        right.className = 'tag tag-skip';
        right.textContent = `SKIP (${r.size_kb} KB)`;
      } else if (r.success) {
        right.className = 'tag tag-ok';
        right.textContent = `OK (${r.size_kb} KB)`;
      } else {
        right.className = 'tag tag-fail';
        right.textContent = 'FAILED';
      }

      rightWrap.appendChild(right);
      row.appendChild(left);
      row.appendChild(rightWrap);
      container.appendChild(row);
    }
  }

  async function refreshFileList() {
    const outDir = document.getElementById('outputDir').value.trim();
    try {
      const resp = await fetch('/api/files?dir=' + encodeURIComponent(outDir));
      const data = await resp.json();
      const tbody = document.getElementById('fileTableBody');
      tbody.innerHTML = '';
      if (!data.success) return;

      document.getElementById('fileCountLabel').textContent = data.files.length;
      for (const f of data.files) {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        const a = document.createElement('a');
        a.className = 'file-link';
        a.href = `/files/${encodeURIComponent(f.name)}?dir=${encodeURIComponent(data.directory)}`;
        a.target = '_blank';
        a.textContent = '📄 ' + f.name;
        tdName.appendChild(a);

        const tdSize = document.createElement('td');
        tdSize.textContent = f.size_kb + ' KB';

        const tdDate = document.createElement('td');
        tdDate.textContent = f.modified;

        const tdValid = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = 'tag tag-ok';
        badge.textContent = 'Verified PDF';
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

  async function openOutputFolder() {
    const outDir = document.getElementById('outputDir').value.trim();
    await fetch('/api/open-folder', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({output_dir: outDir})
    });
  }

  window.addEventListener('DOMContentLoaded', () => {
    refreshFileList();
    updateProxyCountBadge();
  });
</script>
</body>
</html>
"""


class AegisWebRequestHandler(BaseHTTPRequestHandler):
    """HTTP Handler for AegisFetch Web UI Console with CSRF & DNS Rebinding Protection."""

    def log_message(self, format: str, *args: Any):
        pass

    def _is_safe_local_request(self, is_post: bool = False) -> bool:
        """
        Verify Host and Origin headers to defend against DNS Rebinding and Cross-Site Request Forgery (CSRF).
        """
        host = (self.headers.get("Host") or "").lower().strip()
        host_only = host.split(":")[0]
        if host_only not in ("127.0.0.1", "localhost", "[::1]", ""):
            return False

        if is_post:
            origin = (self.headers.get("Origin") or "").lower().strip()
            if origin:
                parsed_orig = urlparse(origin)
                if parsed_orig.hostname not in ("127.0.0.1", "localhost", "::1"):
                    return False
        return True

    def _send_json(self, data: Dict[str, Any], status: int = 200):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 5 * 1024 * 1024:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def do_GET(self):
        if not self._is_safe_local_request(is_post=False):
            self._send_json({"success": False, "message": "Forbidden Host header (DNS Rebinding Protection)."}, 403)
            return

        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        query = {k: v[0] for k, v in qs.items() if v}

        if path == "/" or path == "/index.html":
            page = HTML_DASHBOARD.replace("__DEFAULT_DIR__", DEFAULT_DOWNLOAD_DIR.replace("\\", "/"))
            raw = page.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/assets/icon.svg":
            svg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.svg")
            if os.path.exists(svg_path):
                with open(svg_path, "rb") as f:
                    data = f.read()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        if path == "/api/job":
            job_id = unquote(query.get("job_id", ""))
            with _UI_JOBS_LOCK:
                job = _UI_JOBS.get(job_id)
                if not job:
                    self._send_json({"success": False, "message": "Job not found"}, 404)
                    return
                pct = round((job["completed_items"] / max(1, job["total_items"])) * 100, 1)
                self._send_json({
                    "success": True,
                    "job_id": job["job_id"],
                    "status": job["status"],
                    "total_items": job["total_items"],
                    "completed_items": job["completed_items"],
                    "success_count": job["success_count"],
                    "skipped_count": job["skipped_count"],
                    "failed_count": job["failed_count"],
                    "current_item": job.get("current_item"),
                    "last_proxy": job.get("last_proxy"),
                    "percent": pct,
                    "results": job["results"][-100:]
                })
            return

        if path == "/api/files":
            req_dir = unquote(query.get("dir", "")) or DEFAULT_DOWNLOAD_DIR
            try:
                safe_dir = validate_output_directory(req_dir)
                if not os.path.exists(safe_dir):
                    self._send_json({"success": True, "directory": safe_dir, "files": []})
                    return

                files_info = []
                for fname in sorted(os.listdir(safe_dir)):
                    if fname.lower().endswith(".pdf"):
                        fpath = os.path.join(safe_dir, fname)
                        if os.path.isfile(fpath):
                            st = os.stat(fpath)
                            files_info.append({
                                "name": fname,
                                "size_kb": round(st.st_size / 1024, 1),
                                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
                            })
                self._send_json({"success": True, "directory": safe_dir, "files": files_info})
            except SecurityValidationError as sve:
                self._send_json({"success": False, "message": str(sve)}, 403)
            return

        if path.startswith("/files/"):
            raw_fname = unquote(path[len("/files/"):])
            req_dir = unquote(query.get("dir", "")) or DEFAULT_DOWNLOAD_DIR
            try:
                safe_dir = validate_output_directory(req_dir)
                safe_file = secure_output_path(safe_dir, raw_fname)
                if not os.path.exists(safe_file) or not os.path.isfile(safe_file):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                with open(safe_file, "rb") as f:
                    content = f.read()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except SecurityValidationError:
                self.send_error(HTTPStatus.FORBIDDEN)
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        if not self._is_safe_local_request(is_post=True):
            self._send_json({"success": False, "message": "Forbidden Origin/Host header (CSRF & DNS Rebinding Protection)."}, 403)
            return

        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
        except Exception as e:
            self._send_json({"success": False, "message": f"Invalid JSON: {e}"}, 400)
            return

        if path == "/api/free-proxies":
            if body.get("preset_only"):
                self._send_json({
                    "success": True,
                    "fetched_total": len(DEFAULT_FREE_PROXIES),
                    "working_count": len(DEFAULT_FREE_PROXIES),
                    "working_proxies": list(DEFAULT_FREE_PROXIES)
                })
                return

            verify_live = bool(body.get("verify_live", True))
            target_count = int(body.get("count", 12))
            res = fetch_and_test_free_proxies(
                target_working_count=target_count,
                verify_live=verify_live
            )
            self._send_json(res)
            return

        if path == "/api/start":
            items = body.get("items", [])
            if not items or not isinstance(items, list):
                self._send_json({"success": False, "message": "items list is empty."}, 400)
                return
            if len(items) > 1000:
                self._send_json({"success": False, "message": "Max 1000 items per batch."}, 400)
                return

            proxies = body.get("proxies", [])
            proxy_rotation_mode = body.get("proxy_rotation_mode", "round_robin")
            fallback_to_direct = bool(body.get("fallback_to_direct", True))
            req_dir = body.get("output_dir") or DEFAULT_DOWNLOAD_DIR
            locale = body.get("locale", "ja-jp")
            min_delay = max(0.2, float(body.get("min_delay", 0.8)))
            max_delay = max(min_delay + 0.2, float(body.get("max_delay", 1.8)))

            try:
                target_dir = validate_output_directory(req_dir)
                os.makedirs(target_dir, exist_ok=True)
            except SecurityValidationError as sve:
                self._send_json({"success": False, "message": str(sve)}, 403)
                return

            job_id = f"ui_{uuid.uuid4().hex[:8]}"
            with _UI_JOBS_LOCK:
                _UI_JOBS[job_id] = {
                    "job_id": job_id,
                    "status": "running",
                    "total_items": len(items),
                    "completed_items": 0,
                    "success_count": 0,
                    "skipped_count": 0,
                    "failed_count": 0,
                    "current_item": None,
                    "last_proxy": None,
                    "cancel_requested": False,
                    "output_dir": target_dir,
                    "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "finished_at": None,
                    "results": []
                }

            t = threading.Thread(
                target=_run_ui_download_job,
                args=(
                    job_id,
                    items,
                    target_dir,
                    min_delay,
                    max_delay,
                    True,
                    locale,
                    proxies,
                    proxy_rotation_mode,
                    fallback_to_direct,
                ),
                daemon=True
            )
            t.start()
            self._send_json({"success": True, "job_id": job_id, "output_dir": target_dir})
            return

        if path == "/api/cancel":
            job_id = body.get("job_id", "")
            with _UI_JOBS_LOCK:
                if job_id in _UI_JOBS:
                    _UI_JOBS[job_id]["cancel_requested"] = True
                    self._send_json({"success": True})
                    return
            self._send_json({"success": False, "message": "Job not found"}, 404)
            return

        if path == "/api/extract":
            url = body.get("url", "")
            try:
                links = CatalogExtractor.extract_pdf_links_from_url(url)
                self._send_json({"success": True, "pdf_links": links})
            except Exception as e:
                self._send_json({"success": False, "message": str(e)}, 400)
            return

        if path == "/api/open-folder":
            req_dir = body.get("output_dir") or DEFAULT_DOWNLOAD_DIR
            try:
                safe_dir = validate_output_directory(req_dir)
                os.makedirs(safe_dir, exist_ok=True)
                if sys.platform == "win32":
                    os.startfile(safe_dir)
                self._send_json({"success": True, "directory": safe_dir})
            except Exception as e:
                self._send_json({"success": False, "message": str(e)}, 400)
            return

        self.send_error(HTTPStatus.NOT_FOUND)


def main():
    parser = argparse.ArgumentParser(description="AegisFetch Web UI Dashboard Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Bind address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port number (default: {DEFAULT_PORT})")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically on startup")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), AegisWebRequestHandler)
    url = f"http://{args.host}:{args.port}"

    sys.stderr.write(f"\n=============================================================\n")
    sys.stderr.write(f"  AegisFetch Web UI Console v{__version__} is running!\n")
    sys.stderr.write(f"  URL: {url}\n")
    sys.stderr.write(f"  Press Ctrl+C to stop.\n")
    sys.stderr.write(f"=============================================================\n\n")

    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nShutting down AegisFetch Web UI...\n")
        server.server_close()


if __name__ == "__main__":
    main()
