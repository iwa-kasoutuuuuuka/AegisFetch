"""
AegisFetch Web UI Dashboard (v2.2.0)
====================================
Interactive browser-based GUI for AegisFetch featuring:
- Drag & Drop Excel (.xlsx) / CSV / TXT BOM import (/api/parse-file)
- One-Click Retry Failed Items
- Multi-Locale Auto-Fallback (ja-jp -> en-us -> de-de)
- Cross-Manufacturer Generic Datasheet Search (DuckDuckGo PDF Finder)
- Multi-Threaded Parallel Downloads (1 to 8 workers) with Multi-Proxy IP Rotation
- Catalog Revision / Update Check Mode (ETag / Last-Modified tracking)
- Built-in Free Public Proxy Harvester & Live Tester

Security:
- Bound strictly to 127.0.0.1 by default
- Host/Origin checks (CSRF & DNS Rebinding protection)
- SSRF, Open-Redirect, and Path Traversal guardrails
"""

import os
import io
import csv
import sys
import uuid
import time
import json
import base64
import zipfile
import threading
import webbrowser
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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
MAX_RETAINED_UI_JOBS = 50
MAX_EXPORT_ARCHIVE_BYTES = 250 * 1024 * 1024  # 250MB cap for ZIP/Merged PDF export


def _prune_old_ui_jobs():
    """Evict oldest completed UI jobs when registry exceeds MAX_RETAINED_UI_JOBS."""
    if len(_UI_JOBS) <= MAX_RETAINED_UI_JOBS:
        return
    completed_ids = [
        jid for jid, info in _UI_JOBS.items()
        if info.get("status") != "running"
    ]
    excess = len(_UI_JOBS) - MAX_RETAINED_UI_JOBS
    for jid in completed_ids[:excess]:
        del _UI_JOBS[jid]


MAX_BOM_SCAN_ROWS = 5000
MAX_BOM_EXTRACTED_ITEMS = 1000
MAX_XLSX_UNCOMPRESSED_BYTES = 20 * 1024 * 1024  # 20MB uncompressed limit (ZIP bomb defense)


def _parse_uploaded_bom_file(filename: str, raw_bytes: bytes) -> List[str]:
    """
    Parse .txt, .csv, or .xlsx BOM files and extract part numbers / URLs.
    Includes ZIP decompression bomb defense and row/item caps.
    """
    ext = os.path.splitext(filename.lower())[1]
    extracted: List[str] = []
    seen = set()

    def _add_token(val: str) -> bool:
        if len(extracted) >= MAX_BOM_EXTRACTED_ITEMS:
            return False
        s = (val or "").strip()
        if not s or s.startswith("#"):
            return True
        if s.lower() in ("part", "part_number", "model", "type", "url", "型式", "型番", "品番", "order_code", "name"):
            return True
        if s not in seen:
            seen.add(s)
            extracted.append(s)
        return True

    if ext == ".xlsx":
        # ZIP Bomb Protection: inspect uncompressed size before handing to openpyxl
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                total_uncompressed = sum(info.file_size for info in zf.infolist())
                if total_uncompressed > MAX_XLSX_UNCOMPRESSED_BYTES:
                    raise SecurityValidationError(
                        f"XLSX uncompressed size ({total_uncompressed} bytes) exceeds 20MB limit (ZIP Bomb Protection)."
                    )
        except zipfile.BadZipFile:
            raise ValueError("Invalid or corrupted .xlsx file.")

        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(raw_bytes), read_only=True, data_only=True)
        try:
            ws = wb.active
            for row_idx, row in enumerate(ws.iter_rows(values_only=True), 1):
                if row_idx > MAX_BOM_SCAN_ROWS or len(extracted) >= MAX_BOM_EXTRACTED_ITEMS:
                    break
                for cell in row:
                    if cell is not None:
                        text = str(cell).strip()
                        if text.lower().startswith(("http://", "https://")) or (
                            len(text) >= 4 and any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text)
                        ):
                            _add_token(text)
                            break
        finally:
            wb.close()
    elif ext == ".csv":
        text = raw_bytes.decode("utf-8-sig", errors="replace")
        reader = csv.reader(io.StringIO(text))
        for row_idx, row in enumerate(reader, 1):
            if row_idx > MAX_BOM_SCAN_ROWS or len(extracted) >= MAX_BOM_EXTRACTED_ITEMS:
                break
            for cell in row:
                c = cell.strip()
                if c.lower().startswith(("http://", "https://")) or (
                    len(c) >= 4 and any(ch.isdigit() for ch in c) and any(ch.isalpha() for ch in c)
                ):
                    _add_token(c)
                    break
    else:
        text = raw_bytes.decode("utf-8-sig", errors="replace")
        for row_idx, line in enumerate(text.splitlines(), 1):
            if row_idx > MAX_BOM_SCAN_ROWS or len(extracted) >= MAX_BOM_EXTRACTED_ITEMS:
                break
            _add_token(line)

    return extracted


def _run_ui_download_job(
    job_id: str,
    raw_items: List[str],
    target_dir: str,
    min_delay: float,
    max_delay: float,
    verify_pdf: bool,
    locale: str = "ja-jp",
    auto_fallback_locales: bool = True,
    enable_generic_search: bool = True,
    check_updates: bool = False,
    concurrency: int = 1,
    proxies: Optional[List[str]] = None,
    proxy_rotation_mode: str = "round_robin",
    fallback_to_direct: bool = True,
):
    """Background worker for Web UI batch downloads with parallelism, proxy rotation & cancellation."""
    try:
        fetcher = AegisFetch(
            output_dir=target_dir,
            min_delay=min_delay,
            max_delay=max_delay,
            proxies=proxies,
            proxy_rotation_mode=proxy_rotation_mode,
            fallback_to_direct=fallback_to_direct,
            verify_pdf=verify_pdf,
            check_updates=check_updates,
            quiet=True
        )

        workers = max(1, min(8, concurrency))

        def _process_one(idx: int, raw_line: str) -> Dict[str, Any]:
            with _UI_JOBS_LOCK:
                if _UI_JOBS[job_id].get("cancel_requested"):
                    return {"cancelled": True}
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
                    source_tag = "direct_url"
                else:
                    fetcher._ensure_thread_session(rotate_proxy=(fetcher.proxy_rotator.total_count > 0))
                    try:
                        resolved = CatalogExtractor.resolve_any_part(
                            item,
                            locale=locale,
                            auto_fallback_locales=auto_fallback_locales,
                            enable_generic_search=enable_generic_search,
                            session=fetcher.session
                        )
                    except Exception:
                        if fetcher.current_proxy and fetcher.fallback_to_direct:
                            fetcher.proxy_rotator.report_failure(fetcher.current_proxy)
                            resolved = CatalogExtractor.resolve_any_part(
                                item,
                                locale=locale,
                                auto_fallback_locales=auto_fallback_locales,
                                enable_generic_search=enable_generic_search,
                                session=None
                            )
                        else:
                            raise
                    resolved_url = resolved["url"]
                    source_tag = resolved.get("resolved_locale") or resolved.get("source", "resolved")
                    res = fetcher.download_file(
                        url=resolved["url"],
                        filename=resolved["filename"],
                        referer=resolved.get("referer")
                    )

                return {
                    "index": idx,
                    "input": item,
                    "url": resolved_url,
                    "filename": os.path.basename(res.save_path),
                    "saved_path": res.save_path,
                    "success": res.success,
                    "skipped": res.skipped,
                    "updated": res.updated,
                    "source": source_tag,
                    "size_kb": round(res.size_bytes / 1024, 2),
                    "proxy_used": res.proxy_used or "DIRECT",
                    "error": res.error_msg,
                    "timestamp": time.strftime("%H:%M:%S")
                }
            except Exception as e:
                return {
                    "index": idx,
                    "input": item,
                    "url": None,
                    "filename": None,
                    "saved_path": None,
                    "success": False,
                    "skipped": False,
                    "updated": False,
                    "source": "error",
                    "size_kb": 0,
                    "proxy_used": mask_proxy_credentials(fetcher.current_proxy),
                    "error": str(e),
                    "timestamp": time.strftime("%H:%M:%S")
                }

        def _record_entry(entry: Dict[str, Any]):
            if entry.get("cancelled"):
                return
            with _UI_JOBS_LOCK:
                job = _UI_JOBS[job_id]
                job["completed_items"] += 1
                job["last_proxy"] = entry.get("proxy_used")
                job["results"].append(entry)
                if entry["skipped"]:
                    job["skipped_count"] += 1
                    job["success_count"] += 1
                elif entry["success"]:
                    if entry.get("updated"):
                        job["updated_count"] += 1
                    job["success_count"] += 1
                else:
                    job["failed_count"] += 1

        if workers == 1:
            for idx, raw_line in enumerate(raw_items, 1):
                with _UI_JOBS_LOCK:
                    if _UI_JOBS[job_id].get("cancel_requested"):
                        _UI_JOBS[job_id]["status"] = "cancelled"
                        _UI_JOBS[job_id]["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                        return
                entry = _process_one(idx, raw_line)
                _record_entry(entry)
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [
                    executor.submit(_process_one, idx, raw_line)
                    for idx, raw_line in enumerate(raw_items, 1)
                ]
                for fut in as_completed(futures):
                    with _UI_JOBS_LOCK:
                        if _UI_JOBS[job_id].get("cancel_requested"):
                            _UI_JOBS[job_id]["status"] = "cancelled"
                            _UI_JOBS[job_id]["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                            return
                    entry = fut.result()
                    _record_entry(entry)

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
  <title>AegisFetch Web UI v2.2 - Resilient Catalog Downloader</title>
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
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand img { width: 42px; height: 42px; filter: drop-shadow(0 0 8px rgba(0, 242, 254, 0.4)); }
    .brand-title h1 {
      font-size: 1.25rem; font-weight: 700;
      background: linear-gradient(90deg, var(--cyan), var(--blue));
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .brand-title p { font-size: 0.78rem; color: var(--text-muted); }
    .badge-group { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .badge {
      font-size: 0.74rem; padding: 4px 10px; border-radius: 999px;
      background: rgba(0, 242, 254, 0.1); border: 1px solid rgba(0, 242, 254, 0.3); color: var(--cyan);
    }
    .badge-purple {
      background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.4); color: #d8b4fe;
    }
    .container {
      max-width: 1280px; margin: 22px auto; padding: 0 20px;
      display: grid; grid-template-columns: 1.12fr 0.88fr; gap: 22px;
    }
    @media (max-width: 980px) { .container { grid-template-columns: 1fr; } }
    .card {
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: 14px; padding: 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.35);
    }
    .card-full { grid-column: 1 / -1; }
    .card-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 14px; padding-bottom: 10px;
      border-bottom: 1px solid rgba(255,255,255,0.06); flex-wrap: wrap; gap: 8px;
    }
    .card-header h2 { font-size: 1.02rem; font-weight: 600; display: flex; align-items: center; gap: 8px; }
    label { display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 5px; font-weight: 500; }
    textarea, input[type="text"], input[type="number"], select {
      width: 100%; background: var(--bg-input); border: 1px solid var(--border);
      border-radius: 8px; color: var(--text-main); padding: 9px 12px;
      font-size: 0.84rem; font-family: 'Consolas', 'Monaco', monospace; transition: border-color 0.2s;
    }
    textarea:focus, input:focus, select:focus {
      outline: none; border-color: var(--cyan); box-shadow: 0 0 0 2px rgba(0, 242, 254, 0.15);
    }
    textarea { min-height: 135px; resize: vertical; line-height: 1.45; }
    .drop-zone {
      border: 1.5px dashed rgba(0, 242, 254, 0.35);
      border-radius: 10px;
      padding: 8px;
      transition: all 0.2s;
      background: rgba(0, 242, 254, 0.02);
    }
    .drop-zone.drag-over {
      border-color: var(--cyan);
      background: rgba(0, 242, 254, 0.1);
      box-shadow: 0 0 15px rgba(0, 242, 254, 0.2);
    }
    .drop-hint {
      font-size: 0.74rem; color: var(--text-muted); margin-top: 5px;
      display: flex; justify-content: space-between; align-items: center;
    }
    .proxy-section {
      margin-top: 14px; padding: 12px; background: rgba(14, 20, 36, 0.65);
      border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 10px;
    }
    .proxy-header {
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 8px; flex-wrap: wrap; gap: 6px;
    }
    .proxy-header h3 { font-size: 0.88rem; color: #e9d5ff; }
    .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; }
    .options-box {
      margin-top: 12px; padding: 10px 12px; background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.06); border-radius: 8px;
      display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
    }
    .checkbox-row {
      display: flex; align-items: center; gap: 7px; font-size: 0.79rem;
      color: var(--text-main); cursor: pointer;
    }
    .checkbox-row input { width: auto; }
    .btn-row { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
    button {
      cursor: pointer; border: none; border-radius: 8px; padding: 9px 15px;
      font-size: 0.84rem; font-weight: 600; transition: all 0.2s;
      display: inline-flex; align-items: center; gap: 6px;
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--cyan), var(--blue));
      color: #06101e; box-shadow: 0 4px 14px rgba(0, 242, 254, 0.25);
    }
    .btn-primary:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(0, 242, 254, 0.4); }
    .btn-amber {
      background: rgba(245, 158, 11, 0.18); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.45);
    }
    .btn-amber:hover:not(:disabled) { background: rgba(245, 158, 11, 0.3); }
    .btn-purple {
      background: linear-gradient(135deg, #9333ea, #6366f1); color: #fff; padding: 5px 10px; font-size: 0.75rem;
    }
    .btn-secondary {
      background: #1e293b; color: var(--text-main); border: 1px solid var(--border);
    }
    .btn-secondary:hover:not(:disabled) { background: #283548; border-color: var(--blue); }
    .btn-danger {
      background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4);
    }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    .progress-box {
      background: var(--bg-input); border: 1px solid var(--border); border-radius: 10px; padding: 14px; margin-bottom: 14px;
    }
    .progress-bar-bg { width: 100%; height: 12px; background: #1e293b; border-radius: 999px; overflow: hidden; margin: 10px 0; }
    .progress-bar-fill {
      height: 100%; width: 0%; background: linear-gradient(90deg, var(--cyan), var(--green)); transition: width 0.3s ease;
    }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-top: 10px; }
    .stat-card {
      background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);
      border-radius: 8px; padding: 9px; text-align: center;
    }
    .stat-card .num { font-size: 1.25rem; font-weight: 700; }
    .stat-card .lbl { font-size: 0.7rem; color: var(--text-muted); margin-top: 2px; }
    .log-list {
      max-height: 460px; overflow-y: auto; background: var(--bg-input);
      border: 1px solid var(--border); border-radius: 8px; padding: 10px;
      font-family: 'Consolas', monospace; font-size: 0.78rem;
    }
    .log-item {
      padding: 6px 8px; border-bottom: 1px solid rgba(255,255,255,0.04);
      display: flex; justify-content: space-between; align-items: center; gap: 8px;
    }
    .log-item:last-child { border-bottom: none; }
    .tag { padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; white-space: nowrap; }
    .tag-ok { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .tag-upd { background: rgba(0, 242, 254, 0.2); color: #00f2fe; }
    .tag-skip { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .tag-fail { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .tag-proxy { background: rgba(168, 85, 247, 0.2); color: #d8b4fe; margin-right: 4px; }
    .file-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    .file-table th, .file-table td { padding: 10px 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); }
    .file-table th { color: var(--text-muted); font-weight: 600; font-size: 0.78rem; }
    .file-link { color: var(--cyan); text-decoration: none; font-weight: 500; }
    .file-link:hover { text-decoration: underline; }
    .extractor-box { display: flex; gap: 8px; margin-top: 6px; }
  </style>
</head>
<body>

<header>
  <div class="brand">
    <img src="/assets/icon.svg" alt="AegisFetch" />
    <div class="brand-title">
      <h1>AegisFetch Web Console v2.2</h1>
      <p>Anti-403 WAF-Evading Catalog Downloader, BOM Importer &amp; Multi-Proxy IP Rotator</p>
    </div>
  </div>
  <div class="badge-group">
    <span class="badge">TLS: Chrome124 / Safari</span>
    <span class="badge badge-purple" id="headerProxyBadge">Proxy: DIRECT</span>
    <span class="badge">SSRF &amp; CSRF Guard: ACTIVE</span>
  </div>
</header>

<div class="container">
  <!-- Left Card -->
  <div class="card">
    <div class="card-header">
      <h2>📥 カタログ一括ダウンロード設定</h2>
      <div style="display:flex; gap:6px;">
        <input type="file" id="bomFileInput" accept=".txt,.csv,.xlsx" style="display:none;" onchange="handleBomFileSelect(this.files[0])" />
        <button class="btn-secondary" style="padding:4px 10px; font-size:0.75rem;" onclick="document.getElementById('bomFileInput').click()">📄 Excel/CSV読込</button>
        <button class="btn-secondary" style="padding:4px 10px; font-size:0.75rem;" onclick="loadSampleList()">サンプル挿入</button>
      </div>
    </div>

    <label for="itemsInput">型番リスト（BALLUFF / 他社メーカー型番）または URL を1行ずつ入力:</label>
    <div class="drop-zone" id="dropZone">
      <textarea id="itemsInput" placeholder="ここに型番・URLを入力、または Excel (.xlsx) / CSV / TXT ファイルをドラッグ＆ドロップ！&#10;&#10;例:&#10;BES0002(BES G06EB-NOC40F-S49G)&#10;AM6-CN-3H&#10;https://example.com/datasheet.pdf"></textarea>
      <div class="drop-hint">
        <span>💡 Excel (.xlsx) / CSV / TXT のドラッグ＆ドロップに対応</span>
        <span id="itemCountLabel">0 件</span>
      </div>
    </div>

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
        <div style="display:flex; gap:5px;">
          <button class="btn-purple" id="btnHarvestProxies" onclick="harvestFreeProxies(true)">⚡ 無料プロキシ取得＆テスト</button>
          <button class="btn-secondary" style="padding:4px 8px; font-size:0.73rem;" onclick="loadPresetProxies()">📋 プリセット</button>
          <button class="btn-secondary" style="padding:4px 8px; font-size:0.73rem;" onclick="clearProxies()">クリア</button>
        </div>
      </div>
      <textarea id="proxiesInput" style="min-height: 75px; font-size:0.78rem;" placeholder="http://176.111.37.5:39811&#10;socks5://208.102.51.6:58208 (空欄なら直接通信)" oninput="updateProxyCountBadge()"></textarea>
      <div class="form-grid" style="margin-top:6px;">
        <div>
          <select id="proxyModeSelect" style="padding:6px 10px; font-size:0.78rem;">
            <option value="round_robin" selected>順番に切替 (Round-Robin)</option>
            <option value="random">ランダム切替 (Random)</option>
          </select>
        </div>
        <div style="display:flex; align-items:center;">
          <label class="checkbox-row" style="margin:0;">
            <input type="checkbox" id="fallbackDirectCheck" checked />
            <span>不通時は直接通信(Direct)で救済</span>
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
        <label for="concurrencySelect">並列ダウンロード数 (⑦ 並列高速化):</label>
        <select id="concurrencySelect">
          <option value="1" selected>1 並列 (直列・最も安全)</option>
          <option value="2">2 並列 (高速)</option>
          <option value="3">3 並列 (プロキシ併用推奨)</option>
          <option value="5">5 並列 (爆速・複数プロキシ向け)</option>
        </select>
      </div>
      <div>
        <label for="localeSelect">BALLUFF 優先言語:</label>
        <select id="localeSelect">
          <option value="ja-jp" selected>日本語 (ja-jp)</option>
          <option value="en-us">English (en-us)</option>
          <option value="de-de">Deutsch (de-de)</option>
        </select>
      </div>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
        <div>
          <label for="minDelay">最小待機(秒):</label>
          <input type="number" id="minDelay" value="0.6" step="0.2" min="0.2" />
        </div>
        <div>
          <label for="maxDelay">最大待機(秒):</label>
          <input type="number" id="maxDelay" value="1.5" step="0.2" min="0.4" />
        </div>
      </div>
    </div>

    <!-- Advanced Feature Toggles (6, 8, 9) -->
    <div class="options-box">
      <label class="checkbox-row">
        <input type="checkbox" id="autoLocaleFallbackCheck" checked />
        <span>⑥ 英語/独語 自動フォールバック</span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="genericSearchCheck" checked />
        <span>⑧ 他社型番もWeb自動検索 (PDF探索)</span>
      </label>
      <label class="checkbox-row" style="grid-column: 1 / -1;">
        <input type="checkbox" id="checkUpdatesCheck" />
        <span>⑨ カタログ改訂・更新チェック (既存ファイルの最新版をサーバー確認)</span>
      </label>
    </div>

    <div class="btn-row">
      <button class="btn-primary" id="btnStart" onclick="startDownloadJob()">🚀 ダウンロード開始</button>
      <button class="btn-amber" id="btnRetryFailed" onclick="retryFailedItems()" disabled>🔄 失敗分のみ再試行</button>
      <button class="btn-danger" id="btnCancel" onclick="cancelCurrentJob()" disabled>⏹ 停止</button>
      <button class="btn-secondary" onclick="openOutputFolder()">📂 フォルダを開く</button>
    </div>
  </div>

  <!-- Right Card -->
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
      <div style="font-size:0.75rem; color:#d8b4fe; margin-top:4px;" id="activeProxyText">
        現在の通信経路: DIRECT (標準回線)
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="num" id="statTotal" style="color:var(--text-main);">0</div>
          <div class="lbl">総件数</div>
        </div>
        <div class="stat-card">
          <div class="num" id="statSuccess" style="color:var(--green);">0</div>
          <div class="lbl">成功 / 更新</div>
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

    <label>実行ログ (1件ごとの通信経路 / 言語・検索ソース / 結果):</label>
    <div class="log-list" id="logList">
      <div style="color:var(--text-muted); text-align:center; padding: 30px 0;">
        左側のフォームに型番・URLを入力、または Excel/CSV をドロップしてください。
      </div>
    </div>
  </div>

  <!-- Bottom Card -->
  <div class="card card-full">
    <div class="card-header">
      <h2>📁 ダウンロード済みカタログ一覧 (<span id="fileCountLabel">0</span> ファイル)</h2>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <button class="btn-secondary" id="btnExportCsv" style="padding:6px 12px; font-size:0.8rem;" onclick="exportResultsCsv()" disabled>📊 結果CSV出力</button>
        <button class="btn-secondary" style="padding:6px 12px; font-size:0.8rem;" onclick="downloadAllZip()">📦 ZIP一括ダウンロード</button>
        <button class="btn-secondary" style="padding:6px 12px; font-size:0.8rem;" onclick="mergeAllPdfs()">📑 全PDFを1冊に結合</button>
        <button class="btn-secondary" style="padding:6px 12px; font-size:0.8rem;" onclick="refreshFileList()">🔄 一覧を更新</button>
      </div>
    </div>
    <div style="max-height: 320px; overflow-y: auto;">
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
  let lastFailedItems = [];
  let lastJobResults = [];

  const SETTINGS_KEYS = [
    'outputDir', 'proxiesInput', 'proxyModeSelect', 'concurrencySelect',
    'localeSelect', 'minDelay', 'maxDelay', 'fallbackDirectCheck',
    'autoLocaleFallbackCheck', 'genericSearchCheck', 'checkUpdatesCheck'
  ];

  function saveUiSettings() {
    try {
      const data = {};
      for (const id of SETTINGS_KEYS) {
        const el = document.getElementById(id);
        if (!el) continue;
        data[id] = (el.type === 'checkbox') ? el.checked : el.value;
      }
      localStorage.setItem('aegisfetch_ui_settings_v1', JSON.stringify(data));
    } catch (e) {}
  }

  function restoreUiSettings() {
    try {
      const raw = localStorage.getItem('aegisfetch_ui_settings_v1');
      if (!raw) return;
      const data = JSON.parse(raw);
      for (const id of SETTINGS_KEYS) {
        const el = document.getElementById(id);
        if (!el || !(id in data)) continue;
        if (el.type === 'checkbox') el.checked = Boolean(data[id]);
        else if (data[id] !== undefined && data[id] !== null) el.value = data[id];
      }
    } catch (e) {}
  }

  for (const id of SETTINGS_KEYS) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', saveUiSettings);
    if (el && (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT')) {
      el.addEventListener('input', saveUiSettings);
    }
  }

  function updateItemCount() {
    const raw = document.getElementById('itemsInput').value;
    const count = raw.split(/\\r?\\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#')).length;
    document.getElementById('itemCountLabel').textContent = count + ' 件';
  }
  document.getElementById('itemsInput').addEventListener('input', updateItemCount);

  // Drag & Drop BOM Handler
  const dropZone = document.getElementById('dropZone');
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleBomFileSelect(e.dataTransfer.files[0]);
    }
  });

  async function handleBomFileSelect(file) {
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      alert("ファイルサイズが大きすぎます (上限 5MB)");
      return;
    }
    const reader = new FileReader();
    reader.onload = async () => {
      const b64 = reader.result.split(',')[1];
      try {
        const resp = await fetch('/api/parse-file', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({filename: file.name, content_b64: b64})
        });
        const data = await resp.json();
        if (!data.success) {
          alert("ファイル解析エラー: " + data.message);
          return;
        }
        const ta = document.getElementById('itemsInput');
        const existing = ta.value.trim();
        const loaded = (data.items || []).join("\\n");
        ta.value = existing ? (existing + "\\n" + loaded) : loaded;
        updateItemCount();
        alert(`「${file.name}」から ${data.items.length} 件の型番/URLを読み込みました！`);
      } catch (e) {
        alert("通信エラー: " + e);
      }
    };
    reader.readAsDataURL(file);
  }

  function loadSampleList() {
    document.getElementById('itemsInput').value = [
      "BES0002(BES G06EB-NOC40F-S49G)",
      "BES0003(BES G06EB-NSC40F-S49G)",
      "AM6-CN-3H"
    ].join("\\n");
    updateItemCount();
  }

  function getConfiguredProxies() {
    const raw = document.getElementById('proxiesInput').value;
    return raw.split(/\\r?\\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
  }

  function updateProxyCountBadge() {
    const list = getConfiguredProxies();
    const badge = document.getElementById('headerProxyBadge');
    badge.textContent = list.length > 0 ? `Proxy: ACTIVE (${list.length} IPs)` : 'Proxy: DIRECT';
  }

  async function harvestFreeProxies(verifyLive) {
    const btn = document.getElementById('btnHarvestProxies');
    btn.disabled = true;
    btn.textContent = "⏳ 収集＆生存テスト中(約4秒)...";
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
      document.getElementById('proxiesInput').value = (data.working_proxies || []).join("\\n");
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
    if (!url) { alert("抽出元のWebページURLを入力してください。"); return; }
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
      if (!data.success) { alert("抽出エラー: " + (data.message || "")); return; }
      if (data.pdf_links.length === 0) { alert("PDFリンクが見つかりませんでした。"); return; }
      const ta = document.getElementById('itemsInput');
      const existing = ta.value.trim();
      const newUrls = data.pdf_links.map(x => x.url).join("\\n");
      ta.value = existing ? (existing + "\\n" + newUrls) : newUrls;
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

  async function launchJobWithItems(items) {
    const proxies = getConfiguredProxies();
    const proxy_rotation_mode = document.getElementById('proxyModeSelect').value;
    const fallback_to_direct = document.getElementById('fallbackDirectCheck').checked;
    const output_dir = document.getElementById('outputDir').value.trim();
    const locale = document.getElementById('localeSelect').value;
    const concurrency = parseInt(document.getElementById('concurrencySelect').value, 10) || 1;
    const auto_fallback_locales = document.getElementById('autoLocaleFallbackCheck').checked;
    const enable_generic_search = document.getElementById('genericSearchCheck').checked;
    const check_updates = document.getElementById('checkUpdatesCheck').checked;
    const min_delay = parseFloat(document.getElementById('minDelay').value) || 0.6;
    const max_delay = parseFloat(document.getElementById('maxDelay').value) || 1.5;

    document.getElementById('btnStart').disabled = true;
    document.getElementById('btnRetryFailed').disabled = true;
    document.getElementById('btnCancel').disabled = false;
    lastFailedItems = [];

    try {
      const resp = await fetch('/api/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          items, proxies, proxy_rotation_mode, fallback_to_direct,
          output_dir, locale, concurrency, auto_fallback_locales,
          enable_generic_search, check_updates, min_delay, max_delay
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
      pollTimer = setInterval(pollJobStatus, 700);
    } catch (e) {
      alert("リクエスト失敗: " + e);
      document.getElementById('btnStart').disabled = false;
      document.getElementById('btnCancel').disabled = true;
    }
  }

  function startDownloadJob() {
    const rawText = document.getElementById('itemsInput').value;
    const items = rawText.split(/\\r?\\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
    if (items.length === 0) { alert("型番またはURLを1件以上入力してください。"); return; }
    launchJobWithItems(items);
  }

  function retryFailedItems() {
    if (lastFailedItems.length === 0) return;
    document.getElementById('itemsInput').value = lastFailedItems.join("\\n");
    updateItemCount();
    launchJobWithItems(lastFailedItems);
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

      const results = job.results || [];
      lastJobResults = results;
      renderLogs(results);

      if (job.status === 'running') {
        document.getElementById('currentItemText').textContent = "処理中: " + (job.current_item || "...");
      } else {
        document.getElementById('currentItemText').textContent = `完了 (${job.status})`;
        document.getElementById('btnStart').disabled = false;
        document.getElementById('btnCancel').disabled = true;
        document.getElementById('btnExportCsv').disabled = (results.length === 0);
        lastFailedItems = results.filter(r => !r.success).map(r => r.input);
        document.getElementById('btnRetryFailed').disabled = (lastFailedItems.length === 0);
        clearInterval(pollTimer);
        refreshFileList();
      }
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
      const srcLabel = r.source && r.source !== 'direct_url' ? ` (${r.source})` : '';
      left.textContent = `[#${r.index}] ${r.input}${srcLabel} -> ${r.filename || r.error || ''}`;

      const rightWrap = document.createElement('div');
      rightWrap.style.display = 'flex';
      rightWrap.style.alignItems = 'center';

      if (r.proxy_used && r.proxy_used !== 'SKIPPED' && r.proxy_used !== 'UP-TO-DATE') {
        const pTag = document.createElement('span');
        pTag.className = 'tag tag-proxy';
        pTag.textContent = r.proxy_used;
        rightWrap.appendChild(pTag);
      }

      const right = document.createElement('span');
      if (r.skipped) {
        right.className = 'tag tag-skip';
        right.textContent = r.proxy_used === 'UP-TO-DATE' ? `最新(SKIP)` : `SKIP (${r.size_kb} KB)`;
      } else if (r.updated) {
        right.className = 'tag tag-upd';
        right.textContent = `UPDATED (${r.size_kb} KB)`;
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

  function exportResultsCsv() {
    if (!lastJobResults || lastJobResults.length === 0) return;
    const headers = ['No', 'Input', 'Filename', 'Status', 'SizeKB', 'Source', 'ProxyUsed', 'URL', 'Error', 'Time'];
    const esc = (v) => {
      let s = String(v === null || v === undefined ? '' : v);
      // Neutralize CSV / Excel Formula Injection
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return '"' + s.replace(/"/g, '""') + '"';
    };
    const rows = [headers.join(',')];
    for (const r of lastJobResults) {
      const st = r.skipped ? 'SKIPPED' : (r.updated ? 'UPDATED' : (r.success ? 'OK' : 'FAILED'));
      rows.push([
        esc(r.index), esc(r.input), esc(r.filename), esc(st),
        esc(r.size_kb), esc(r.source), esc(r.proxy_used), esc(r.url), esc(r.error), esc(r.timestamp)
      ].join(','));
    }
    const blob = new Blob(['\\uFEFF' + rows.join('\\r\\n')], {type: 'text/csv;charset=utf-8;'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'aegisfetch_report.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function downloadAllZip() {
    const outDir = document.getElementById('outputDir').value.trim();
    window.open('/api/download-zip?dir=' + encodeURIComponent(outDir), '_blank');
  }

  function mergeAllPdfs() {
    const outDir = document.getElementById('outputDir').value.trim();
    window.open('/api/merge-pdf?dir=' + encodeURIComponent(outDir), '_blank');
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
    restoreUiSettings();
    refreshFileList();
    updateProxyCountBadge();
    updateItemCount();
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
        if length <= 0 or length > 8 * 1024 * 1024:
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
                    "updated_count": job.get("updated_count", 0),
                    "failed_count": job["failed_count"],
                    "current_item": job.get("current_item"),
                    "last_proxy": job.get("last_proxy"),
                    "percent": pct,
                    "results": job["results"][-200:]
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

        if path == "/api/download-zip":
            req_dir = unquote(query.get("dir", "")) or DEFAULT_DOWNLOAD_DIR
            try:
                safe_dir = validate_output_directory(req_dir)
                if not os.path.exists(safe_dir):
                    self._send_json({"success": False, "message": "Directory does not exist."}, 404)
                    return

                real_safe_dir = os.path.realpath(safe_dir)
                pdf_files = []
                for f in sorted(os.listdir(safe_dir)):
                    if not f.lower().endswith(".pdf"):
                        continue
                    fp = os.path.join(safe_dir, f)
                    if os.path.islink(fp) or not os.path.isfile(fp):
                        continue
                    if os.path.commonpath([real_safe_dir, os.path.realpath(fp)]) != real_safe_dir:
                        continue
                    pdf_files.append(f)

                if not pdf_files:
                    self._send_json({"success": False, "message": "No PDF files found to archive."}, 404)
                    return

                buf = io.BytesIO()
                total_size = 0
                with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for fname in pdf_files:
                        fpath = os.path.join(safe_dir, fname)
                        total_size += os.path.getsize(fpath)
                        if total_size > MAX_EXPORT_ARCHIVE_BYTES:
                            self._send_json({"success": False, "message": "Total size exceeds 250MB export limit."}, 400)
                            return
                        zf.write(fpath, arcname=fname)

                zip_bytes = buf.getvalue()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", 'attachment; filename="aegisfetch_catalogs.zip"')
                self.send_header("Content-Length", str(len(zip_bytes)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(zip_bytes)
            except SecurityValidationError as sve:
                self._send_json({"success": False, "message": str(sve)}, 403)
            return

        if path == "/api/merge-pdf":
            req_dir = unquote(query.get("dir", "")) or DEFAULT_DOWNLOAD_DIR
            try:
                safe_dir = validate_output_directory(req_dir)
                if not os.path.exists(safe_dir):
                    self._send_json({"success": False, "message": "Directory does not exist."}, 404)
                    return

                real_safe_dir = os.path.realpath(safe_dir)
                pdf_files = []
                for f in sorted(os.listdir(safe_dir)):
                    if not f.lower().endswith(".pdf"):
                        continue
                    fp = os.path.join(safe_dir, f)
                    if os.path.islink(fp) or not os.path.isfile(fp):
                        continue
                    if os.path.commonpath([real_safe_dir, os.path.realpath(fp)]) != real_safe_dir:
                        continue
                    pdf_files.append(f)

                if not pdf_files:
                    self._send_json({"success": False, "message": "No PDF files found to merge."}, 404)
                    return

                from pypdf import PdfWriter
                writer = PdfWriter()
                try:
                    total_size = 0
                    merged_count = 0
                    for fname in pdf_files:
                        fpath = os.path.join(safe_dir, fname)
                        total_size += os.path.getsize(fpath)
                        if total_size > MAX_EXPORT_ARCHIVE_BYTES:
                            self._send_json({"success": False, "message": "Total size exceeds 250MB merge limit."}, 400)
                            return
                        try:
                            writer.append(fpath)
                            merged_count += 1
                        except Exception:
                            continue

                    if merged_count == 0:
                        self._send_json({"success": False, "message": "No valid PDF files could be merged."}, 400)
                        return

                    out_buf = io.BytesIO()
                    writer.write(out_buf)
                    merged_bytes = out_buf.getvalue()
                finally:
                    writer.close()

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", 'attachment; filename="merged_catalogs.pdf"')
                self.send_header("Content-Length", str(len(merged_bytes)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(merged_bytes)
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
            # Drain small unread POST body to prevent Windows TCP RST (WinError 10054) on early 403 close
            try:
                cl = int(self.headers.get("Content-Length", "0"))
                if 0 < cl <= 65536:
                    self.rfile.read(cl)
            except Exception:
                pass
            self._send_json({"success": False, "message": "Forbidden Origin/Host header (CSRF & DNS Rebinding Protection)."}, 403)
            return

        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
        except Exception as e:
            self._send_json({"success": False, "message": f"Invalid JSON: {e}"}, 400)
            return

        if path == "/api/parse-file":
            filename = body.get("filename", "")
            content_b64 = body.get("content_b64", "")
            if not filename or not content_b64:
                self._send_json({"success": False, "message": "Missing file data"}, 400)
                return
            try:
                raw_bytes = base64.b64decode(content_b64)
                if len(raw_bytes) > 5 * 1024 * 1024:
                    self._send_json({"success": False, "message": "File exceeds 5MB limit"}, 400)
                    return
                items = _parse_uploaded_bom_file(filename, raw_bytes)
                self._send_json({"success": True, "count": len(items), "items": items})
            except Exception as e:
                self._send_json({"success": False, "message": str(e)}, 400)
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
            auto_fallback_locales = bool(body.get("auto_fallback_locales", True))
            enable_generic_search = bool(body.get("enable_generic_search", True))
            check_updates = bool(body.get("check_updates", False))
            concurrency = max(1, min(8, int(body.get("concurrency", 1))))
            min_delay = max(0.2, float(body.get("min_delay", 0.6)))
            max_delay = max(min_delay + 0.2, float(body.get("max_delay", 1.5)))

            try:
                target_dir = validate_output_directory(req_dir)
                os.makedirs(target_dir, exist_ok=True)
            except SecurityValidationError as sve:
                self._send_json({"success": False, "message": str(sve)}, 403)
                return

            job_id = f"ui_{uuid.uuid4().hex[:8]}"
            with _UI_JOBS_LOCK:
                _prune_old_ui_jobs()
                _UI_JOBS[job_id] = {
                    "job_id": job_id,
                    "status": "running",
                    "total_items": len(items),
                    "completed_items": 0,
                    "success_count": 0,
                    "skipped_count": 0,
                    "updated_count": 0,
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
                    auto_fallback_locales,
                    enable_generic_search,
                    check_updates,
                    concurrency,
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
