# AegisFetch

<p align="center">
  <img src="assets/icon.svg" alt="AegisFetch Icon" width="160" height="160">
</p>

<p align="center">
  <b>Resilient Catalog & PDF Downloader with Adaptive Flow Control</b><br>
  <i>WAFや403遮断・レート制限に強い高耐久カタログ＆PDFダウンローダー</i>
</p>

---

## English Overview

**AegisFetch** is a Python utility engineered for reliable, large-scale document downloading. When scraping technical catalogs or datasheets, standard HTTP requests often encounter `403 Forbidden` or `429 Too Many Requests` due to TLS fingerprint analysis, strict bot detection, or rate limiting. 

AegisFetch mitigates these issues by emulating modern browser TLS fingerprints, adapting request timing dynamically, and verifying payload integrity before saving.

### Key Capabilities
- **TLS/JA3/JA4 Impersonation**: Emulates Chrome and Safari transport signatures via `curl_cffi` to avoid automated detection.
- **Adaptive Jitter & Backoff**: Adds randomized delays between requests and exponentially throttles when encountering restrictive status codes.
- **Circuit Breaker**: Automatically enters a cooldown period if repeated errors occur, resetting session state before continuing.
- **Integrity Verification**: Inspects file headers (such as `%PDF`) to reject error pages masquerading as valid downloads.
- **Atomic File Operations**: Writes to temporary buffers before finalizing files, ensuring incomplete downloads are discarded.
- **Intelligent Resume**: Detects and verifies pre-existing files to skip duplicate downloads.

---

## 日本語 概要 (Japanese Overview)

**AegisFetch** は、Webサイトから仕様書・カタログ・PDFを大量収集する際のエラー（403 Forbidden、429 レート制限）を防ぐために設計された高耐久ダウンローダーです。

通常のスクリプト（`urllib` や `requests`）は TLS ハンドシェイクの特徴からスクリプトであると即座に判定されがちです。AegisFetch はブラウザの通信特徴（フィンガープリント）を再現し、自律的な流量制御を行うことで安定したダウンロードを実現します。

### 主な特長
- **ブラウザ指紋（TLS/HTTP2）エミュレーション**: `curl_cffi` により Chrome や Safari の通信指紋を再現。
- **ゆらぎ（Jitter）待機と指数バックオフ**: 一定間隔ではなくランダムな待機時間を挟み、403/429 検知時は自動で待機時間を延長。
- **サーキットブレーカー**: 連続失敗時に長時間のクールダウン（冷却）を自動実行し、IPブロックを防止。
- **ファイル整合性チェック**: マジックバイト（`%PDF-`）を検証し、HTMLエラー画面がPDFとして保存されるトラブルを排除。
- **アトミック書き込み**: `.tmp` ファイル経由で保存し、通信切断時の破損ファイルを防止。
- **レジューム（途中再開）**: 既にダウンロード済みの正常ファイルを自動スキップ。

---

## Architecture / 設計思想

```
+-----------------------------------------------------------+
|                        AegisFetch                         |
+-----------------------------------------------------------+
| [1] Stealth Transport Layer (curl_cffi TLS impersonation) |
| [2] Adaptive Flow Control   (Jitter, Backoff, Breaker)    |
| [3] Storage Integrity Layer (Magic Bytes, Atomic Writes)  |
+-----------------------------------------------------------+
```

---

## Installation / インストール

```bash
git clone https://github.com/iwa-kasoutuuuuuka/AegisFetch.git
cd AegisFetch
pip install -e .
```

---

## Usage / 使い方

### 1. Web UI Console (Browser GUI) / ブラウザ操作画面

Launch the interactive Web UI dashboard (automatically opens `http://127.0.0.1:8765` in your browser):
ブラウザから直感的に型番リストの貼り付け・ページ内PDF抽出・リアルタイム進捗確認・PDF閲覧ができる Web UI モードを起動します：

```bash
# Command line launch / コマンドで起動
aegisfetch-ui

# Or double-click on Windows / またはバッチファイルをダブルクリック
Start_AegisFetch_WebUI.bat
```

### 2. Chrome / Edge Extension (`AegisFetch Companion` - v2.4.0) / Chrome・Edge 拡張機能

Send PDF links and selected part numbers directly from your everyday Chrome/Edge browser (even on login-protected or JS-rendered pages) to your local AegisFetch server:
普段お使いの Chrome / Edge で開いているページ（要ログイン会員サイトや JS 動的ページを含む）から、ワンクリックや右クリックメニューで AegisFetch にダウンロードを送信できます：

1. **Start Web UI / Web UI 起動**: Launch `aegisfetch-ui` (or `Start_AegisFetch_WebUI.bat`).
2. **Load Extension / 拡張機能の読み込み (約30秒)**:
   - Open `chrome://extensions` (or `edge://extensions`) and enable **Developer mode / デベロッパー モード**.
   - Click **Load unpacked / パッケージ化されていない拡張機能を読み込む** and select the `chrome_extension/` folder.
3. **Token Pairing / トークン連携**:
   - Click **`🔑 拡張トークンをコピー`** in the Web UI header.
   - Open the **AegisFetch Companion** popup (`⚙️`) and paste the token to connect securely.

**Capabilities / 主な機能**:
- **Auto-Scan Active Tab**: Detects `.pdf` / `pdfengine` / datasheet links inside the active page and lets you pick items with checkboxes.
- **Right-Click Context Menu**: Highlight any part number (e.g., `BES0002`) or right-click a link ➔ **`🛡️ AegisFetch で取得`**.
- **Strict Least-Privilege Security**: Uses `activeTab` only (no `<all_urls>` spy permissions), strict MV3 CSP (`script-src 'self'`), and `X-Aegis-Token` + `chrome-extension://` Origin verification.

### 3. Command Line (CLI)

```bash
# 1. Download directly via URLs / URLを直接指定
aegisfetch --urls "https://example.com/item1.pdf" "https://example.com/item2.pdf" --out-dir "./my_catalogs"

# 2. Resolve & download by Part Numbers (e.g. BALLUFF) / 型番から自動検索＆ダウンロード
aegisfetch --balluff-parts BES0002 BES0003 --out-dir "./my_catalogs"

# 3. Extract all PDFs from a product page / 製品ページからPDFを自動抽出
aegisfetch --extract-url "https://www.balluff.com/ja-jp/products/BES0002" --out-dir "./my_catalogs"

# 4. Download from a list file (URLs or part numbers) / リストファイルから一括取得
aegisfetch --list-file "urls.txt" --out-dir "./my_catalogs" --min-delay 1.0 --max-delay 2.5

# 5. Download with Multi-Proxy IP Rotation & Auto Free Proxies / 無料プロキシ自動取得＆1件ごとIPローテーション
aegisfetch --list-file "urls.txt" --auto-free-proxies --out-dir "./my_catalogs"
```

### Python SDK

```python
from aegisfetch import AegisFetch

client = AegisFetch(
    output_dir="./downloads",
    min_delay=1.0,
    max_delay=2.5,
    max_retries=4,
    verify_pdf=True
)

items = [
    {"url": "https://example.com/spec.pdf", "filename": "spec.pdf"}
]

results = client.download_batch(items)
```

---

### Model Context Protocol (MCP) Server / MCPサーバー (v2.2.0)

AegisFetch includes a native MCP server for seamless integration with **Antigravity**, **Claude Code**, and **Claude Desktop**.
Antigravity や Claude Code から直接ツール呼び出しでダウンロード・型番解決・他社データシート検索・無料プロキシ取得・非同期並列バッチ処理を実行できます。

#### 1. Configuration / 設定例 (`claude_desktop_config.json` / Antigravity)

```json
{
  "mcpServers": {
    "aegisfetch": {
      "command": "aegisfetch-mcp",
      "env": {
        "AEGISFETCH_DOWNLOAD_DIR": "./downloads"
      }
    }
  }
}
```

#### 2. Available MCP Tools (10 Tools) / 提供ツール一覧

- `aegisfetch_download_single`: Download a single document with WAF evasion and hop-by-hop SSRF guards.
- `aegisfetch_download_by_part_number`: Automatically resolve part numbers (e.g. `BES0002`) into official PDF URLs and download them.
- `aegisfetch_search_generic_datasheet`: Search the public web for datasheet PDF links for **any manufacturer part number** (Omron, Keyence, SMC, TI, etc.).
- `aegisfetch_extract_pdf_links`: Scan a product webpage and extract all PDF links (with automatic Playwright SPA fallback).
- `aegisfetch_download_batch`: Synchronous batch download (up to 50 items) with jitter and circuit breaker protection.
- `aegisfetch_start_batch_job`: Start a non-blocking background job (up to 500 items, supports `concurrency`, `proxies` rotation, and `check_updates`) to avoid MCP 60s tool timeouts.
- `aegisfetch_get_job_status`: Check real-time progress and results of a background download job.
- `aegisfetch_fetch_free_proxies`: Harvest & live-test public HTTP/SOCKS5 proxies against Cloudflare HTTPS trace.
- `aegisfetch_verify_file`: Validate local file integrity (`%PDF` magic byte check).
- `aegisfetch_get_status`: Report server health, active jobs, and active security guardrails.

---

## Advanced Productivity Features (v2.3.0) / 実務支援機能

- **ZIP Bulk Export & PDF Merger**: Download all fetched catalogs as a single `.zip` archive or merge them into one unified `merged_catalogs.pdf` directly from the Web UI.
- **CSV Report Export & Auto-Saved Settings**: Export full download results as BOM UTF-8 CSV and automatically persist your UI settings/proxy lists in `localStorage`.
- **Excel (.xlsx) / CSV / TXT Drag & Drop BOM Import**: Drop any BOM file directly onto the Web UI input area to extract part numbers and URLs automatically.
- **One-Click Retry Failed**: Re-queue only failed items after a batch run with a single click.
- **Multi-Locale Auto-Fallback (`ja-jp` ➔ `en-us` ➔ `de-de`)**: Automatically retrieves English or German datasheets if a Japanese version does not exist.
- **Multi-Threaded Parallel Downloads (`concurrency=1..8`)**: Thread-local `curl_cffi` sessions combined with proxy rotation dramatically accelerate bulk downloads across both part resolution and file fetching.
- **Cross-Manufacturer Generic Datasheet Search**: Automatically searches public PDF datasheets for non-BALLUFF part numbers.
- **Catalog Revision / Update Check (`--check-updates`)**: Tracks `ETag`, `Last-Modified`, and `SHA-256` in `.aegisfetch_meta.json` with automatic `GET Range: bytes=0-0` fallback when `HEAD` is blocked.

---

## Multi-Proxy IP Rotation & Free Proxy Harvester / 複数プロキシ自動ローテーション

AegisFetch v2.2 supports switching proxy IP on **every single file download** (Round-Robin or Random):
- **Web UI Integration**: Paste multiple proxies into the dashboard or click **"⚡ 無料プロキシ取得＆テスト"** to harvest & verify live proxies in ~4 seconds.
- **Dead-Proxy Eviction & Direct Fallback**: Automatically drops broken proxies and falls back to direct connection on the final retry so downloads succeed reliably.
- **Credential Masking**: Proxy passwords (`http://user:pass@host:port`) are automatically masked as `***:***` in all logs, API responses, and UI views.

---

## Security & Verification / セキュリティと脆弱性対策 (82/82 Tests Passing)

AegisFetch v2.4.0 is built with deep-defense security guardrails audited across 82 automated tests (71 offline checks across Ubuntu & Windows GitHub Actions CI):
- **Browser Extension Local Bridge Security**: Enforces `X-Aegis-Token` (`hmac.compare_digest`), strict `chrome-extension://` Origin + local Host validation, CORS preflight gating, strict MV3 CSP (`script-src 'self'`), zero unsafe DOM sinks (`textContent`-only), and `activeTab` least privilege.
- **Direct, Open-Redirect (GET & HEAD) & Proxy-based SSRF Prevention**: Inspects every redirect hop (`301`/`302`/`307`/`308`) for both GET and revision-check HEAD requests, `page_referer`, and proxy targets, blocking private IP ranges (RFC 1918), loopback (`127.0.0.1`), and cloud metadata endpoints (`169.254.169.254`).
- **XLSX ZIP Decompression Bomb Defense**: Pre-inspects uncompressed ZIP entry sizes in uploaded `.xlsx` BOM files (20MB cap, 5,000-row scan limit) before parsing.
- **Web UI CSRF & DNS Rebinding Protection**: Strictly validates `Host` and `Origin` headers on local Web UI API endpoints (`127.0.0.1` / `localhost` only) and enforces `X-Frame-Options: DENY` & `X-Content-Type-Options: nosniff`.
- **System Directory & Path Traversal Defense**: Blocks writes to critical OS folders (`C:\Windows`, `/etc`, Startup) and confines output paths via `os.path.commonpath`.
- **Streamed Chunk Size Cutoff**: Streams downloads in 64KB chunks and aborts immediately if payload exceeds 100MB to prevent RAM/disk exhaustion.
- **Zero MCP Stdio Pollution**: Directs all runtime logs strictly to `stderr` with safe CP932 fallback so MCP JSON-RPC streams remain 100% pure.

Run the full verification suite:
```bash
python test_mcp_security.py
```

---

## Options / 設定オプション

| Option | Default | Description (EN / JA) |
| :--- | :--- | :--- |
| `--out-dir` | `./downloads` | Destination folder / 保存先フォルダ |
| `--min-delay` | `1.0` | Minimum wait between requests (sec) / 最小待機時間(秒) |
| `--max-delay` | `2.5` | Maximum wait between requests (sec) / 最大待機時間(秒) |
| `--concurrency` | `1` | Parallel worker threads (1-8) / 並列ダウンロード数 |
| `--check-updates` | `False` | Check remote ETag/Last-Modified for updates / 改訂チェックモード |
| `--proxy` | `None` | Single HTTP/SOCKS5 proxy URL / 単一プロキシ指定 |
| `--proxies` | `None` | Multiple proxy URLs for per-file rotation / 複数プロキシ自動切替 |
| `--proxy-file` | `None` | Text file containing proxy list / プロキシリストファイル |
| `--auto-free-proxies` | `False` | Auto-harvest & test free proxies / 無料プロキシ自動取得＆利用 |
| `--no-direct-fallback` | `False` | Disable direct fallback when proxies fail / 直接通信フォールバック無効化 |

---

## Changelog / 更新履歴

- **v2.4.1**:
  - **SSRF & Proxy Hardening (`security.py`, `proxy_manager.py`, `extractors.py`)**: Fixed `SecurityValidationError` swallowing during IP parsing, blocked IPv4-mapped/6to4/Teredo/scoped IPv6, legacy `inet_aton` IP notations (decimal/hex/octal/shorthand), `.localhost`/trailing-dot hostnames, CRLF/NUL injection, and backslash authority confusion; added Playwright `page.route` SSRF guard with clean `unroute_all` teardown and strict BALLUFF `locale` validation.
  - **Web UI Bridge Security & Validation (`web_ui.py`)**: Fixed IPv6 `[::1]:port` Host parsing and userinfo smuggling, enforced `http`/`https` schemes for local web origins, escaped `EXTENSION_TOKEN` via `json.dumps` Unicode escaping, added `Cache-Control: no-store` on `/` and `/files/`, enforced `0o600` POSIX token file permissions, added `.pdf`/`islink`/`realpath` confinement on `/api/files` & `/files/<name>`, differentiated 403 `error_code`, and added strict HTTP `400` validation for malformed POST payloads.
  - **Chrome / Edge Extension Fixes (`chrome_extension/`)**: Added `getSafePublicReferer()` to omit private/intranet `page_referer` on part-number or internal-page requests, differentiated `error_code === "invalid_token"` from SSRF/security 403s, trimmed scanned URLs before `javascript:`/`#` checks, added double-submit guard (`popup.js`), and managed badge timer cleanup (`background.js`).
  - **Regression Tests**: Expanded suite to **108/108 PASS** online (**97/97 PASS** offline CI) plus Playwright Chromium MV3 live extension verification.
- **v2.4.0**:
  - Added **AegisFetch Companion** Chrome / Edge extension (`chrome_extension/`, Manifest V3) with active-tab PDF scanner, right-click context menus (selection part numbers & links), live job progress bar, and PNG icons (`16x16`, `48x48`, `128x128`).
  - Upgraded `web_ui.py` local bridge with persistent `X-Aegis-Token` auth, strict `chrome-extension://` CORS & preflight handling, `GET /api/health`, `page_referer` SSRF validation in `POST /api/start`, and header token copy button.
  - Added 18 automated MV3 manifest, icon, XSS/CSP, and bridge auth/CORS/SSRF tests (82/82 online, 71/71 offline CI).
- **v2.3.1**:
  - Fixed cross-platform system directory validation (`C:\Windows` checks on Ubuntu Linux CI) and Python 3.12 docstring escape warning.
  - Added CSV / Excel Formula Injection protection (`=`, `+`, `-`, `@`) to Web UI report exports.
  - Hardened `/api/download-zip` and `/api/merge-pdf` against symlink traversal (`islink` + `realpath` confinement) and ensured deterministic `PdfWriter.close()`.
  - Added automatic Direct fallback when proxy-routed part resolution fails.
- **v2.3.0**:
  - Added Web UI ZIP bulk download (`/api/download-zip`), PDF merger (`/api/merge-pdf` via `pypdf`), BOM UTF-8 CSV report export, and `localStorage` auto-saved UI settings.
  - Shared thread-local proxy-rotated sessions with `CatalogExtractor` part resolution to eliminate redundant TLS handshakes and prevent Cloudflare blocks on product pages.
  - Added automatic `GET Range: bytes=0-0` fallback in revision checking for servers blocking `HEAD` requests.
  - Added automatic job history pruning (50-job cap) in both Web UI and MCP server registries to prevent memory growth during long-running sessions.
  - Added GitHub Actions CI workflow (`.github/workflows/test.yml`) running offline security & unit tests across Ubuntu & Windows.
- **v2.2.1**:
  - Fixed Open-Redirect SSRF vector in revision-check `HEAD` requests via shared hop-by-hop validator.
  - Added `.xlsx` ZIP decompression bomb protection (20MB uncompressed cap, 5,000-row scan limit).
  - Fixed false-positive revision updates on dynamic PDF engines where `Last-Modified` mirrors server `Date`.
  - Upgraded file replacement to thread-safe atomic `os.replace()` and added safe POST body draining on early HTTP 403 to prevent Windows TCP RST.
- **v2.2.0**:
  - Added Web UI Excel (`.xlsx`) / CSV / TXT Drag & Drop BOM importer, One-Click Retry Failed, multi-locale auto-fallback (`ja-jp` ➔ `en-us` ➔ `de-de`), multi-threaded parallel downloads (`concurrency=1..8`), cross-vendor datasheet search, and catalog revision tracking (`--check-updates`).
- **v2.1.1**:
  - Added Proxy-based SSRF prevention, automatic proxy credential masking (`***:***`), and Web UI CSRF / DNS Rebinding defenses.
- **v2.1.0**:
  - Added Multi-Proxy IP Rotation (Round-Robin / Random), Free Public Proxy Harvester with Cloudflare HTTPS trace verification, and Web UI proxy console.
- **v2.0.0**:
  - Added native MCP Server (`aegisfetch-mcp`), Web UI console (`aegisfetch-ui`), Extractor Engine, non-blocking Background Job Queue, and deep-defense security suite.

---

## License

MIT License - Copyright (c) 2026 iwa-kasoutuuuuuka
