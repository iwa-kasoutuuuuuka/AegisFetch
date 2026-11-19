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
|     ステルス通信層 (ブラウザTLS指紋エミュレーション)       |
| [2] Adaptive Flow Control   (Jitter, Backoff, Breaker)    |
|     自律流量制御層 (ゆらぎ待機・バックオフ・遮断機)        |
| [3] Storage Integrity Layer (Magic Bytes, Atomic Writes)  |
|     保存整合性層   (マジックバイト検証・アトミック書込)    |
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

### 2. Chrome / Edge Extension (`AegisFetch Companion` - v2.5.0) / Chrome・Edge 拡張機能

Send PDF links and selected part numbers directly from your everyday Chrome/Edge browser (even on login-protected or JS-rendered pages) to your local AegisFetch server:
普段お使いの Chrome / Edge で開いているページ（要ログイン会員サイトや JS 動的ページを含む）から、ワンクリックや右クリックメニューで AegisFetch にダウンロードを送信できます：

1. **Start Web UI / Web UI 起動**:
   - Launch `aegisfetch-ui` (or `Start_AegisFetch_WebUI.bat`). / `aegisfetch-ui`（または `Start_AegisFetch_WebUI.bat`）を起動します。
2. **Load Extension / 拡張機能の読み込み (約30秒)**:
   - Open `chrome://extensions` (or `edge://extensions`) and enable **Developer mode**. / `chrome://extensions`（または `edge://extensions`）を開き、**デベロッパー モード** を有効にします。
   - Click **Load unpacked** and select the `chrome_extension/` folder. / **パッケージ化されていない拡張機能を読み込む** をクリックし、`chrome_extension/` フォルダを選択します。
3. **Token Pairing / トークン連携**:
   - Click **`🔑 拡張トークンをコピー`** in the Web UI header. / Web UI ヘッダーの **`🔑 拡張トークンをコピー`** をクリックします。
   - Open the **AegisFetch Companion** popup (`⚙️`) and paste the token to connect securely. / 拡張機能のポップアップ右上 (`⚙️`) を開き、トークンを貼り付けて保存します。

**Capabilities / 主な機能**:
- **Auto-Scan Active Tab / 開いているページのPDF自動スキャン**: Detects `.pdf` / `pdfengine` / datasheet links inside the active page and lets you pick items with checkboxes. / 表示中ページ内の `.pdf`・`pdfengine`・データシートリンクを検出し、チェックボックスで選んで一括送信できます。
- **Right-Click Context Menu / 右クリックメニュー**: Highlight any part number (e.g., `BES0002`) or right-click a link ➔ **`🛡️ AegisFetch で取得`**. / ページ上の型番テキストを選択、またはリンクを右クリックして **`🛡️ AegisFetch で取得`** から即座にダウンロードを開始できます。
- **Strict Least-Privilege Security / 最小権限セキュリティ**: Uses `activeTab` only (no `<all_urls>` spy permissions), strict MV3 CSP (`script-src 'self'`), and `X-Aegis-Token` + `chrome-extension://` Origin verification. / 最小権限（`activeTab` のみで `<all_urls>` 不使用）、厳格な MV3 CSP（`script-src 'self'`）、`X-Aegis-Token`＋`chrome-extension://` Origin 検証を採用しています。

### 3. Command Line (CLI) / コマンドライン

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

### Python SDK / Python ライブラリ利用例

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
Antigravity や Claude Code / Claude Desktop から直接ツール呼び出しでダウンロード・型番解決・他社データシート検索・無料プロキシ取得・非同期並列バッチ処理を実行できます。

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

- `aegisfetch_download_single`: Download a single document with WAF evasion and hop-by-hop SSRF guards. / WAF回避とリダイレクト先SSRF検証付きで単一ファイルをダウンロードします。
- `aegisfetch_download_by_part_number`: Automatically resolve part numbers (e.g. `BES0002`) into official PDF URLs and download them. / 型番（例: `BES0002`）から公式PDF URLを自動解決してダウンロードします。
- `aegisfetch_search_generic_datasheet`: Search the public web for datasheet PDF links for **any manufacturer part number** (Omron, Keyence, SMC, TI, etc.). / 他社を含む任意のメーカー型番のデータシートPDFリンクをWeb検索します。
- `aegisfetch_extract_pdf_links`: Scan a product webpage and extract all PDF links (with automatic Playwright SPA fallback). / 製品Webページを解析し、PDFリンクをすべて抽出します（SPA対応）。
- `aegisfetch_download_batch`: Synchronous batch download (up to 50 items) with jitter and circuit breaker protection. / ゆらぎ待機とサーキットブレーカー保護付きで同期一括ダウンロード（最大50件）を行います。
- `aegisfetch_start_batch_job`: Start a non-blocking background job (up to 500 items, supports `concurrency`, `proxies` rotation, and `check_updates`) to avoid MCP 60s tool timeouts. / 60秒タイムアウトを回避する非同期バックグラウンドジョブ（最大500件、並列数・プロキシローテーション・改訂チェック対応）を開始します。
- `aegisfetch_get_job_status`: Check real-time progress and results of a background download job. / バックグラウンドジョブのリアルタイム進捗と結果を取得します。
- `aegisfetch_fetch_free_proxies`: Harvest & live-test public HTTP/SOCKS5 proxies against Cloudflare HTTPS trace. / 公開HTTP/SOCKS5プロキシを収集し、Cloudflare HTTPS通信で生存テストを行います。
- `aegisfetch_verify_file`: Validate local file integrity (`%PDF` magic byte check). / ローカルファイルの整合性（`%PDF` マジックバイト）を検証します。
- `aegisfetch_get_status`: Report server health, active jobs, and active security guardrails. / サーバー稼働状況、実行中ジョブ、有効なセキュリティガードを返します。

---

## Advanced Productivity Features (v2.3.0) / 実務支援機能

- **ZIP Bulk Export & PDF Merger / ZIP一括出力＆PDF結合**: Download all fetched catalogs as a single `.zip` archive or merge them into one unified `merged_catalogs.pdf` directly from the Web UI. / 取得済みカタログをWeb UIからワンクリックで1つの `.zip` または結合済み `merged_catalogs.pdf` として出力できます。
- **CSV Report Export & Auto-Saved Settings / CSV結果出力＆設定自動保存**: Export full download results as BOM UTF-8 CSV and automatically persist your UI settings/proxy lists in `localStorage`. / ダウンロード結果をBOM付きUTF-8 CSVで出力し、UI設定やプロキシリストを `localStorage` に自動保存します。
- **Excel (.xlsx) / CSV / TXT Drag & Drop BOM Import / BOMファイル読込**: Drop any BOM file directly onto the Web UI input area to extract part numbers and URLs automatically. / Excel・CSV・TXTファイルをWeb UIへドラッグ＆ドロップするだけで型番・URLを自動抽出します。
- **One-Click Retry Failed / 失敗分ワンクリック再試行**: Re-queue only failed items after a batch run with a single click. / バッチ実行後に失敗した項目だけをワンクリックで再実行できます。
- **Multi-Locale Auto-Fallback (`ja-jp` ➔ `en-us` ➔ `de-de`) / 多言語自動フォールバック**: Automatically retrieves English or German datasheets if a Japanese version does not exist. / 日本語版が存在しない場合、英語版・ドイツ語版のデータシートを自動でフォールバック取得します。
- **Multi-Threaded Parallel Downloads (`concurrency=1..8`) / 並列高速ダウンロード**: Thread-local `curl_cffi` sessions combined with proxy rotation dramatically accelerate bulk downloads across both part resolution and file fetching. / スレッドローカルな `curl_cffi` セッションとプロキシ切替により、型番解決からPDF取得までを並列高速化します。
- **Cross-Manufacturer Generic Datasheet Search / 他社型番の横断PDF検索**: Automatically searches public PDF datasheets for non-BALLUFF part numbers. / BALLUFF以外のメーカー型番についても公開データシートPDFを自動探索します。
- **Catalog Revision / Update Check (`--check-updates`) / カタログ改訂・更新チェック**: Tracks `ETag`, `Last-Modified`, and `SHA-256` in `.aegisfetch_meta.json` with automatic `GET Range: bytes=0-0` fallback when `HEAD` is blocked. / `ETag`・`Last-Modified`・`SHA-256` を `.aegisfetch_meta.json` で管理し、`HEAD` 遮断時は `Range: bytes=0-0` にフォールバックして最新版のみ再取得します。

---

## Multi-Proxy IP Rotation & Free Proxy Harvester / 複数プロキシ自動ローテーション

AegisFetch v2.2+ supports switching proxy IP on **every single file download** (Round-Robin or Random):
AegisFetch v2.2 以降では、**1ファイルのダウンロードごとに別のプロキシIPへ切り替える**（ラウンドロビン / ランダム）ことができます：

- **Web UI Integration / Web UI 連携**: Paste multiple proxies into the dashboard or click **"⚡ 無料プロキシ取得＆テスト"** to harvest & verify live proxies in ~4 seconds. / ダッシュボードに複数プロキシを貼り付けるか、「⚡ 無料プロキシ取得＆テスト」ボタンで生存プロキシを約4秒で自動収集できます。
- **Dead-Proxy Eviction & Direct Fallback / 不通プロキシ除外＆直接通信救済**: Automatically drops broken proxies and falls back to direct connection on the final retry so downloads succeed reliably. / 応答しないプロキシを自動除外し、最終リトライ時は直接通信へフォールバックして成功率を高めます。
- **Credential Masking / 認証情報の自動マスク**: Proxy passwords (`http://user:pass@host:port`) are automatically masked as `***:***` in all logs, API responses, and UI views. / プロキシのユーザー名・パスワードはログ、API応答、UI表示のすべてで `***:***` に自動マスクされます。

---

## Security & Verification / セキュリティと脆弱性対策 (115/115 Tests Passing)

AegisFetch v2.5.0 is built with deep-defense security guardrails audited across 115 automated tests (104 offline checks across Ubuntu & Windows GitHub Actions CI):
AegisFetch v2.5.0 は多層防御セキュリティ設計に基づいており、115件の自動テスト（GitHub Actions CI 上の Ubuntu / Windows オフライン検証 104件を含む）で安全性を検証しています：

- **Browser Extension Local Bridge Security / 拡張機能ローカルブリッジ認証**: Enforces `X-Aegis-Token` (`hmac.compare_digest`), strict `chrome-extension://` Origin + local Host validation (`[::1]` IPv6 & userinfo smuggling checks), `Cache-Control: no-store`, `0o600` POSIX token file permissions, strict MV3 CSP (`script-src 'self'`), zero unsafe DOM sinks (`textContent`-only), and `activeTab` least privilege. / `X-Aegis-Token` 検証（`hmac.compare_digest`）、`chrome-extension://` Origin とローカル Host 検証、`Cache-Control: no-store`、POSIX `0o600` トークンファイル権限、厳格な MV3 CSP、安全な DOM 操作（`textContent` のみ）、`activeTab` 最小権限を徹底しています。
- **Direct, Open-Redirect (GET & HEAD), Playwright & Proxy-based SSRF Prevention / 多層SSRF防御**: Inspects every redirect hop (`301`/`302`/`307`/`308`) for GET/HEAD requests, Playwright subresource routes, `page_referer`, and proxy targets—blocking IPv4-mapped/6to4/Teredo/scoped IPv6, legacy `inet_aton` notations, `.localhost`, private IP ranges (RFC 1918), loopback (`127.0.0.1`), and cloud metadata endpoints (`169.254.169.254`). / GET/HEAD リダイレクト、Playwright 通信、`page_referer`、プロキシ設定のすべてでプライベートIP・ループバック・クラウドメタデータ・IPv6マップドIP・特殊IP表記・`.localhost` への到達を遮断します。
- **XLSX ZIP Decompression Bomb Defense / XLSX ZIPボム防御**: Pre-inspects uncompressed ZIP entry sizes in uploaded `.xlsx` BOM files (20MB cap, 5,000-row scan limit) before parsing. / アップロードされた `.xlsx` の展開後サイズ（上限20MB・5,000行上限）を解析前に検証します。
- **Web UI CSRF & DNS Rebinding Protection / CSRF・DNSリバインディング防御**: Strictly validates `Host` and `Origin` headers on local Web UI API endpoints (`127.0.0.1` / `localhost` / `[::1]` only) and enforces `X-Frame-Options: DENY` & `X-Content-Type-Options: nosniff`. / `Host`/`Origin` ヘッダをローカル限定で厳格検証し、セキュリティヘッダを付与します。
- **System Directory, Symlink & Path Traversal Defense / システム領域・シンボリックリンク防御**: Blocks writes to critical OS folders (`C:\Windows`, `/etc`, Startup) and enforces `islink` + `realpath`/`commonpath` confinement across downloads, ZIP/PDF exports, and `/files/` serving. / 重要システムフォルダへの書き込みを禁止し、ダウンロード保存・ZIP/PDF出力・`/files/` 配信のすべてでパストラバーサルとシンボリックリンク脱出を遮断します。
- **Streamed Chunk Size Cutoff / ストリームサイズ上限**: Streams downloads in 64KB chunks and aborts immediately if payload exceeds 100MB to prevent RAM/disk exhaustion. / 64KB チャンク単位で受信し、100MB 超過時は即座に中断してメモリ・ディスク枯渇を防ぎます。
- **Zero MCP Stdio Pollution / MCP標準出力の純粋性保証**: Directs all runtime logs strictly to `stderr` with safe CP932 fallback so MCP JSON-RPC streams remain 100% pure. / すべての実行ログを `stderr`（CP932フォールバック付き）へ分離し、MCP の JSON-RPC 通信を汚染しません。

Run the full verification suite / フル検証スイートの実行コマンド:
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

- **v2.5.0**:
  - **EN**: Enhanced Chrome/Edge MV3 extension & local bridge UX (`GET /api/jobs` auto-sync in Web UI, `POST /api/save-browser-pdf` for login-protected PDFs via active browser session, popup `concurrency`/`locale`/`check_updates` options, and shared ES module `chrome_extension/shared.js`); upgraded `extractors.py` with OMRON/KEYENCE/SMC/MITSUBISHI manufacturer prefix detection & 2-stage official-domain search; added atomic job history persistence (`~/.aegisfetch_ui_history.json`); separated Web UI static assets (`web_ui_static/`); and added Node.js 24 + `node --check` JS syntax verification in CI (**115/115 PASS** online, **104/104 PASS** offline CI).
  - **JA**: Chrome/Edge 拡張と Web UI の連携を強化（Web UI 側の `GET /api/jobs` 自動同期、会員限定PDF向けのブラウザ認証セッション経由保存 `POST /api/save-browser-pdf`、拡張ポップアップでの並列数/言語/改訂チェック設定、`chrome_extension/shared.js` 共通モジュール化）。OMRON・KEYENCE・SMC・三菱電機向け2段階公式ドメイン検索、ジョブ履歴のローカル永続化、Web UI 静的ファイル分離（`web_ui_static/`）、CI での Node24 対応および JS 構文チェックを追加（オンライン **115/115 PASS**、オフラインCI **104/104 PASS**）。
- **v2.4.1**:
  - **EN**: Hardened SSRF & proxy validation (IPv6-mapped/6to4/Teredo/scoped IPv6, legacy `inet_aton` notations, `.localhost`, CRLF/backslash authority confusion, Playwright `page.route` SSRF guard with clean teardown); fixed Web UI IPv6 `[::1]:port` Host parsing, `EXTENSION_TOKEN` JSON/Unicode escaping, `Cache-Control: no-store`, `0o600` token permissions, `/api/files` & `/files/` symlink/PDF confinement, and strict HTTP `400` validation; added `getSafePublicReferer()` and `error_code` 403 differentiation in the MV3 extension. Expanded test suite to **108/108 PASS** online (**97/97 PASS** offline CI).
  - **JA**: SSRF/プロキシ検証を強化（IPv6マップドIP・特殊IP表記・`.localhost`・CRLF・バックスラッシュ混乱・PlaywrightサブリソースSSRFの遮断）。Web UI の IPv6 `Host` 解析修正、トークンXSSエスケープと `Cache-Control: no-store`、`/files/` のシンボリックリンク・非PDF遮断、不正入力の HTTP `400` 応答を実装。拡張機能側でイントラネット `page_referer` 除外と 403 `error_code` 判別に対応（オンライン 108/108 PASS、オフラインCI 97/97 PASS）。
- **v2.4.0**:
  - **EN**: Added **AegisFetch Companion** Chrome / Edge MV3 extension (`chrome_extension/`) with active-tab PDF scanner, right-click context menus, live job progress bar, and PNG icons; upgraded `web_ui.py` local bridge with `X-Aegis-Token` auth, strict `chrome-extension://` CORS/preflight, `GET /api/health`, `page_referer` SSRF validation, and header token copy button (82/82 online, 71/71 offline CI).
  - **JA**: Chrome/Edge 用 MV3 拡張機能 **AegisFetch Companion**（ページ内PDFスキャン、右クリック取得メニュー、進捗バー、PNGアイコン）を追加し、`web_ui.py` に `X-Aegis-Token` 認証・厳格な CORS/Preflight・`/api/health`・トークンコピー機能を実装（オンライン 82/82、オフライン 71/71）。
- **v2.3.1**:
  - **EN**: Fixed cross-platform system directory validation (`C:\Windows` checks on Ubuntu Linux CI) and Python 3.12 docstring escape warning; added CSV Formula Injection protection; hardened `/api/download-zip` and `/api/merge-pdf` against symlink traversal; added Direct fallback on proxy-routed part resolution failure.
  - **JA**: Ubuntu/Windows クロスプラットフォームでのシステム領域判定修正、CSV 数式インジェクション対策、ZIP/PDF結合のシンボリックリンク対策、プロキシ失敗時の直接通信フォールバックを追加。
- **v2.3.0**:
  - **EN**: Added Web UI ZIP bulk download, PDF merger (`pypdf`), BOM UTF-8 CSV export, `localStorage` saved UI settings, shared thread-local proxy sessions, `GET Range: bytes=0-0` revision-check fallback, 50-job registry pruning, and GitHub Actions CI.
  - **JA**: ZIP一括ダウンロード、PDF結合、BOM付きUTF-8 CSV出力、`localStorage` 設定保存、スレッドローカルプロキシ共有、`Range` リクエストによる改訂チェック、ジョブ履歴50件上限プルーニング、GitHub Actions CI を追加。
- **v2.2.1**:
  - **EN**: Fixed Open-Redirect SSRF vector in revision-check `HEAD` requests, added `.xlsx` ZIP decompression bomb protection (20MB cap, 5,000-row limit), fixed dynamic `Last-Modified` false positives, upgraded to atomic `os.replace()`, and added POST body draining on early HTTP 403.
  - **JA**: 改訂チェック `HEAD` のオープンリダイレクトSSRF対策、`.xlsx` ZIPボム防御、動的 `Last-Modified` 誤検知修正、アトミック置換 `os.replace()`、早期403応答時のPOSTボディドレインを実装。
- **v2.2.0**:
  - **EN**: Added Web UI Excel (`.xlsx`) / CSV / TXT Drag & Drop BOM importer, One-Click Retry Failed, multi-locale auto-fallback (`ja-jp` ➔ `en-us` ➔ `de-de`), parallel downloads (`concurrency=1..8`), cross-vendor datasheet search, and catalog revision tracking (`--check-updates`).
  - **JA**: Excel/CSV/TXT ドラッグ＆ドロップ読込、失敗分ワンクリック再試行、多言語自動フォールバック、並列ダウンロード（1〜8並列）、他社型番横断検索、改訂チェックモードを追加。
- **v2.1.1**:
  - **EN**: Added Proxy-based SSRF prevention, automatic proxy credential masking (`***:***`), and Web UI CSRF / DNS Rebinding defenses.
  - **JA**: プロキシ経由SSRF防御、認証情報の自動マスク（`***:***`）、Web UI の CSRF / DNS リバインディング対策を追加。
- **v2.1.0**:
  - **EN**: Added Multi-Proxy IP Rotation (Round-Robin / Random), Free Public Proxy Harvester with Cloudflare HTTPS trace verification, and Web UI proxy console.
  - **JA**: 複数プロキシIPローテーション（順番/ランダム）、Cloudflare検証付き無料プロキシ自動収集、Web UI プロキシ操作画面を追加。
- **v2.0.0**:
  - **EN**: Added native MCP Server (`aegisfetch-mcp`), Web UI console (`aegisfetch-ui`), Extractor Engine, non-blocking Background Job Queue, and deep-defense security suite.
  - **JA**: ネイティブ MCP サーバー（`aegisfetch-mcp`）、Web UI コンソール（`aegisfetch-ui`）、PDFリンク/型番抽出エンジン、非同期バックグラウンドジョブキュー、多層セキュリティ検証スイートを追加。

---

## License / ライセンス

MIT License - Copyright (c) 2026 iwa-kasoutuuuuuka
