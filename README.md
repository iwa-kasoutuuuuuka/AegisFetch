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

### 2. Command Line (CLI)

```bash
# 1. Download directly via URLs / URLを直接指定
aegisfetch --urls "https://example.com/item1.pdf" "https://example.com/item2.pdf" --out-dir "./my_catalogs"

# 2. Resolve & download by Part Numbers (e.g. BALLUFF) / 型番から自動検索＆ダウンロード
aegisfetch --balluff-parts BES0002 BES0003 --out-dir "./my_catalogs"

# 3. Extract all PDFs from a product page / 製品ページからPDFを自動抽出
aegisfetch --extract-url "https://www.balluff.com/ja-jp/products/BES0002" --out-dir "./my_catalogs"

# 4. Download from a list file (URLs or part numbers) / リストファイルから一括取得
aegisfetch --list-file "urls.txt" --out-dir "./my_catalogs" --min-delay 1.0 --max-delay 2.5
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

### Model Context Protocol (MCP) Server / MCPサーバー (v2.0)

AegisFetch includes a native MCP server for seamless integration with **Antigravity**, **Claude Code**, and **Claude Desktop**.
Antigravity や Claude Code から直接ツール呼び出しでダウンロード・型番解決・非同期バッチ処理を実行できます。

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

#### 2. Available MCP Tools (8 Tools) / 提供ツール一覧

- `aegisfetch_download_single`: Download a single document with WAF evasion and hop-by-hop SSRF guards.
- `aegisfetch_download_by_part_number`: Automatically resolve part numbers (e.g. `BES0002`) into official PDF URLs and download them.
- `aegisfetch_extract_pdf_links`: Scan a product webpage and extract all PDF links (with automatic Playwright SPA fallback).
- `aegisfetch_download_batch`: Synchronous batch download (up to 50 items) with jitter and circuit breaker protection.
- `aegisfetch_start_batch_job`: Start a non-blocking background job (up to 500 items) to avoid MCP 60s tool timeouts.
- `aegisfetch_get_job_status`: Check real-time progress and results of a background download job.
- `aegisfetch_verify_file`: Validate local file integrity (`%PDF` magic byte check).
- `aegisfetch_get_status`: Report server health, active jobs, and active security guardrails.

---

## Security & Verification / セキュリティと脆弱性対策 (30/30 Tests Passing)

AegisFetch v2.0 is built with deep-defense security guardrails:
- **Direct & Open-Redirect SSRF Prevention**: Inspects every redirect hop (`301`/`302`/`307`/`308`) and blocks private IP ranges (RFC 1918), loopback (`127.0.0.1`), and cloud metadata endpoints (`169.254.169.254`).
- **System Directory & Path Traversal Defense**: Blocks writes to critical OS folders (`C:\Windows`, `/etc`, Startup) and confines output paths via `os.path.commonpath`.
- **Streamed Chunk Size Cutoff**: Streams downloads in 64KB chunks and aborts immediately if payload exceeds 100MB to prevent RAM/disk exhaustion.

Run the verification suite:
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
| `--proxy` | `None` | HTTP or SOCKS5 proxy URL / プロキシ指定 |

---

## License

MIT License - Copyright (c) 2026 iwa-kasoutuuuuuka
