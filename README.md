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
pip install -r requirements.txt
```

---

## Usage / 使い方

### Command Line (CLI)

```bash
# 1. Download directly via URLs
python aegisfetch.py --urls "https://example.com/item1.pdf" "https://example.com/item2.pdf" --out-dir "./my_catalogs"

# 2. Download from a list file (one URL per line)
python aegisfetch.py --list-file "urls.txt" --out-dir "./my_catalogs" --min-delay 1.5 --max-delay 3.0
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
