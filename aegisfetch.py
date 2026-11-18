"""
AegisFetch (PhantomDL)
======================
High-resilience, anti-403, and WAF-evading catalog & document downloader.
TLS/JA3/JA4 fingerprint impersonation, adaptive rate-limiting, and atomic verification.

Copyright (c) 2026 iwa-kasoutuuuuuka
Licensed under the MIT License.
"""

import os
import sys
import time
import random
import argparse
from typing import Optional, List, Dict, Callable
from dataclasses import dataclass
from curl_cffi import requests

__version__ = "1.0.0"

@dataclass
class DownloadResult:
    url: str
    save_path: str
    success: bool
    status_code: Optional[int] = None
    size_bytes: int = 0
    error_msg: Optional[str] = None
    skipped: bool = False


class AegisFetch:
    """
    AegisFetch Downloader Core Engine
    """
    # Supported browser impersonation targets
    IMPERSONATE_TARGETS = ["chrome124", "chrome120", "safari15_5", "chrome110"]

    def __init__(
        self,
        output_dir: str = "./downloads",
        min_delay: float = 1.0,
        max_delay: float = 2.5,
        max_retries: int = 4,
        circuit_breaker_threshold: int = 5,
        proxy: Optional[str] = None,
        verify_pdf: bool = True
    ):
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        self.min_delay = min_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.proxy = proxy
        self.verify_pdf = verify_pdf

        self.consecutive_failures = 0
        self.session: Optional[requests.Session] = None
        self._init_session()

    def _init_session(self):
        """Initialize or rotate HTTP/2 & TLS browser fingerprint session."""
        target = random.choice(self.IMPERSONATE_TARGETS)
        self.session = requests.Session(impersonate=target)
        if self.proxy:
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy
            }
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,*/*;q=0.8",
            "Accept-Language": "ja,en-US;q=0.9,en;q=0.8",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
        })

    def _wait_jitter(self):
        """Randomized sleep interval to break rate-limit detection patterns."""
        delay = random.uniform(self.min_delay, self.max_delay)
        time.sleep(delay)

    def _check_file_validity(self, file_path: str) -> bool:
        """Verify downloaded file integrity (exclude HTML error pages and 0-byte files)."""
        if not os.path.exists(file_path):
            return False
        if os.path.getsize(file_path) < 512:
            return False

        if self.verify_pdf and file_path.lower().endswith(".pdf"):
            with open(file_path, "rb") as f:
                header = f.read(5)
                return header.startswith(b"%PDF")
        return True

    def download_file(
        self,
        url: str,
        filename: Optional[str] = None,
        referer: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None
    ) -> DownloadResult:
        """Download a single resource with resilience checks."""
        if not filename:
            filename = url.split("?")[0].split("/")[-1] or "download.pdf"
            if not os.path.splitext(filename)[1]:
                filename += ".pdf"

        safe_filename = "".join(c for c in filename if c.isalnum() or c in "._- ")
        final_path = os.path.join(self.output_dir, safe_filename)
        temp_path = final_path + ".tmp"

        # Resume Check: Skip if intact file already exists
        if os.path.exists(final_path) and self._check_file_validity(final_path):
            return DownloadResult(
                url=url,
                save_path=final_path,
                success=True,
                size_bytes=os.path.getsize(final_path),
                skipped=True
            )

        # Circuit Breaker: Trip when consecutive failures exceed threshold
        if self.consecutive_failures >= self.circuit_breaker_threshold:
            cooldown = 45.0 + random.uniform(5.0, 15.0)
            print(f"\n[AegisFetch Circuit Breaker] {self.consecutive_failures} consecutive errors. Cooling down for {cooldown:.1f}s...")
            time.sleep(cooldown)
            self._init_session()
            self.consecutive_failures = 0

        headers = {}
        if referer:
            headers["Referer"] = referer
        if custom_headers:
            headers.update(custom_headers)

        last_error = None
        last_status = None

        for attempt in range(1, self.max_retries + 1):
            try:
                self._wait_jitter()
                resp = self.session.get(url, headers=headers, timeout=25)
                last_status = resp.status_code

                # Exponential backoff on 403 / 429
                if resp.status_code in (403, 429):
                    backoff = (2 ** attempt) * 3 + random.uniform(1.0, 3.0)
                    print(f" [HTTP {resp.status_code} detected] Backoff wait {backoff:.1f}s (Attempt {attempt}/{self.max_retries})...")
                    time.sleep(backoff)
                    self._init_session()
                    continue

                if resp.status_code == 200:
                    content = resp.content

                    # Validate PDF magic bytes
                    if self.verify_pdf and final_path.lower().endswith(".pdf"):
                        if not content.startswith(b"%PDF"):
                            raise ValueError("Received invalid payload (Likely HTML block challenge instead of PDF)")

                    # Atomic save (.tmp -> target)
                    with open(temp_path, "wb") as f:
                        f.write(content)

                    if os.path.exists(final_path):
                        os.remove(final_path)
                    os.rename(temp_path, final_path)

                    self.consecutive_failures = 0
                    return DownloadResult(
                        url=url,
                        save_path=final_path,
                        success=True,
                        status_code=200,
                        size_bytes=len(content)
                    )
                else:
                    last_error = f"HTTP {resp.status_code}"

            except Exception as e:
                last_error = str(e)
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                time.sleep(2.0 * attempt)

        self.consecutive_failures += 1
        return DownloadResult(
            url=url,
            save_path=final_path,
            success=False,
            status_code=last_status,
            error_msg=last_error
        )

    def download_batch(
        self,
        targets: List[Dict[str, str]],
        on_progress: Optional[Callable[[int, int, DownloadResult], None]] = None
    ) -> List[DownloadResult]:
        """Download multiple files sequentially with adaptive throttling."""
        total = len(targets)
        results = []

        print(f"\n🛡️ AegisFetch v{__version__} Starting Download Task ({total} items)")
        print(f"📁 Destination: {self.output_dir}")
        print(f"⏱️ Jitter Interval: {self.min_delay}s - {self.max_delay}s")
        print("-" * 65)

        for idx, item in enumerate(targets, 1):
            url = item["url"]
            fname = item.get("filename")
            ref = item.get("referer")

            print(f"[{idx}/{total}] Fetching: {fname or url} ...", end=" ", flush=True)
            res = self.download_file(url, filename=fname, referer=ref)
            results.append(res)

            if res.skipped:
                print(f"[SKIP] (Existing: {res.size_bytes // 1024} KB)")
            elif res.success:
                print(f"[OK] ({res.size_bytes // 1024} KB)")
            else:
                print(f"[FAILED] ({res.error_msg or res.status_code})")

            if on_progress:
                on_progress(idx, total, res)

        success_count = sum(1 for r in results if r.success)
        skipped_count = sum(1 for r in results if r.skipped)
        failed_count = sum(1 for r in results if not r.success)

        print("-" * 65)
        print(f"✨ Finished! Total: {total} | Success: {success_count} (Skipped: {skipped_count}) | Failed: {failed_count}\n")
        return results

# Backwards compatibility alias
RobustDownloader = AegisFetch


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ AegisFetch: High-resilience, Anti-403 WAF-Evading Catalog & Document Downloader"
    )
    parser.add_argument("--urls", nargs="+", help="Target URLs to download")
    parser.add_argument("--list-file", help="Path to text file containing URLs (one per line)")
    parser.add_argument("--out-dir", default="./downloads", help="Output directory path (default: ./downloads)")
    parser.add_argument("--min-delay", type=float, default=1.0, help="Minimum jitter delay in seconds (default: 1.0)")
    parser.add_argument("--max-delay", type=float, default=2.5, help="Maximum jitter delay in seconds (default: 2.5)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)")
    parser.add_argument("--version", action="version", version=f"AegisFetch v{__version__}")

    args = parser.parse_args()

    targets = []
    if args.urls:
        for u in args.urls:
            targets.append({"url": u.strip()})
    elif args.list_file and os.path.exists(args.list_file):
        with open(args.list_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append({"url": line})
    else:
        parser.print_help()
        sys.exit(1)

    fetcher = AegisFetch(
        output_dir=args.out_dir,
        min_delay=args.min_delay,
        max_delay=args.max_delay,
        proxy=args.proxy
    )
    fetcher.download_batch(targets)


if __name__ == "__main__":
    main()
