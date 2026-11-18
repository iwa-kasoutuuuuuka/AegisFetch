"""
AegisFetch (PhantomDL) v2.0
===========================
High-resilience, anti-403, and WAF-evading catalog & document downloader.
Features:
- TLS/JA3/JA4 fingerprint impersonation (curl_cffi)
- SSRF-safe hop-by-hop redirect validation
- Streamed chunk downloading with strict max file size guard (100MB default)
- Adaptive rate-limiting (Jitter, Exponential Backoff, Circuit Breaker)
- Automatic Playwright headless fallback for JS-heavy / SPA endpoints
- Built-in Part Number Extractor (BALLUFF & Generic web pages)

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

from security import (
    validate_url,
    validate_redirect_target,
    validate_output_directory,
    sanitize_filename,
    secure_output_path,
    SecurityValidationError,
    DEFAULT_MAX_FILE_SIZE,
    MAX_REDIRECT_HOPS,
)

__version__ = "2.0.0"


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
    AegisFetch v2.0 Downloader Core Engine
    """
    IMPERSONATE_TARGETS = ["chrome124", "chrome120", "safari15_5", "chrome110"]

    def __init__(
        self,
        output_dir: str = "./downloads",
        min_delay: float = 1.0,
        max_delay: float = 2.5,
        max_retries: int = 4,
        circuit_breaker_threshold: int = 5,
        proxy: Optional[str] = None,
        verify_pdf: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        enable_playwright_fallback: bool = True,
    ):
        self.output_dir = validate_output_directory(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        self.min_delay = min_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.proxy = proxy
        self.verify_pdf = verify_pdf
        self.max_file_size = max_file_size
        self.enable_playwright_fallback = enable_playwright_fallback

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
                "https": self.proxy,
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
        size = os.path.getsize(file_path)
        if size < 512 or size > self.max_file_size:
            return False

        if self.verify_pdf and file_path.lower().endswith(".pdf"):
            with open(file_path, "rb") as f:
                header = f.read(5)
                return header.startswith(b"%PDF")
        return True

    def _get_with_safe_redirects(
        self,
        url: str,
        headers: Dict[str, str],
        stream: bool = True
    ) -> requests.Response:
        """
        Execute GET request while manually validating every HTTP redirect hop against SSRF.
        """
        current_url = validate_url(url)
        for _ in range(MAX_REDIRECT_HOPS):
            resp = self.session.get(
                current_url,
                headers=headers,
                allow_redirects=False,
                stream=stream,
                timeout=25
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location") or resp.headers.get("location")
                current_url = validate_redirect_target(current_url, loc)
                continue
            return resp

        raise SecurityValidationError(f"Exceeded maximum redirect hops ({MAX_REDIRECT_HOPS}).")

    def _stream_to_temp_file(self, resp: requests.Response, temp_path: str, is_pdf: bool) -> int:
        """
        Stream response chunks to disk while enforcing max_file_size and magic byte checks.
        Prevents memory exhaustion on huge payloads.
        """
        # Check Content-Length header upfront if present
        cl_header = resp.headers.get("Content-Length") or resp.headers.get("content-length")
        if cl_header and cl_header.isdigit():
            declared_size = int(cl_header)
            if declared_size > self.max_file_size:
                raise SecurityValidationError(
                    f"Declared Content-Length ({declared_size} bytes) exceeds max allowed size ({self.max_file_size} bytes)."
                )

        total_bytes = 0
        first_chunk_checked = False

        with open(temp_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                if not first_chunk_checked:
                    first_chunk_checked = True
                    if is_pdf and self.verify_pdf and not chunk.startswith(b"%PDF"):
                        raise ValueError(
                            "Received invalid payload (Likely HTML block challenge instead of PDF)"
                        )
                total_bytes += len(chunk)
                if total_bytes > self.max_file_size:
                    raise SecurityValidationError(
                        f"Stream exceeded maximum allowed file size ({self.max_file_size} bytes). Aborting."
                    )
                f.write(chunk)

        if total_bytes < 512:
            raise ValueError(f"Downloaded payload too small ({total_bytes} bytes) to be a valid document.")

        return total_bytes

    def download_file(
        self,
        url: str,
        filename: Optional[str] = None,
        referer: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None
    ) -> DownloadResult:
        """Download a single resource with full security and resilience checks."""
        if not filename:
            filename = url.split("?")[0].split("/")[-1] or "download.pdf"
            if not os.path.splitext(filename)[1]:
                filename += ".pdf"

        safe_filename = sanitize_filename(filename)
        final_path = secure_output_path(self.output_dir, safe_filename)
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
            headers["Referer"] = validate_url(referer)
        if custom_headers:
            headers.update(custom_headers)

        last_error = None
        last_status = None
        is_pdf = final_path.lower().endswith(".pdf")

        for attempt in range(1, self.max_retries + 1):
            try:
                self._wait_jitter()
                resp = self._get_with_safe_redirects(url, headers=headers, stream=True)
                last_status = resp.status_code

                # Exponential backoff on 403 / 429
                if resp.status_code in (403, 429):
                    backoff = (2 ** attempt) * 3 + random.uniform(1.0, 3.0)
                    print(f" [HTTP {resp.status_code} detected] Backoff wait {backoff:.1f}s (Attempt {attempt}/{self.max_retries})...")
                    time.sleep(backoff)
                    self._init_session()
                    continue

                if resp.status_code == 200:
                    total_bytes = self._stream_to_temp_file(resp, temp_path, is_pdf=is_pdf)

                    if os.path.exists(final_path):
                        os.remove(final_path)
                    os.rename(temp_path, final_path)

                    self.consecutive_failures = 0
                    return DownloadResult(
                        url=url,
                        save_path=final_path,
                        success=True,
                        status_code=200,
                        size_bytes=total_bytes
                    )
                else:
                    last_error = f"HTTP {resp.status_code}"

            except SecurityValidationError as sve:
                # Security violations should not be retried
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                return DownloadResult(
                    url=url,
                    save_path=final_path,
                    success=False,
                    status_code=last_status,
                    error_msg=f"SecurityValidationError: {sve}"
                )
            except Exception as e:
                last_error = str(e)
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                time.sleep(1.5 * attempt)

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
        description="🛡️ AegisFetch v2.0: High-resilience, Anti-403 WAF-Evading Catalog & Document Downloader"
    )
    parser.add_argument("--urls", nargs="+", help="Target URLs to download directly")
    parser.add_argument("--list-file", help="Path to text file containing URLs or part numbers (one per line)")
    parser.add_argument("--balluff-parts", nargs="+", help="BALLUFF order codes / part numbers to resolve and download (e.g. BES0002)")
    parser.add_argument("--extract-url", help="Product web page URL from which to automatically extract and download all PDFs")
    parser.add_argument("--out-dir", default="./downloads", help="Output directory path (default: ./downloads)")
    parser.add_argument("--min-delay", type=float, default=1.0, help="Minimum jitter delay in seconds (default: 1.0)")
    parser.add_argument("--max-delay", type=float, default=2.5, help="Maximum jitter delay in seconds (default: 2.5)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--version", action="version", version=f"AegisFetch v{__version__}")

    args = parser.parse_args()

    from extractors import CatalogExtractor

    fetcher = AegisFetch(
        output_dir=args.out_dir,
        min_delay=args.min_delay,
        max_delay=args.max_delay,
        proxy=args.proxy
    )

    targets = []

    if args.balluff_parts:
        for part in args.balluff_parts:
            try:
                info = CatalogExtractor.resolve_balluff_part(part, session=fetcher.session)
                targets.append(info)
            except Exception as e:
                print(f"[Extractor Error] {part}: {e}")
    elif args.extract_url:
        targets.extend(CatalogExtractor.extract_pdf_links_from_url(args.extract_url, session=fetcher.session))
    elif args.urls:
        for u in args.urls:
            targets.append({"url": u.strip()})
    elif args.list_file and os.path.exists(args.list_file):
        with open(args.list_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if line.lower().startswith("http"):
                        targets.append({"url": line})
                    else:
                        try:
                            info = CatalogExtractor.resolve_balluff_part(line, session=fetcher.session)
                            targets.append(info)
                        except Exception as e:
                            print(f"[Extractor Error] {line}: {e}")
    else:
        parser.print_help()
        sys.exit(1)

    if targets:
        fetcher.download_batch(targets)


if __name__ == "__main__":
    main()
