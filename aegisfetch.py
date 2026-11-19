"""
AegisFetch (PhantomDL) v2.1.0
=============================
High-resilience, anti-403, and WAF-evading catalog & document downloader.
Features:
- TLS/JA3/JA4 fingerprint impersonation (curl_cffi)
- Multi-Proxy Automatic Rotation (1 file = 1 distinct IP) with Dead-Proxy Eviction & Direct Fallback
- Built-in Free Public Proxy Harvester (verified against Cloudflare HTTPS trace)
- SSRF-safe hop-by-hop redirect validation with proper socket cleanup
- Streamed chunk downloading with strict max file size guard (100MB default)
- Adaptive rate-limiting (Jitter, Exponential Backoff, Circuit Breaker)
- Strict stderr logging (Zero stdout pollution for MCP stdio JSON-RPC safety & CP932 compatibility)
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
from proxy_manager import ProxyRotator, fetch_and_test_free_proxies

__version__ = "2.1.0"


@dataclass
class DownloadResult:
    url: str
    save_path: str
    success: bool
    status_code: Optional[int] = None
    size_bytes: int = 0
    error_msg: Optional[str] = None
    skipped: bool = False
    proxy_used: Optional[str] = None


class AegisFetch:
    """
    AegisFetch v2.1.0 Downloader Core Engine with Multi-Proxy Rotation
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
        proxies: Optional[List[str]] = None,
        proxy_rotation_mode: str = "round_robin",
        fallback_to_direct: bool = True,
        verify_pdf: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        enable_playwright_fallback: bool = True,
        quiet: bool = False,
    ):
        self.output_dir = validate_output_directory(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        self.min_delay = min_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.fallback_to_direct = fallback_to_direct
        self.verify_pdf = verify_pdf
        self.max_file_size = max_file_size
        self.enable_playwright_fallback = enable_playwright_fallback
        self.quiet = quiet

        # Setup Proxy Rotator
        combined_proxies: List[str] = []
        if proxies:
            combined_proxies.extend(proxies)
        if proxy:
            combined_proxies.append(proxy)

        self.proxy_rotator = ProxyRotator(
            proxies=combined_proxies,
            mode=proxy_rotation_mode
        )
        self.current_proxy: Optional[str] = None

        self.consecutive_failures = 0
        self.session: Optional[requests.Session] = None
        self._init_session(rotate_proxy=True)

    def _log(self, msg: str, end: str = "\n", flush: bool = True):
        """
        Output logs exclusively to sys.stderr (never sys.stdout) to preserve
        MCP stdio JSON-RPC stream integrity, with safe encoding fallback for Windows CP932.
        """
        if self.quiet:
            return
        try:
            sys.stderr.write(msg + end)
            if flush:
                sys.stderr.flush()
        except UnicodeEncodeError:
            safe_msg = (msg + end).encode("ascii", errors="replace").decode("ascii")
            sys.stderr.write(safe_msg)
            if flush:
                sys.stderr.flush()

    def _init_session(self, rotate_proxy: bool = True, force_direct: bool = False):
        """Initialize or rotate HTTP/2 & TLS browser fingerprint session and proxy IP."""
        if self.session is not None:
            try:
                self.session.close()
            except Exception:
                pass

        target = random.choice(self.IMPERSONATE_TARGETS)
        self.session = requests.Session(impersonate=target)

        if force_direct:
            self.current_proxy = None
        elif rotate_proxy and self.proxy_rotator.total_count > 0:
            self.current_proxy = self.proxy_rotator.get_next_proxy()

        if self.current_proxy:
            self.session.proxies = {
                "http": self.current_proxy,
                "https": self.current_proxy,
            }
        else:
            self.session.proxies = {}

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
        stream: bool = True,
        timeout: int = 20
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
                timeout=timeout
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location") or resp.headers.get("location")
                resp.close()
                current_url = validate_redirect_target(current_url, loc)
                continue
            return resp

        raise SecurityValidationError(f"Exceeded maximum redirect hops ({MAX_REDIRECT_HOPS}).")

    def _stream_to_temp_file(self, resp: requests.Response, temp_path: str, is_pdf: bool) -> int:
        """
        Stream response chunks to disk while enforcing max_file_size and magic byte checks.
        """
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
        """
        Download a single resource with automatic proxy rotation (1 file = 1 new proxy IP).
        """
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
                skipped=True,
                proxy_used="SKIPPED"
            )

        # Rotate proxy before starting this file download so every item uses the next IP
        if self.proxy_rotator.total_count > 0:
            self._init_session(rotate_proxy=True)

        # Circuit Breaker: Trip when consecutive failures exceed threshold
        if self.consecutive_failures >= self.circuit_breaker_threshold:
            cooldown = 45.0 + random.uniform(5.0, 15.0)
            self._log(f"\n[AegisFetch Circuit Breaker] {self.consecutive_failures} consecutive errors. Cooling down for {cooldown:.1f}s...")
            time.sleep(cooldown)
            self._init_session(rotate_proxy=True)
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
            resp = None
            # If proxies are configured and all proxy retries failed, fallback to Direct on final attempt
            use_direct_fallback = (
                self.proxy_rotator.total_count > 0
                and self.fallback_to_direct
                and attempt == self.max_retries
            )
            if use_direct_fallback:
                self._init_session(rotate_proxy=False, force_direct=True)

            active_route = self.current_proxy or "DIRECT"
            req_timeout = 12 if self.current_proxy else 25

            try:
                self._wait_jitter()
                resp = self._get_with_safe_redirects(url, headers=headers, stream=True, timeout=req_timeout)
                last_status = resp.status_code

                # Exponential backoff or proxy switch on 403 / 429
                if resp.status_code in (403, 429):
                    resp.close()
                    if self.current_proxy:
                        self.proxy_rotator.report_failure(self.current_proxy)
                        self._log(f" [HTTP {resp.status_code} via {active_route}] Rotating to next proxy IP (Attempt {attempt}/{self.max_retries})...")
                        self._init_session(rotate_proxy=True)
                    else:
                        backoff = (2 ** attempt) * 3 + random.uniform(1.0, 3.0)
                        self._log(f" [HTTP {resp.status_code} detected] Backoff wait {backoff:.1f}s (Attempt {attempt}/{self.max_retries})...")
                        time.sleep(backoff)
                        self._init_session(rotate_proxy=False)
                    continue

                if resp.status_code == 200:
                    total_bytes = self._stream_to_temp_file(resp, temp_path, is_pdf=is_pdf)
                    resp.close()

                    if os.path.exists(final_path):
                        os.remove(final_path)
                    os.rename(temp_path, final_path)

                    if self.current_proxy:
                        self.proxy_rotator.report_success(self.current_proxy)

                    self.consecutive_failures = 0
                    return DownloadResult(
                        url=url,
                        save_path=final_path,
                        success=True,
                        status_code=200,
                        size_bytes=total_bytes,
                        proxy_used=active_route
                    )
                else:
                    last_error = f"HTTP {resp.status_code}"
                    if self.current_proxy:
                        self.proxy_rotator.report_failure(self.current_proxy)
                        self._init_session(rotate_proxy=True)

            except SecurityValidationError as sve:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
                return DownloadResult(
                    url=url,
                    save_path=final_path,
                    success=False,
                    status_code=last_status,
                    error_msg=f"SecurityValidationError: {sve}",
                    proxy_used=active_route
                )
            except Exception as e:
                last_error = str(e)
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
                if self.current_proxy:
                    self.proxy_rotator.report_failure(self.current_proxy)
                    self._init_session(rotate_proxy=True)
                else:
                    time.sleep(1.5 * attempt)
            finally:
                if resp is not None:
                    try:
                        resp.close()
                    except Exception:
                        pass

        self.consecutive_failures += 1
        return DownloadResult(
            url=url,
            save_path=final_path,
            success=False,
            status_code=last_status,
            error_msg=last_error,
            proxy_used=self.current_proxy or "DIRECT"
        )

    def download_batch(
        self,
        targets: List[Dict[str, str]],
        on_progress: Optional[Callable[[int, int, DownloadResult], None]] = None
    ) -> List[DownloadResult]:
        """Download multiple files sequentially with adaptive throttling and proxy rotation."""
        total = len(targets)
        results = []

        self._log(f"\n[AegisFetch v{__version__}] Starting Download Task ({total} items)")
        self._log(f"Destination: {self.output_dir}")
        self._log(f"Jitter Interval: {self.min_delay}s - {self.max_delay}s")
        if self.proxy_rotator.total_count > 0:
            self._log(f"Proxy Rotation: ACTIVE ({self.proxy_rotator.total_count} proxies loaded, Mode={self.proxy_rotator.mode})")
        else:
            self._log("Proxy Rotation: DIRECT (No proxies configured)")
        self._log("-" * 65)

        for idx, item in enumerate(targets, 1):
            url = item["url"]
            fname = item.get("filename")
            ref = item.get("referer")

            self._log(f"[{idx}/{total}] Fetching: {fname or url} ...", end=" ")
            res = self.download_file(url, filename=fname, referer=ref)
            results.append(res)

            route_info = f" via {res.proxy_used}" if res.proxy_used and res.proxy_used not in ("DIRECT", "SKIPPED") else ""
            if res.skipped:
                self._log(f"[SKIP] (Existing: {res.size_bytes // 1024} KB)")
            elif res.success:
                self._log(f"[OK{route_info}] ({res.size_bytes // 1024} KB)")
            else:
                self._log(f"[FAILED{route_info}] ({res.error_msg or res.status_code})")

            if on_progress:
                on_progress(idx, total, res)

        success_count = sum(1 for r in results if r.success)
        skipped_count = sum(1 for r in results if r.skipped)
        failed_count = sum(1 for r in results if not r.success)

        self._log("-" * 65)
        self._log(f"Finished! Total: {total} | Success: {success_count} (Skipped: {skipped_count}) | Failed: {failed_count}\n")
        return results


# Backwards compatibility alias
RobustDownloader = AegisFetch


def main():
    parser = argparse.ArgumentParser(
        description="AegisFetch v2.1.0: High-resilience, Anti-403 WAF-Evading Catalog & Document Downloader with Proxy Rotation"
    )
    parser.add_argument("--urls", nargs="+", help="Target URLs to download directly")
    parser.add_argument("--list-file", help="Path to text file containing URLs or part numbers (one per line)")
    parser.add_argument("--balluff-parts", nargs="+", help="BALLUFF order codes / part numbers to resolve and download (e.g. BES0002)")
    parser.add_argument("--extract-url", help="Product web page URL from which to automatically extract and download all PDFs")
    parser.add_argument("--out-dir", default="./downloads", help="Output directory path (default: ./downloads)")
    parser.add_argument("--min-delay", type=float, default=1.0, help="Minimum jitter delay in seconds (default: 1.0)")
    parser.add_argument("--max-delay", type=float, default=2.5, help="Maximum jitter delay in seconds (default: 2.5)")
    parser.add_argument("--proxy", help="Single proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--proxies", nargs="+", help="Multiple proxy URLs for automatic rotation (1 request = 1 distinct IP)")
    parser.add_argument("--proxy-file", help="Path to text file containing proxy URLs (one per line)")
    parser.add_argument("--auto-free-proxies", action="store_true", help="Automatically harvest and test free public proxies before starting")
    parser.add_argument("--no-direct-fallback", action="store_true", help="Disable direct connection fallback if all proxies fail")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress logs")
    parser.add_argument("--version", action="version", version=f"AegisFetch v{__version__}")

    args = parser.parse_args()

    from extractors import CatalogExtractor

    proxy_list: List[str] = []
    if args.proxies:
        proxy_list.extend(args.proxies)
    if args.proxy_file and os.path.exists(args.proxy_file):
        with open(args.proxy_file, "r", encoding="utf-8") as pf:
            proxy_list.extend([l.strip() for l in pf if l.strip() and not l.strip().startswith("#")])
    if args.auto_free_proxies:
        if not args.quiet:
            sys.stderr.write("[AegisFetch] Harvesting and testing free public proxies...\n")
        harv = fetch_and_test_free_proxies(target_working_count=12)
        proxy_list.extend(harv.get("working_proxies", []))
        if not args.quiet:
            sys.stderr.write(f"[AegisFetch] Loaded {len(proxy_list)} verified free proxies!\n")

    fetcher = AegisFetch(
        output_dir=args.out_dir,
        min_delay=args.min_delay,
        max_delay=args.max_delay,
        proxy=args.proxy,
        proxies=proxy_list,
        fallback_to_direct=not args.no_direct_fallback,
        quiet=args.quiet
    )

    targets = []

    if args.balluff_parts:
        for part in args.balluff_parts:
            try:
                info = CatalogExtractor.resolve_balluff_part(part, session=fetcher.session)
                targets.append(info)
            except Exception as e:
                sys.stderr.write(f"[Extractor Error] {part}: {e}\n")
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
                            sys.stderr.write(f"[Extractor Error] {line}: {e}\n")
    else:
        parser.print_help()
        sys.exit(1)

    if targets:
        fetcher.download_batch(targets)


if __name__ == "__main__":
    main()
