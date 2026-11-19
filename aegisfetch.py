"""
AegisFetch (PhantomDL) v2.2.0
=============================
High-resilience, anti-403, and WAF-evading catalog & document downloader.
Features:
- TLS/JA3/JA4 fingerprint impersonation (curl_cffi)
- Thread-safe Multi-Proxy Automatic Rotation (1 file = 1 distinct IP)
- Multi-threaded Parallel Downloads (concurrency=1..8 with per-thread sessions)
- Catalog Revision / Update Detection (ETag, Last-Modified, Content-Length & SHA-256 tracking)
- SSRF-safe hop-by-hop redirect validation with proper socket cleanup
- Streamed chunk downloading with strict max file size guard (100MB default)
- Adaptive rate-limiting (Jitter, Exponential Backoff, Circuit Breaker)
- Strict stderr logging (Zero stdout pollution for MCP stdio JSON-RPC safety & CP932 compatibility)

Copyright (c) 2026 iwa-kasoutuuuuuka
Licensed under the MIT License.
"""

import os
import sys
import json
import time
import hashlib
import random
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Callable, Any
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
from proxy_manager import ProxyRotator, fetch_and_test_free_proxies, mask_proxy_credentials

__version__ = "2.2.1"


@dataclass
class DownloadResult:
    url: str
    save_path: str
    success: bool
    status_code: Optional[int] = None
    size_bytes: int = 0
    error_msg: Optional[str] = None
    skipped: bool = False
    updated: bool = False
    proxy_used: Optional[str] = None


class AegisFetch:
    """
    AegisFetch v2.2.0 Downloader Core Engine with Parallelism & Revision Tracking
    """
    IMPERSONATE_TARGETS = ["chrome124", "chrome120", "safari15_5", "chrome110"]
    META_FILENAME = ".aegisfetch_meta.json"

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
        check_updates: bool = False,
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
        self.check_updates = check_updates
        self.quiet = quiet

        combined_proxies: List[str] = []
        if proxies:
            combined_proxies.extend(proxies)
        if proxy:
            combined_proxies.append(proxy)

        self.proxy_rotator = ProxyRotator(
            proxies=combined_proxies,
            mode=proxy_rotation_mode
        )

        self._state_lock = threading.Lock()
        self._meta_lock = threading.Lock()
        self._file_lock = threading.Lock()
        self._thread_local = threading.local()
        self.consecutive_failures = 0

        # Initialize main thread session for backward compatibility
        self._init_session(rotate_proxy=True)

    @property
    def session(self) -> Optional[requests.Session]:
        return getattr(self._thread_local, "session", None)

    @session.setter
    def session(self, value: Optional[requests.Session]):
        self._thread_local.session = value

    @property
    def current_proxy(self) -> Optional[str]:
        return getattr(self._thread_local, "current_proxy", None)

    @current_proxy.setter
    def current_proxy(self, value: Optional[str]):
        self._thread_local.current_proxy = value

    def _log(self, msg: str, end: str = "\n", flush: bool = True):
        """
        Thread-safe logging to sys.stderr (never sys.stdout) to preserve
        MCP stdio JSON-RPC stream integrity, with safe CP932 encoding fallback.
        """
        if self.quiet:
            return
        with self._state_lock:
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
        """Initialize or rotate thread-local HTTP/2 & TLS browser fingerprint session and proxy IP."""
        old_sess = self.session
        if old_sess is not None:
            try:
                old_sess.close()
            except Exception:
                pass

        target = random.choice(self.IMPERSONATE_TARGETS)
        sess = requests.Session(impersonate=target)

        if force_direct:
            self.current_proxy = None
        elif rotate_proxy and self.proxy_rotator.total_count > 0:
            self.current_proxy = self.proxy_rotator.get_next_proxy()
        elif self.proxy_rotator.total_count == 0:
            self.current_proxy = None

        if self.current_proxy:
            sess.proxies = {
                "http": self.current_proxy,
                "https": self.current_proxy,
            }
        else:
            sess.proxies = {}

        sess.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,*/*;q=0.8",
            "Accept-Language": "ja,en-US;q=0.9,en;q=0.8",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
        })
        self.session = sess

    def _ensure_thread_session(self, rotate_proxy: bool = True):
        if self.session is None or rotate_proxy:
            self._init_session(rotate_proxy=rotate_proxy)

    def _wait_jitter(self):
        delay = random.uniform(self.min_delay, self.max_delay)
        time.sleep(delay)

    def _meta_path(self) -> str:
        return os.path.join(self.output_dir, self.META_FILENAME)

    def _load_meta(self) -> Dict[str, Any]:
        with self._meta_lock:
            p = self._meta_path()
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    return {}
            return {}

    def _save_meta_entry(self, filename: str, entry: Dict[str, Any]):
        with self._meta_lock:
            p = self._meta_path()
            data = {}
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    data = {}
            data[filename] = entry
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, p)

    def _check_file_validity(self, file_path: str) -> bool:
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

    def _request_with_safe_redirects(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        stream: bool = True,
        timeout: int = 20
    ) -> requests.Response:
        """
        Execute GET or HEAD request while validating every HTTP redirect hop against SSRF.
        """
        current_url = validate_url(url)
        for _ in range(MAX_REDIRECT_HOPS):
            req_fn = self.session.head if method.upper() == "HEAD" else self.session.get
            kwargs: Dict[str, Any] = {
                "headers": headers,
                "allow_redirects": False,
                "timeout": timeout,
            }
            if method.upper() != "HEAD":
                kwargs["stream"] = stream

            resp = req_fn(current_url, **kwargs)
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location") or resp.headers.get("location")
                resp.close()
                current_url = validate_redirect_target(current_url, loc)
                continue
            return resp

        raise SecurityValidationError(f"Exceeded maximum redirect hops ({MAX_REDIRECT_HOPS}).")

    def _get_with_safe_redirects(
        self,
        url: str,
        headers: Dict[str, str],
        stream: bool = True,
        timeout: int = 20
    ) -> requests.Response:
        return self._request_with_safe_redirects("GET", url, headers=headers, stream=stream, timeout=timeout)

    def _has_remote_revision_changed(self, url: str, final_path: str, headers: Dict[str, str]) -> bool:
        """
        Check via SSRF-safe HTTP HEAD whether the remote catalog has been revised compared to local metadata.
        Returns True if an update/revision is detected, False if unchanged.
        """
        meta = self._load_meta()
        fname = os.path.basename(final_path)
        prev = meta.get(fname)
        if not prev:
            return True

        try:
            self._ensure_thread_session(rotate_proxy=False)
            resp = self._request_with_safe_redirects("HEAD", url, headers=headers, stream=False, timeout=12)
            if resp.status_code != 200:
                resp.close()
                return False

            remote_etag = (resp.headers.get("ETag") or resp.headers.get("etag") or "").strip()
            remote_lm = (resp.headers.get("Last-Modified") or resp.headers.get("last-modified") or "").strip()
            remote_date = (resp.headers.get("Date") or resp.headers.get("date") or "").strip()
            remote_cl = (resp.headers.get("Content-Length") or resp.headers.get("content-length") or "").strip()
            resp.close()

            if remote_etag and prev.get("etag") and remote_etag != prev.get("etag"):
                return True

            # Ignore Last-Modified when a dynamic PDF generator simply echoes the current server Date
            is_dynamic_lm = bool(remote_lm and remote_date and remote_lm == remote_date)
            if remote_lm and not is_dynamic_lm and prev.get("last_modified") and remote_lm != prev.get("last_modified"):
                return True

            if remote_cl and remote_cl.isdigit() and prev.get("size_bytes") and int(remote_cl) != int(prev.get("size_bytes")):
                return True

            return False
        except SecurityValidationError:
            raise
        except Exception:
            return False

    def _stream_to_temp_file(self, resp: requests.Response, temp_path: str, is_pdf: bool) -> Dict[str, Any]:
        cl_header = resp.headers.get("Content-Length") or resp.headers.get("content-length")
        if cl_header and cl_header.isdigit():
            declared_size = int(cl_header)
            if declared_size > self.max_file_size:
                raise SecurityValidationError(
                    f"Declared Content-Length ({declared_size} bytes) exceeds max allowed size ({self.max_file_size} bytes)."
                )

        total_bytes = 0
        first_chunk_checked = False
        sha256 = hashlib.sha256()

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
                sha256.update(chunk)
                f.write(chunk)

        if total_bytes < 512:
            raise ValueError(f"Downloaded payload too small ({total_bytes} bytes) to be a valid document.")

        return {
            "size_bytes": total_bytes,
            "sha256": sha256.hexdigest(),
            "etag": (resp.headers.get("ETag") or resp.headers.get("etag") or "").strip(),
            "last_modified": (resp.headers.get("Last-Modified") or resp.headers.get("last-modified") or "").strip(),
        }

    def download_file(
        self,
        url: str,
        filename: Optional[str] = None,
        referer: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        check_updates: Optional[bool] = None
    ) -> DownloadResult:
        """
        Download a single resource with thread-safe proxy rotation and revision check support.
        """
        if not filename:
            filename = url.split("?")[0].split("/")[-1] or "download.pdf"
            if not os.path.splitext(filename)[1]:
                filename += ".pdf"

        safe_filename = sanitize_filename(filename)
        final_path = secure_output_path(self.output_dir, safe_filename)
        temp_path = final_path + f".{threading.get_ident()}.tmp"

        headers = {}
        if referer:
            headers["Referer"] = validate_url(referer)
        if custom_headers:
            headers.update(custom_headers)

        do_update_check = self.check_updates if check_updates is None else check_updates
        file_exists_and_valid = os.path.exists(final_path) and self._check_file_validity(final_path)
        is_revision_update = False

        if file_exists_and_valid:
            if not do_update_check:
                return DownloadResult(
                    url=url,
                    save_path=final_path,
                    success=True,
                    size_bytes=os.path.getsize(final_path),
                    skipped=True,
                    proxy_used="SKIPPED"
                )
            # Revision check enabled (SSRF-safe HEAD)
            try:
                if not self._has_remote_revision_changed(url, final_path, headers):
                    return DownloadResult(
                        url=url,
                        save_path=final_path,
                        success=True,
                        size_bytes=os.path.getsize(final_path),
                        skipped=True,
                        proxy_used="UP-TO-DATE"
                    )
            except SecurityValidationError as sve:
                return DownloadResult(
                    url=url,
                    save_path=final_path,
                    success=False,
                    error_msg=f"SecurityValidationError: {sve}",
                    proxy_used="BLOCKED"
                )
            is_revision_update = True

        # Ensure thread-local session and rotate proxy
        self._ensure_thread_session(rotate_proxy=(self.proxy_rotator.total_count > 0))

        # Circuit Breaker check (thread-safe)
        with self._state_lock:
            failures = self.consecutive_failures
            if failures >= self.circuit_breaker_threshold:
                self.consecutive_failures = 0
                should_cooldown = True
            else:
                should_cooldown = False

        if should_cooldown:
            cooldown = 45.0 + random.uniform(5.0, 15.0)
            self._log(f"\n[AegisFetch Circuit Breaker] {failures} consecutive errors. Cooling down for {cooldown:.1f}s...")
            time.sleep(cooldown)
            self._init_session(rotate_proxy=True)

        last_error = None
        last_status = None
        is_pdf = final_path.lower().endswith(".pdf")

        for attempt in range(1, self.max_retries + 1):
            resp = None
            use_direct_fallback = (
                self.proxy_rotator.total_count > 0
                and self.fallback_to_direct
                and attempt == self.max_retries
            )
            if use_direct_fallback:
                self._init_session(rotate_proxy=False, force_direct=True)

            active_route = mask_proxy_credentials(self.current_proxy)
            req_timeout = 12 if self.current_proxy else 25

            try:
                self._wait_jitter()
                resp = self._get_with_safe_redirects(url, headers=headers, stream=True, timeout=req_timeout)
                last_status = resp.status_code

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
                    meta_info = self._stream_to_temp_file(resp, temp_path, is_pdf=is_pdf)
                    resp.close()

                    with self._file_lock:
                        os.replace(temp_path, final_path)

                    # Persist revision metadata
                    self._save_meta_entry(safe_filename, {
                        "url": url,
                        "size_bytes": meta_info["size_bytes"],
                        "sha256": meta_info["sha256"],
                        "etag": meta_info["etag"],
                        "last_modified": meta_info["last_modified"],
                        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")
                    })

                    if self.current_proxy:
                        self.proxy_rotator.report_success(self.current_proxy)

                    with self._state_lock:
                        self.consecutive_failures = 0

                    return DownloadResult(
                        url=url,
                        save_path=final_path,
                        success=True,
                        status_code=200,
                        size_bytes=meta_info["size_bytes"],
                        updated=is_revision_update,
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

        with self._state_lock:
            self.consecutive_failures += 1

        return DownloadResult(
            url=url,
            save_path=final_path,
            success=False,
            status_code=last_status,
            error_msg=last_error,
            proxy_used=mask_proxy_credentials(self.current_proxy)
        )

    def download_batch(
        self,
        targets: List[Dict[str, str]],
        concurrency: int = 1,
        on_progress: Optional[Callable[[int, int, DownloadResult], None]] = None
    ) -> List[DownloadResult]:
        """
        Download multiple files sequentially (concurrency=1) or in parallel (concurrency=2..8).
        """
        total = len(targets)
        workers = max(1, min(8, concurrency))
        results: List[Optional[DownloadResult]] = [None] * total

        self._log(f"\n[AegisFetch v{__version__}] Starting Download Task ({total} items, Concurrency={workers})")
        self._log(f"Destination: {self.output_dir}")
        self._log(f"Jitter Interval: {self.min_delay}s - {self.max_delay}s | Revision Check: {self.check_updates}")
        if self.proxy_rotator.total_count > 0:
            self._log(f"Proxy Rotation: ACTIVE ({self.proxy_rotator.total_count} proxies loaded, Mode={self.proxy_rotator.mode})")
        else:
            self._log("Proxy Rotation: DIRECT (No proxies configured)")
        self._log("-" * 65)

        completed_counter = 0

        def _worker(idx_zero: int, item: Dict[str, str]) -> DownloadResult:
            return self.download_file(
                url=item["url"],
                filename=item.get("filename"),
                referer=item.get("referer")
            )

        if workers == 1:
            for idx_zero, item in enumerate(targets):
                res = _worker(idx_zero, item)
                results[idx_zero] = res
                completed_counter += 1
                self._log_item_result(completed_counter, total, item, res)
                if on_progress:
                    on_progress(completed_counter, total, res)
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {
                    executor.submit(_worker, idx_zero, item): (idx_zero, item)
                    for idx_zero, item in enumerate(targets)
                }
                for fut in as_completed(future_map):
                    idx_zero, item = future_map[fut]
                    res = fut.result()
                    results[idx_zero] = res
                    completed_counter += 1
                    self._log_item_result(completed_counter, total, item, res)
                    if on_progress:
                        on_progress(completed_counter, total, res)

        final_results = [r for r in results if r is not None]
        success_count = sum(1 for r in final_results if r.success)
        skipped_count = sum(1 for r in final_results if r.skipped)
        updated_count = sum(1 for r in final_results if r.updated)
        failed_count = sum(1 for r in final_results if not r.success)

        self._log("-" * 65)
        self._log(
            f"Finished! Total: {total} | Success: {success_count} "
            f"(Updated: {updated_count}, Skipped: {skipped_count}) | Failed: {failed_count}\n"
        )
        return final_results

    def _log_item_result(self, idx: int, total: int, item: Dict[str, str], res: DownloadResult):
        label = item.get("filename") or item["url"]
        route_info = f" via {res.proxy_used}" if res.proxy_used and res.proxy_used not in ("DIRECT", "SKIPPED", "UP-TO-DATE") else ""
        if res.skipped:
            self._log(f"[{idx}/{total}] {label} -> [SKIP] (Existing: {res.size_bytes // 1024} KB)")
        elif res.updated:
            self._log(f"[{idx}/{total}] {label} -> [UPDATED{route_info}] ({res.size_bytes // 1024} KB)")
        elif res.success:
            self._log(f"[{idx}/{total}] {label} -> [OK{route_info}] ({res.size_bytes // 1024} KB)")
        else:
            self._log(f"[{idx}/{total}] {label} -> [FAILED{route_info}] ({res.error_msg or res.status_code})")


# Backwards compatibility alias
RobustDownloader = AegisFetch


def main():
    parser = argparse.ArgumentParser(
        description="AegisFetch v2.2.0: High-resilience, Anti-403 WAF-Evading Catalog & Document Downloader"
    )
    parser.add_argument("--urls", nargs="+", help="Target URLs to download directly")
    parser.add_argument("--list-file", help="Path to text file containing URLs or part numbers (one per line)")
    parser.add_argument("--balluff-parts", nargs="+", help="Part numbers to resolve and download (e.g. BES0002)")
    parser.add_argument("--extract-url", help="Product web page URL from which to automatically extract and download all PDFs")
    parser.add_argument("--out-dir", default="./downloads", help="Output directory path (default: ./downloads)")
    parser.add_argument("--min-delay", type=float, default=1.0, help="Minimum jitter delay in seconds (default: 1.0)")
    parser.add_argument("--max-delay", type=float, default=2.5, help="Maximum jitter delay in seconds (default: 2.5)")
    parser.add_argument("--concurrency", type=int, default=1, help="Parallel worker threads 1-8 (default: 1)")
    parser.add_argument("--check-updates", action="store_true", help="Check remote ETag/Last-Modified for catalog revisions")
    parser.add_argument("--proxy", help="Single proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--proxies", nargs="+", help="Multiple proxy URLs for automatic rotation")
    parser.add_argument("--proxy-file", help="Path to text file containing proxy URLs (one per line)")
    parser.add_argument("--auto-free-proxies", action="store_true", help="Automatically harvest and test free public proxies")
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
        check_updates=args.check_updates,
        quiet=args.quiet
    )

    targets = []

    if args.balluff_parts:
        for part in args.balluff_parts:
            try:
                info = CatalogExtractor.resolve_any_part(part, session=fetcher.session)
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
                            info = CatalogExtractor.resolve_any_part(line, session=fetcher.session)
                            targets.append(info)
                        except Exception as e:
                            sys.stderr.write(f"[Extractor Error] {line}: {e}\n")
    else:
        parser.print_help()
        sys.exit(1)

    if targets:
        fetcher.download_batch(targets, concurrency=args.concurrency)


if __name__ == "__main__":
    main()
