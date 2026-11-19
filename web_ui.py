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
import re
import csv
import sys
import hmac
import html
import math
import uuid
import time
import json
import base64
import secrets
import zipfile
import threading
import webbrowser
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote, parse_qs
from typing import Dict, Any, List, Optional, Tuple

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


def _load_or_create_extension_token() -> str:
    """
    Load extension authentication token from env or ~/.aegisfetch_token,
    or generate a new random token and persist it locally.
    """
    env_tok = os.environ.get("AEGISFETCH_EXTENSION_TOKEN", "").strip()
    if env_tok:
        return env_tok

    token_path = os.path.join(os.path.expanduser("~"), ".aegisfetch_token")
    if os.path.exists(token_path):
        try:
            with open(token_path, "r", encoding="utf-8") as f:
                existing = f.read().strip()
                if existing:
                    return existing
        except OSError:
            pass

    new_tok = secrets.token_urlsafe(24)
    try:
        if os.name != "nt":
            fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(new_tok)
            os.chmod(token_path, 0o600)
        else:
            with open(token_path, "w", encoding="utf-8") as f:
                f.write(new_tok)
    except OSError:
        pass
    return new_tok


EXTENSION_TOKEN = _load_or_create_extension_token()
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_ui_static")


def _load_static_asset(filename: str) -> bytes:
    """Load a static Web UI asset safely from web_ui_static/."""
    safe_name = os.path.basename(filename)
    full_path = os.path.join(_STATIC_DIR, safe_name)
    with open(full_path, "rb") as f:
        return f.read()


def _get_history_path() -> str:
    env_path = os.environ.get("AEGISFETCH_HISTORY_FILE", "").strip()
    if env_path:
        return env_path
    return os.path.join(os.path.expanduser("~"), ".aegisfetch_ui_history.json")


_UI_JOBS_LOCK = threading.Lock()
_UI_JOBS: Dict[str, Dict[str, Any]] = {}
MAX_RETAINED_UI_JOBS = 50
MAX_PERSISTED_JOBS = 20
MAX_EXPORT_ARCHIVE_BYTES = 250 * 1024 * 1024  # 250MB cap for ZIP/Merged PDF export
MAX_BROWSER_PDF_BYTES = 25 * 1024 * 1024  # 25MB cap for browser-authenticated PDF upload


def _load_job_history():
    """Load persisted UI job summaries/results from disk on startup."""
    hist_path = _get_history_path()
    if not os.path.exists(hist_path):
        return
    try:
        with open(hist_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return
        with _UI_JOBS_LOCK:
            for item in data[-MAX_PERSISTED_JOBS:]:
                if isinstance(item, dict) and isinstance(item.get("job_id"), str):
                    if item.get("status") == "running":
                        item["status"] = "interrupted"
                    _UI_JOBS[item["job_id"]] = item
    except Exception:
        pass


def _save_job_history():
    """Persist recent completed/cancelled UI jobs atomically to disk."""
    hist_path = _get_history_path()
    try:
        with _UI_JOBS_LOCK:
            snapshot = []
            for info in list(_UI_JOBS.values())[-MAX_PERSISTED_JOBS:]:
                copy_info = dict(info)
                copy_info["results"] = list(info.get("results", []))[-200:]
                snapshot.append(copy_info)
        parent = os.path.dirname(os.path.abspath(hist_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp_path = hist_path + f".{os.getpid()}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, hist_path)
    except Exception:
        pass


_load_job_history()


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
    page_referer: Optional[str] = None,
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
                    res = fetcher.download_file(url=safe_u, filename=fname, referer=page_referer)
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
        _save_job_history()


class AegisWebRequestHandler(BaseHTTPRequestHandler):
    """HTTP Handler for AegisFetch Web UI Console with CSRF, DNS Rebinding & Extension Token Auth."""

    _EXT_ORIGIN_RE = re.compile(r"^(chrome-extension|extension)://[a-z0-9]{16,64}$", re.I)

    def log_message(self, format: str, *args: Any):
        pass

    def _is_valid_local_host(self) -> bool:
        host = (self.headers.get("Host") or "").lower().strip()
        if not host:
            return True
        try:
            parsed = urlparse(f"http://{host}")
            _ = parsed.port
        except ValueError:
            return False
        if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            return False
        return parsed.hostname in ("127.0.0.1", "localhost", "::1")

    def _get_validated_extension_origin(self) -> Optional[str]:
        origin = (self.headers.get("Origin") or "").strip()
        if origin and self._EXT_ORIGIN_RE.match(origin):
            return origin
        return None

    def _has_valid_extension_token(self) -> bool:
        provided = (self.headers.get("X-Aegis-Token") or "").strip()
        return bool(provided) and hmac.compare_digest(provided, EXTENSION_TOKEN)

    def _check_local_request(self, is_post: bool = False) -> Tuple[bool, str, str]:
        if not self._is_valid_local_host():
            return False, "Forbidden Host header (DNS Rebinding Protection).", "forbidden_host"

        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return True, "", ""

        if self._EXT_ORIGIN_RE.match(origin):
            if self._has_valid_extension_token():
                return True, "", ""
            return False, "Invalid or missing X-Aegis-Token header for browser extension.", "invalid_token"

        parsed_orig = urlparse(origin)
        if parsed_orig.scheme in ("http", "https") and parsed_orig.hostname in ("127.0.0.1", "localhost", "::1"):
            return True, "", ""

        return False, "Forbidden Origin/Host header (CSRF & DNS Rebinding Protection).", "forbidden_origin"

    def _is_safe_local_request(self, is_post: bool = False) -> bool:
        ok, _, _ = self._check_local_request(is_post=is_post)
        return ok

    def _send_json(self, data: Dict[str, Any], status: int = 200):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        ext_origin = self._get_validated_extension_origin()
        if ext_origin:
            self.send_header("Access-Control-Allow-Origin", ext_origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self, max_bytes: int = 8 * 1024 * 1024) -> Dict[str, Any]:
        raw_cl = (self.headers.get("Content-Length") or "0").strip()
        try:
            length = int(raw_cl)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header.") from exc
        if length <= 0:
            return {}
        if length > max_bytes:
            raise ValueError(f"Request body exceeds {max_bytes // (1024 * 1024)}MB limit.")
        raw = self.rfile.read(length)
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON body must be an object.")
        return parsed

    def do_OPTIONS(self):
        ext_origin = self._get_validated_extension_origin()
        if self._is_valid_local_host() and ext_origin:
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", ext_origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Aegis-Token")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send_json({"success": False, "error_code": "forbidden_origin", "message": "Forbidden CORS preflight."}, 403)

    def do_GET(self):
        ok, reason, err_code = self._check_local_request(is_post=False)
        if not ok:
            self._send_json({"success": False, "error_code": err_code, "message": reason}, 403)
            return

        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        query = {k: v[0] for k, v in qs.items() if v}

        if path == "/" or path == "/index.html":
            safe_default_dir = html.escape(DEFAULT_DOWNLOAD_DIR.replace("\\", "/"), quote=True)
            safe_token_json = (
                json.dumps(EXTENSION_TOKEN)
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
            )
            safe_version = html.escape(__version__, quote=True)
            html_template = _load_static_asset("index.html").decode("utf-8")
            page = (
                html_template
                .replace("__DEFAULT_DIR__", safe_default_dir)
                .replace("__EXTENSION_TOKEN_JSON__", safe_token_json)
                .replace("__VERSION__", safe_version)
            )
            raw = page.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/assets/style.css":
            data = _load_static_asset("style.css")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/assets/app.js":
            data = _load_static_asset("app.js")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/health":
            self._send_json({
                "success": True,
                "status": "ok",
                "version": __version__,
                "default_dir": DEFAULT_DOWNLOAD_DIR,
            })
            return

        if path == "/api/jobs":
            with _UI_JOBS_LOCK:
                jobs_list = []
                for jid in reversed(list(_UI_JOBS.keys())[-MAX_PERSISTED_JOBS:]):
                    j = _UI_JOBS[jid]
                    jobs_list.append({
                        "job_id": j.get("job_id"),
                        "status": j.get("status"),
                        "source": j.get("source", "webui"),
                        "total_items": j.get("total_items", 0),
                        "completed_items": j.get("completed_items", 0),
                        "success_count": j.get("success_count", 0),
                        "failed_count": j.get("failed_count", 0),
                        "started_at": j.get("started_at"),
                        "finished_at": j.get("finished_at"),
                    })
            self._send_json({"success": True, "jobs": jobs_list})
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

                real_safe_dir = os.path.realpath(safe_dir)
                files_info = []
                for fname in sorted(os.listdir(safe_dir)):
                    if fname.lower().endswith(".pdf"):
                        fpath = os.path.join(safe_dir, fname)
                        if os.path.islink(fpath) or not os.path.isfile(fpath):
                            continue
                        try:
                            if os.path.commonpath([real_safe_dir, os.path.realpath(fpath)]) != real_safe_dir:
                                continue
                        except ValueError:
                            continue
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
                if not safe_file.lower().endswith(".pdf") or os.path.islink(safe_file):
                    self.send_error(HTTPStatus.FORBIDDEN)
                    return
                real_safe_dir = os.path.realpath(safe_dir)
                real_safe_file = os.path.realpath(safe_file)
                try:
                    confined = os.path.commonpath([real_safe_dir, real_safe_file]) == real_safe_dir
                except ValueError:
                    confined = False
                if not confined:
                    self.send_error(HTTPStatus.FORBIDDEN)
                    return
                if not os.path.exists(safe_file) or not os.path.isfile(safe_file):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                with open(safe_file, "rb") as f:
                    content = f.read()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(content)
            except SecurityValidationError:
                self.send_error(HTTPStatus.FORBIDDEN)
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        ok, reason, err_code = self._check_local_request(is_post=True)
        if not ok:
            # Drain small unread POST body to prevent Windows TCP RST (WinError 10054) on early 403 close
            try:
                cl = int(self.headers.get("Content-Length", "0"))
                if 0 < cl <= 65536:
                    self.rfile.read(cl)
            except Exception:
                pass
            self._send_json({"success": False, "error_code": err_code, "message": reason}, 403)
            return

        parsed = urlparse(self.path)
        path = parsed.path

        max_json_bytes = 36 * 1024 * 1024 if path == "/api/save-browser-pdf" else 8 * 1024 * 1024
        try:
            body = self._read_json_body(max_bytes=max_json_bytes)
        except Exception as e:
            self._send_json({"success": False, "message": f"Invalid JSON: {e}"}, 400)
            return

        if path == "/api/parse-file":
            filename = body.get("filename", "")
            content_b64 = body.get("content_b64", "")
            if not isinstance(filename, str) or not isinstance(content_b64, str) or not filename or not content_b64:
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
            raw_count = body.get("count", 12)
            if isinstance(raw_count, bool):
                self._send_json({"success": False, "message": "Invalid count parameter."}, 400)
                return
            try:
                target_count = max(1, min(50, int(raw_count)))
            except (ValueError, TypeError):
                self._send_json({"success": False, "message": "Invalid count parameter."}, 400)
                return
            res = fetch_and_test_free_proxies(
                target_working_count=target_count,
                verify_live=verify_live
            )
            self._send_json(res)
            return

        if path == "/api/start":
            raw_items = body.get("items", [])
            if not isinstance(raw_items, list) or not all(isinstance(x, str) for x in raw_items):
                self._send_json({"success": False, "message": "items must be a list of strings."}, 400)
                return
            items = [x.strip() for x in raw_items if x.strip()]
            if not items:
                self._send_json({"success": False, "message": "items list is empty."}, 400)
                return
            if len(items) > 1000:
                self._send_json({"success": False, "message": "Max 1000 items per batch."}, 400)
                return

            raw_proxies = body.get("proxies", [])
            if raw_proxies is None:
                raw_proxies = []
            if not isinstance(raw_proxies, list) or not all(isinstance(p, str) for p in raw_proxies):
                self._send_json({"success": False, "message": "proxies must be a list of strings."}, 400)
                return
            proxies = raw_proxies

            raw_referer = body.get("page_referer")
            if raw_referer is not None and not isinstance(raw_referer, str):
                self._send_json({"success": False, "message": "page_referer must be a string."}, 400)
                return
            page_referer = (raw_referer or "").strip() or None

            raw_conc = body.get("concurrency", 1)
            raw_min_delay = body.get("min_delay", 0.6)
            raw_max_delay = body.get("max_delay", 1.5)
            if any(isinstance(v, bool) for v in (raw_conc, raw_min_delay, raw_max_delay)):
                self._send_json({"success": False, "message": "Invalid numeric parameter type."}, 400)
                return
            try:
                concurrency = max(1, min(8, int(raw_conc)))
                parsed_min = float(raw_min_delay)
                parsed_max = float(raw_max_delay)
                if not (math.isfinite(parsed_min) and math.isfinite(parsed_max)):
                    raise ValueError("Non-finite delay value")
                min_delay = max(0.2, min(60.0, parsed_min))
                max_delay = max(min_delay + 0.2, min(60.0, parsed_max))
            except (ValueError, TypeError):
                self._send_json({"success": False, "message": "Invalid numeric parameters (concurrency/min_delay/max_delay)."}, 400)
                return

            proxy_rotation_mode = str(body.get("proxy_rotation_mode") or "round_robin")
            fallback_to_direct = bool(body.get("fallback_to_direct", True))
            req_dir = body.get("output_dir") or DEFAULT_DOWNLOAD_DIR
            locale = str(body.get("locale") or "ja-jp")
            auto_fallback_locales = bool(body.get("auto_fallback_locales", True))
            enable_generic_search = bool(body.get("enable_generic_search", True))
            check_updates = bool(body.get("check_updates", False))

            try:
                if page_referer:
                    page_referer = validate_url(page_referer)
                target_dir = validate_output_directory(req_dir)
                os.makedirs(target_dir, exist_ok=True)
            except SecurityValidationError as sve:
                self._send_json({
                    "success": False,
                    "error_code": "security_validation_error",
                    "message": str(sve)
                }, 403)
                return

            job_id = f"ui_{uuid.uuid4().hex[:8]}"
            job_source = "extension" if self._get_validated_extension_origin() else "webui"
            with _UI_JOBS_LOCK:
                _prune_old_ui_jobs()
                _UI_JOBS[job_id] = {
                    "job_id": job_id,
                    "status": "running",
                    "source": job_source,
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
                    page_referer,
                ),
                daemon=True
            )
            t.start()
            self._send_json({"success": True, "job_id": job_id, "output_dir": target_dir})
            return

        if path == "/api/cancel":
            job_id = body.get("job_id", "")
            if not isinstance(job_id, str) or not job_id:
                self._send_json({"success": False, "message": "Invalid job_id"}, 400)
                return
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

        if path == "/api/save-browser-pdf":
            if not self._get_validated_extension_origin() or not self._has_valid_extension_token():
                self._send_json({
                    "success": False,
                    "error_code": "invalid_token",
                    "message": "Extension authentication required."
                }, 403)
                return

            raw_name = body.get("filename", "")
            content_b64 = body.get("content_b64", "")
            req_dir = body.get("output_dir") or DEFAULT_DOWNLOAD_DIR
            if not isinstance(raw_name, str) or not isinstance(content_b64, str) or not raw_name.strip() or not content_b64:
                self._send_json({"success": False, "message": "Missing filename or content_b64."}, 400)
                return

            try:
                pdf_bytes = base64.b64decode(content_b64, validate=True)
            except Exception:
                self._send_json({"success": False, "message": "Invalid base64 payload."}, 400)
                return

            if len(pdf_bytes) < 512 or len(pdf_bytes) > MAX_BROWSER_PDF_BYTES:
                self._send_json({"success": False, "message": "PDF size out of allowed bounds (512B..25MB)."}, 400)
                return

            if not pdf_bytes.startswith(b"%PDF"):
                self._send_json({"success": False, "message": "Payload is not a valid PDF (%PDF header missing)."}, 400)
                return

            try:
                target_dir = validate_output_directory(req_dir)
                os.makedirs(target_dir, exist_ok=True)
                safe_name = sanitize_filename(raw_name)
                if not safe_name.lower().endswith(".pdf"):
                    safe_name += ".pdf"
                final_path = secure_output_path(target_dir, safe_name)
                tmp_path = final_path + f".{threading.get_ident()}.tmp"
                with open(tmp_path, "wb") as f:
                    f.write(pdf_bytes)
                os.replace(tmp_path, final_path)
                self._send_json({
                    "success": True,
                    "filename": os.path.basename(final_path),
                    "saved_path": final_path,
                    "size_kb": round(len(pdf_bytes) / 1024, 2)
                })
            except SecurityValidationError as sve:
                self._send_json({"success": False, "error_code": "security_validation_error", "message": str(sve)}, 403)
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
    sys.stderr.write(f"  Extension Token Auth: ACTIVE (Copy via Web UI header button)\n")
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
