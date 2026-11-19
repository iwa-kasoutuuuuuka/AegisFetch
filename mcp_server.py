"""
AegisFetch MCP Server (v2.0)
============================
Model Context Protocol (MCP) server for Antigravity, Claude Code, and Claude Desktop.
Features:
- Single & Batch PDF/Catalog downloads with WAF/403 evasion
- Automatic Part Number -> PDF resolution (Extractor Engine)
- Generic Web Page PDF Link discovery (with Playwright SPA fallback)
- Non-blocking Background Job Queue (prevents 60s MCP tool call timeouts on huge batches)
- Deep-defense SSRF (including Open Redirect hops), Path Traversal, and Stream Size guards
"""

import os
import uuid
import time
import json
import threading
from typing import Optional, List, Dict, Any
from mcp.server.mcpserver import MCPServer

from aegisfetch import AegisFetch, __version__
from extractors import CatalogExtractor
from proxy_manager import fetch_and_test_free_proxies, DEFAULT_FREE_PROXIES
from security import (
    validate_url,
    validate_output_directory,
    sanitize_filename,
    secure_output_path,
    SecurityValidationError,
    DEFAULT_MAX_FILE_SIZE,
)

# Initialize MCP Server instance
server = MCPServer(
    name="AegisFetch",
    version=__version__,
    instructions=(
        "AegisFetch v2.0 is a high-resilience catalog and PDF downloader. "
        "It can download direct URLs, extract PDF links from web pages, resolve part numbers (like BALLUFF order codes) "
        "automatically into datasheets, and run large batches as non-blocking background jobs."
    )
)

DEFAULT_BASE_DIR = os.path.abspath(os.environ.get("AEGISFETCH_DOWNLOAD_DIR", "./downloads"))

# In-memory background job registry for non-blocking large batch downloads
_JOBS_LOCK = threading.Lock()
_BACKGROUND_JOBS: Dict[str, Dict[str, Any]] = {}


@server.tool(
    name="aegisfetch_download_single",
    description=(
        "Download a single catalog or PDF document safely. "
        "Bypasses 403/WAF blocks using browser TLS fingerprinting, hop-by-hop redirect SSRF validation, "
        "and streamed file size limits."
    )
)
def download_single(
    url: str,
    filename: Optional[str] = None,
    referer: Optional[str] = None,
    output_dir: Optional[str] = None,
    verify_pdf: bool = True
) -> str:
    """
    Download a single file from a URL.
    """
    try:
        safe_url = validate_url(url)
        target_dir = validate_output_directory(output_dir or DEFAULT_BASE_DIR)
        os.makedirs(target_dir, exist_ok=True)

        safe_name = sanitize_filename(filename or safe_url.split("?")[0].split("/")[-1])
        if verify_pdf and not safe_name.lower().endswith(".pdf"):
            safe_name += ".pdf"

        secure_output_path(target_dir, safe_name)

        fetcher = AegisFetch(
            output_dir=target_dir,
            min_delay=0.5,
            max_delay=1.2,
            verify_pdf=verify_pdf,
            quiet=True
        )

        result = fetcher.download_file(
            url=safe_url,
            filename=safe_name,
            referer=referer
        )

        return json.dumps({
            "success": result.success,
            "url": result.url,
            "saved_path": result.save_path,
            "size_bytes": result.size_bytes,
            "size_kb": round(result.size_bytes / 1024, 2),
            "skipped_because_exists": result.skipped,
            "error": result.error_msg
        }, ensure_ascii=False, indent=2)

    except SecurityValidationError as sve:
        return json.dumps({
            "success": False,
            "error_type": "SecurityValidationError",
            "message": str(sve)
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error_type": type(e).__name__,
            "message": str(e)
        }, ensure_ascii=False, indent=2)


@server.tool(
    name="aegisfetch_download_by_part_number",
    description=(
        "Automatically resolve product part numbers / order codes (such as BALLUFF 'BES0002') "
        "into their official datasheet PDF URLs and download them."
    )
)
def download_by_part_number(
    part_numbers: List[str],
    output_dir: Optional[str] = None,
    locale: str = "ja-jp"
) -> str:
    """
    Resolve part numbers and download their datasheets.
    
    Args:
        part_numbers: List of part numbers or order codes (e.g. ['BES0002', 'BES0003']). Max 25 for synchronous call.
        output_dir: Optional destination directory.
        locale: Country/language locale code (default 'ja-jp').
    """
    if not part_numbers or not isinstance(part_numbers, list):
        return json.dumps({"success": False, "message": "part_numbers must be a non-empty list."})

    if len(part_numbers) > 25:
        return json.dumps({
            "success": False,
            "message": "For more than 25 part numbers, please use 'aegisfetch_start_batch_job' to avoid MCP timeouts."
        })

    try:
        target_dir = validate_output_directory(output_dir or DEFAULT_BASE_DIR)
        os.makedirs(target_dir, exist_ok=True)

        fetcher = AegisFetch(output_dir=target_dir, min_delay=0.5, max_delay=1.2, quiet=True)
        results = []
        errors = []

        for part in part_numbers:
            try:
                resolved = CatalogExtractor.resolve_balluff_part(
                    part,
                    locale=locale,
                    session=fetcher.session
                )
                dl_res = fetcher.download_file(
                    url=resolved["url"],
                    filename=resolved["filename"],
                    referer=resolved["referer"]
                )
                results.append({
                    "part_number": part,
                    "order_code": resolved["order_code"],
                    "pdf_url": resolved["url"],
                    "saved_path": dl_res.save_path,
                    "success": dl_res.success,
                    "size_kb": round(dl_res.size_bytes / 1024, 2),
                    "skipped": dl_res.skipped,
                    "error": dl_res.error_msg
                })
            except Exception as e:
                errors.append({"part_number": part, "error": str(e)})

        return json.dumps({
            "success": True,
            "total_requested": len(part_numbers),
            "downloaded_count": sum(1 for r in results if r["success"]),
            "failed_count": len(errors) + sum(1 for r in results if not r["success"]),
            "results": results,
            "resolution_errors": errors
        }, ensure_ascii=False, indent=2)

    except SecurityValidationError as sve:
        return json.dumps({"success": False, "error_type": "SecurityValidationError", "message": str(sve)})
    except Exception as e:
        return json.dumps({"success": False, "error_type": type(e).__name__, "message": str(e)})


@server.tool(
    name="aegisfetch_extract_pdf_links",
    description=(
        "Scan a product web page URL and extract all downloadable PDF / datasheet links. "
        "Automatically falls back to headless Playwright browser if the page requires JavaScript."
    )
)
def extract_pdf_links(page_url: str, use_playwright_fallback: bool = True) -> str:
    """
    Extract PDF links from a web page.
    """
    try:
        links = CatalogExtractor.extract_pdf_links_from_url(
            page_url=page_url,
            use_playwright_fallback=use_playwright_fallback
        )
        return json.dumps({
            "success": True,
            "page_url": page_url,
            "found_count": len(links),
            "pdf_links": links
        }, ensure_ascii=False, indent=2)
    except SecurityValidationError as sve:
        return json.dumps({"success": False, "error_type": "SecurityValidationError", "message": str(sve)})
    except Exception as e:
        return json.dumps({"success": False, "error_type": type(e).__name__, "message": str(e)})


@server.tool(
    name="aegisfetch_download_batch",
    description=(
        "Synchronously download up to 25 URLs in batch. "
        "For larger lists (26 to 500 items), use 'aegisfetch_start_batch_job' instead to prevent timeouts."
    )
)
def download_batch(
    urls: List[str],
    output_dir: Optional[str] = None,
    min_delay: float = 0.8,
    max_delay: float = 1.8,
    verify_pdf: bool = True
) -> str:
    """
    Synchronous batch download for small-to-medium lists.
    """
    if not urls or not isinstance(urls, list):
        return json.dumps({"success": False, "message": "urls must be a non-empty list of URLs."})

    if len(urls) > 50:
        return json.dumps({
            "success": False,
            "message": "Batch size limit exceeded (max 50 for synchronous call). Use 'aegisfetch_start_batch_job' for large batches."
        })

    try:
        target_dir = validate_output_directory(output_dir or DEFAULT_BASE_DIR)
        os.makedirs(target_dir, exist_ok=True)
    except SecurityValidationError as sve:
        return json.dumps({"success": False, "error_type": "SecurityValidationError", "message": str(sve)})

    validated_targets = []
    rejected_urls = []

    for u in urls:
        try:
            safe_u = validate_url(u)
            fname = sanitize_filename(safe_u.split("?")[0].split("/")[-1])
            validated_targets.append({"url": safe_u, "filename": fname})
        except SecurityValidationError as sve:
            rejected_urls.append({"url": u, "reason": str(sve)})

    fetcher = AegisFetch(
        output_dir=target_dir,
        min_delay=max(0.4, min_delay),
        max_delay=max(0.8, max_delay),
        verify_pdf=verify_pdf,
        quiet=True
    )

    results = fetcher.download_batch(validated_targets)

    return json.dumps({
        "total_requested": len(urls),
        "total_validated": len(validated_targets),
        "total_rejected_security": len(rejected_urls),
        "total_success": sum(1 for r in results if r.success),
        "total_skipped": sum(1 for r in results if r.skipped),
        "total_failed": sum(1 for r in results if not r.success),
        "output_directory": target_dir,
        "items": [
            {
                "url": r.url,
                "saved_path": r.save_path,
                "success": r.success,
                "size_kb": round(r.size_bytes / 1024, 2),
                "skipped": r.skipped,
                "error": r.error_msg
            }
            for r in results
        ],
        "security_rejected": rejected_urls
    }, ensure_ascii=False, indent=2)


def _run_background_job(
    job_id: str,
    items: List[str],
    is_part_numbers: bool,
    target_dir: str,
    min_delay: float,
    max_delay: float
):
    """Worker thread function for non-blocking large batch downloads."""
    try:
        fetcher = AegisFetch(output_dir=target_dir, min_delay=min_delay, max_delay=max_delay, quiet=True)

        for idx, item in enumerate(items, 1):
            try:
                if is_part_numbers and not item.lower().startswith("http"):
                    resolved = CatalogExtractor.resolve_balluff_part(item, session=fetcher.session)
                    res = fetcher.download_file(
                        url=resolved["url"],
                        filename=resolved["filename"],
                        referer=resolved["referer"]
                    )
                else:
                    safe_u = validate_url(item)
                    fname = sanitize_filename(safe_u.split("?")[0].split("/")[-1])
                    res = fetcher.download_file(url=safe_u, filename=fname)

                entry = {
                    "item": item,
                    "saved_path": res.save_path,
                    "success": res.success,
                    "skipped": res.skipped,
                    "size_kb": round(res.size_bytes / 1024, 2),
                    "error": res.error_msg
                }
            except Exception as e:
                entry = {
                    "item": item,
                    "saved_path": None,
                    "success": False,
                    "skipped": False,
                    "size_kb": 0,
                    "error": str(e)
                }

            with _JOBS_LOCK:
                job = _BACKGROUND_JOBS[job_id]
                job["completed_items"] = idx
                job["results"].append(entry)
                if entry["success"]:
                    job["success_count"] += 1
                else:
                    job["failed_count"] += 1
    finally:
        with _JOBS_LOCK:
            if job_id in _BACKGROUND_JOBS:
                _BACKGROUND_JOBS[job_id]["status"] = "completed"
                _BACKGROUND_JOBS[job_id]["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


@server.tool(
    name="aegisfetch_start_batch_job",
    description=(
        "Start a non-blocking background job to download a large list of URLs or part numbers (up to 500 items). "
        "Returns a job_id immediately so MCP never times out. Poll progress with 'aegisfetch_get_job_status'."
    )
)
def start_batch_job(
    items: List[str],
    is_part_numbers: bool = False,
    output_dir: Optional[str] = None,
    min_delay: float = 0.8,
    max_delay: float = 1.8
) -> str:
    """
    Launch an asynchronous background batch download job.
    """
    if not items or not isinstance(items, list):
        return json.dumps({"success": False, "message": "items must be a non-empty list."})

    if len(items) > 500:
        return json.dumps({"success": False, "message": "Maximum 500 items allowed per background job."})

    try:
        target_dir = validate_output_directory(output_dir or DEFAULT_BASE_DIR)
        os.makedirs(target_dir, exist_ok=True)
    except SecurityValidationError as sve:
        return json.dumps({"success": False, "error_type": "SecurityValidationError", "message": str(sve)})

    job_id = f"job_{uuid.uuid4().hex[:8]}"
    with _JOBS_LOCK:
        _BACKGROUND_JOBS[job_id] = {
            "job_id": job_id,
            "status": "running",
            "total_items": len(items),
            "completed_items": 0,
            "success_count": 0,
            "failed_count": 0,
            "output_dir": target_dir,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "finished_at": None,
            "results": []
        }

    worker = threading.Thread(
        target=_run_background_job,
        args=(job_id, items, is_part_numbers, target_dir, max(0.4, min_delay), max(0.8, max_delay)),
        daemon=True
    )
    worker.start()

    return json.dumps({
        "success": True,
        "job_id": job_id,
        "status": "running",
        "total_items": len(items),
        "output_dir": target_dir,
        "message": f"Background job '{job_id}' started. Call 'aegisfetch_get_job_status' with this job_id to check progress."
    }, ensure_ascii=False, indent=2)


@server.tool(
    name="aegisfetch_get_job_status",
    description="Check the progress and results of a background download job started by 'aegisfetch_start_batch_job'."
)
def get_job_status(job_id: str) -> str:
    """
    Retrieve status of a background job.
    """
    with _JOBS_LOCK:
        job = _BACKGROUND_JOBS.get(job_id)
        if not job:
            return json.dumps({"success": False, "message": f"Job ID '{job_id}' not found."})

        return json.dumps({
            "success": True,
            "job_id": job["job_id"],
            "status": job["status"],
            "progress": f"{job['completed_items']}/{job['total_items']}",
            "percent": round((job["completed_items"] / max(1, job["total_items"])) * 100, 1),
            "success_count": job["success_count"],
            "failed_count": job["failed_count"],
            "output_dir": job["output_dir"],
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
            "recent_results": job["results"][-10:]
        }, ensure_ascii=False, indent=2)


@server.tool(
    name="aegisfetch_verify_file",
    description="Inspect a downloaded file to verify its integrity, file size, and magic bytes (%PDF header vs HTML error page)."
)
def verify_file(file_path: str) -> str:
    """
    Verify integrity of a downloaded file.
    """
    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        return json.dumps({"exists": False, "message": f"File does not exist: {abs_path}"})

    size_bytes = os.path.getsize(abs_path)
    with open(abs_path, "rb") as f:
        head = f.read(512)

    is_pdf = head.startswith(b"%PDF")
    is_html = b"<html" in head.lower() or b"<!doctype html" in head.lower()

    file_type = "unknown"
    if is_pdf:
        file_type = "Valid PDF Document"
    elif is_html:
        file_type = "HTML Webpage (Likely a WAF challenge or error page)"

    return json.dumps({
        "exists": True,
        "file_path": abs_path,
        "size_bytes": size_bytes,
        "size_kb": round(size_bytes / 1024, 2),
        "file_type": file_type,
        "is_valid_pdf": is_pdf,
        "is_suspicious_html": is_html
    }, ensure_ascii=False, indent=2)


@server.tool(
    name="aegisfetch_fetch_free_proxies",
    description=(
        "Harvest and live-test free public HTTP/SOCKS5 proxies against Cloudflare HTTPS trace. "
        "Returns a verified list of fast, working proxies for automatic IP rotation."
    )
)
def fetch_free_proxies(target_count: int = 12, verify_live: bool = True) -> str:
    """
    Harvest and verify free public proxies.
    """
    res = fetch_and_test_free_proxies(
        target_working_count=min(30, max(1, target_count)),
        verify_live=verify_live
    )
    return json.dumps(res, ensure_ascii=False, indent=2)


@server.tool(
    name="aegisfetch_get_status",
    description="Get AegisFetch MCP server operational status, version, active jobs, and security capabilities."
)
def get_status() -> str:
    """Return status and configuration."""
    with _JOBS_LOCK:
        active_jobs = sum(1 for j in _BACKGROUND_JOBS.values() if j["status"] == "running")
        total_jobs = len(_BACKGROUND_JOBS)

    return json.dumps({
        "status": "online",
        "name": "AegisFetch MCP Server",
        "version": __version__,
        "supported_fingerprints": AegisFetch.IMPERSONATE_TARGETS,
        "default_download_dir": DEFAULT_BASE_DIR,
        "max_file_size_mb": DEFAULT_MAX_FILE_SIZE // (1024 * 1024),
        "background_jobs": {
            "active": active_jobs,
            "total": total_jobs
        },
        "security_features": [
            "SSRF Prevention (Private/Loopback/Metadata IP Block)",
            "Open-Redirect SSRF Hop Inspection (Max 5 Hops)",
            "System Directory Write Protection",
            "Path Traversal Prevention (Strict basename & commonpath check)",
            "Streamed Chunk Download with 100MB Size Cutoff",
            "Magic Byte Payload Inspection (%PDF validation)",
            "Atomic Disk Writes (.tmp before rename)",
            "Adaptive Exponential Backoff & Circuit Breaker"
        ]
    }, ensure_ascii=False, indent=2)


def main():
    """Run the MCP server over standard input/output (stdio)."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
