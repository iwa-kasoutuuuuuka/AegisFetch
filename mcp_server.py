"""
AegisFetch MCP Server
=====================
Model Context Protocol (MCP) server for Antigravity, Claude Code, and Claude Desktop.
Enables LLMs to download catalogs, technical datasheets, and PDFs while bypassing 403 blocks
with built-in SSRF and Path Traversal guardrails.
"""

import os
import sys
import json
from typing import Optional, List, Dict, Any
from mcp.server.mcpserver import MCPServer

from aegisfetch import AegisFetch, __version__
from security import (
    validate_url,
    sanitize_filename,
    secure_output_path,
    SecurityValidationError,
    DEFAULT_MAX_FILE_SIZE
)

# Initialize MCP Server instance
server = MCPServer(
    name="AegisFetch",
    version=__version__,
    instructions=(
        "AegisFetch is a high-resilience catalog and PDF document downloader. "
        "Use this tool when downloading files from websites protected by Cloudflare or strict WAFs "
        "that return 403 Forbidden or 429 Too Many Requests to standard downloaders."
    )
)

DEFAULT_BASE_DIR = os.path.abspath(os.environ.get("AEGISFETCH_DOWNLOAD_DIR", "./downloads"))


@server.tool(
    name="aegisfetch_download_single",
    description=(
        "Download a single catalog or PDF document safely. "
        "Bypasses 403/WAF blocks using browser TLS fingerprinting and adaptive flow control. "
        "Protected against SSRF and Path Traversal."
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
    Download a single file.
    
    Args:
        url: The HTTP/HTTPS URL of the target document.
        filename: Optional desired local filename (e.g., 'BES0002.pdf').
        referer: Optional HTTP Referer header to bypass hotlink protection.
        output_dir: Optional destination directory (defaults to ./downloads).
        verify_pdf: Verify that the payload is a valid PDF (%PDF header).
    """
    try:
        # Security Guardrail 1: SSRF Validation
        safe_url = validate_url(url)

        # Security Guardrail 2: Path Traversal Validation
        target_dir = os.path.abspath(output_dir or DEFAULT_BASE_DIR)
        os.makedirs(target_dir, exist_ok=True)
        
        safe_name = sanitize_filename(filename or url.split("?")[0].split("/")[-1])
        if verify_pdf and not safe_name.lower().endswith(".pdf"):
            safe_name += ".pdf"

        # Ensure path stays inside target_dir
        final_path = secure_output_path(target_dir, safe_name)

        # Execute Download
        fetcher = AegisFetch(
            output_dir=target_dir,
            min_delay=0.5,
            max_delay=1.5,
            verify_pdf=verify_pdf
        )

        result = fetcher.download_file(
            url=safe_url,
            filename=safe_name,
            referer=referer
        )

        res_dict = {
            "success": result.success,
            "url": result.url,
            "saved_path": result.save_path,
            "size_bytes": result.size_bytes,
            "size_kb": round(result.size_bytes / 1024, 2),
            "skipped_because_exists": result.skipped,
            "error": result.error_msg
        }
        return json.dumps(res_dict, ensure_ascii=False, indent=2)

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
    name="aegisfetch_download_batch",
    description=(
        "Download multiple catalogs or documents in batch. "
        "Executes with randomized jitter, automatic exponential backoff on 403/429, "
        "and circuit breaker protection to avoid IP bans."
    )
)
def download_batch(
    urls: List[str],
    output_dir: Optional[str] = None,
    min_delay: float = 1.0,
    max_delay: float = 2.5,
    verify_pdf: bool = True
) -> str:
    """
    Download a list of URLs with flow control.
    
    Args:
        urls: List of HTTP/HTTPS URLs (maximum 50 items per call).
        output_dir: Destination directory.
        min_delay: Minimum delay between requests in seconds.
        max_delay: Maximum delay between requests in seconds.
        verify_pdf: Check for %PDF header.
    """
    if not urls or not isinstance(urls, list):
        return json.dumps({"success": False, "message": "urls must be a non-empty list of URLs."})

    if len(urls) > 50:
        return json.dumps({"success": False, "message": "Batch size limit exceeded. Maximum 50 URLs allowed per batch call."})

    target_dir = os.path.abspath(output_dir or DEFAULT_BASE_DIR)
    os.makedirs(target_dir, exist_ok=True)

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
        min_delay=max(0.5, min_delay),
        max_delay=max(1.0, max_delay),
        verify_pdf=verify_pdf
    )

    results = fetcher.download_batch(validated_targets)

    summary = {
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
    }
    return json.dumps(summary, ensure_ascii=False, indent=2)


@server.tool(
    name="aegisfetch_verify_file",
    description="Inspect a downloaded file to verify its integrity, file size, and magic bytes (%PDF header vs HTML error page)."
)
def verify_file(file_path: str) -> str:
    """
    Verify integrity of a downloaded file.
    
    Args:
        file_path: Full path to the file to inspect.
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
    name="aegisfetch_get_status",
    description="Get AegisFetch MCP server operational status, version, and configuration."
)
def get_status() -> str:
    """Return status and configuration."""
    return json.dumps({
        "status": "online",
        "name": "AegisFetch MCP Server",
        "version": __version__,
        "supported_fingerprints": AegisFetch.IMPERSONATE_TARGETS,
        "default_download_dir": DEFAULT_BASE_DIR,
        "security_features": [
            "SSRF Prevention (Private/Loopback/Metadata IP Block)",
            "Path Traversal Prevention (Strict basename & commonpath check)",
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
