"""
AegisFetch Security Guardrails
==============================
SSRF, Path Traversal, and Resource Exhaustion protection for MCP operations.
"""

import os
import re
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Optional, Tuple

# Disallowed private / internal IP networks (SSRF prevention)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # Cloud metadata (AWS, GCP, Azure)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 blocked ranges
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),              # Loopback
    ipaddress.ip_network("fc00::/7"),             # Unique local
    ipaddress.ip_network("fe80::/10"),            # Link-local
    ipaddress.ip_network("ff00::/8"),             # Multicast
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
}

# Max file size limit: 100 MB by default to prevent disk exhaustion
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024


class SecurityValidationError(ValueError):
    """Raised when an operation violates security policy."""
    pass


def validate_url(url: str, allow_private_ip: bool = False) -> str:
    """
    Validate target URL against SSRF attacks.
    - Protocol must be http or https
    - Hostname must not resolve to internal/private IP
    """
    if not url or not isinstance(url, str):
        raise SecurityValidationError("URL must be a non-empty string.")

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise SecurityValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise SecurityValidationError("URL has no valid hostname.")

    hostname_lower = hostname.lower()
    if hostname_lower in BLOCKED_HOSTNAMES:
        raise SecurityValidationError(f"Access to blocked internal hostname '{hostname}' is forbidden.")

    if not allow_private_ip:
        # Check if hostname is already an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            for net in BLOCKED_NETWORKS:
                if ip in net:
                    raise SecurityValidationError(f"Access to private/internal IP address '{ip}' is blocked (SSRF Protection).")
        except ValueError:
            # Hostname is a domain name -> Resolve DNS to inspect target IP
            try:
                addr_info = socket.getaddrinfo(hostname, None)
                for item in addr_info:
                    raw_ip = item[4][0]
                    ip = ipaddress.ip_address(raw_ip)
                    for net in BLOCKED_NETWORKS:
                        if ip in net:
                            raise SecurityValidationError(
                                f"Hostname '{hostname}' resolves to private/internal IP '{ip}', which is blocked (SSRF Protection)."
                            )
            except socket.gaierror as e:
                # DNS failure: will fail during fetch anyway, but let it proceed if unresolvable here
                pass

    return url


def sanitize_filename(filename: Optional[str], default_name: str = "download.pdf") -> str:
    """
    Prevent Path Traversal by stripping directory components and disallowed chars.
    """
    if not filename or not isinstance(filename, str):
        filename = default_name

    # Strip any directory traversal components (../../ etc)
    base = os.path.basename(filename.strip().replace("\\", "/"))
    # Allow only safe characters: alphanumeric, dot, underscore, hyphen
    safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", base)
    safe = safe.strip("._ ")
    if not safe:
        safe = default_name
    return safe


def secure_output_path(base_dir: str, filename: str) -> str:
    """
    Ensure the resolved path strictly resides within base_dir.
    """
    abs_base = os.path.abspath(base_dir)
    safe_name = sanitize_filename(filename)
    target_path = os.path.abspath(os.path.join(abs_base, safe_name))

    # Verify that target_path starts with abs_base
    try:
        common = os.path.commonpath([abs_base, target_path])
        if common != abs_base:
            raise SecurityValidationError("Path traversal detected: Target path escapes output directory.")
    except ValueError:
        raise SecurityValidationError("Path traversal detected: Target path is on a different drive or invalid.")

    return target_path
