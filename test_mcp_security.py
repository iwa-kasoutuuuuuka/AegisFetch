"""
AegisFetch MCP Server - Debug, Functional & Vulnerability Verification Suite
=============================================================================
Tests:
1. Tool Registration & Schema Integrity
2. Normal Functionality (Download, Verify, Status)
3. SSRF Vulnerability Defenses (Loopback, Metadata IP, Private RFC1918, Invalid Schemes)
4. Path Traversal Defenses (Directory traversal sequences, absolute Windows paths)
5. DoS / Batch Limit Defenses
"""

import os
import sys
import json
import asyncio

# Ensure AegisFetch directory is in path
sys.path.insert(0, os.path.abspath("e:/temp/AegisFetch"))

from mcp_server import server, download_single, download_batch, verify_file, get_status
from security import validate_url, sanitize_filename, secure_output_path, SecurityValidationError

passed_tests = 0
failed_tests = 0

def record_test(name: str, passed: bool, detail: str = ""):
    global passed_tests, failed_tests
    if passed:
        passed_tests += 1
        print(f"  [PASS] {name} {detail}")
    else:
        failed_tests += 1
        print(f"  [FAIL] {name} - {detail}")


async def test_mcp_registration():
    print("\n--- 1. Testing MCP Server Registration ---")
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    expected = [
        "aegisfetch_download_single",
        "aegisfetch_download_batch",
        "aegisfetch_verify_file",
        "aegisfetch_get_status"
    ]
    for exp in expected:
        record_test(f"Tool '{exp}' registered", exp in tool_names)


def test_status_and_verification():
    print("\n--- 2. Testing Functional Verification ---")
    
    # Test get_status
    status_raw = get_status()
    status_data = json.loads(status_raw)
    record_test("get_status response format", status_data.get("status") == "online")

    # Test verify_file with dummy valid PDF
    test_pdf = "e:/temp/test_valid.pdf"
    with open(test_pdf, "wb") as f:
        f.write(b"%PDF-1.4\n%EOF" + b"0" * 600)
    
    v_res = json.loads(verify_file(test_pdf))
    record_test("verify_file correctly identifies valid PDF", v_res.get("is_valid_pdf") is True)

    # Test verify_file with dummy HTML error page
    test_html = "e:/temp/test_error.html"
    with open(test_html, "wb") as f:
        f.write(b"<!DOCTYPE html><html><body>Error 403 Forbidden</body></html>" + b"0" * 600)

    h_res = json.loads(verify_file(test_html))
    record_test("verify_file correctly flags suspicious HTML", h_res.get("is_suspicious_html") is True)

    # Cleanup test files
    for p in [test_pdf, test_html]:
        if os.path.exists(p):
            os.remove(p)


def test_ssrf_vulnerabilities():
    print("\n--- 3. Testing SSRF Vulnerability Defenses ---")
    
    malicious_urls = [
        ("http://127.0.0.1:8080/admin", "Loopback IPv4"),
        ("http://127.0.0.1/etc/passwd", "Localhost loopback"),
        ("http://localhost:3000/", "Localhost domain name"),
        ("http://169.254.169.254/latest/meta-data/", "AWS/Cloud Metadata Service"),
        ("http://192.168.1.1/router_config", "Private LAN RFC1918 Class C"),
        ("http://10.0.0.5/internal_db", "Private LAN RFC1918 Class A"),
        ("http://172.16.0.1/vault", "Private LAN RFC1918 Class B"),
        ("file:///C:/Windows/System32/drivers/etc/hosts", "Local file scheme"),
        ("ftp://internal.ftp.server/data", "FTP non-HTTP scheme"),
        ("gopher://127.0.0.1:6379/_flushall", "Gopher scheme injection"),
    ]

    for url, desc in malicious_urls:
        blocked = False
        try:
            validate_url(url)
        except SecurityValidationError:
            blocked = True
        record_test(f"SSRF Block: {desc}", blocked, f"({url})")

    # Legitimate URL test
    try:
        val = validate_url("https://www.balluff.com/ja-jp/products/BES0002")
        record_test("Legitimate public URL permitted", True)
    except SecurityValidationError as e:
        record_test("Legitimate public URL permitted", False, str(e))


def test_path_traversal_vulnerabilities():
    print("\n--- 4. Testing Path Traversal Defenses ---")
    
    base_dir = "e:/temp/test_downloads"
    os.makedirs(base_dir, exist_ok=True)

    traversal_inputs = [
        ("../../secret.txt", "Relative directory jump ../.."),
        ("../../../../../Windows/System32/calc.exe", "Deep root traversal"),
        ("C:\\Windows\\malicious.bat", "Absolute Windows drive path"),
        ("subdir/../../../etc/passwd", "Subdir mixed traversal"),
        ("filename with ; rm -rf /", "Command injection characters"),
        ("nul.pdf", "Windows reserved device name sanitization"),
    ]

    for fname, desc in traversal_inputs:
        safe_path = secure_output_path(base_dir, fname)
        abs_base = os.path.abspath(base_dir)
        stays_inside = os.path.commonpath([abs_base, safe_path]) == abs_base
        record_test(f"Path Traversal neutralized: {desc}", stays_inside, f"-> {os.path.basename(safe_path)}")

    # Cleanup base_dir
    if os.path.exists(base_dir):
        try:
            os.rmdir(base_dir)
        except:
            pass


def test_batch_limit_vulnerability():
    print("\n--- 5. Testing Batch Overload (DoS) Defenses ---")
    oversized_urls = [f"https://example.com/file_{i}.pdf" for i in range(55)]
    res_raw = download_batch(oversized_urls)
    res_data = json.loads(res_raw)
    record_test("Batch size > 50 rejected immediately", res_data.get("success") is False)


async def main():
    print("=============================================================")
    print("   AegisFetch MCP Server - Full Security & Test Suite")
    print("=============================================================")
    await test_mcp_registration()
    test_status_and_verification()
    test_ssrf_vulnerabilities()
    test_path_traversal_vulnerabilities()
    test_batch_limit_vulnerability()

    print("\n======================= TEST SUMMARY =======================")
    print(f"Total Passed: {passed_tests}")
    print(f"Total Failed: {failed_tests}")
    print("=============================================================")
    if failed_tests > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
