"""
AegisFetch v2.0 MCP Server - Full Security, Extractor & Background Job Test Suite
==================================================================================
Tests:
1. All 8 MCP Tools Registration & Schema Integrity
2. Normal Functionality (Download, Verify, Status)
3. SSRF Vulnerability Defenses (Loopback, Metadata IP, Private RFC1918, Invalid Schemes)
4. Open-Redirect SSRF Hop Defenses (302 Redirect to 127.0.0.1 / 169.254.169.254)
5. System Directory Write Protection (C:\Windows, /etc, Startup folder)
6. Path Traversal Defenses (Directory traversal sequences, absolute Windows paths)
7. Extractor Engine (Part Number -> PDF resolution & Web Page PDF Link discovery)
8. Non-Blocking Background Job Queue (start_batch_job -> get_job_status)
"""

import os
import sys
import time
import json
import asyncio

sys.path.insert(0, os.path.abspath("e:/temp/AegisFetch"))

from mcp_server import (
    server,
    download_single,
    download_by_part_number,
    extract_pdf_links,
    download_batch,
    start_batch_job,
    get_job_status,
    verify_file,
    get_status,
)
from security import (
    validate_url,
    validate_redirect_target,
    validate_output_directory,
    secure_output_path,
    SecurityValidationError,
)
from extractors import CatalogExtractor

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
    print("\n--- 1. Testing MCP Server v2.0 Tool Registration (8 Tools) ---")
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    expected = [
        "aegisfetch_download_single",
        "aegisfetch_download_by_part_number",
        "aegisfetch_extract_pdf_links",
        "aegisfetch_download_batch",
        "aegisfetch_start_batch_job",
        "aegisfetch_get_job_status",
        "aegisfetch_verify_file",
        "aegisfetch_fetch_free_proxies",
        "aegisfetch_get_status",
    ]
    for exp in expected:
        record_test(f"Tool '{exp}' registered", exp in tool_names)


def test_ssrf_and_redirect_vulnerabilities():
    print("\n--- 2. Testing SSRF & Open-Redirect Hop Defenses ---")

    malicious_urls = [
        ("http://127.0.0.1:8080/admin", "Loopback IPv4"),
        ("http://localhost:3000/", "Localhost domain"),
        ("http://169.254.169.254/latest/meta-data/", "AWS/Cloud Metadata Service"),
        ("http://192.168.1.1/router_config", "Private LAN RFC1918 Class C"),
        ("http://10.0.0.5/internal_db", "Private LAN RFC1918 Class A"),
        ("http://172.16.0.1/vault", "Private LAN RFC1918 Class B"),
        ("file:///C:/Windows/System32/drivers/etc/hosts", "Local file scheme"),
        ("gopher://127.0.0.1:6379/_flushall", "Gopher scheme injection"),
    ]

    for url, desc in malicious_urls:
        blocked = False
        try:
            validate_url(url)
        except SecurityValidationError:
            blocked = True
        record_test(f"SSRF Direct Block: {desc}", blocked)

    # Open Redirect SSRF tests
    redirect_cases = [
        ("https://public-site.com/dl", "http://127.0.0.1/admin", "Redirect to 127.0.0.1"),
        ("https://public-site.com/dl", "http://169.254.169.254/latest/meta-data/", "Redirect to Cloud Metadata"),
        ("https://public-site.com/dl", "file:///etc/passwd", "Redirect to file:// scheme"),
    ]
    for origin, loc, desc in redirect_cases:
        blocked = False
        try:
            validate_redirect_target(origin, loc)
        except SecurityValidationError:
            blocked = True
        record_test(f"Open-Redirect SSRF Block: {desc}", blocked)


def test_system_dir_and_path_traversal():
    print("\n--- 3. Testing System Directory Protection & Path Traversal ---")

    forbidden_dirs = [
        ("C:\\Windows\\System32", "Windows System32 folder"),
        ("C:\\Program Files\\Common Files", "Program Files folder"),
        ("/etc/systemd", "Linux /etc directory"),
        ("C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "Windows Startup folder"),
    ]
    for d, desc in forbidden_dirs:
        blocked = False
        try:
            validate_output_directory(d)
        except SecurityValidationError:
            blocked = True
        record_test(f"Forbidden Output Dir Blocked: {desc}", blocked)

    base_dir = "e:/temp/test_downloads_v2"
    os.makedirs(base_dir, exist_ok=True)
    for fname in ["../../secret.txt", "C:\\Windows\\cmd.exe", "sub/../../../etc/shadow"]:
        safe_path = secure_output_path(base_dir, fname)
        abs_base = os.path.abspath(base_dir)
        stays_inside = os.path.commonpath([abs_base, safe_path]) == abs_base
        record_test(f"Path Traversal confined: {fname}", stays_inside, f"-> {os.path.basename(safe_path)}")

    if os.path.exists(base_dir):
        try:
            os.rmdir(base_dir)
        except:
            pass


def test_extractor_and_background_jobs():
    print("\n--- 4. Testing Extractor Engine & Background Job Queue ---")

    # 1. Test BALLUFF part code parser (with and without space before parenthesis)
    code, fname = CatalogExtractor.parse_balluff_code("BES0002(BES G06EB-NOC40F-S49G)")
    record_test("Extractor parses order code & filename", code == "BES0002" and "BES0002" in fname)
    code2, fname2 = CatalogExtractor.parse_balluff_code("BES0002 (BES G06EB-NOC40F-S49G)")
    record_test("Extractor handles whitespace before parenthesis", fname2 == "BES0002_BES_G06EB-NOC40F-S49G.pdf")

    # 2. Test live PDF link extraction from product page
    links_raw = extract_pdf_links("https://www.balluff.com/ja-jp/products/BES0002", use_playwright_fallback=False)
    links_data = json.loads(links_raw)
    record_test(
        "Live extract_pdf_links from BALLUFF product page",
        links_data.get("success") is True and links_data.get("found_count", 0) >= 1,
        f"(Found {links_data.get('found_count')} PDF link)"
    )

    # 3. Test Non-Blocking Background Job Queue
    bg_dir = "e:/temp/test_bg_job"
    job_raw = start_batch_job(
        items=["BES0002"],
        is_part_numbers=True,
        output_dir=bg_dir,
        min_delay=0.4,
        max_delay=0.6
    )
    job_data = json.loads(job_raw)
    job_id = job_data.get("job_id")
    record_test("Background job started non-blocking", job_data.get("success") is True and bool(job_id), f"(job_id={job_id})")

    # Wait for background worker to finish
    for _ in range(20):
        st_raw = get_job_status(job_id)
        st = json.loads(st_raw)
        if st.get("status") == "completed":
            break
        time.sleep(0.8)

    st_final = json.loads(get_job_status(job_id))
    record_test(
        "Background job completed & downloaded datasheet",
        st_final.get("status") == "completed" and st_final.get("success_count") == 1,
        f"(Progress: {st_final.get('progress')})"
    )

    # Cleanup
    if os.path.exists(bg_dir):
        for f in os.listdir(bg_dir):
            try:
                os.remove(os.path.join(bg_dir, f))
            except:
                pass
        try:
            os.rmdir(bg_dir)
        except:
            pass


async def main():
    print("==================================================================")
    print("   AegisFetch v2.0.1 - Full Security, Extractor & Job Test Suite")
    print("==================================================================")
    await test_mcp_registration()
    test_ssrf_and_redirect_vulnerabilities()
    test_system_dir_and_path_traversal()
    test_extractor_and_background_jobs()
    test_stdio_jsonrpc_integrity()
    test_web_ui_endpoints()

    print("\n========================== TEST SUMMARY ==========================")
    print(f"Total Passed: {passed_tests}")
    print(f"Total Failed: {failed_tests}")
    print("==================================================================")
    if failed_tests > 0:
        sys.exit(1)


def test_stdio_jsonrpc_integrity():
    print("\n--- 5. Testing MCP Stdio JSON-RPC Protocol Purity ---")
    import io
    import subprocess

    # Verify zero stdout pollution during tool execution
    buf = io.StringIO()
    old_out = sys.stdout
    sys.stdout = buf
    try:
        get_status()
    finally:
        sys.stdout = old_out
    record_test("Zero stdout pollution during MCP tool calls", len(buf.getvalue()) == 0)

    # Verify real subprocess stdio JSON-RPC initialize handshake
    proc = subprocess.Popen(
        [sys.executable, os.path.abspath("e:/temp/AegisFetch/mcp_server.py")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-suite", "version": "1.0.0"},
            },
        }
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        resp = json.loads(line)
        record_test(
            "Subprocess stdio JSON-RPC handshake valid",
            resp.get("id") == 1 and resp.get("result", {}).get("serverInfo", {}).get("name") == "AegisFetch",
        )
    finally:
        proc.terminate()


def test_web_ui_endpoints():
    print("\n--- 6. Testing Web UI Dashboard Server & API Security ---")
    import threading
    import shutil
    import urllib.request
    import urllib.error
    from http.server import ThreadingHTTPServer
    from web_ui import AegisWebRequestHandler

    ui_server = ThreadingHTTPServer(("127.0.0.1", 18765), AegisWebRequestHandler)
    t = threading.Thread(target=ui_server.serve_forever, daemon=True)
    t.start()
    base_url = "http://127.0.0.1:18765"
    test_dir = "e:/temp/test_webui_dl"

    try:
        # 1. Dashboard HTML
        with urllib.request.urlopen(base_url + "/") as r:
            html_text = r.read().decode("utf-8")
            record_test("Web UI GET / serves HTML dashboard", r.status == 200 and "AegisFetch Web Console" in html_text)

        # 2. Icon SVG
        with urllib.request.urlopen(base_url + "/assets/icon.svg") as r:
            svg_bytes = r.read()
            record_test("Web UI GET /assets/icon.svg serves SVG", r.status == 200 and b"<svg" in svg_bytes)

        # 3. Security check on forbidden output_dir
        req_forbidden = urllib.request.Request(
            base_url + "/api/start",
            data=json.dumps({"items": ["BES0002"], "output_dir": "C:\\Windows\\System32"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        blocked_403 = False
        try:
            urllib.request.urlopen(req_forbidden)
        except urllib.error.HTTPError as e:
            blocked_403 = (e.code == 403)
        record_test("Web UI POST /api/start blocks System32 with HTTP 403", blocked_403)

        # 4. Launch real download job from Web UI
        req_dl = urllib.request.Request(
            base_url + "/api/start",
            data=json.dumps({"items": ["BES0002"], "output_dir": test_dir, "min_delay": 0.3, "max_delay": 0.5}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req_dl) as r:
            start_data = json.loads(r.read().decode("utf-8"))
            job_id = start_data.get("job_id")
            record_test("Web UI POST /api/start launches download job", start_data.get("success") is True and bool(job_id))

        job_state = {}
        for _ in range(25):
            with urllib.request.urlopen(f"{base_url}/api/job?job_id={job_id}") as r:
                job_state = json.loads(r.read().decode("utf-8"))
                if job_state.get("status") == "completed":
                    break
            time.sleep(0.5)

        record_test(
            "Web UI GET /api/job completes download",
            job_state.get("status") == "completed" and job_state.get("success_count") == 1,
        )

        # 5. List and serve downloaded PDF via Web UI
        with urllib.request.urlopen(f"{base_url}/api/files?dir={test_dir}") as r:
            fdata = json.loads(r.read().decode("utf-8"))
            files = fdata.get("files", [])
            record_test("Web UI GET /api/files lists downloaded PDF", len(files) == 1)
            fname = files[0]["name"]

        with urllib.request.urlopen(f"{base_url}/files/{fname}?dir={test_dir}") as r:
            pdf_bytes = r.read()
            record_test("Web UI GET /files/<name> streams valid PDF", pdf_bytes.startswith(b"%PDF"))

        # 6. Test ProxyRotator & Web UI POST /api/free-proxies
        from proxy_manager import ProxyRotator
        rot = ProxyRotator(["1.1.1.1:8080", "http://2.2.2.2:3128", "socks5://3.3.3.3:1080"])
        p1, p2, p3, p4 = rot.get_next_proxy(), rot.get_next_proxy(), rot.get_next_proxy(), rot.get_next_proxy()
        record_test(
            "ProxyRotator round-robin switches IP on every call",
            p1 == "http://1.1.1.1:8080" and p2 == "http://2.2.2.2:3128" and p3 == "socks5://3.3.3.3:1080" and p4 == p1
        )

        # Dead proxy eviction test
        rot.report_failure("http://1.1.1.1:8080")
        rot.report_failure("http://1.1.1.1:8080")
        record_test("ProxyRotator evicts dead proxy after threshold", "http://1.1.1.1:8080" not in rot.active_proxies)

        # Web UI /api/free-proxies endpoint test
        req_fp = urllib.request.Request(
            base_url + "/api/free-proxies",
            data=json.dumps({"preset_only": True}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req_fp) as r:
            fp_data = json.loads(r.read().decode("utf-8"))
            record_test(
                "Web UI POST /api/free-proxies returns proxy list",
                fp_data.get("success") is True and len(fp_data.get("working_proxies", [])) >= 5
            )

    finally:
        ui_server.shutdown()
        ui_server.server_close()
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
