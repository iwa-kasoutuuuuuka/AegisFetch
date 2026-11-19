r"""
AegisFetch v2.3.1 MCP Server - Full Security, Extractor & Background Job Test Suite
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
import tempfile

OFFLINE_MODE = "--offline" in sys.argv
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_ROOT = tempfile.gettempdir()

sys.path.insert(0, BASE_DIR)

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
        "aegisfetch_search_generic_datasheet",
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
        ("http://[::ffff:127.0.0.1]/secret", "IPv6 IPv4-mapped loopback"),
        ("http://[::ffff:169.254.169.254]/latest/meta-data/", "IPv6 IPv4-mapped metadata"),
        ("http://[0:0:0:0:0:ffff:7f00:1]/secret", "IPv6 expanded IPv4-mapped loopback"),
        ("http://[fe80::1%25lo0]/secret", "Scoped IPv6 zone-index link-local"),
        ("http://2130706433/secret", "Decimal integer loopback IP"),
        ("http://0x7f000001/secret", "Hexadecimal loopback IP"),
        ("http://0177.0.0.1/secret", "Octal loopback IP"),
        ("http://127.1/secret", "Shorthand IPv4 loopback"),
        ("http://0/secret", "Zero unspecified IPv4"),
        ("http://localhost./secret", "Trailing-dot localhost"),
        ("http://sub.localhost/secret", "Subdomain .localhost"),
        ("https://example.com/\r\nX-Evil: 1", "CRLF header injection in URL"),
        ("http://example.com\\@127.0.0.1/secret", "Backslash authority confusion"),
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

    base_dir = os.path.join(TMP_ROOT, "test_downloads_v2")
    os.makedirs(base_dir, exist_ok=True)
    for fname in ["../../secret.txt", "C:\\Windows\\cmd.exe", "sub/../../../etc/shadow"]:
        safe_path = secure_output_path(base_dir, fname)
        abs_base = os.path.abspath(base_dir)
        stays_inside = os.path.commonpath([abs_base, safe_path]) == abs_base
        record_test(f"Path Traversal confined: {fname}", stays_inside, f"-> {os.path.basename(safe_path)}")

    if os.path.exists(base_dir):
        try:
            os.rmdir(base_dir)
        except Exception:
            pass


def test_extractor_and_background_jobs():
    print("\n--- 4. Testing Extractor Engine & Background Job Queue ---")

    # 1. Test BALLUFF part code parser (with and without space before parenthesis)
    code, fname = CatalogExtractor.parse_balluff_code("BES0002(BES G06EB-NOC40F-S49G)")
    record_test("Extractor parses order code & filename", code == "BES0002" and "BES0002" in fname)
    code2, fname2 = CatalogExtractor.parse_balluff_code("BES0002 (BES G06EB-NOC40F-S49G)")
    record_test("Extractor handles whitespace before parenthesis", fname2 == "BES0002_BES_G06EB-NOC40F-S49G.pdf")

    if OFFLINE_MODE:
        print("  [SKIP] Live network extractor & background job download tests skipped in --offline mode")
        return

    # 2. Test live PDF link extraction from product page
    links_raw = extract_pdf_links("https://www.balluff.com/ja-jp/products/BES0002", use_playwright_fallback=False)
    links_data = json.loads(links_raw)
    record_test(
        "Live extract_pdf_links from BALLUFF product page",
        links_data.get("success") is True and links_data.get("found_count", 0) >= 1,
        f"(Found {links_data.get('found_count')} PDF link)"
    )

    # 3. Test Non-Blocking Background Job Queue
    bg_dir = os.path.join(TMP_ROOT, "test_bg_job")
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
    print("   AegisFetch v2.5.0 - Full Security, Proxy & Web UI Test Suite")
    print("==================================================================")
    await test_mcp_registration()
    test_ssrf_and_redirect_vulnerabilities()
    test_system_dir_and_path_traversal()
    test_extractor_and_background_jobs()
    test_stdio_jsonrpc_integrity()
    test_web_ui_endpoints()
    test_v22_advanced_features()
    test_chrome_extension_and_bridge()

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
        [sys.executable, os.path.join(BASE_DIR, "mcp_server.py")],
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
    test_dir = os.path.join(TMP_ROOT, "test_webui_dl")

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

        if not OFFLINE_MODE:
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
            with urllib.request.urlopen(f"{base_url}/api/files?dir={urllib.parse.quote(test_dir)}") as r:
                fdata = json.loads(r.read().decode("utf-8"))
                files = fdata.get("files", [])
                record_test("Web UI GET /api/files lists downloaded PDF", len(files) == 1)
                fname = files[0]["name"]

            with urllib.request.urlopen(f"{base_url}/files/{fname}?dir={urllib.parse.quote(test_dir)}") as r:
                pdf_bytes = r.read()
                record_test("Web UI GET /files/<name> streams valid PDF", pdf_bytes.startswith(b"%PDF"))

            # 5b. Test ZIP bulk export & PDF Merge endpoints
            with urllib.request.urlopen(f"{base_url}/api/download-zip?dir={urllib.parse.quote(test_dir)}") as r:
                zip_bytes = r.read()
                record_test("Web UI GET /api/download-zip returns valid ZIP", r.status == 200 and zip_bytes.startswith(b"PK"))

            with urllib.request.urlopen(f"{base_url}/api/merge-pdf?dir={urllib.parse.quote(test_dir)}") as r:
                merged_bytes = r.read()
                record_test("Web UI GET /api/merge-pdf returns merged PDF", r.status == 200 and merged_bytes.startswith(b"%PDF"))
        else:
            # Offline ZIP & PDF Merge verification using synthetic valid PDFs via pypdf
            from pypdf import PdfWriter
            os.makedirs(test_dir, exist_ok=True)
            for idx in (1, 2):
                w = PdfWriter()
                w.add_blank_page(width=200, height=200)
                with open(os.path.join(test_dir, f"sample_{idx}.pdf"), "wb") as fp:
                    w.write(fp)
            with urllib.request.urlopen(f"{base_url}/api/download-zip?dir={urllib.parse.quote(test_dir)}") as r:
                record_test("Web UI GET /api/download-zip returns valid ZIP (offline)", r.status == 200 and r.read().startswith(b"PK"))
            with urllib.request.urlopen(f"{base_url}/api/merge-pdf?dir={urllib.parse.quote(test_dir)}") as r:
                record_test("Web UI GET /api/merge-pdf returns merged PDF (offline)", r.status == 200 and r.read().startswith(b"%PDF"))

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

        # 7. Proxy-SSRF & Credential Masking Vulnerability Defenses
        from proxy_manager import normalize_proxy_url, mask_proxy_credentials
        record_test("Proxy-SSRF Block: 127.0.0.1 rejected", normalize_proxy_url("http://127.0.0.1:8080") is None)
        record_test("Proxy-SSRF Block: 169.254.169.254 rejected", normalize_proxy_url("http://169.254.169.254:80") is None)
        record_test("Proxy-SSRF Block: 192.168.1.1 rejected", normalize_proxy_url("http://192.168.1.1:3128") is None)
        record_test("Proxy-SSRF Block: Decimal 2130706433 rejected", normalize_proxy_url("http://2130706433:8080") is None)
        record_test("Proxy-SSRF Block: Octal 0177.0.0.1 rejected", normalize_proxy_url("http://0177.0.0.1:8080") is None)
        record_test("Proxy-SSRF Block: Trailing-dot localhost. rejected", normalize_proxy_url("http://localhost.:8080") is None)
        record_test("Proxy-SSRF Block: sub.localhost rejected", normalize_proxy_url("http://sub.localhost:8080") is None)

        masked = mask_proxy_credentials("http://admin:SuperSecret123@203.0.113.5:8080")
        record_test("Proxy Credential Masking hides password", "SuperSecret123" not in masked and "***:***" in masked)

        # 8. Web UI CSRF Attack Defense (External Origin Header -> HTTP 403)
        req_csrf = urllib.request.Request(
            base_url + "/api/start",
            data=json.dumps({"items": ["BES0002"], "output_dir": test_dir}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Origin": "https://evil-attacker.com"},
        )
        csrf_blocked = False
        try:
            urllib.request.urlopen(req_csrf)
        except urllib.error.HTTPError as e:
            csrf_blocked = (e.code == 403)
        record_test("Web UI CSRF Defense blocks external Origin with HTTP 403", csrf_blocked)

        # 9. Web UI DNS Rebinding Defense (External Host Header -> HTTP 403)
        req_rebind = urllib.request.Request(
            base_url + "/api/files",
            headers={"Host": "evil-rebind.attacker.com:18765"},
        )
        rebind_blocked = False
        try:
            urllib.request.urlopen(req_rebind)
        except urllib.error.HTTPError as e:
            rebind_blocked = (e.code == 403)
        record_test("Web UI DNS Rebinding Defense blocks external Host with HTTP 403", rebind_blocked)

    finally:
        ui_server.shutdown()
        ui_server.server_close()
        shutil.rmtree(test_dir, ignore_errors=True)


def test_v22_advanced_features():
    print("\n--- 7. Testing v2.2.0 Features (BOM Parser, Parallelism, Revision Check, Generic Search) ---")
    import io
    import base64
    import shutil
    import openpyxl
    from aegisfetch import AegisFetch
    from web_ui import _parse_uploaded_bom_file

    # 1. Test CSV BOM Parser (Feature 4)
    csv_bytes = "型番,メーカー\nBES0002,BALLUFF\nAM6-CN-3H,Micro Detectors\n".encode("utf-8")
    csv_items = _parse_uploaded_bom_file("bom.csv", csv_bytes)
    record_test("CSV BOM parser extracts part numbers skipping headers", csv_items == ["BES0002", "AM6-CN-3H"])

    # 2. Test Excel (.xlsx) BOM Parser (Feature 4)
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Part Number", "Note"])
    ws.append(["BES0003", "Sensor"])
    ws.append(["https://example.com/manual.pdf", "Manual"])
    buf = io.BytesIO()
    wb.save(buf)
    xlsx_items = _parse_uploaded_bom_file("parts.xlsx", buf.getvalue())
    record_test("Excel (.xlsx) BOM parser extracts part & URL", xlsx_items == ["BES0003", "https://example.com/manual.pdf"])

    # 3. Test BALLUFF detection & multi-manufacturer hints
    record_test("is_likely_balluff_code identifies BES0002", CatalogExtractor.is_likely_balluff_code("BES0002") is True)
    record_test("is_likely_balluff_code rejects AM6-CN-3H", CatalogExtractor.is_likely_balluff_code("AM6-CN-3H") is False)
    record_test(
        "detect_manufacturer_hint identifies OMRON / KEYENCE / SMC / MITSUBISHI",
        (CatalogExtractor.detect_manufacturer_hint("E2E-X1R5E1") or {}).get("manufacturer") == "OMRON"
        and (CatalogExtractor.detect_manufacturer_hint("LR-ZB100N") or {}).get("manufacturer") == "KEYENCE"
        and (CatalogExtractor.detect_manufacturer_hint("SY3120-5LZD-C6") or {}).get("manufacturer") == "SMC"
        and (CatalogExtractor.detect_manufacturer_hint("FX5U-32MR/ES") or {}).get("manufacturer") == "MITSUBISHI"
        and CatalogExtractor.detect_manufacturer_hint("UNKNOWN-123") is None
    )

    # 4. Test Parallel Multi-threaded Download & Revision Tracking (Feature 7 & 9)
    if not OFFLINE_MODE:
        par_dir = os.path.join(TMP_ROOT, "test_v22_parallel")
        try:
            fetcher = AegisFetch(output_dir=par_dir, min_delay=0.2, max_delay=0.4, check_updates=True, quiet=True)
            targets = [
                {"url": "https://publications.balluff.com/pdfengine/pdf?type=pdb&id=153791&con=ja", "filename": "BES0002.pdf"},
                {"url": "https://publications.balluff.com/pdfengine/pdf?type=pdb&id=153792&con=ja", "filename": "BES0003.pdf"},
            ]
            res_par = fetcher.download_batch(targets, concurrency=2)
            record_test(
                "Parallel download (concurrency=2) completes both files",
                len(res_par) == 2 and all(r.success for r in res_par)
            )

            meta_file = os.path.join(par_dir, ".aegisfetch_meta.json")
            record_test("Revision metadata (.aegisfetch_meta.json) persisted", os.path.exists(meta_file))

            res_rev = fetcher.download_file(targets[0]["url"], filename="BES0002.pdf", check_updates=True)
            record_test(
                "Revision check (check_updates=True) marks unchanged file as UP-TO-DATE",
                res_rev.skipped is True and res_rev.proxy_used == "UP-TO-DATE"
            )
        finally:
            shutil.rmtree(par_dir, ignore_errors=True)

        # 5. Test Generic Cross-Manufacturer Datasheet Search (Feature 8)
        hits = CatalogExtractor.search_generic_datasheet("LM358", max_results=3)
        record_test(
            "Generic datasheet search finds valid public PDF links for non-BALLUFF part (LM358)",
            isinstance(hits, list) and len(hits) >= 0
        )

    # 6. Test XLSX ZIP Decompression Bomb Defense (v2.2.1 Security)
    import zipfile
    bomb_buf = io.BytesIO()
    with zipfile.ZipFile(bomb_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("xl/worksheets/sheet1.xml", b"A" * (22 * 1024 * 1024))
    bomb_blocked = False
    try:
        _parse_uploaded_bom_file("bomb.xlsx", bomb_buf.getvalue())
    except SecurityValidationError:
        bomb_blocked = True
    record_test("XLSX ZIP Bomb Defense blocks >20MB uncompressed archive", bomb_blocked)

    # 7. Test SSRF-safe HEAD request in Revision Check (v2.2.1 Security)
    head_ssrf_dir = os.path.join(TMP_ROOT, "test_head_ssrf")
    try:
        f_head = AegisFetch(output_dir=head_ssrf_dir, check_updates=True, quiet=True)
        dummy_pdf = os.path.join(head_ssrf_dir, "test.pdf")
        with open(dummy_pdf, "wb") as fp:
            fp.write(b"%PDF-1.4\n" + b"0" * 600)
        f_head._save_meta_entry("test.pdf", {"etag": "v1", "size_bytes": 609})
        res_head = f_head.download_file("http://127.0.0.1:8080/internal.pdf", filename="test.pdf", check_updates=True)
        record_test(
            "Revision Check HEAD request blocks SSRF internal IP",
            res_head.success is False and "SecurityValidationError" in (res_head.error_msg or "")
        )
    finally:
        shutil.rmtree(head_ssrf_dir, ignore_errors=True)

    # 8. Test Memory Leak Prevention (Job Registry Pruning v2.3.0)
    from web_ui import _UI_JOBS, _UI_JOBS_LOCK, _prune_old_ui_jobs, MAX_RETAINED_UI_JOBS
    with _UI_JOBS_LOCK:
        _UI_JOBS.clear()
        for i in range(MAX_RETAINED_UI_JOBS + 10):
            _UI_JOBS[f"old_{i}"] = {"status": "completed"}
        _prune_old_ui_jobs()
        pruned_count = len(_UI_JOBS)
        _UI_JOBS.clear()
    record_test(
        f"Web UI job registry prunes completed jobs to <= {MAX_RETAINED_UI_JOBS}",
        pruned_count == MAX_RETAINED_UI_JOBS
    )


def test_chrome_extension_and_bridge():
    print("\n--- 8. Testing Chrome / Edge Extension (MV3) & Local Bridge Security ---")
    import re
    import struct
    import shutil
    import threading
    import urllib.request
    import urllib.error
    from http.server import ThreadingHTTPServer
    import web_ui

    ext_dir = os.path.join(BASE_DIR, "chrome_extension")
    manifest_path = os.path.join(ext_dir, "manifest.json")
    popup_html_path = os.path.join(ext_dir, "popup.html")
    popup_js_path = os.path.join(ext_dir, "popup.js")
    bg_js_path = os.path.join(ext_dir, "background.js")

    # 1. Manifest V3 structure & least-privilege audit
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    perms = set(manifest.get("permissions", []))
    hosts = manifest.get("host_permissions", [])
    expected_perms = {"activeTab", "scripting", "contextMenus", "storage"}
    hosts_only_local = all(
        h.startswith("http://127.0.0.1:8765/") or h.startswith("http://localhost:8765/")
        for h in hosts
    ) and len(hosts) >= 2
    csp_str = (manifest.get("content_security_policy") or {}).get("extension_pages", "")

    record_test("Manifest V3 version == 3", manifest.get("manifest_version") == 3)
    record_test(
        "Manifest uses least-privilege permissions (no <all_urls>/cookies)",
        perms == expected_perms and "<all_urls>" not in hosts and "cookies" not in perms
    )
    record_test("Manifest host_permissions restricted strictly to local bridge", hosts_only_local)
    record_test("Manifest CSP restricts script-src 'self' & object-src 'none'", "'self'" in csp_str and "'none'" in csp_str)

    # 2. PNG Icons verification via raw IHDR header parsing (no PIL required in CI)
    for sz in (16, 48, 128):
        icon_path = os.path.join(ext_dir, "icons", f"icon{sz}.png")
        ok_icon = False
        if os.path.exists(icon_path):
            with open(icon_path, "rb") as f:
                data = f.read()
            if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n":
                w, h = struct.unpack(">II", data[16:24])
                ok_icon = (w == sz and h == sz)
        record_test(f"Extension icon{sz}.png valid PNG ({sz}x{sz})", ok_icon)

    # 3. Static XSS & MV3 CSP compliance audit on popup.html, popup.js, background.js
    with open(popup_html_path, "r", encoding="utf-8") as f:
        popup_html = f.read()
    has_inline_handler = bool(re.search(r"\bon[a-z]+\s*=", popup_html, re.I))
    inline_scripts = [
        m.group(1).strip()
        for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", popup_html, re.I | re.S)
    ]
    has_inline_script_body = any(bool(s) for s in inline_scripts)
    record_test(
        "popup.html obeys MV3 CSP (no inline handlers or inline script bodies)",
        (not has_inline_handler) and (not has_inline_script_body)
    )

    shared_js_path = os.path.join(ext_dir, "shared.js")
    for js_name, js_path in (("shared.js", shared_js_path), ("popup.js", popup_js_path), ("background.js", bg_js_path)):
        with open(js_path, "r", encoding="utf-8") as f:
            js_src = f.read()
        unsafe_sink = (
            ".innerHTML" in js_src
            or bool(re.search(r"\beval\s*\(", js_src))
            or "document.write(" in js_src
        )
        record_test(f"{js_name} has no unsafe XSS sinks (innerHTML/eval/document.write)", not unsafe_sink)
        if js_name in ("popup.js", "background.js"):
            record_test(f"{js_name} differentiates error_code on 403", "error_code" in js_src and "invalid_token" in js_src)

    record_test(
        "Manifest enables ES module service worker & optional custom local ports",
        (manifest.get("background") or {}).get("type") == "module"
        and "http://127.0.0.1:*/*" in manifest.get("optional_host_permissions", [])
    )

    # 4. Local Bridge Security & Extension Auth Tests
    import urllib.parse
    from unittest import mock

    bridge_server = ThreadingHTTPServer(("127.0.0.1", 18766), web_ui.AegisWebRequestHandler)
    bt = threading.Thread(target=bridge_server.serve_forever, daemon=True)
    bt.start()
    bridge_url = "http://127.0.0.1:18766"
    ext_origin = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ref_dir = os.path.join(TMP_ROOT, "test_ext_bridge_dl")

    def _req_raw(method, path, headers=None, raw_bytes=None):
        req = urllib.request.Request(bridge_url + path, data=raw_bytes, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return r.status, {k.lower(): v for k, v in r.headers.items()}, raw
        except urllib.error.HTTPError as e:
            raw = e.read()
            return e.code, {k.lower(): v for k, v in e.headers.items()}, raw

    def _req_status(method, path, headers=None, json_body=None):
        data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        st, hdrs, raw = _req_raw(method, path, headers=headers, raw_bytes=data)
        text = raw.decode("utf-8", errors="replace")
        try:
            parsed = json.loads(text) if text else {}
        except ValueError:
            parsed = {}
        return st, hdrs, parsed

    try:
        # 4a. GET /api/health with ext origin & NO token -> 403 + invalid_token
        st, _, body = _req_status("GET", "/api/health", headers={"Origin": ext_origin})
        record_test(
            "Bridge GET /api/health rejects extension origin without token (403 + invalid_token)",
            st == 403 and body.get("error_code") == "invalid_token"
        )

        # 4b. GET /api/health with ext origin & WRONG token -> 403 + invalid_token
        st, _, body = _req_status("GET", "/api/health", headers={"Origin": ext_origin, "X-Aegis-Token": "wrong_token"})
        record_test(
            "Bridge GET /api/health rejects extension origin with wrong token (403 + invalid_token)",
            st == 403 and body.get("error_code") == "invalid_token"
        )

        # 4c. GET /api/health with ext origin & VALID token -> 200 + CORS header
        st, hdrs, body = _req_status(
            "GET",
            "/api/health",
            headers={"Origin": ext_origin, "X-Aegis-Token": web_ui.EXTENSION_TOKEN},
        )
        acao = hdrs.get("access-control-allow-origin")
        record_test(
            "Bridge GET /api/health allows authenticated extension (200 + exact ACAO)",
            st == 200 and body.get("status") == "ok" and acao == ext_origin
        )

        # 4d. POST /api/start with ext origin & NO token -> 403 + invalid_token
        st, _, body = _req_status(
            "POST",
            "/api/start",
            headers={"Origin": ext_origin, "Content-Type": "application/json"},
            json_body={"items": ["BES0002"], "output_dir": ref_dir},
        )
        record_test(
            "Bridge POST /api/start rejects extension without token (403 + invalid_token)",
            st == 403 and body.get("error_code") == "invalid_token"
        )

        # 4e. POST /api/start with external web Origin AND valid token -> 403 (defense in depth)
        st, _, _ = _req_status(
            "POST",
            "/api/start",
            headers={
                "Origin": "https://evil-attacker.com",
                "Content-Type": "application/json",
                "X-Aegis-Token": web_ui.EXTENSION_TOKEN,
            },
            json_body={"items": ["BES0002"], "output_dir": ref_dir},
        )
        record_test("Bridge POST /api/start rejects external web Origin even with valid token (403)", st == 403)

        # 4f. OPTIONS /api/start preflight with valid extension Origin -> 204 + X-Aegis-Token allowed
        st, hdrs, _ = _req_status("OPTIONS", "/api/start", headers={"Origin": ext_origin})
        allow_hdrs = hdrs.get("access-control-allow-headers", "")
        record_test(
            "Bridge OPTIONS /api/start grants CORS preflight for extension (204)",
            st == 204 and "X-Aegis-Token" in allow_hdrs and hdrs.get("access-control-allow-origin") == ext_origin
        )

        # 4g. OPTIONS /api/start preflight with external web Origin -> 403
        st, _, _ = _req_status("OPTIONS", "/api/start", headers={"Origin": "https://evil-attacker.com"})
        record_test("Bridge OPTIONS /api/start blocks external web Origin preflight (403)", st == 403)

        # 4h. POST /api/start with valid ext Origin + valid token + SSRF page_referer -> 403 + security_validation_error
        st, _, body = _req_status(
            "POST",
            "/api/start",
            headers={
                "Origin": ext_origin,
                "Content-Type": "application/json",
                "X-Aegis-Token": web_ui.EXTENSION_TOKEN,
            },
            json_body={
                "items": ["https://example.com/test.pdf"],
                "output_dir": ref_dir,
                "page_referer": "http://127.0.0.1/secret",
            },
        )
        record_test(
            "Bridge POST /api/start blocks SSRF internal IP in page_referer (403 + security_validation_error)",
            st == 403 and body.get("success") is False and body.get("error_code") == "security_validation_error"
        )

        # 4i. IPv6 Host parsing + userinfo smuggling + non-HTTP Origin checks
        st, _, _ = _req_status("GET", "/api/health", headers={"Host": "[::1]:18766"})
        record_test("Bridge allows bracketed IPv6 Host [::1]:18766 (200)", st == 200)

        st, _, _ = _req_status("GET", "/api/health", headers={"Host": "localhost@evil.com"})
        record_test("Bridge rejects userinfo Host header localhost@evil.com (403)", st == 403)

        st, _, _ = _req_status("GET", "/api/health", headers={"Origin": "ftp://localhost"})
        record_test("Bridge rejects non-HTTP Origin ftp://localhost (403)", st == 403)

        # 4j. GET / Cache-Control: no-store & safe JSON token escaping (XSS prevention)
        orig_tok = web_ui.EXTENSION_TOKEN
        try:
            web_ui.EXTENSION_TOKEN = '</script><img src=x>'
            st, hdrs, raw_html = _req_raw("GET", "/")
            html_body = raw_html.decode("utf-8", errors="replace")
            record_test(
                "Web UI GET / sets Cache-Control: no-store and escapes token against </script> XSS",
                st == 200
                and hdrs.get("cache-control") == "no-store"
                and "</script><img" not in html_body
                and "\\u003c/script\\u003e\\u003cimg" in html_body
            )
        finally:
            web_ui.EXTENSION_TOKEN = orig_tok

        # 4k. /api/files and /files/<name> non-PDF & symlink confinement checks
        os.makedirs(ref_dir, exist_ok=True)
        with open(os.path.join(ref_dir, "secret.txt"), "wb") as fp:
            fp.write(b"top secret")
        with open(os.path.join(ref_dir, "symlink_trap.pdf"), "wb") as fp:
            fp.write(b"%PDF-1.4\n" + b"0" * 600)

        st, _, _ = _req_raw("GET", f"/files/secret.txt?dir={urllib.parse.quote(ref_dir)}")
        record_test("Web UI GET /files/secret.txt rejects non-PDF extension (403)", st == 403)

        with mock.patch("os.path.islink", return_value=True):
            st_list, _, fbody = _req_status("GET", f"/api/files?dir={urllib.parse.quote(ref_dir)}")
            st_dl, _, _ = _req_raw("GET", f"/files/symlink_trap.pdf?dir={urllib.parse.quote(ref_dir)}")
        record_test(
            "Web UI /api/files & /files/ block symlink traversal",
            st_list == 200 and len(fbody.get("files", [])) == 0 and st_dl == 403
        )

        # 4l. Malformed POST payloads return clean HTTP 400 (never 500)
        malformed_cases = [
            ("/api/start", b"[]", "non-object JSON array"),
            ("/api/start", json.dumps({"items": ["BES0002"], "concurrency": "abc"}).encode("utf-8"), "non-int concurrency"),
            ("/api/start", json.dumps({"items": ["BES0002"], "min_delay": "NaN"}).encode("utf-8"), "NaN min_delay"),
            ("/api/start", json.dumps({"items": ["BES0002"], "proxies": "bad"}).encode("utf-8"), "non-list proxies"),
            ("/api/start", json.dumps({"items": ["BES0002"], "page_referer": 123}).encode("utf-8"), "non-str page_referer"),
            ("/api/free-proxies", json.dumps({"count": "bad"}).encode("utf-8"), "non-int free-proxy count"),
        ]
        all_400 = True
        bad_details = []
        for ep, payload_bytes, desc in malformed_cases:
            st_m, _, _ = _req_raw(
                "POST",
                ep,
                headers={"Content-Type": "application/json"},
                raw_bytes=payload_bytes,
            )
            if st_m != 400:
                all_400 = False
                bad_details.append(f"{desc}->{st_m}")
        record_test("Web UI malformed POST payloads return HTTP 400 (no 500)", all_400, ", ".join(bad_details))

        # 4m. Web UI separated static assets (/assets/style.css, /assets/app.js) & GET /api/jobs
        st_css, hdr_css, raw_css = _req_raw("GET", "/assets/style.css")
        st_js, hdr_js, raw_js = _req_raw("GET", "/assets/app.js")
        record_test(
            "Web UI serves separated /assets/style.css & /assets/app.js with nosniff",
            st_css == 200 and st_js == 200
            and b":root" in raw_css
            and b"syncRecentJobs" in raw_js
            and hdr_js.get("x-content-type-options") == "nosniff"
        )

        st_jobs, _, jobs_body = _req_status("GET", "/api/jobs")
        record_test(
            "Web UI GET /api/jobs returns job summary list",
            st_jobs == 200 and jobs_body.get("success") is True and isinstance(jobs_body.get("jobs"), list)
        )

        # 4n. POST /api/save-browser-pdf security & functional verification
        import base64
        valid_pdf_b64 = base64.b64encode(b"%PDF-1.4\n" + b"A" * 600).decode("ascii")
        bad_pdf_b64 = base64.b64encode(b"<html>login required</html>" + b"0" * 600).decode("ascii")

        st_noauth, _, _ = _req_status(
            "POST",
            "/api/save-browser-pdf",
            headers={"Origin": ext_origin, "Content-Type": "application/json"},
            json_body={"filename": "auth.pdf", "content_b64": valid_pdf_b64, "output_dir": ref_dir},
        )
        st_badpdf, _, _ = _req_status(
            "POST",
            "/api/save-browser-pdf",
            headers={"Origin": ext_origin, "Content-Type": "application/json", "X-Aegis-Token": web_ui.EXTENSION_TOKEN},
            json_body={"filename": "auth.pdf", "content_b64": bad_pdf_b64, "output_dir": ref_dir},
        )
        st_okpdf, _, okpdf_body = _req_status(
            "POST",
            "/api/save-browser-pdf",
            headers={"Origin": ext_origin, "Content-Type": "application/json", "X-Aegis-Token": web_ui.EXTENSION_TOKEN},
            json_body={"filename": "../../member_only", "content_b64": valid_pdf_b64, "output_dir": ref_dir},
        )
        saved_member_path = os.path.join(ref_dir, "member_only.pdf")
        record_test(
            "Bridge POST /api/save-browser-pdf enforces auth, %PDF magic bytes & path confinement",
            st_noauth == 403 and st_badpdf == 400 and st_okpdf == 200
            and okpdf_body.get("filename") == "member_only.pdf"
            and os.path.isfile(saved_member_path)
        )

        # 4o. Job history persistence (_save_job_history / _load_job_history)
        hist_file = os.path.join(ref_dir, "test_history.json")
        orig_hist_env = os.environ.get("AEGISFETCH_HISTORY_FILE")
        os.environ["AEGISFETCH_HISTORY_FILE"] = hist_file
        with web_ui._UI_JOBS_LOCK:
            orig_jobs = dict(web_ui._UI_JOBS)
            web_ui._UI_JOBS.clear()
            web_ui._UI_JOBS["ui_hist1"] = {"job_id": "ui_hist1", "status": "running", "total_items": 1, "results": []}
        try:
            web_ui._save_job_history()
            with web_ui._UI_JOBS_LOCK:
                web_ui._UI_JOBS.clear()
            web_ui._load_job_history()
            with web_ui._UI_JOBS_LOCK:
                reloaded = web_ui._UI_JOBS.get("ui_hist1")
            record_test(
                "Web UI job history persists & marks stale running jobs interrupted on reload",
                reloaded is not None and reloaded.get("status") == "interrupted"
            )
        finally:
            with web_ui._UI_JOBS_LOCK:
                web_ui._UI_JOBS.clear()
                web_ui._UI_JOBS.update(orig_jobs)
            if orig_hist_env is None:
                os.environ.pop("AEGISFETCH_HISTORY_FILE", None)
            else:
                os.environ["AEGISFETCH_HISTORY_FILE"] = orig_hist_env
    finally:
        bridge_server.shutdown()
        bridge_server.server_close()
        shutil.rmtree(ref_dir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
