"""
AegisFetch Extractor Engine (v2.0)
==================================
Resolves product part numbers or web page URLs into direct PDF download URLs.
Includes built-in support for BALLUFF order codes, generic HTML PDF link extraction,
and automatic Playwright headless browser fallback for heavy JS/SPA pages.
"""

import re
import html
from urllib.parse import urljoin
from typing import List, Optional, Dict, Tuple
from curl_cffi import requests

from security import validate_url, validate_redirect_target, MAX_REDIRECT_HOPS, SecurityValidationError


def fetch_html_secure(
    url: str,
    session: Optional[requests.Session] = None,
    use_playwright_fallback: bool = True
) -> str:
    """
    Fetch HTML with SSRF-safe manual redirect inspection and optional Playwright SPA fallback.
    """
    current_url = validate_url(url)
    own_session = False
    if session is None:
        session = requests.Session(impersonate="chrome124")
        own_session = True

    try:
        for _ in range(MAX_REDIRECT_HOPS):
            resp = session.get(current_url, allow_redirects=False, timeout=20)
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location") or resp.headers.get("location")
                current_url = validate_redirect_target(current_url, loc)
                continue

            if resp.status_code == 200:
                text = resp.text
                # Check if blocked by interactive JS challenge
                if "Just a moment..." in text and use_playwright_fallback:
                    break
                return text
            break
    finally:
        if own_session:
            session.close()

    # Fallback to Playwright if enabled and available
    if use_playwright_fallback:
        return _fetch_html_playwright(current_url)

    raise RuntimeError(f"Failed to retrieve page content from {url}")


def _fetch_html_playwright(url: str) -> str:
    """
    Fallback renderer using Playwright Chromium for SPA / JS-rendered pages.
    """
    validate_url(url)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError("Playwright is not installed for SPA fallback.")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            )
            page.goto(url, wait_until="domcontentloaded", timeout=25000)
            return page.content()
        finally:
            browser.close()


class CatalogExtractor:
    """
    Resolves part numbers and product page URLs into downloadable PDF targets.
    """

    @staticmethod
    def parse_balluff_code(raw_input: str) -> Tuple[str, str]:
        """
        Parse strings like 'BES0002(BES G06EB-NOC40F-S49G)' or 'BES0002'
        into (order_code, full_filename).
        """
        raw = raw_input.strip()
        m = re.match(r"^([A-Z0-9]{7})(?:\((.*?)\))?", raw, re.I)
        if m:
            order_code = m.group(1).upper()
            part_desc = m.group(2) or ""
            safe_desc = re.sub(r"[^a-zA-Z0-9_\-]", "_", part_desc).strip("_")
            fname = f"{order_code}_{safe_desc}.pdf" if safe_desc else f"{order_code}.pdf"
            return order_code, fname
        safe_raw = re.sub(r"[^a-zA-Z0-9_\-]", "_", raw).strip("_")
        return raw, f"{safe_raw}.pdf"

    @classmethod
    def resolve_balluff_part(
        cls,
        part_Code: str,
        locale: str = "ja-jp",
        session: Optional[requests.Session] = None,
        use_playwright_fallback: bool = True
    ) -> Dict[str, str]:
        """
        Given a BALLUFF order code (e.g. 'BES0002'), resolve its datasheet PDF URL.
        """
        order_code, filename = cls.parse_balluff_code(part_Code)
        product_url = f"https://www.balluff.com/{locale}/products/{order_code}"

        page_html = fetch_html_secure(
            product_url,
            session=session,
            use_playwright_fallback=use_playwright_fallback
        )

        matches = re.findall(
            r"https://publications\.balluff\.com/pdfengine/pdf\?[^\s\"'<>]+",
            page_html
        )
        if not matches:
            matches = re.findall(
                r"https:[\\/]+publications\.balluff\.com[\\/]pdfengine[\\/]pdf\?[^\"'\s>]+",
                page_html
            )

        if not matches:
            raise ValueError(f"Datasheet PDF link not found on page for {order_code}")

        pdf_url = html.unescape(matches[0].replace("\\/", "/"))
        return {
            "part_number": part_Code,
            "order_code": order_code,
            "product_url": product_url,
            "url": pdf_url,
            "filename": filename,
            "referer": product_url
        }

    @classmethod
    def extract_pdf_links_from_url(
        cls,
        page_url: str,
        session: Optional[requests.Session] = None,
        use_playwright_fallback: bool = True
    ) -> List[Dict[str, str]]:
        """
        Extract all PDF / datasheet links from any product web page.
        """
        valid_page_url = validate_url(page_url)
        page_html = fetch_html_secure(
            valid_page_url,
            session=session,
            use_playwright_fallback=use_playwright_fallback
        )

        found_urls = []
        seen = set()

        # 1. Direct .pdf hrefs
        href_matches = re.findall(r'href=[\'"]([^\'"]+\.pdf(?:\?[^\'"]*)?)[\'"]', page_html, re.I)
        # 2. BALLUFF pdfengine links
        engine_matches = re.findall(r'(https://publications\.balluff\.com/pdfengine/pdf\?[^\s"\'<>]+)', page_html, re.I)

        for raw_link in href_matches + engine_matches:
            clean_link = html.unescape(raw_link.strip())
            abs_link = urljoin(valid_page_url, clean_link)
            try:
                validate_url(abs_link)
            except SecurityValidationError:
                continue

            if abs_link not in seen:
                seen.add(abs_link)
                fname = abs_link.split("?")[0].split("/")[-1]
                if not fname.lower().endswith(".pdf"):
                    fname = f"document_{len(found_urls) + 1}.pdf"
                found_urls.append({
                    "url": abs_link,
                    "filename": fname,
                    "referer": valid_page_url
                })

        return found_urls
