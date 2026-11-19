"""
AegisFetch Extractor Engine (v2.2.0)
====================================
Resolves product part numbers or web page URLs into direct PDF download URLs.
Features:
- BALLUFF part code parser & multi-locale auto-fallback (ja-jp -> en-us -> de-de)
- Generic cross-manufacturer datasheet PDF search engine (via DuckDuckGo HTML)
- Generic product webpage PDF link extractor with Playwright SPA fallback
- Strict SSRF & Open-Redirect validation on all extracted URLs
"""

import re
import html
from urllib.parse import urljoin, quote_plus, urlparse, parse_qs, unquote
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
                resp.close()
                current_url = validate_redirect_target(current_url, loc)
                continue

            if resp.status_code == 200:
                text = resp.text
                resp.close()
                if "Just a moment..." in text and use_playwright_fallback:
                    break
                return text
            resp.close()
            break
    finally:
        if own_session:
            session.close()

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
        Parse strings like 'BES0002(BES G06EB-NOC40F-S49G)' or 'BES0002 (BES ...)'
        into (order_code, full_filename).
        """
        raw = raw_input.strip()
        m = re.match(r"^([A-Z0-9]{7})\s*(?:\((.*?)\))?", raw, re.I)
        if m:
            order_code = m.group(1).upper()
            part_desc = (m.group(2) or "").strip()
            safe_desc = re.sub(r"[^a-zA-Z0-9_\-]", "_", part_desc).strip("_")
            fname = f"{order_code}_{safe_desc}.pdf" if safe_desc else f"{order_code}.pdf"
            return order_code, fname
        safe_raw = re.sub(r"[^a-zA-Z0-9_\-]", "_", raw).strip("_")
        return raw, f"{safe_raw}.pdf"

    @staticmethod
    def is_likely_balluff_code(raw_input: str) -> bool:
        """Check if input matches BALLUFF 7-char order code pattern (e.g. BES0002, BNI005H)."""
        raw = raw_input.strip()
        return bool(re.match(r"^B[A-Z]{2}[0-9A-Z]{4}(?:\s*\(.*\))?$", raw, re.I))

    @classmethod
    def resolve_balluff_part(
        cls,
        part_code: str,
        locale: str = "ja-jp",
        auto_fallback_locales: bool = True,
        session: Optional[requests.Session] = None,
        use_playwright_fallback: bool = True
    ) -> Dict[str, str]:
        """
        Given a BALLUFF order code (e.g. 'BES0002'), resolve its datasheet PDF URL.
        If auto_fallback_locales is True, automatically falls back across ja-jp -> en-us -> de-de
        if the datasheet is missing in the primary locale.
        """
        order_code, filename = cls.parse_balluff_code(part_code)

        locales_to_try = [locale]
        if auto_fallback_locales:
            for fb in ("ja-jp", "en-us", "de-de"):
                if fb not in locales_to_try:
                    locales_to_try.append(fb)

        last_err = None
        for loc in locales_to_try:
            product_url = f"https://www.balluff.com/{loc}/products/{order_code}"
            try:
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
                if matches:
                    pdf_url = html.unescape(matches[0].replace("\\/", "/"))
                    return {
                        "part_number": part_code,
                        "order_code": order_code,
                        "resolved_locale": loc,
                        "product_url": product_url,
                        "url": pdf_url,
                        "filename": filename,
                        "referer": product_url,
                        "source": "balluff_official"
                    }
            except Exception as e:
                last_err = e
                continue

        raise ValueError(
            f"Datasheet PDF link not found for {order_code} across locales {locales_to_try}"
            + (f" ({last_err})" if last_err else "")
        )

    @classmethod
    def search_generic_datasheet(
        cls,
        part_number: str,
        max_results: int = 5,
        session: Optional[requests.Session] = None
    ) -> List[Dict[str, str]]:
        """
        Search the public web (via DuckDuckGo HTML) for datasheet PDF links matching any
        manufacturer part number (e.g., Omron, Keyence, SMC, Micro Detectors, TI, etc.).
        All discovered URLs are strictly validated against SSRF.
        """
        query = f'"{part_number.strip()}" datasheet filetype:pdf'
        search_url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"

        own_session = False
        if session is None:
            session = requests.Session(impersonate="chrome124")
            own_session = True

        candidates: List[Dict[str, str]] = []
        seen = set()

        try:
            resp = session.get(search_url, timeout=15)
            if resp.status_code != 200:
                return []
            page_html = resp.text
            resp.close()

            # Extract DuckDuckGo result links (uddg=... or direct hrefs)
            raw_hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', page_html, re.I)
            safe_part = re.sub(r"[^a-zA-Z0-9_\-]", "_", part_number.strip()).strip("_")

            for href in raw_hrefs:
                target_url = html.unescape(href)
                # Decode DuckDuckGo redirect wrapper: //duckduckgo.com/l/?uddg=https%3A%2F%2F...
                if "uddg=" in target_url:
                    parsed = urlparse(target_url)
                    qs = parse_qs(parsed.query)
                    if "uddg" in qs and qs["uddg"]:
                        target_url = unquote(qs["uddg"][0])

                if not target_url.lower().startswith(("http://", "https://")):
                    continue
                if "duckduckgo.com" in target_url.lower():
                    continue
                if ".pdf" not in target_url.lower():
                    continue

                try:
                    valid_u = validate_url(target_url)
                except SecurityValidationError:
                    continue

                if valid_u not in seen:
                    seen.add(valid_u)
                    idx = len(candidates) + 1
                    fname = f"{safe_part}.pdf" if idx == 1 else f"{safe_part}_alt{idx}.pdf"
                    candidates.append({
                        "part_number": part_number,
                        "url": valid_u,
                        "filename": fname,
                        "referer": "https://duckduckgo.com/",
                        "source": "generic_web_search"
                    })
                    if len(candidates) >= max_results:
                        break
        finally:
            if own_session:
                session.close()

        return candidates

    @classmethod
    def resolve_any_part(
        cls,
        part_input: str,
        locale: str = "ja-jp",
        auto_fallback_locales: bool = True,
        enable_generic_search: bool = True,
        session: Optional[requests.Session] = None
    ) -> Dict[str, str]:
        """
        Unified resolver:
        1. If input looks like a BALLUFF code, resolve via BALLUFF official pages (with locale fallback).
        2. If BALLUFF resolution fails or input is another brand's part number, search public web for PDF.
        """
        if cls.is_likely_balluff_code(part_input):
            try:
                return cls.resolve_balluff_part(
                    part_input,
                    locale=locale,
                    auto_fallback_locales=auto_fallback_locales,
                    session=session
                )
            except Exception as balluff_err:
                if not enable_generic_search:
                    raise balluff_err

        if enable_generic_search:
            hits = cls.search_generic_datasheet(part_input, max_results=3, session=session)
            if hits:
                return hits[0]

        raise ValueError(f"Could not find datasheet PDF for part number: {part_input}")

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

        href_matches = re.findall(r'href=[\'"]([^\'"]+\.pdf(?:\?[^\'"]*)?)[\'"]', page_html, re.I)
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
