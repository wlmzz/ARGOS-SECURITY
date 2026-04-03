"""
browser_recon.py — ARGOS plugin
AI-driven web automation for security reconnaissance using browser-use and Firecrawl.
Automates browser-based testing, web crawling, form analysis, and OSINT gathering.
https://github.com/browser-use/browser-use
https://github.com/mendableai/firecrawl
"""

import subprocess
import json
import os
import re
import shutil
import asyncio
import urllib.request
import urllib.parse
from datetime import datetime

MANIFEST = {
    "id": "browser_recon",
    "name": "Browser Recon",
    "version": "1.0.0",
    "description": "AI-driven web recon: browser-use automation, Firecrawl crawling, form analysis",
    "author": "ARGOS",
    "category": "osint",
    "tools": [
        "web_crawl",
        "browser_screenshot",
        "form_analyzer",
        "js_recon",
        "firecrawl_scrape",
    ],
}

RESULTS_DIR = "/opt/argos/logs/browser_recon"
os.makedirs(RESULTS_DIR, exist_ok=True)


def _run(cmd: list, timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _fetch(url: str, timeout: int = 15, headers: dict = None) -> tuple[str, int]:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore"), resp.getcode()
    except Exception as e:
        return "", 0


def _ensure_playwright() -> tuple[bool, str]:
    """Install playwright + chromium if not present."""
    try:
        import playwright
        return True, ""
    except ImportError:
        pass

    rc, _, err = _run(
        ["pip3", "install", "playwright", "browser-use", "--break-system-packages", "-q"],
        timeout=120,
    )
    if rc != 0:
        return False, f"pip install failed: {err[:300]}"

    # Install chromium
    rc2, _, err2 = _run(
        ["python3", "-m", "playwright", "install", "chromium", "--with-deps"],
        timeout=300,
    )
    if rc2 != 0:
        return False, f"playwright install chromium failed: {err2[:300]}"

    return True, ""


def web_crawl(url: str, max_pages: int = 20, depth: int = 2,
               extract_links: bool = True, extract_forms: bool = True,
               find_admin: bool = True) -> dict:
    """
    Crawl a website to map its structure, extract links, forms, and find admin panels.
    Uses requests/aiohttp with JavaScript fallback via Playwright.

    Args:
        url: Starting URL to crawl
        max_pages: Maximum pages to crawl (default: 20)
        depth: Crawl depth (default: 2)
        extract_links: Collect all internal/external links (default: True)
        extract_forms: Extract HTML forms and input fields (default: True)
        find_admin: Look for admin/login panels (default: True)

    Returns:
        Site map, all links, forms, admin panels, and security-relevant headers
    """
    if not re.match(r"^https?://", url):
        return {"error": "URL must start with http:// or https://"}

    base_domain = re.sub(r"https?://([^/]+).*", r"\1", url)
    visited = set()
    queue = {url}
    pages = []
    all_links = set()
    all_forms = []
    admin_panels = []
    interesting_headers = {}

    # Common admin paths
    admin_paths = [
        "/admin", "/administrator", "/wp-admin", "/login", "/signin",
        "/dashboard", "/panel", "/manage", "/control", "/backend",
        "/wp-login.php", "/phpmyadmin", "/cpanel", "/webmail",
        "/api", "/api/v1", "/api/v2", "/swagger", "/docs",
        "/robots.txt", "/.git/HEAD", "/.env", "/config.php",
        "/phpinfo.php", "/server-info", "/server-status",
    ]

    result = {
        "target": url,
        "base_domain": base_domain,
        "crawl_time": datetime.utcnow().isoformat(),
        "pages": [],
        "links": {"internal": [], "external": []},
        "forms": [],
        "admin_panels": [],
        "security_headers": {},
        "sensitive_files": [],
    }

    # Crawl pages (simple BFS without JS)
    current_depth = 0
    current_level = {url}

    while current_level and len(visited) < max_pages and current_depth <= depth:
        next_level = set()
        for page_url in current_level:
            if page_url in visited or len(visited) >= max_pages:
                break
            visited.add(page_url)

            html, status = _fetch(page_url)
            if not html:
                continue

            page_info = {
                "url": page_url,
                "status": status,
                "title": re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S),
            }
            if page_info["title"]:
                page_info["title"] = page_info["title"].group(1).strip()[:100]

            pages.append(page_info)

            # Extract links
            if extract_links:
                for href in re.findall(r'href=["\']([^"\'#]+)["\']', html):
                    if href.startswith("//"):
                        href = f"https:{href}"
                    elif href.startswith("/"):
                        href = f"https://{base_domain}{href}"
                    elif not href.startswith("http"):
                        continue

                    all_links.add(href)
                    if base_domain in href:
                        next_level.add(href)

            # Extract forms
            if extract_forms:
                for form_match in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.I | re.S):
                    form_html = form_match.group(0)
                    action = re.search(r'action=["\']([^"\']+)["\']', form_html, re.I)
                    method = re.search(r'method=["\']([^"\']+)["\']', form_html, re.I)
                    inputs = re.findall(
                        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']+)["\'])?',
                        form_html, re.I
                    )
                    all_forms.append({
                        "page": page_url,
                        "action": action.group(1) if action else "",
                        "method": (method.group(1) if method else "GET").upper(),
                        "fields": [{"name": i[0], "type": i[1] or "text"} for i in inputs],
                        "has_password": any(i[1].lower() == "password" for i in inputs
                                            if len(i) > 1 and i[1]),
                    })

        current_level = next_level
        current_depth += 1

    # Check admin paths
    if find_admin:
        for path in admin_paths:
            test_url = f"https://{base_domain}{path}"
            _, status = _fetch(test_url, timeout=5)
            if status and status != 404:
                entry = {"url": test_url, "status": status}
                if status == 200:
                    entry["accessible"] = True
                if path in ["/.env", "/.git/HEAD", "/phpinfo.php"]:
                    entry["severity"] = "CRITICAL"
                elif path in ["/wp-admin", "/phpmyadmin", "/cpanel"]:
                    entry["severity"] = "HIGH"
                admin_panels.append(entry)

    # Separate internal/external links
    internal = [l for l in all_links if base_domain in l]
    external = [l for l in all_links if base_domain not in l]

    result["pages"] = pages[:50]
    result["links"]["internal"] = list(internal)[:100]
    result["links"]["external"] = list(external)[:50]
    result["forms"] = all_forms[:30]
    result["admin_panels"] = admin_panels
    result["summary"] = {
        "pages_crawled": len(pages),
        "links_found": len(all_links),
        "forms_found": len(all_forms),
        "admin_panels_found": len(admin_panels),
        "sensitive_exposed": [a for a in admin_panels if a.get("severity") == "CRITICAL"],
    }

    # Save report
    outfile = os.path.join(
        RESULTS_DIR,
        f"crawl_{base_domain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(outfile, "w") as f:
        json.dump(result, f, indent=2)
    result["report_file"] = outfile

    return result


def browser_screenshot(url: str, output_file: str = None,
                         full_page: bool = True) -> dict:
    """
    Capture a screenshot of a webpage using headless Chromium (Playwright).
    Useful for documenting findings, phishing detection, and visual recon.

    Args:
        url: URL to screenshot
        output_file: Output PNG file path (default: auto-generated)
        full_page: Capture full page (not just viewport) (default: True)

    Returns:
        Screenshot file path and page info
    """
    if not re.match(r"^https?://", url):
        return {"error": "URL must start with http:// or https://"}

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    domain = re.sub(r"https?://([^/]+).*", r"\1", url)
    outfile = output_file or os.path.join(RESULTS_DIR, f"screenshot_{domain}_{ts}.png")

    ok, err_msg = _ensure_playwright()
    if not ok:
        return {"error": f"Playwright not available: {err_msg}",
                "install": "pip3 install playwright && playwright install chromium --with-deps"}

    # Write and execute screenshot script
    script = f"""
import asyncio
from playwright.async_api import async_playwright

async def screenshot():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
        page = await browser.new_page()
        await page.goto("{url}", timeout=30000, wait_until="networkidle")
        title = await page.title()
        await page.screenshot(path="{outfile}", full_page={full_page})
        await browser.close()
        return title

title = asyncio.run(screenshot())
print(title)
"""
    script_file = f"/tmp/argos_screenshot_{ts}.py"
    with open(script_file, "w") as f:
        f.write(script)

    rc, out, err = _run(["python3", script_file], timeout=45)

    try:
        os.unlink(script_file)
    except Exception:
        pass

    if rc == 0 and os.path.exists(outfile):
        return {
            "url": url,
            "screenshot_file": outfile,
            "page_title": out.strip(),
            "file_size_bytes": os.path.getsize(outfile),
            "capture_time": datetime.utcnow().isoformat(),
        }

    return {"error": f"Screenshot failed: {err[:500]}", "url": url}


def form_analyzer(url: str) -> dict:
    """
    Deep analysis of web forms on a page.
    Identifies login forms, search forms, file uploads, CSRF tokens, and injection points.

    Args:
        url: URL of page to analyze forms on

    Returns:
        All forms with input fields, CSRF status, potential injection vectors
    """
    html, status = _fetch(url)
    if not html:
        return {"error": f"Cannot fetch {url}"}

    forms = []
    for form_match in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.I | re.S):
        attrs = form_match.group(1)
        body = form_match.group(2)

        action = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        enctype = re.search(r'enctype=["\']([^"\']*)["\']', attrs, re.I)

        # Extract all input fields
        inputs = []
        for inp in re.finditer(r'<input([^>]*)>', body, re.I):
            iattrs = inp.group(1)
            inp_type = re.search(r'type=["\']([^"\']*)["\']', iattrs, re.I)
            inp_name = re.search(r'name=["\']([^"\']*)["\']', iattrs, re.I)
            inp_val = re.search(r'value=["\']([^"\']*)["\']', iattrs, re.I)
            inputs.append({
                "type": inp_type.group(1) if inp_type else "text",
                "name": inp_name.group(1) if inp_name else "",
                "value_present": bool(inp_val),
            })

        # Textareas and selects
        for ta in re.finditer(r'<textarea([^>]*)>', body, re.I):
            name = re.search(r'name=["\']([^"\']*)["\']', ta.group(1), re.I)
            inputs.append({"type": "textarea", "name": name.group(1) if name else ""})

        # Security analysis
        has_csrf = any(
            inp.get("name", "").lower() in ["csrf_token", "csrfmiddlewaretoken",
                                              "_token", "authenticity_token", "__requestverificationtoken"]
            for inp in inputs
        )
        has_file_upload = any(inp.get("type", "").lower() == "file" for inp in inputs)
        has_password = any(inp.get("type", "").lower() == "password" for inp in inputs)

        injection_vectors = [inp["name"] for inp in inputs
                             if inp.get("type") in ("text", "textarea", "search", "")
                             and inp.get("name")]

        form_data = {
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "enctype": enctype.group(1) if enctype else "",
            "inputs": inputs,
            "security": {
                "has_csrf_token": has_csrf,
                "has_file_upload": has_file_upload,
                "is_login_form": has_password,
                "missing_csrf": has_password and not has_csrf,
                "injection_vectors": injection_vectors[:10],
            },
        }

        if has_file_upload:
            form_data["security"]["file_upload_risk"] = "Check for unrestricted file upload"
        if not has_csrf and (method.group(1) if method else "GET").upper() == "POST":
            form_data["security"]["csrf_risk"] = "POST form without CSRF protection"

        forms.append(form_data)

    return {
        "url": url,
        "form_count": len(forms),
        "forms": forms,
        "summary": {
            "login_forms": sum(1 for f in forms if f["security"].get("is_login_form")),
            "file_uploads": sum(1 for f in forms if f["security"].get("has_file_upload")),
            "csrf_missing": sum(1 for f in forms if f["security"].get("missing_csrf")),
            "injection_points": sum(len(f["security"].get("injection_vectors", [])) for f in forms),
        },
        "analysis_time": datetime.utcnow().isoformat(),
    }


def js_recon(url: str, follow_links: bool = False) -> dict:
    """
    JavaScript reconnaissance: find API endpoints, secrets, and sensitive info in JS files.
    Extracts hardcoded credentials, API keys, internal paths, and endpoint definitions.

    Args:
        url: URL of page or JavaScript file to analyze
        follow_links: Also analyze linked JS files found on the page (default: False)

    Returns:
        Found endpoints, secrets, API keys, and internal paths from JavaScript
    """
    results = {
        "target": url,
        "js_files": [],
        "endpoints": [],
        "secrets": [],
        "internal_paths": [],
        "analysis_time": datetime.utcnow().isoformat(),
    }

    html, status = _fetch(url)
    if not html:
        return {"error": f"Cannot fetch {url}"}

    # Find all JS files
    base_domain = re.sub(r"https?://([^/]+).*", r"\1", url)
    js_urls = set()

    # Inline scripts
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.I | re.S)

    # External scripts
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = f"https://{base_domain}{src}"
        if src.startswith("http"):
            js_urls.add(src)

    # Analyze inline scripts
    all_js = "\n".join(inline_scripts)

    # Fetch external scripts
    if follow_links:
        for js_url in list(js_urls)[:10]:
            js_content, _ = _fetch(js_url, timeout=10)
            if js_content:
                all_js += "\n" + js_content
                results["js_files"].append(js_url)

    # Pattern matching on JS
    patterns = {
        "api_endpoints": [
            r'(?:fetch|axios\.get|axios\.post|\.get|\.post)\s*\(["\']([^"\']+)["\']',
            r'(?:url|endpoint|api_url|apiUrl|baseURL)\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']/(api|v\d|rest|graphql)[^"\']*["\']',
        ],
        "secrets": [
            r'(?:api[_-]?key|apikey|api_token|access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9\-_\.]{10,})["\']',
            r'(?:password|passwd|secret|private[_-]?key)\s*[:=]\s*["\']([^"\']{6,})["\']',
            r'(?:aws[_-]?access[_-]?key|AKIA)[A-Z0-9]{16}',
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # JWT
        ],
        "internal_paths": [
            r'["\']/(admin|dashboard|internal|private|debug|test|staging)[^"\']*["\']',
            r'["\'][^"\']*\.(config|env|yaml|yml|json|xml)["\']',
        ],
    }

    for pattern_name, pattern_list in patterns.items():
        for pattern in pattern_list:
            for m in re.finditer(pattern, all_js, re.I):
                val = m.group(1) if m.lastindex else m.group(0)
                if val and len(val) > 3:
                    target_list = results.get(pattern_name, [])
                    if val not in target_list:
                        target_list.append(val)
                        if pattern_name == "api_endpoints":
                            results["endpoints"].append(val)
                        elif pattern_name == "secrets":
                            results["secrets"].append(val)
                        elif pattern_name == "internal_paths":
                            results["internal_paths"].append(val)

    # Deduplicate
    results["endpoints"] = list(set(results["endpoints"]))[:50]
    results["secrets"] = list(set(results["secrets"]))[:20]
    results["internal_paths"] = list(set(results["internal_paths"]))[:30]
    results["js_files_found"] = list(js_urls)[:20]

    results["summary"] = {
        "endpoints_found": len(results["endpoints"]),
        "secrets_found": len(results["secrets"]),
        "internal_paths": len(results["internal_paths"]),
        "risk": "HIGH" if results["secrets"] else ("MEDIUM" if results["endpoints"] else "LOW"),
    }

    return results


def firecrawl_scrape(url: str, api_key: str = None, mode: str = "scrape",
                      crawl_limit: int = 10, include_markdown: bool = True) -> dict:
    """
    Scrape websites using Firecrawl API or self-hosted instance.
    Returns clean markdown/text even from JavaScript-heavy sites.
    Useful for threat intelligence gathering and dark web monitoring.

    Args:
        url: URL to scrape (or crawl if mode='crawl')
        api_key: Firecrawl API key (uses env FIRECRAWL_API_KEY if not provided)
                 Or use 'local' for self-hosted instance at http://localhost:3002
        mode: 'scrape' (single page) or 'crawl' (multi-page) (default: scrape)
        crawl_limit: Maximum pages to crawl (default: 10, only for mode='crawl')
        include_markdown: Return markdown-formatted content (default: True)

    Returns:
        Extracted content and metadata from the page(s)
    """
    key = api_key or os.environ.get("FIRECRAWL_API_KEY", "")

    # Try firecrawl Python SDK first
    try:
        from firecrawl import FirecrawlApp
        app = FirecrawlApp(api_key=key or "local")

        if mode == "crawl":
            result = app.crawl_url(url, params={
                "limit": crawl_limit,
                "scrapeOptions": {"formats": ["markdown"] if include_markdown else ["rawHtml"]},
            })
        else:
            result = app.scrape_url(url, params={
                "formats": ["markdown", "links"] if include_markdown else ["rawHtml"],
            })

        return {
            "url": url,
            "mode": mode,
            "result": result,
            "tool": "firecrawl-sdk",
            "scrape_time": datetime.utcnow().isoformat(),
        }

    except ImportError:
        pass

    # Fallback: REST API
    if not key:
        # Try self-hosted
        base_url = os.environ.get("FIRECRAWL_URL", "")
        if not base_url:
            # Pure Python fallback
            return _scrape_fallback(url, include_markdown)

    api_base = "https://api.firecrawl.dev" if key else "http://localhost:3002"
    endpoint = f"{api_base}/v1/scrape"

    body = json.dumps({
        "url": url,
        "formats": ["markdown", "links"] if include_markdown else ["rawHtml"],
    }).encode()

    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}" if key else "",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return {
            "url": url,
            "mode": mode,
            "content": data.get("data", {}).get("markdown", ""),
            "links": data.get("data", {}).get("links", []),
            "metadata": data.get("data", {}).get("metadata", {}),
            "tool": "firecrawl-api",
            "scrape_time": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return _scrape_fallback(url, include_markdown)


def _scrape_fallback(url: str, markdown: bool) -> dict:
    """Basic scrape fallback using requests."""
    html, status = _fetch(url, timeout=20)
    if not html:
        return {"error": f"Cannot fetch {url}",
                "install": "pip3 install firecrawl-py  OR  set FIRECRAWL_API_KEY"}

    # Strip tags
    text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.S | re.I)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.S | re.I)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()

    links = list(set(re.findall(r'href=["\']([^"\']+)["\']', html)))

    return {
        "url": url,
        "mode": "scrape",
        "content": text[:20000],
        "links": links[:50],
        "tool": "basic-fallback",
        "scrape_time": datetime.utcnow().isoformat(),
    }


TOOLS = {
    "web_crawl": web_crawl,
    "browser_screenshot": browser_screenshot,
    "form_analyzer": form_analyzer,
    "js_recon": js_recon,
    "firecrawl_scrape": firecrawl_scrape,
}
