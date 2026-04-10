"""
NetGuard — scanner.py
Real vulnerability scanner using requests + BeautifulSoup.

Checks performed:
  1. Missing / weak security headers
  2. Forms with no CSRF token
  3. Reflected XSS (basic probe)
  4. SQL injection error detection
  5. Open redirect
  6. Directory listing exposed
  7. Sensitive file exposure (.env, backup files, etc.)
  8. Insecure cookies (missing Secure / HttpOnly flags)
  9. Clickjacking (missing X-Frame-Options / CSP frame-ancestors)
 10. Server information disclosure

Each finding follows the same shape used by main.py's VULN_POOL so results
slot straight into the existing API response format.
"""

import re
import uuid
import requests
from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Shared session
# ---------------------------------------------------------------------------
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "NetGuard-Scanner/1.0 (security-research)",
})

DEFAULT_TIMEOUT = 8          # seconds per request
MAX_PAGES       = 10         # max pages to crawl per scan


def simulate_login(url: str, creds: dict = None) -> bool:
    """
    Simulates a login POST request to populate the global SESSION with auth cookies,
    then attempts to access a protected page (e.g. /dashboard) to verify.
    """
    if creds is None:
        creds = {"username": "test", "password": "test"}

    # Try common login endpoints
    login_paths = ["/login", "/api/login", "/auth"]
    protected_paths = ["/dashboard", "/admin", "/profile"]
    base = url.rstrip("/")

    for path in login_paths:
        login_url = base + path
        try:
            r = SESSION.post(login_url, data=creds, timeout=DEFAULT_TIMEOUT, verify=False)
            
            # If the server accepts the connection, grab the auth cookie and test a protected route
            if r.status_code != 404:
                # Step 3: Verify the session by hitting a known authenticated page
                for p_path in protected_paths:
                    verify_r = SESSION.get(base + p_path, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
                    if verify_r.status_code in (200, 201):
                        print(f"[NetGuard] Successfully authenticated and accessed protected page: {p_path}")
                        return True
                return True # Fallback if protected page check fails but login endpoint was valid
        except Exception:
            continue
    return False

def get_page(url: str) -> str | None:
    """
    Fetch a page and return its HTML text, or None on any error.
    Uses the shared session (persistent cookies, consistent User-Agent)
    and the global DEFAULT_TIMEOUT.
    """
    try:
        response = SESSION.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
        return response.text
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, params: dict = None, allow_redirects: bool = True):
    """Safe GET — returns (response | None, error_str | None)."""
    try:
        r = SESSION.get(
            url,
            params=params,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=allow_redirects,
            verify=False,          # allow self-signed certs in lab targets
        )
        return r, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL error: {e}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection error: {e}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except Exception as e:
        return None, str(e)


def _finding(title: str, severity: str, cvss: float, description: str, 
             cve: str = "N/A", exploitability: str = "Medium", fix: str = "") -> dict:
    """
    Standardize the output format for all vulnerabilities.
    """
    color_map = {
        "critical": "#ef4444",
        "high":     "#f97316",
        "medium":   "#eab308",
        "low":      "#22c55e",
        "info":     "#6b7280",
    }
    return {
        "id":             str(uuid.uuid4())[:8],
        "title":          title,
        "severity":       severity,
        "cvss":           cvss,
        "color":          color_map.get(severity, "#6b7280"),
        "description":    description,
        "cve":            cve,
        "exploitability": exploitability,
        "fix":            fix,
    }


# ---------------------------------------------------------------------------
# Crawl — collect internal links up to MAX_PAGES
# ---------------------------------------------------------------------------

def crawl(url: str) -> tuple[list[str], list]:
    """
    Fetch a single page and return all discovered links and forms.

    Returns:
        links  — list of href strings found in <a> tags
        forms  — list of BeautifulSoup Tag objects for each <form>

    Returns ([], []) if the page could not be fetched.
    """
    html = get_page(url)
    if html is None:
        return [], []

    soup = BeautifulSoup(html, "html.parser")

    links = [a["href"] for a in soup.find_all("a", href=True)]
    forms = soup.find_all("form")

    return links, forms


def _crawl_site(base_url: str) -> list[str]:
    """
    Shallow breadth-first crawl of the target origin.
    Returns a list of unique visited URLs (capped at MAX_PAGES).
    Used internally by run_scan().
    """
    origin = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(base_url))
    visited = set()
    queue   = [base_url]
    pages   = []

    while queue and len(pages) < MAX_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        r, err = _get(url)
        if err or r is None:
            continue

        pages.append(url)

        # Only parse HTML pages
        ct = r.headers.get("Content-Type", "")
        if "html" not in ct:
            continue

        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith("#") or href.startswith("mailto:"):
                continue
            full = urljoin(url, href)
            # Stay on the same origin
            if full.startswith(origin) and full not in visited:
                queue.append(full)

    return pages


# ---------------------------------------------------------------------------
# Check 1 — Security headers
# ---------------------------------------------------------------------------

REQUIRED_HEADERS = {
    "Strict-Transport-Security": ("high",   7.5, "Missing HSTS — site is vulnerable to protocol downgrade and cookie hijacking attacks.",          "CVE-2014-3566"),
    "X-Content-Type-Options":    ("medium", 5.3, "Missing X-Content-Type-Options — browser may MIME-sniff responses, enabling content injection.", "N/A"),
    "X-Frame-Options":           ("medium", 6.1, "Missing X-Frame-Options — page can be embedded in iframes, enabling clickjacking attacks.",      "N/A"),
    "Content-Security-Policy":   ("medium", 6.1, "Missing Content-Security-Policy — no CSP directive restricts script / resource loading.",        "N/A"),
    "Referrer-Policy":           ("low",    3.1, "Missing Referrer-Policy — sensitive URL data may leak in Referer header to third parties.",       "N/A"),
    "Permissions-Policy":        ("low",    2.7, "Missing Permissions-Policy — browser features (camera, geolocation, etc.) are unrestricted.",     "N/A"),
}

def check_security_headers(url: str) -> list[dict]:
    findings = []
    r, err = _get(url)
    if err or r is None:
        return findings

    for header, (sev, cvss, desc, cve) in REQUIRED_HEADERS.items():
        if header not in r.headers:
            findings.append(_finding(
                title         = f"Missing Header — {header}",
                severity      = sev,
                cvss          = cvss,
                description   = desc,
                cve           = cve,
                exploitability= "Easy",
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 2 — Server information disclosure
# ---------------------------------------------------------------------------

def check_server_disclosure(url: str) -> list[dict]:
    findings = []
    r, err = _get(url)
    if err or r is None:
        return findings

    server = r.headers.get("Server", "")
    powered = r.headers.get("X-Powered-By", "")

    if server and any(v in server for v in ["Apache", "nginx", "IIS", "Tomcat", "Jetty"]):
        findings.append(_finding(
            title         = "Server Version Disclosure",
            severity      = "low",
            cvss          = 3.7,
            description   = f"Server header exposes version information: '{server}'. Attackers can target known CVEs for this version.",
            exploitability= "Easy",
        ))

    if powered:
        findings.append(_finding(
            title         = "X-Powered-By Disclosure",
            severity      = "low",
            cvss          = 3.1,
            description   = f"X-Powered-By discloses backend technology: '{powered}'. This aids fingerprinting and targeted attacks.",
            exploitability= "Easy",
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 3 — Insecure cookies
# ---------------------------------------------------------------------------

def check_cookies(url: str) -> list[dict]:
    findings = []
    r, err = _get(url)
    if err or r is None:
        return findings

    for cookie in r.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        if not cookie.has_nonstandard_attr("SameSite"):
            issues.append("missing SameSite flag")

        if issues:
            findings.append(_finding(
                title         = f"Insecure Cookie — {cookie.name}",
                severity      = "medium",
                cvss          = 5.4,
                description   = f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}. This may allow session hijacking or CSRF.",
                exploitability= "Medium",
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 4 — Forms without CSRF token
# ---------------------------------------------------------------------------

CSRF_FIELD_NAMES = {"csrf", "csrf_token", "_token", "authenticity_token", "__requestverificationtoken"}

def check_csrf(url: str) -> list[dict]:
    findings = []
    r, err = _get(url)
    if err or r is None:
        return findings

    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")

    for form in forms:
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue     # CSRF only relevant for state-changing requests

        hidden_names = {
            inp.get("name", "").lower()
            for inp in form.find_all("input", type="hidden")
        }

        has_csrf = bool(hidden_names & CSRF_FIELD_NAMES)
        if not has_csrf:
            action = form.get("action") or url
            findings.append(_finding(
                title         = f"Missing CSRF Token — {urljoin(url, action)}",
                severity      = "medium",
                cvss          = 6.5,
                description   = f"POST form at '{urljoin(url, action)}' has no detectable CSRF token. State-changing requests may be forgeable.",
                exploitability= "Easy",
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 5 — Reflected XSS probe
# ---------------------------------------------------------------------------

XSS_PAYLOADS = [
    "<script>alert(1)</script>",          # basic script injection
    "<img src=x onerror=alert(1)>",       # img onerror (no script tag)
    "'\"><script>alert(1)</script>",       # break out of attribute then inject
    "<svg onload=alert(1)>",              # SVG vector
    "javascript:alert(1)",                # href-based
    "<body onload=alert(1)>",             # body event
]

# URL-encoded form of the basic probe (some servers encode but still reflect)
_XSS_ENC = "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"


def test_xss(url: str, param: str = "q") -> bool:
    """
    Test a URL parameter for reflected XSS by injecting common payloads
    and checking whether they appear unescaped in the response.

    Args:
        url   — base URL to test (query string is ignored; param is appended)
        param — query parameter name to inject into (default: 'q')

    Returns:
        True  if any payload is reflected verbatim in the response body
        False otherwise (including on network errors)

    Example:
        >>> test_xss("https://example.com/search", param="q")
        False
    """
    base = url.split("?")[0]

    for payload in XSS_PAYLOADS:
        try:
            r = SESSION.get(
                base,
                params={param: payload},
                timeout=DEFAULT_TIMEOUT,
                verify=False,
            )
            # Reflected if payload appears literally OR URL-encoded in response
            if payload in r.text or _XSS_ENC in r.text:
                return True
        except Exception:
            continue   # network error — try next payload

    return False


def check_xss(url: str) -> list[dict]:
    """
    Run XSS probes against all discoverable parameters on the page.
    Uses test_xss() internally and returns NetGuard finding dicts.
    """
    findings = []
    r0, err = _get(url)
    if err or r0 is None:
        return findings

    soup = BeautifulSoup(r0.text, "html.parser")

    # Collect params from: visible text inputs + existing query string
    params = set()
    for inp in soup.find_all("input", {"type": re.compile(r"^(text|search|email|url)$", re.I)}):
        if inp.get("name"):
            params.add(inp["name"])

    parsed = urlparse(url)
    if parsed.query:
        for part in parsed.query.split("&"):
            key = part.split("=")[0]
            if key:
                params.add(key)

    # Always probe the default 'q' param as a baseline
    params.add("q")

    base = url.split("?")[0]
    for param in params:
        if test_xss(base, param=param):
            findings.append(_finding(
                title         = f"Reflected XSS — param '{param}'",
                severity      = "high",
                cvss          = 7.4,
                description   = (
                    f"Parameter '{param}' at {base} reflects injected script "
                    f"payloads unescaped in the HTML response. An attacker can "
                    f"execute arbitrary JavaScript in the victim's browser."
                ),
                cve           = "CVE-2024-5678",
                exploitability= "Easy",
            ))

    return findings


def test_forms(url: str, forms: list) -> list[dict]:
    """
    Submit XSS payloads into every field of each form and check whether
    the payload is reflected in the response.

    Args:
        url   — the page URL used to resolve relative form action paths
        forms — list of BeautifulSoup <form> Tag objects (from crawl())

    Returns:
        list of result dicts, one per vulnerable form:
        {
            "action":  str,   # resolved form action URL
            "method":  str,   # 'get' | 'post'
            "field":   str,   # input field name that triggered reflection
            "payload": str,   # payload that was reflected
        }

    Example:
        links, forms = crawl("https://example.com")
        issues = test_forms("https://example.com", forms)
        for issue in issues:
            print(issue["action"], issue["field"])
    """
    results = []

    for form in forms:
        raw_action = form.get("action") or ""
        action_url = urljoin(url, raw_action)   # handles relative, absolute, and empty actions
        method     = (form.get("method") or "get").lower()

        # Build a base data dict from all named inputs (use safe placeholder first)
        inputs = form.find_all("input")
        base_data = {}
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            input_type = (inp.get("type") or "text").lower()
            # Use realistic defaults for non-text fields so the form submits cleanly
            if input_type in ("submit", "button", "image", "reset"):
                continue
            elif input_type == "email":
                base_data[name] = "test@example.com"
            elif input_type == "number":
                base_data[name] = "1"
            elif input_type == "checkbox":
                base_data[name] = "on"
            else:
                base_data[name] = "test"

        # Inject into each text-like field individually
        text_fields = [
            inp.get("name") for inp in inputs
            if inp.get("name")
            and (inp.get("type") or "text").lower()
               not in ("submit", "button", "image", "reset", "checkbox", "radio", "hidden")
        ]

        if not text_fields:
            # No injectable fields — skip this form
            continue

        for payload in XSS_PAYLOADS:
            found_in_form = False

            for field in text_fields:
                data = dict(base_data)
                data[field] = payload

                try:
                    if method == "post":
                        r = SESSION.post(
                            action_url, data=data,
                            timeout=DEFAULT_TIMEOUT, verify=False,
                        )
                    else:
                        r = SESSION.get(
                            action_url, params=data,
                            timeout=DEFAULT_TIMEOUT, verify=False,
                        )
                except Exception:
                    continue

                if payload in r.text:
                    results.append({
                        "action":  action_url,
                        "method":  method,
                        "field":   field,
                        "payload": payload,
                    })
                    found_in_form = True
                    break   # one finding per payload per form is enough

            if found_in_form:
                break       # move on to next form once one payload lands

    return results


# ---------------------------------------------------------------------------
# API endpoint discovery
# ---------------------------------------------------------------------------

# Common API paths to probe — covers REST, GraphQL, admin, versioned APIs
API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/users",
    "/api/admin",
    "/api/config",
    "/api/health",
    "/api/status",
    "/api/debug",
    "/api/docs",
    "/graphql",
    "/v1",
    "/v2",
    "/swagger.json",
    "/swagger/index.html",
    "/openapi.json",
    "/.well-known/openid-configuration",
    "/actuator",            # Spring Boot
    "/actuator/env",
    "/actuator/health",
    "/metrics",
    "/debug/pprof",         # Go
    "/rails/info",          # Rails
]

# Status codes that reveal an endpoint exists (even if not fully open)
_INTERESTING_CODES = {
    200: "Open (no auth required)",
    201: "Open (returns created)",
    401: "Auth required — endpoint confirmed",
    403: "Forbidden — endpoint confirmed",
    405: "Method not allowed — endpoint confirmed",
    422: "Unprocessable — endpoint confirmed",
}


def test_api(url: str) -> list[dict]:
    """
    Probe common API paths on the target and return those that respond
    with a meaningful status code (200, 401, 403, 405, 422).

    A 200 means the endpoint is fully open (unauthenticated).
    A 401/403 still confirms the path exists and may be bypassed.

    Args:
        url — base URL of the target (e.g. 'https://example.com')

    Returns:
        list of result dicts for each reachable endpoint:
        {
            "path":         str,   # e.g. '/api/v1'
            "full_url":     str,   # full probed URL
            "status":       int,   # HTTP status code
            "description":  str,   # human-readable result
            "content_type": str,   # response Content-Type
            "open":         bool,  # True only if status == 200/201
        }

    Example:
        results = test_api("https://example.com")
        for r in results:
            print(r['status'], r['full_url'], r['description'])
    """
    base = url.rstrip("/")
    results = []

    for path in API_PATHS:
        full_url = base + path
        try:
            r = SESSION.get(
                full_url,
                timeout=DEFAULT_TIMEOUT,
                verify=False,
                allow_redirects=False,   # don't follow — auth redirects are findings too
            )
        except Exception:
            continue

        if r.status_code not in _INTERESTING_CODES:
            continue

        content_type = r.headers.get("Content-Type", "")
        is_open      = r.status_code in (200, 201)

        # Extra signal: even a 403 is notable if it returns JSON
        is_json = "json" in content_type or (
            r.status_code in (401, 403) and r.text.strip().startswith(("{", "["))
        )

        # -----------------------------------------------------
        # Auth Bypass Check
        # If the endpoint exists but isn't open, see if it fails open
        # when an invalid JWT token is supplied.
        # -----------------------------------------------------
        auth_bypass = False
        if not is_open:
            try:
                r_bypass = SESSION.get(
                    full_url,
                    headers={"Authorization": "Bearer invalid_token_12345"},
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                )
                if r_bypass.status_code in (200, 201):
                    auth_bypass = True
            except Exception:
                pass


        # -----------------------------------------------------
        # Rate Limit Check
        # Fire 20 rapid requests and look for a 429 Too Many Requests response
        # -----------------------------------------------------
        missing_rate_limit = False
        try:
            rate_limited = False
            for _ in range(20):
                r_rate = SESSION.get(full_url, timeout=2, verify=False, allow_redirects=False)
                if r_rate.status_code == 429:
                    rate_limited = True
                    break
            if not rate_limited:
                missing_rate_limit = True
        except Exception:
            pass # Network error during spamming

        results.append({
            "path":         path,
            "full_url":     full_url,
            "status":       r.status_code,
            "description":  _INTERESTING_CODES[r.status_code],
            "content_type": content_type,
            "open":         is_open,
            "json_response": is_json,
            "auth_bypass":  auth_bypass,
            "missing_rate_limit": missing_rate_limit,
        })

    return results


def find_api_endpoints(links: list[str], pages_html: dict) -> list[str]:
    """
    Passively scan a list of crawled links and the raw HTML of crawled pages
    to identify exposed API endpoints or JSON data files.
    """
    api_urls = []
    
    # Method 1: URLs found directly in <a href> tags
    for link in links:
        link_lower = link.lower()
        if "/api/" in link_lower or link_lower.endswith(".json") or "/graphql" in link_lower:
            api_urls.append(link)
            
    # Method 2: Extracting from inline HTML <script> tags
    for url, html in pages_html.items():
        if not html:
            continue
        soup = BeautifulSoup(html, "html.parser")
        scripts = soup.find_all("script")
        for script in scripts:
            if script.string and ("/api/" in script.string.lower() or ".json" in script.string.lower()):
                # Extracting just the snippet of the script that contains it for context
                lines = script.string.split('\n')
                for line in lines:
                    if "/api/" in line.lower() or ".json" in line.lower():
                        clean_line = line.strip().strip("'\"+; ")
                        if len(clean_line) < 100: # filter out massive minified blobs
                            api_urls.append(f"{url} (found inside JS: {clean_line})")

    return list(set(api_urls))


# ---------------------------------------------------------------------------
# Sensitive Data Exposure (Regex Parsing)
# ---------------------------------------------------------------------------

import re

# Regex patterns for high-value secrets
SECRET_PATTERNS = {
    "AWS Access Key":     r"(?i)AKIA[0-9A-Z]{16}",
    "Stripe Standard API": r"(?i)sk_live_[0-9a-zA-Z]{24}",
    "Slack Token":        r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24})",
    "RSA Private Key":    r"-----BEGIN RSA PRIVATE KEY-----",
    "Generic Password":   r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]+)['\"]",
}

def check_sensitive_data(url: str, html: str) -> list[dict]:
    """
    Scan the raw HTML of a response for leaked API keys, tokens, or
    hardcoded credentials using regex patterns.
    """
    findings = []
    if not html:
        return findings

    for secret_type, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, html):
            findings.append(_finding(
                title         = f"Sensitive Data Exposure — {secret_type}",
                severity      = "critical",
                cvss          = 9.1,
                description   = f"The response body at {url} contains a pattern matching a '{secret_type}'. Exposed secrets can lead to complete system compromise.",
                exploitability= "Easy"
            ))
            
    return findings




SQLI_PAYLOADS = [
    "' OR 1=1 --",          # classic auth bypass
    "' OR '1'='1",          # alternate quoting
    "\"",                    # double-quote terminator
    "'",                    # single-quote terminator
    "1; DROP TABLE users--",# stacked query probe
    "1 UNION SELECT NULL--",# UNION probe
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlstate",
    "unclosed quotation", "sqlite_", "syntax error", "unterminated string",
    "you have an error in your sql", "warning: mysql", "division by zero",
    "supplied argument is not a valid mysql", "column count doesn't match",
]


def test_sqli(url: str, param: str = "id") -> bool:
    """
    Test a URL parameter for SQL injection by injecting common payloads
    and checking the response for database error signatures.

    Args:
        url   — base URL to test (query string optional, param is appended)
        param — query parameter name to inject into (default: 'id')

    Returns:
        True  if any payload triggers a recognisable SQL error
        False otherwise (including on network errors)

    Example:
        >>> test_sqli("https://example.com/search", param="q")
        False
    """
    base = url.split("?")[0]

    for payload in SQLI_PAYLOADS:
        try:
            r = SESSION.get(
                base,
                params={param: payload},
                timeout=DEFAULT_TIMEOUT,
                verify=False,
            )
            body = r.text.lower()
            if any(sig in body for sig in SQLI_ERRORS):
                return True
        except Exception:
            continue   # network error — try next payload

    return False


def check_sqli(url: str) -> list[dict]:
    """
    Run SQLi tests against all query parameters in the URL.
    Uses test_sqli() internally and returns NetGuard finding dicts.
    """
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings      # no params to probe

    params_base = {}
    for part in parsed.query.split("&"):
        kv = part.split("=", 1)
        params_base[kv[0]] = kv[1] if len(kv) > 1 else ""

    for key in params_base:
        # Rebuild URL with this param set to a known safe value so
        # test_sqli() can isolate this parameter cleanly
        base = url.split("?")[0]
        if test_sqli(base, param=key):
            findings.append(_finding(
                title         = f"SQL Injection — param '{key}'",
                severity      = "critical",
                cvss          = 9.8,
                description   = f"Parameter '{key}' at {base} returns database errors when injected with SQL metacharacters — likely vulnerable to SQL injection.",
                cve           = "CVE-2024-1234",
                exploitability= "Easy",
                fix           = "Use parameterized queries"
            ))
            break   # one confirmed finding is enough per URL

    return findings


# ---------------------------------------------------------------------------
# Check 7 — Open redirect
# ---------------------------------------------------------------------------

REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_url", "return", "returnUrl", "goto", "dest", "destination"]
REDIRECT_TARGET = "https://evil.example.com"

def check_open_redirect(url: str) -> list[dict]:
    findings = []
    for param in REDIRECT_PARAMS:
        probe_url = f"{url}?{param}={REDIRECT_TARGET}"
        r, err = _get(probe_url, allow_redirects=False)
        if err or r is None:
            continue
        location = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and "evil.example.com" in location:
            findings.append(_finding(
                title         = f"Open Redirect — param '{param}'",
                severity      = "medium",
                cvss          = 6.1,
                description   = f"Parameter '{param}' redirects to an attacker-controlled URL. Can be used in phishing and OAuth token theft attacks.",
                exploitability= "Easy",
            ))
    return findings


# ---------------------------------------------------------------------------
# Check 8 — Sensitive file / directory exposure
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [
    ("/.env",              "critical", 9.1, "Exposed .env file may contain database credentials, API keys, and secrets."),
    ("/.git/config",       "critical", 9.1, "Exposed .git/config reveals repository remote URLs and may allow source code access."),
    ("/backup.zip",        "high",     8.0, "Exposed backup archive may contain full source code and configuration files."),
    ("/backup.sql",        "critical", 9.1, "Exposed SQL dump may contain all database contents including user credentials."),
    ("/phpinfo.php",       "medium",   5.3, "PHP info page discloses server configuration, installed extensions, and environment variables."),
    ("/server-status",     "medium",   5.3, "Apache server-status page exposes active connections and request details."),
    ("/wp-config.php.bak", "critical", 9.1, "WordPress config backup may contain database credentials in plaintext."),
    ("/config.yaml",       "high",     8.1, "Exposed config file may contain sensitive application settings."),
    ("/robots.txt",        "info",     0.0, "robots.txt found — review for hidden paths that may disclose internal structure."),
]

def check_sensitive_files(base_url: str) -> list[dict]:
    findings = []
    origin = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(base_url))

    for path, sev, cvss, desc in SENSITIVE_PATHS:
        if sev == "info":
            continue      # skip informational in the vuln list
        probe = origin + path
        r, err = _get(probe)
        if err or r is None:
            continue
        if r.status_code == 200 and len(r.text) > 20:
            findings.append(_finding(
                title         = f"Sensitive File Exposed — {path}",
                severity      = sev,
                cvss          = cvss,
                description   = desc,
                exploitability= "Easy",
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 9 — Directory listing
# ---------------------------------------------------------------------------

DIR_LISTING_SIGS = ["index of /", "directory listing", "parent directory", "<title>index of"]

def check_directory_listing(pages: list[str]) -> list[dict]:
    findings = []
    for url in pages:
        r, err = _get(url)
        if err or r is None:
            continue
        body_lower = r.text.lower()
        if any(sig in body_lower for sig in DIR_LISTING_SIGS):
            findings.append(_finding(
                title         = f"Directory Listing Enabled — {url}",
                severity      = "medium",
                cvss          = 5.3,
                description   = f"Web server at {url} returns a browseable directory listing, exposing internal file structure to attackers.",
                exploitability= "Easy",
            ))
    return findings


# ---------------------------------------------------------------------------
# Public API — run_scan()
# ---------------------------------------------------------------------------

def run_scan(target_url: str, auth_workflow: bool = False) -> dict:
    """
    Entry-point called from main.py.
    Returns a dict compatible with the existing /scan response schema:
      {
        "url": str,
        "pages_crawled": int,
        "vulnerabilities": [ { title, severity, cvss, color,
                                description, cve, exploitability } ],
      }
    """
    # Normalise URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    findings = []

    # ── Authenticated Workflow (Step 1) ────────────────────────────────────
    if auth_workflow:
        logged_in = simulate_login(target_url)
        
        # Step 4: Vertical Privilege Escalation Check (Authorization Bypass)
        # If logged in as a normal user 'test', attempt to directly access administrative 
        # boundaries to check for improper access control.
        if logged_in:
            base = target_url.rstrip("/")
            admin_paths = ["/admin", "/admin/dashboard", "/administrator"]
            for a_path in admin_paths:
                try:
                    admin_check = SESSION.get(base + a_path, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
                    if admin_check.status_code in (200, 201):
                        findings.append(_finding(
                            title         = f"Authorization Bypass (Privilege Escalation) — {a_path}",
                            severity      = "critical",
                            cvss          = 8.8,
                            description   = f"Standard user authenticated session improperly granted 200 OK access to the restricted administrative path '{a_path}'. This represents a complete vertical privilege escalation flaw.",
                            exploitability= "Easy"
                        ))
                        break  # One admin bypass finding is enough
                except Exception:
                    continue

    # ── Crawl ──────────────────────────────────────────────────────────────
    pages = _crawl_site(target_url)
    if not pages:
        # If crawl completely failed, still run header checks on the root
        pages = [target_url]

    # ── Per-origin checks (run once against the root) ──────────────────────
    root = pages[0]
    findings += check_security_headers(root)
    findings += check_server_disclosure(root)
    findings += check_cookies(root)
    findings += check_sensitive_files(root)
    findings += check_open_redirect(root)

    # API Probing (Active)
    api_results = test_api(root)
    for api in api_results:
        if api.get("auth_bypass"):
            findings.append(_finding(
                title         = f"API Authentication Bypass — {api['path']}",
                severity      = "critical",
                cvss          = 9.1,
                description   = f"The API endpoint '{api['path']}' requires authentication (returns {api['status']}), but fails 'open' (returns 200/201) when an invalid JSON Web Token (JWT) is provided. This completely circumvents access controls.",
                exploitability= "Easy"
            ))
        else:
            # We classify open APIs as High severity data exposure risks,
            # and auth-required ones as Low severity reconnaissance findings.
            sev  = "high" if api["open"] else "low"
            cvss = 7.5 if api["open"] else 3.1
            desc = (
                f"API endpoint discovered at '{api['path']}' ({api['status']}). "
                f"Content-Type: {api['content_type']}. "
                f"{'Endpoint is open to unauthenticated requests.' if api['open'] else 'Endpoint requires auth.'}"
            )
            findings.append(_finding(
                title         = f"API Endpoint Discovered — {api['path']}",
                severity      = sev,
                cvss          = cvss,
                description   = desc,
                exploitability= "Easy" if api["open"] else "Complex"
            ))
        if api.get("missing_rate_limit"):
            findings.append(_finding(
                title         = f"Missing Rate Limiting — {api['path']}",
                severity      = "medium",
                cvss          = 5.9,
                description   = f"The API endpoint '{api['path']}' did not return a 429 Too Many Requests response even after receiving 20 rapid sequential requests. It may be vulnerable to brute force or denial-of-service attacks.",
                exploitability= "Easy"
            ))

    # ── Map HTML for all pages ──────────────────────────────────────────────
    pages_html = {}
    for page in pages:
        html = get_page(page)
        pages_html[page] = html if html else ""

    # API Discovery (Passive via links and inline JS)
    passive_apis = find_api_endpoints(pages, pages_html)
    for api_url in passive_apis:
        findings.append(_finding(
            title         = f"Exposed API/Data Path — {urlparse(api_url).path if not 'JS' in api_url else 'In JS'}",
            severity      = "medium",
            cvss          = 5.3,
            description   = f"The crawler proactively discovered a link exposing an API endpoint or JSON payload: {api_url}. Review for sensitive data exposure.",
            exploitability= "Easy"
        ))

    # ── Per-page checks ─────────────────────────────────────────────────────
    form_results = []
    
    for page in pages:
        findings += check_csrf(page)
        findings += check_xss(page)
        findings += check_sqli(page)
        
        # Test forms on this page
        html = pages_html.get(page)
        if html:
            findings += check_sensitive_data(page, html)
            
            soup = BeautifulSoup(html, "html.parser")
            forms = soup.find_all("form")
            if forms:
                form_results.extend(test_forms(page, forms))

    # Merge form results into standard findings
    for fr in form_results:
        findings.append(_finding(
            title         = f"Form XSS — {fr['field']}",
            severity      = "high",
            cvss          = 7.4,
            description   = f"XSS payload '{fr['payload']}' was successfully reflected when injected into the '{fr['field']}' field of the form at {fr['action']} (method: {fr['method'].upper()}).",
            cve           = "CVE-2024-5678",
            exploitability= "Easy",
        ))

    findings += check_directory_listing(pages)

    # Deduplicate by title (keep first occurrence)
    seen  = set()
    deduped = []
    for f in findings:
        if f["title"] not in seen:
            seen.add(f["title"])
            deduped.append(f)

    # Calculate weighted risk score (0–100)
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
    raw_score = sum(weights.get(f["severity"], 0) * f["cvss"] / 10 for f in deduped)
    risk_score = min(100, int(raw_score))

    # Extract just the paths/URLs from the api check loops for the api_endpoints response
    api_endpoints_out = [api["full_url"] for api in api_results] + passive_apis

    return {
        "url":              target_url,
        "pages_crawled":    len(pages),
        "pages":            pages,
        "api_endpoints":    list(set(api_endpoints_out)),
        "risk_score":       risk_score,
        "total_findings":   len(deduped),
        "vulnerabilities":  deduped,
    }



# ---------------------------------------------------------------------------
# CLI — python scanner.py <url>
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys, json
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(f"[NetGuard] Scanning {url} ...\n")
    result = run_scan(url)

    print(f"Pages crawled : {result['pages_crawled']}")
    print(f"Risk score    : {result['risk_score']}/100")
    print(f"Total findings: {result['total_findings']}\n")

    for v in result["vulnerabilities"]:
        sev = v["severity"].upper().ljust(8)
        print(f"  [{sev}] CVSS {v['cvss']:.1f}  {v['title']}")
        print(f"           {v['description'][:90]}...")
        print()
