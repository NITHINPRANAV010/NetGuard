from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
import datetime
import uuid
import asyncio
import random
import os
import httpx
import json
from concurrent.futures import ThreadPoolExecutor
import urllib3
import scanner as netguard_scanner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
_executor = ThreadPoolExecutor(max_workers=4)

# --- Supabase (direct REST) ---
SUPABASE_URL = "https://dqwczzekgcwyfzhihixh.supabase.co"
SUPABASE_KEY = "sb_publishable_Lu7wJmye3AQ4hqPZPskE_g_xlD_GSmC"
_SUPABASE_HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
}

def save_scan_result(url: str, vulnerabilities: list):
    """Persist a completed scan result to Supabase via REST API."""
    try:
        payload = {"url": url, "vulnerabilities": json.dumps(vulnerabilities)}
        with httpx.Client(timeout=10) as client:
            r = client.post(
                f"{SUPABASE_URL}/rest/v1/scan_results",
                headers=_SUPABASE_HEADERS,
                json=payload,
            )
        if r.status_code not in (200, 201):
            print(f"[Supabase] Insert failed {r.status_code}: {r.text}")
        else:
            print(f"[Supabase] Scan result saved for {url}")
    except Exception as e:
        print(f"[Supabase] Failed to save scan result: {e}")

app = FastAPI(title="NetGuard API | Security Intelligence")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Mount static files - this will allow app.js and styles.css to be loaded
app.mount("/assets", StaticFiles(directory="."), name="assets")

@app.get("/")
async def root():
    return FileResponse("index.html")

@app.get("/app.js")
async def get_js():
    return FileResponse("app.js")

@app.get("/styles.css")
async def get_css():
    return FileResponse("styles.css")

# --- Models ---

class Scan(BaseModel):
    id: str
    url: str
    type: str
    status: str
    progress: int
    vulns: str
    started: str
    duration: str

class NewScanRequest(BaseModel):
    target_url: str
    scan_type: str
    depth: int
    threads: int
    auth_method: str
    options: Optional[dict] = None

class Finding(BaseModel):
    title: str
    sev: str
    color: str
    target: str
    desc: str

class Activity(BaseModel):
    color: str
    title: str
    sub: str
    time: str

# Simple scan request — matches the frontend snippet { url: ... }
class QuickScanRequest(BaseModel):
    url: str
    auth: Optional[bool] = False

# --- Persistence (In-Memory) ---

scans_db = [
    {"id": "SC-041", "url": "api.shopify-enterprise.com", "type": "API Discovery & Test", "status": "running", "progress": 78, "vulns": "—", "started": "14:32", "duration": "~3m left"},
    {"id": "SC-040", "url": "portal.acme-corp.io", "type": "Auth-Aware Crawl", "status": "running", "progress": 45, "vulns": "—", "started": "14:45", "duration": "~9m left"},
    {"id": "SC-022", "url": "shop.acme.io", "type": "Full Crawl", "status": "completed", "progress": 100, "vulns": "18", "started": "12:00", "duration": "31m 22s"},
]

findings_db = [
    {"title": "SQL Injection — /api/search", "sev": "critical", "color": "#ef4444", "target": "api.shopify-enterprise.com", "desc": "Unsanitized parameter in GET /api/search allows full DB dump via UNION-based SQLi"},
    {"title": "Business Logic Flaw — Price Override", "sev": "high", "color": "#f97316", "target": "shop.acme.io", "desc": "Cart total can be manipulated client-side; server does not re-validate pricing"},
    {"title": "RBAC Bypass — Admin Panel", "sev": "high", "color": "#f97316", "target": "portal.acme-corp.io", "desc": "Role check missing on /admin/users; low-privilege user can access admin endpoints"},
    {"title": "DOM-based XSS — SPA Route Param", "sev": "medium", "color": "#eab308", "target": "staging.myapp.dev", "desc": "React router param written to innerHTML without sanitisation; reflected in browser DOM"},
]

activity_db = [
    {"color": "#ef4444", "title": "SQL Injection detected", "sub": "UNION-based SQLi — api.shopify/api/search", "time": "1m"},
    {"color": "#f97316", "title": "Business logic flaw found", "sub": "Price override via cart param — shop.acme.io", "time": "9m"},
    {"color": "#3b82f6", "title": "API endpoint map completed", "sub": "47 endpoints discovered", "time": "22m"},
]

reports_db = [
    { "id": 'RPT-022', "target": 'shop.acme.io', "date": 'Apr 9, 2026', "critical": 4, "high": 6, "medium": 5, "low": 7, "score": 78 },
    { "id": 'RPT-021', "target": 'api.shopify-enterprise.com', "date": 'Apr 8, 2026', "critical": 2, "high": 5, "medium": 8, "low": 10, "score": 65 },
]

findings_detailed_db = [
    { "title": 'SQL Injection — /api/search', "sev": 'critical', "color": '#ef4444', "cvss": '9.8', "exploit": 'Easy', "target": 'shop.acme.io', "cve": 'CVE-2024-1234', "desc": 'UNION-based SQL injection in GET /api/search?q= allows full database dump.' },
    { "title": 'Logic Workflow: Price Override', "sev": 'critical', "color": '#ef4444', "cvss": '9.1', "exploit": 'Medium', "target": 'shop.acme.io', "cve": 'N/A', "desc": 'Cart total is computed client-side only. Server accepts any price value.' },
    { "title": 'RBAC Bypass — /admin/users', "sev": 'high', "color": '#f97316', "cvss": '8.6', "exploit": 'Easy', "target": 'portal.acme-corp.io', "cve": 'N/A', "desc": 'Authorization check on /admin/users endpoint is missing.' },
]

# --- Background Simulation ---

async def simulate_scan(scan_id: str):
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan: return

    while scan["progress"] < 100:
        await asyncio.sleep(random.randint(2, 5))
        scan["progress"] += random.randint(5, 15)
        if scan["progress"] > 100: scan["progress"] = 100
        
        # Randomly find a vulnerability
        if random.random() > 0.7:
            vuln_count = scan["vulns"]
            if vuln_count == "—": vuln_count = 0
            scan["vulns"] = str(int(vuln_count) + 1)
            
            # Add to activity feed
            new_activity = {
                "color": "#f97316",
                "title": f"Finding detected in {scan['id']}",
                "sub": f"Potential vulnerability on {scan['url']}",
                "time": "Just now"
            }
            activity_db.insert(0, new_activity)

    scan["status"] = "completed"
    scan["duration"] = "Finished in ~4m"

# --- Endpoints ---

@app.get("/api/stats")
async def get_stats():
    return {
        "scans": len([s for s in scans_db if s["status"] in ["running", "queued"]]),
        "vulns": 128,
        "apis": 342,
        "fp": 94,
        "risk_score": 68
    }

@app.get("/api/scans", response_model=List[Scan])
async def get_scans():
    return scans_db

@app.get("/api/scans/active", response_model=List[Scan])
async def get_active_scans():
    return [s for s in scans_db if s["status"] == "running"]

@app.post("/api/scans/start")
async def start_scan(req: NewScanRequest, background_tasks: BackgroundTasks):
    new_id = f"SC-{str(uuid.uuid4())[:3].upper()}"
    new_scan = {
        "id": new_id,
        "url": req.target_url,
        "type": req.scan_type,
        "status": "running",
        "progress": 0,
        "vulns": "—",
        "started": datetime.datetime.now().strftime("%H:%M"),
        "duration": "Scanning..."
    }
    scans_db.insert(0, new_scan)
    background_tasks.add_task(simulate_scan, new_id)
    return {"status": "success", "scan_id": new_id}

@app.get("/api/findings/recent", response_model=List[Finding])
async def get_recent_findings():
    return findings_db[:4]

@app.get("/api/activity", response_model=List[Activity])
async def get_activity():
    return activity_db[:8]

@app.get("/api/reports")
async def get_reports():
    return reports_db

# --- /scan endpoint (matches frontend snippet) ---

# Vulnerability pool used to simulate realistic scan results
VULN_POOL = [
    {"title": "SQL Injection",                "sev": "critical", "color": "#ef4444", "cvss": 9.8, "desc": "Unsanitized input allows UNION-based database dump.",          "cve": "CVE-2024-1234", "exploit": "Easy"},
    {"title": "Cross-Site Scripting (XSS)",   "sev": "high",     "color": "#f97316", "cvss": 7.4, "desc": "Reflected XSS via unescaped query parameter.",                "cve": "CVE-2024-5678", "exploit": "Easy"},
    {"title": "CSRF — Settings Endpoint",     "sev": "medium",   "color": "#eab308", "cvss": 6.5, "desc": "POST /settings lacks CSRF token validation.",                 "cve": "N/A",           "exploit": "Easy"},
    {"title": "Insecure Direct Object Ref",   "sev": "high",     "color": "#f97316", "cvss": 8.1, "desc": "User can access other accounts' data by changing the ID.",   "cve": "N/A",           "exploit": "Medium"},
    {"title": "JWT Algorithm Confusion",      "sev": "high",     "color": "#f97316", "cvss": 8.1, "desc": "Server accepts JWTs with 'none' algorithm — token forgery.", "cve": "CVE-2024-9012", "exploit": "Complex"},
    {"title": "Open Redirect",                "sev": "medium",   "color": "#eab308", "cvss": 6.1, "desc": "Unvalidated redirect target allows phishing attacks.",        "cve": "N/A",           "exploit": "Easy"},
    {"title": "Sensitive Data Exposure",      "sev": "high",     "color": "#f97316", "cvss": 7.5, "desc": "API response leaks internal server paths and stack traces.",  "cve": "N/A",           "exploit": "Easy"},
    {"title": "Business Logic — Price Abuse", "sev": "critical", "color": "#ef4444", "cvss": 9.1, "desc": "Cart total computed client-side; server accepts any value.",  "cve": "N/A",           "exploit": "Medium"},
    {"title": "Missing Rate Limiting",        "sev": "medium",   "color": "#eab308", "cvss": 5.9, "desc": "Login endpoint has no brute-force protection.",               "cve": "N/A",           "exploit": "Easy"},
    {"title": "Outdated TLS / Weak Cipher",   "sev": "low",      "color": "#22c55e", "cvss": 4.3, "desc": "Server supports TLS 1.0 and RC4 cipher suites.",             "cve": "CVE-2011-3389", "exploit": "Complex"},
]

@app.post("/scan")
async def quick_scan(req: QuickScanRequest, background_tasks: BackgroundTasks):
    """Real scan endpoint — crawls the target and runs vulnerability checks."""
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    import attack_chain as atck

    # Run blocking scanner in thread pool so we don't block the event loop
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            _executor, netguard_scanner.run_scan, url, req.auth
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scanner error: {e}")

    result["attack_chain"] = atck.attack_chain
    result["impact"] = atck.impact

    vulnerabilities = result["vulnerabilities"]
    risk_score      = result["risk_score"]
    pages_crawled   = result.get("pages_crawled", 1)
    scan_id         = f"SC-{str(uuid.uuid4())[:4].upper()}"

    # Persist scan into scans_db so it appears in the Dashboard
    new_scan = {
        "id":       scan_id,
        "url":      url,
        "type":     "Real Scan",
        "status":   "completed",
        "progress": 100,
        "vulns":    str(len(vulnerabilities)),
        "started":  datetime.datetime.now().strftime("%H:%M"),
        "duration": f"{pages_crawled} page(s) crawled",
    }
    scans_db.insert(0, new_scan)

    # Add to activity feed
    activity_db.insert(0, {
        "color": "#a855f7",
        "title": f"Scan completed — {len(vulnerabilities)} findings",
        "sub":   url,
        "time":  "Just now",
    })

    # Persist to Supabase
    save_scan_result(url, vulnerabilities)

    return result

import report_generator

@app.post("/generate-report")
def generate_report():
    # Example data (replace with real scan result)
    data = {
        "url": "https://example.com", 
        "vulnerabilities": [
            {"type": "SQL Injection", "severity": "HIGH"}, 
            {"type": "XSS", "severity": "MEDIUM"}
        ]
    }

    file_path = report_generator.generate_pdf_report(data)
    return FileResponse(file_path, media_type="application/pdf", filename="report.pdf")

@app.get("/api/findings/detailed")
async def get_detailed_findings():
    return findings_detailed_db


@app.get("/api/vuln-summary")
async def get_vuln_summary():
    """Categorise all known findings by type and return counts + bar percentages."""
    all_findings = findings_db + findings_detailed_db
    cats = {
        "SQL Injection":  {"color": "#ef4444", "count": 0},
        "XSS / DOM":      {"color": "#f97316", "count": 0},
        "Business Logic": {"color": "#f97316", "count": 0},
        "RBAC / Authz":   {"color": "#eab308", "count": 0},
        "API Flaws":      {"color": "#eab308", "count": 0},
        "Attack Chains":  {"color": "#a855f7", "count": 0},
    }
    for f in all_findings:
        t = (f.get("title") or "").lower()
        if "sql" in t or "injection" in t:
            cats["SQL Injection"]["count"] += 1
        elif "xss" in t or "dom" in t or "redirect" in t or "clickjack" in t:
            cats["XSS / DOM"]["count"] += 1
        elif "logic" in t or "price" in t or "workflow" in t or "business" in t:
            cats["Business Logic"]["count"] += 1
        elif "rbac" in t or "auth" in t or "bypass" in t or "privilege" in t or "csrf" in t:
            cats["RBAC / Authz"]["count"] += 1
        elif "api" in t or "endpoint" in t:
            cats["API Flaws"]["count"] += 1
        else:
            cats["Attack Chains"]["count"] += 1
    max_count = max((v["count"] for v in cats.values()), default=1) or 1
    return [
        {"label": label, "count": v["count"], "color": v["color"],
         "pct": int((v["count"] / max_count) * 100)}
        for label, v in cats.items()
    ]


@app.get("/api/scan-activity")
async def get_scan_activity():
    """Return per-day scan counts for the last 14 days derived from scans_db."""
    import datetime as dt
    today = dt.date.today()
    days_list = [(today - dt.timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    buckets = {d: 0 for d in days_list}
    for i, scan in enumerate(scans_db):
        idx = len(days_list) - 1 - (i % len(days_list))
        buckets[days_list[idx]] += 1
    return [{"date": d, "scans": buckets[d], "label": d[5:]} for d in days_list]


@app.get("/api/attack-chain")
async def get_attack_chain():
    """
    Return the current simulated attack chain and its impact rating.

    The chain is re-evaluated on every call so that any changes to the
    scan results (e.g. after a fresh scan) are reflected immediately.

    Response shape:
        {
            "attack_chain": ["User logged in", ...],
            "impact": "CRITICAL"
        }
    """
    import attack_chain as atck
    import importlib
    importlib.reload(atck)          # always reflect the latest state

    # Derive a human-readable impact label from the module variable
    raw_impact: str = getattr(atck, "impact", "LOW RISK")
    if "critical" in raw_impact.lower():
        impact_label = "CRITICAL"
    elif "high" in raw_impact.lower():
        impact_label = "HIGH"
    elif "medium" in raw_impact.lower():
        impact_label = "MEDIUM"
    else:
        impact_label = "LOW"

    return {
        "attack_chain": atck.attack_chain,
        "impact": impact_label,
    }




@app.get("/get_results")
async def get_results():
    """Fetch all saved scan results from Supabase, newest first."""
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(
                f"{SUPABASE_URL}/rest/v1/scan_results",
                headers={
                    **_SUPABASE_HEADERS,
                    "Prefer": "return=representation",
                },
                params={
                    "select": "*",
                    "order": "created_at.desc",
                },
            )
        if r.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Supabase error: {r.text}")

        rows = r.json()
        # Parse vulnerabilities JSON string back to list if stored as text
        for row in rows:
            if isinstance(row.get("vulnerabilities"), str):
                try:
                    row["vulnerabilities"] = json.loads(row["vulnerabilities"])
                except Exception:
                    pass
        return rows
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
