import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

STATUS_REVIEW = "needs_manual_review"
STATUS_INFO = "informational"

PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "'; DROP TABLE users--",
    "1' ORDER BY 1--",
    "' UNION SELECT NULL--",
    "admin'--",
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query",
    "syntax error",
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
]

def get_forms(url, session):
    try:
        resp = session.get(url, timeout=8)
        soup = BeautifulSoup(resp.content, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for tag in form.find_all("input"):
        input_type = tag.attrs.get("type", "text")
        input_name = tag.attrs.get("name")
        input_value = tag.attrs.get("value", "test")
        if input_name:
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    content = response.content.decode(errors="ignore").lower()
    return any(sig in content for sig in ERROR_SIGNATURES)

def scan(url):
    results = []
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (VulnScanner/1.0)"

    # Test URL parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if params:
        for param in params:
            for payload in PAYLOADS[:3]:
                test_params = params.copy()
                test_params[param] = payload
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                try:
                    resp = session.get(test_url, timeout=8)
                    if is_vulnerable(resp):
                        results.append({
                            "type": "SQL Injection",
                            "severity": "HIGH",
                            "verification_status": STATUS_REVIEW,
                            "confidence": 0.75,
                            "location": f"URL parameter: {param}",
                            "payload": payload,
                            "description": "SQL error detected in response — parameter may be injectable.",
                        })
                        break
                except Exception:
                    pass

    # Test forms
    forms = get_forms(url, session)
    for i, form in enumerate(forms):
        details = get_form_details(form)
        action_url = urljoin(url, details["action"]) if details["action"] else url
        for payload in PAYLOADS[:4]:
            data = {}
            for inp in details["inputs"]:
                if inp["type"] in ("text", "search", "email", "password", ""):
                    data[inp["name"]] = payload
                else:
                    data[inp["name"]] = inp["value"]
            try:
                if details["method"] == "post":
                    resp = session.post(action_url, data=data, timeout=8)
                else:
                    resp = session.get(action_url, params=data, timeout=8)
                if is_vulnerable(resp):
                    results.append({
                        "type": "SQL Injection",
                        "severity": "HIGH",
                        "verification_status": STATUS_REVIEW,
                        "confidence": 0.75,
                        "location": f"Form #{i+1} (action: {details['action'] or '/'})",
                        "payload": payload,
                        "description": "SQL error in form response — form input may be injectable.",
                    })
                    break
            except Exception:
                pass

    if not results:
        results.append({
            "type": "SQL Injection",
            "severity": "INFO",
            "verification_status": STATUS_INFO,
            "confidence": 0.8,
            "location": "All tested inputs",
            "payload": "-",
            "description": "No obvious SQL injection vulnerabilities detected.",
        })
    return results
