import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "\"'><script>alert('XSS')</script>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
]

def get_forms(url, session):
    try:
        resp = session.get(url, timeout=8)
        soup = BeautifulSoup(resp.content, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []

def get_form_details(form):
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for tag in form.find_all("input"):
        name = tag.attrs.get("name")
        itype = tag.attrs.get("type", "text")
        value = tag.attrs.get("value", "test")
        if name:
            inputs.append({"type": itype, "name": name, "value": value})
    return {"action": action, "method": method, "inputs": inputs}

def scan(url):
    results = []
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (VulnScanner/1.0)"

    # Check URL parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if params:
        for param in params:
            for payload in XSS_PAYLOADS[:3]:
                test_params = params.copy()
                test_params[param] = payload
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                try:
                    resp = session.get(test_url, timeout=8)
                    if payload in resp.text:
                        results.append({
                            "type": "XSS (Reflected)",
                            "severity": "HIGH",
                            "location": f"URL parameter: {param}",
                            "payload": payload,
                            "description": "Payload reflected in response — possible Reflected XSS.",
                        })
                        break
                except Exception:
                    pass

    # Check forms
    forms = get_forms(url, session)
    for i, form in enumerate(forms):
        details = get_form_details(form)
        action_url = urljoin(url, details["action"]) if details["action"] else url
        for payload in XSS_PAYLOADS:
            data = {}
            for inp in details["inputs"]:
                if inp["type"] in ("text", "search", "email", ""):
                    data[inp["name"]] = payload
                else:
                    data[inp["name"]] = inp["value"]
            try:
                if details["method"] == "post":
                    resp = session.post(action_url, data=data, timeout=8)
                else:
                    resp = session.get(action_url, params=data, timeout=8)
                if payload in resp.text:
                    results.append({
                        "type": "XSS (Reflected)",
                        "severity": "HIGH",
                        "location": f"Form #{i+1} field",
                        "payload": payload,
                        "description": "XSS payload reflected in response without sanitization.",
                    })
                    break
            except Exception:
                pass

    if not results:
        results.append({
            "type": "XSS",
            "severity": "INFO",
            "location": "All tested inputs",
            "payload": "-",
            "description": "No reflected XSS vulnerabilities detected in tested inputs.",
        })
    return results
