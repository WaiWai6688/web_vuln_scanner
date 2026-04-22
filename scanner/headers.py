import requests

STATUS_CONFIRMED = "confirmed"
STATUS_REVIEW = "needs_manual_review"
STATUS_INFO = "informational"
STATUS_INCONCLUSIVE = "inconclusive"

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS missing — site vulnerable to protocol downgrade and cookie hijacking attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "CSP missing — no policy to prevent XSS and data injection attacks.",
        "recommendation": "Add a Content-Security-Policy header restricting allowed sources.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "X-Frame-Options missing — site may be vulnerable to Clickjacking attacks.",
        "recommendation": "Add: X-Frame-Options: DENY  or  SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "X-Content-Type-Options missing — browser may MIME-sniff responses.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Referrer-Policy missing — full URL may be sent as Referer to third parties.",
        "recommendation": "Add: Referrer-Policy: no-referrer-when-downgrade",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Permissions-Policy missing — browser features not explicitly restricted.",
        "recommendation": "Add Permissions-Policy to disable unneeded browser features.",
    },
}

EXPOSED_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

def scan(url):
    results = []
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (VulnScanner/1.0)"})
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing security headers
        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                results.append({
                    "type": "Missing Security Header",
                    "severity": info["severity"],
                    "verification_status": STATUS_REVIEW,
                    "confidence": 0.55 if header in {"Strict-Transport-Security", "Content-Security-Policy"} else 0.45,
                    "location": f"HTTP Header: {header}",
                    "payload": "-",
                    "description": info["description"],
                    "recommendation": info["recommendation"],
                })
            else:
                results.append({
                    "type": "Security Header Present",
                    "severity": "INFO",
                    "verification_status": STATUS_INFO,
                    "confidence": 0.95,
                    "location": f"HTTP Header: {header}",
                    "payload": headers[header.lower()],
                    "description": f"{header} is properly set.",
                    "recommendation": "",
                })

        # Check for information-leaking headers
        for header in EXPOSED_HEADERS:
            if header.lower() in headers:
                results.append({
                    "type": "Information Disclosure",
                    "severity": "LOW",
                    "verification_status": STATUS_INFO,
                    "confidence": 0.5,
                    "location": f"HTTP Header: {header}",
                    "payload": headers[header.lower()],
                    "description": f"{header} header reveals server/technology details.",
                    "recommendation": f"Remove or obscure the {header} header to reduce fingerprinting.",
                })

        # HTTPS check
        if not url.startswith("https://"):
            results.append({
                "type": "Insecure Protocol",
                "severity": "HIGH",
                "verification_status": STATUS_CONFIRMED,
                "confidence": 0.98,
                "location": "URL scheme",
                "payload": url,
                "description": "Site is served over HTTP — all data transmitted in plaintext.",
                "recommendation": "Migrate to HTTPS and redirect all HTTP traffic.",
            })

    except requests.exceptions.SSLError:
        results.append({
            "type": "SSL Certificate Error",
            "severity": "MEDIUM",
            "verification_status": STATUS_INCONCLUSIVE,
            "confidence": 0.5,
            "location": "SSL/TLS",
            "payload": "-",
            "description": "SSL certificate is invalid, expired, or self-signed.",
            "recommendation": "Verify the certificate behavior manually before treating this as a confirmed TLS issue.",
        })
    except Exception as e:
        results.append({
            "type": "Header Scan Error",
            "severity": "INFO",
            "verification_status": STATUS_INCONCLUSIVE,
            "confidence": 1.0,
            "location": "-",
            "payload": "-",
            "description": f"Could not retrieve headers: {str(e)}",
            "recommendation": "",
        })

    return results
