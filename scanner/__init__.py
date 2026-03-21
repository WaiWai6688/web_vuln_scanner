from . import sqli, xss, headers, ssl_check

def run_all(url):
    results = {
        "sql_injection": sqli.scan(url),
        "xss": xss.scan(url),
        "headers": headers.scan(url),
        "ssl_ports": ssl_check.scan(url),
    }

    all_findings = []
    for category, findings in results.items():
        for f in findings:
            f["category"] = category
            all_findings.append(f)

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 4))

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        counts[f.get("severity", "INFO")] += 1

    score = max(0, 100 - (counts["HIGH"] * 25) - (counts["MEDIUM"] * 10) - (counts["LOW"] * 3))

    return {
        "findings": all_findings,
        "counts": counts,
        "score": score,
    }
