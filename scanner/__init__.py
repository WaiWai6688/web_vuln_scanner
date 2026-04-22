from . import sqli, xss, headers, ssl_check

DEFAULT_STATUS = "informational"
DEFAULT_CONFIDENCE = 0.5
STATUS_CONFIRMED = "confirmed"
STATUS_REVIEW = "needs_manual_review"
STATUS_INFO = "informational"
STATUS_INCONCLUSIVE = "inconclusive"
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
STATUS_GRADE = {
    STATUS_CONFIRMED: 3,
    STATUS_REVIEW: 2,
    STATUS_INFO: 1,
    STATUS_INCONCLUSIVE: 0,
}
SCORE_WEIGHTS = {
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 3,
    "INFO": 0,
}


def normalize_finding(finding):
    finding.setdefault("verification_status", DEFAULT_STATUS)
    finding.setdefault("confidence", DEFAULT_CONFIDENCE)
    try:
        finding["confidence"] = round(float(finding["confidence"]), 2)
    except (TypeError, ValueError):
        finding["confidence"] = DEFAULT_CONFIDENCE
    finding.setdefault("original_severity", finding.get("severity", "INFO"))
    finding["severity"] = finding.get("severity", "INFO").upper()
    finding["display_severity"] = finding["severity"]
    return finding


def effective_severity(finding):
    severity = finding.get("severity", "INFO")
    status = finding.get("verification_status", DEFAULT_STATUS)
    confidence = finding.get("confidence", DEFAULT_CONFIDENCE)

    if status == STATUS_CONFIRMED or confidence >= 0.85:
        return severity

    if severity == "HIGH":
        if status == STATUS_REVIEW:
            return "MEDIUM"
        return "INFO"

    if severity == "MEDIUM":
        if status == STATUS_REVIEW:
            return "LOW"
        if status == STATUS_INCONCLUSIVE:
            return "INFO"
        return "LOW"

    if severity == "LOW" and status == STATUS_INCONCLUSIVE:
        return "INFO"

    return severity


def sort_key(finding):
    return (
        SEVERITY_ORDER.get(finding.get("severity", "INFO"), 4),
        -STATUS_GRADE.get(finding.get("verification_status", DEFAULT_STATUS), 0),
        -finding.get("confidence", DEFAULT_CONFIDENCE),
        finding.get("type", ""),
    )


def score_penalty(finding):
    status = finding.get("verification_status", DEFAULT_STATUS)
    severity = finding.get("severity", "INFO")
    confidence = finding.get("confidence", DEFAULT_CONFIDENCE)
    base = SCORE_WEIGHTS.get(severity, 0)

    if status == STATUS_CONFIRMED:
        return round(base * confidence)
    if status == STATUS_REVIEW:
        return round(base * confidence * 0.45)
    return 0

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
            normalize_finding(f)
            f["severity"] = effective_severity(f)
            f["category"] = category
            all_findings.append(f)

    all_findings.sort(key=sort_key)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        counts[f.get("severity", "INFO")] += 1

    score = max(0, 100 - sum(score_penalty(f) for f in all_findings))

    return {
        "findings": all_findings,
        "counts": counts,
        "score": score,
    }
