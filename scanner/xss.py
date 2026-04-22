import html
import json
import re
from collections import deque
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

TIMEOUT = 8
MAX_CRAWL_PAGES = 10
MAX_TESTS_PER_ENTRYPOINT = 4
USER_AGENT = "Mozilla/5.0 (WebShield-XSS-Audit/2.0)"
CANARY = "xsscanary9f31"

PAYLOADS = [
    {
        "name": "text-reflection",
        "value": CANARY,
        "goal": "Check whether unsanitized user input is reflected in page content.",
    },
    {
        "name": "attribute-breakout",
        "value": f"\"{CANARY}",
        "goal": "Check whether input is reflected inside HTML attributes without escaping.",
    },
    {
        "name": "tag-breakout",
        "value": f"'><{CANARY}>",
        "goal": "Check whether input can break out of the current HTML element.",
    },
    {
        "name": "script-breakout",
        "value": f"';{CANARY}//",
        "goal": "Check whether input is reflected inside inline JavaScript.",
    },
]

DOM_PATTERNS = [
    (
        "innerHTML with URL source",
        re.compile(
            r"(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\s*[\s\S]{0,160}"
            r"(location|document\.URL|document\.documentURI|document\.location|location\.(hash|search|href)|document\.referrer)",
            re.IGNORECASE,
        ),
    ),
    (
        "eval-like sink with URL source",
        re.compile(
            r"(eval|Function|setTimeout|setInterval)\s*\([\s\S]{0,160}"
            r"(location|document\.URL|document\.documentURI|document\.location|location\.(hash|search|href)|document\.referrer)",
            re.IGNORECASE,
        ),
    ),
]

DEFAULT_RECOMMENDATION = (
    "Apply context-aware output encoding, validate input server-side, and prefer safe DOM APIs "
    "such as textContent instead of HTML sinks."
)

STATUS_CONFIRMED = "confirmed"
STATUS_REVIEW = "needs_manual_review"
STATUS_INFO = "informational"
STATUS_INCONCLUSIVE = "inconclusive"


def new_session():
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    return session


def same_origin(base_url, candidate_url):
    return urlparse(base_url).netloc == urlparse(candidate_url).netloc


def normalize_url(url):
    parsed = urlparse(url)
    clean_path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, clean_path, "", parsed.query, ""))


def fetch_page(url, session):
    try:
        response = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return None
        return response
    except requests.RequestException:
        return None


def extract_links(soup, base_url):
    discovered = set()
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "").strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        candidate = normalize_url(urljoin(base_url, href))
        if same_origin(base_url, candidate):
            discovered.add(candidate)
    return discovered


def get_form_details(form):
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for tag in form.find_all(["input", "textarea", "select"]):
        name = tag.attrs.get("name")
        if not name:
            continue
        input_type = tag.attrs.get("type", "text").lower()
        value = tag.attrs.get("value", "")

        if tag.name == "textarea":
            value = tag.text or value
            input_type = "textarea"
        elif tag.name == "select":
            selected = tag.find("option", selected=True) or tag.find("option")
            value = selected.get("value", "") if selected else value
            input_type = "select"

        inputs.append({"type": input_type, "name": name, "value": value})

    return {"action": action, "method": method, "inputs": inputs}


def should_inject_input(input_meta):
    injectable_types = {
        "",
        "email",
        "hidden",
        "number",
        "search",
        "select",
        "tel",
        "text",
        "textarea",
        "url",
    }
    return input_meta["type"] in injectable_types


def build_default_input_value(input_meta):
    input_type = input_meta["type"]
    if input_type == "email":
        return "audit@example.com"
    if input_type == "number":
        return "1"
    if input_type == "tel":
        return "123456789"
    if input_type == "url":
        return "https://example.com"
    return input_meta["value"] or "audit"


def crawl_targets(start_url, session):
    queue = deque([normalize_url(start_url)])
    seen = set()
    pages = []
    entrypoints = []

    while queue and len(pages) < MAX_CRAWL_PAGES:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)

        response = fetch_page(current, session)
        if not response:
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        pages.append({"url": current, "response": response, "soup": soup})

        parsed = urlparse(current)
        query_params = sorted(parse_qs(parsed.query).keys())
        if query_params:
            entrypoints.append(
                {"kind": "url", "page_url": current, "action_url": current, "params": query_params}
            )

        forms = soup.find_all("form")
        for index, form in enumerate(forms, start=1):
            details = get_form_details(form)
            if not details["inputs"]:
                continue
            action_url = normalize_url(urljoin(current, details["action"])) if details["action"] else current
            if not same_origin(start_url, action_url):
                continue
            entrypoints.append(
                {
                    "kind": "form",
                    "page_url": current,
                    "action_url": action_url,
                    "method": details["method"],
                    "form_index": index,
                    "inputs": details["inputs"],
                }
            )

        for link in extract_links(soup, current):
            if link not in seen:
                queue.append(link)

    return pages, entrypoints


def detect_dom_indicators(page):
    findings = []
    script_blocks = page["soup"].find_all("script")
    for index, script in enumerate(script_blocks, start=1):
        script_body = script.string or script.get_text(" ", strip=False)
        if not script_body:
            continue
        compact_script = " ".join(script_body.split())
        for label, pattern in DOM_PATTERNS:
            if pattern.search(compact_script):
                findings.append(
                    {
                        "type": "DOM XSS Indicator",
                        "severity": "MEDIUM",
                        "verification_status": STATUS_REVIEW,
                        "confidence": 0.45,
                        "location": f"{page['url']} -> inline script #{index}",
                        "payload": "-",
                        "description": (
                            f"Found a client-side pattern matching '{label}'. The page appears to combine "
                            "URL-controlled data with a dangerous DOM sink."
                        ),
                        "recommendation": DEFAULT_RECOMMENDATION,
                        "evidence": compact_script[:180],
                    }
                )
                break
    return findings


def find_contexts(soup, payload):
    contexts = []

    for script in soup.find_all("script"):
        script_body = script.string or script.get_text(" ", strip=False)
        if script_body and payload in script_body:
            contexts.append("script")
            break

    for tag in soup.find_all(True):
        for attribute_name, attribute_value in tag.attrs.items():
            joined_value = " ".join(attribute_value) if isinstance(attribute_value, list) else str(attribute_value)
            if payload in joined_value:
                if attribute_name.lower().startswith("on"):
                    contexts.append("event-handler")
                else:
                    contexts.append("attribute")
                break

    text_match = soup.find(string=lambda text: text and payload in text)
    if text_match:
        parent_name = getattr(text_match.parent, "name", "")
        if parent_name not in {"script", "style"}:
            contexts.append("html-text")

    return sorted(set(contexts))


def build_snippet(response_text, payload, size=80):
    index = response_text.find(payload)
    if index == -1:
        return ""
    start = max(0, index - size)
    end = min(len(response_text), index + len(payload) + size)
    snippet = response_text[start:end].replace("\n", " ").replace("\r", " ")
    return " ".join(snippet.split())


def looks_like_analytics_reflection(snippet):
    lowered = snippet.lower()
    markers = (
        "monsterinsights",
        "page_location",
        "ivorysearchvars",
        "gtm-",
        "datalayer",
        "utm_",
        "googletagmanager",
    )
    return any(marker in lowered for marker in markers)


def is_backslash_escaped(text, index):
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def has_raw_occurrence(text, payload):
    start = 0
    while True:
        index = text.find(payload, start)
        if index == -1:
            return False
        if not is_backslash_escaped(text, index):
            return True
        start = index + len(payload)


def escaped_variants(payload):
    return {
        html.escape(payload, quote=True),
        json.dumps(payload)[1:-1],
        payload.replace('"', '\\"').replace("'", "\\'"),
    }


def classify_reflection(response_text, payload_meta, contexts, snippet):
    payload = payload_meta["value"]
    escaped_payloads = escaped_variants(payload)

    if payload not in response_text:
        if any(escaped_payload in response_text for escaped_payload in escaped_payloads):
            return {
                "type": "Input Reflection (Escaped)",
                "severity": "INFO",
                "verification_status": STATUS_INFO,
                "confidence": 0.95,
                "description": "Input was reflected but appears HTML-escaped in the response.",
            }
        return None

    if any(escaped_payload in snippet for escaped_payload in escaped_payloads if escaped_payload):
        return {
            "type": "Input Reflection (Escaped)",
            "severity": "INFO",
            "verification_status": STATUS_INFO,
            "confidence": 0.9,
            "description": "Input was reflected in a script or HTML context, but escaping appears to be applied.",
        }

    if "script" in contexts or "event-handler" in contexts:
        if payload_meta["name"] == "text-reflection":
            if looks_like_analytics_reflection(snippet):
                return {
                    "type": "Script String Reflection (Analytics)",
                    "severity": "INFO",
                    "verification_status": STATUS_INFO,
                    "confidence": 0.85,
                    "description": "Input was copied into an analytics or tracking script string. This is reflective behavior, not proof of executable XSS.",
                }
            return {
                "type": "Script String Reflection (Review Required)",
                "severity": "LOW",
                "verification_status": STATUS_REVIEW,
                "confidence": 0.4,
                "description": "Input reached a script string, but this payload did not demonstrate breakout or execution.",
            }

        if not has_raw_occurrence(snippet, payload):
            return {
                "type": "Input Reflection (Escaped)",
                "severity": "INFO",
                "verification_status": STATUS_INFO,
                "confidence": 0.9,
                "description": "Input was reflected in a script context, but escaping appears to be applied.",
            }

        if looks_like_analytics_reflection(snippet):
            return {
                "type": "Script String Reflection (Analytics)",
                "severity": "LOW",
                "verification_status": STATUS_REVIEW,
                "confidence": 0.35,
                "description": "Input reached a tracking-related script string. Manual verification is still required before treating this as XSS.",
            }

        return {
            "type": "Potential XSS (Script Context)",
            "severity": "HIGH",
            "verification_status": STATUS_REVIEW,
            "confidence": 0.7,
            "description": "Input reached executable JavaScript or an event handler without clear output encoding.",
        }

    if "attribute" in contexts and any(marker in payload for marker in ['"', "'", "<", ">"]):
        return {
            "type": "Potential XSS (Attribute Context)",
            "severity": "HIGH",
            "verification_status": STATUS_REVIEW,
            "confidence": 0.65,
            "description": "Input was reflected inside an HTML attribute with breakout characters preserved.",
        }

    if "html-text" in contexts and any(marker in payload for marker in ["<", ">"]):
        return {
            "type": "Potential XSS (HTML Context)",
            "severity": "MEDIUM",
            "verification_status": STATUS_REVIEW,
            "confidence": 0.55,
            "description": "Input appears in raw HTML output with tag-like characters preserved.",
        }

    if contexts:
        return {
            "type": "Input Reflection (Review Required)",
            "severity": "LOW",
            "verification_status": STATUS_REVIEW,
            "confidence": 0.35,
            "description": "Input was reflected unsanitized, but the observed context was not directly executable.",
        }

    return {
        "type": "Input Reflection (Review Required)",
        "severity": "LOW",
        "verification_status": STATUS_REVIEW,
        "confidence": 0.3,
        "description": "Input was reflected in the response. Manual verification is still needed to confirm exploitability.",
    }


def dedupe_key(classification, location, snippet):
    return (classification["type"], location, snippet[:80])


def audit_url_entrypoint(entrypoint, session, findings, seen_keys):
    parsed = urlparse(entrypoint["action_url"])
    original_params = parse_qs(parsed.query)

    for param_name in entrypoint["params"][:MAX_TESTS_PER_ENTRYPOINT]:
        for payload in PAYLOADS:
            test_params = {key: value[:] for key, value in original_params.items()}
            test_params[param_name] = [payload["value"]]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

            try:
                response = session.get(test_url, timeout=TIMEOUT)
            except requests.RequestException:
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            contexts = find_contexts(soup, payload["value"])
            snippet = build_snippet(response.text, payload["value"])
            classification = classify_reflection(response.text, payload, contexts, snippet)
            if not classification:
                continue
            location = f"URL parameter '{param_name}' on {entrypoint['page_url']}"
            key = dedupe_key(classification, location, snippet)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            findings.append(
                {
                    "type": classification["type"],
                    "severity": classification["severity"],
                    "location": location,
                    "payload": payload["value"],
                    "description": classification["description"],
                    "recommendation": DEFAULT_RECOMMENDATION,
                    "evidence": snippet,
                    "technique": payload["name"],
                }
            )


def audit_form_entrypoint(entrypoint, session, findings, seen_keys):
    injectable_inputs = [field for field in entrypoint["inputs"] if should_inject_input(field)]
    if not injectable_inputs:
        return

    for field in injectable_inputs[:MAX_TESTS_PER_ENTRYPOINT]:
        for payload in PAYLOADS:
            data = {}
            for input_meta in entrypoint["inputs"]:
                if input_meta["name"] == field["name"]:
                    data[input_meta["name"]] = payload["value"]
                else:
                    data[input_meta["name"]] = build_default_input_value(input_meta)

            try:
                if entrypoint["method"] == "post":
                    response = session.post(entrypoint["action_url"], data=data, timeout=TIMEOUT)
                else:
                    response = session.get(entrypoint["action_url"], params=data, timeout=TIMEOUT)
            except requests.RequestException:
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            contexts = find_contexts(soup, payload["value"])
            snippet = build_snippet(response.text, payload["value"])
            classification = classify_reflection(response.text, payload, contexts, snippet)
            if not classification:
                continue
            location = (
                f"Form #{entrypoint['form_index']} field '{field['name']}' on {entrypoint['page_url']}"
            )
            key = dedupe_key(classification, location, snippet)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            findings.append(
                {
                    "type": classification["type"],
                    "severity": classification["severity"],
                    "location": location,
                    "payload": payload["value"],
                    "description": classification["description"],
                    "recommendation": DEFAULT_RECOMMENDATION,
                    "evidence": snippet,
                    "technique": f"{entrypoint['method'].upper()} form / {payload['name']}",
                }
            )


def scan(url):
    findings = []
    seen_keys = set()
    session = new_session()

    pages, entrypoints = crawl_targets(url, session)

    for page in pages:
        findings.extend(detect_dom_indicators(page))

    for entrypoint in entrypoints:
        if entrypoint["kind"] == "url":
            audit_url_entrypoint(entrypoint, session, findings, seen_keys)
        elif entrypoint["kind"] == "form":
            audit_form_entrypoint(entrypoint, session, findings, seen_keys)

    findings.insert(
        0,
        {
            "type": "XSS Audit Coverage",
            "severity": "INFO",
            "verification_status": STATUS_INFO,
            "confidence": 1.0,
            "location": url,
            "payload": "-",
            "description": (
                f"Crawled {len(pages)} same-origin page(s) and audited {len(entrypoints)} reflective entrypoint(s) "
                "for XSS indicators."
            ),
            "recommendation": "Increase crawl depth or add authentication-aware support if more coverage is needed.",
        },
    )

    if not pages:
        findings.append(
            {
                "type": "XSS Scan Limitation",
                "severity": "INFO",
                "verification_status": STATUS_INCONCLUSIVE,
                "confidence": 1.0,
                "location": url,
                "payload": "-",
                "description": "No same-origin HTML pages were crawled. Results are inconclusive for JavaScript-heavy or blocked targets.",
                "recommendation": "Use a browser-aware workflow or authenticated/manual review for this target.",
            }
        )

    if len(findings) == 1:
        findings.append(
            {
                "type": "XSS",
                "severity": "INFO",
                "verification_status": STATUS_INFO,
                "confidence": 0.8,
                "location": "All tested inputs",
                "payload": "-",
                "description": "No obvious reflected or DOM-based XSS indicators were detected in the tested pages.",
                "recommendation": "Manual verification is still recommended for authenticated and JavaScript-heavy flows.",
            }
        )

    return findings
