# WebShield XSS Audit

WebShield XSS Audit is a Flask-based web security scanner with an upgraded XSS-focused audit engine. It is designed for educational use and authorized security assessments on targets you own or have explicit permission to test.

## What's improved

- Same-origin crawling across multiple pages instead of testing only the first URL
- Form and query parameter discovery across the crawled pages
- Context-aware reflection analysis for:
  - inline script reflections
  - HTML attribute reflections
  - raw HTML/tag reflections
  - escaped reflections that are likely safe
- Passive DOM XSS indicator detection in inline scripts
- Evidence snippets and testing technique metadata in the report output
- Safer canary-style payloads for audit workflows instead of JavaScript `alert()` payloads

## Current scope

The upgraded scanner is still a lightweight audit tool. It works best for:

- Reflected XSS discovery on public pages
- Quick review of unauthenticated forms and query parameters
- Flagging suspicious client-side DOM sink patterns for manual follow-up

It does not yet execute JavaScript in a browser, maintain authenticated sessions, or prove exploitability automatically.

## Installation

```bash
git clone https://github.com/your-username/web_vuln_scanner.git
cd web_vuln_scanner
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000`.

## How the XSS audit works

1. Crawl up to 10 same-origin HTML pages
2. Collect GET parameters and HTML forms
3. Inject audit canaries into discovered entrypoints
4. Classify reflections by context
5. Report potential XSS findings with evidence snippets and remediation guidance

## Example findings

- `Potential XSS (Script Context)` - input reaches inline JavaScript or event handler code
- `Potential XSS (Attribute Context)` - input reflects into HTML attributes with breakout characters preserved
- `Potential XSS (HTML Context)` - raw tag-like reflection appears in HTML output
- `DOM XSS Indicator` - inline client-side code appears to combine URL-controlled data with dangerous DOM sinks
- `Input Reflection (Escaped)` - input is reflected but HTML-escaped

## Project structure

```text
app.py
report.py
scanner/
  headers.py
  sqli.py
  ssl_check.py
  xss.py
templates/
  index.html
```

## Responsible use

Only scan systems you own or have written authorization to test. This project is intended for defensive research, learning, and internal security review.
