from flask import Flask, render_template, request, jsonify, send_file, session
import scanner
import report
import os
import json
import tempfile
import re

app = Flask(__name__)
app.secret_key = "vuln_scanner_bca_2024"

def is_valid_url(url):
    pattern = re.compile(
        r'^(https?://)'
        r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'
        r'(:\d+)?'
        r'(/.*)?$'
    )
    return bool(pattern.match(url))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL format."}), 400

    try:
        data = scanner.run_all(url)
        session["last_scan"] = {"url": url, "data": data}
        return jsonify({"success": True, "url": url, "data": data})
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

@app.route("/report/download")
def download_report():
    scan_info = session.get("last_scan")
    if not scan_info:
        return "No scan data found. Please run a scan first.", 400

    url = scan_info["url"]
    data = scan_info["data"]

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    tmp.close()
    report.generate(url, data, tmp.name)

    return send_file(
        tmp.name,
        as_attachment=True,
        download_name="vulnerability_report.pdf",
        mimetype="application/pdf"
    )

if __name__ == "__main__":
    app.run(debug=True, port=5000)

import os

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))