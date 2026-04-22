from fpdf import FPDF
import datetime

SEVERITY_COLORS = {
    "HIGH":   (220, 53,  69),
    "MEDIUM": (255, 140, 0),
    "LOW":    (200, 160, 0),
    "INFO":   (13,  110, 253),
}

def safe(text):
    replacements = {
        "\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2022": "*", "\u2026": "...",
        "\u2192": "->", "\u2190": "<-", "\u00d7": "x", "\u00e9": "e",
        "\u2713": "OK", "\u2715": "X", "\u26a0": "!",
    }
    for ch, rep in replacements.items():
        text = text.replace(ch, rep)
    return text.encode("latin-1", errors="replace").decode("latin-1")


class ReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(30, 30, 30)
        self.cell(0, 10, "Web Vulnerability Scanner - Security Report", ln=1, align="C")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, safe("Generated: " + datetime.datetime.now().strftime("%d %B %Y, %H:%M")), ln=1, align="C")
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, safe("Page " + str(self.page_no()) + " | BCA Final Year Project - Web Vulnerability Scanner"), align="C")


def generate(url, scan_data, output_path):
    pdf = ReportPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    findings = scan_data["findings"]
    counts   = scan_data["counts"]
    score    = scan_data["score"]

    # --- Summary Section ---
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_fill_color(230, 230, 230)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "Scan Summary", ln=1, fill=True)
    pdf.ln(1)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, safe("Target URL    : " + url), ln=1)
    pdf.cell(0, 7, safe("Security Score: " + str(score) + " / 100"), ln=1)
    pdf.cell(0, 7, safe(
        "Total Findings: " + str(len(findings)) +
        "   HIGH: " + str(counts["HIGH"]) +
        "   MEDIUM: " + str(counts["MEDIUM"]) +
        "   LOW: " + str(counts["LOW"]) +
        "   INFO: " + str(counts["INFO"])
    ), ln=1)
    pdf.ln(6)

    # --- Findings Section ---
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_fill_color(230, 230, 230)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "Detailed Findings", ln=1, fill=True)
    pdf.ln(2)

    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, (13, 110, 253))

        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*color)
        pdf.cell(0, 6, safe(str(i) + ". [" + sev + "] " + f.get("type", "")), ln=1)

        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, safe("   Location : " + f.get("location", "-")), ln=1)
        pdf.cell(0, 5, safe("   Payload  : " + str(f.get("payload", "-"))), ln=1)
        pdf.cell(0, 5, safe("   Status   : " + f.get("verification_status", "informational")), ln=1)
        pdf.cell(0, 5, safe("   Confidence: " + str(f.get("confidence", "-"))), ln=1)

        technique = f.get("technique", "")
        if technique:
            pdf.cell(0, 5, safe("   Method   : " + technique), ln=1)

        desc = f.get("description", "")
        if desc:
            pdf.multi_cell(0, 5, safe("   Details  : " + desc))

        evidence = f.get("evidence", "")
        if evidence:
            pdf.multi_cell(0, 5, safe("   Evidence : " + evidence))

        rec = f.get("recommendation", "")
        if rec:
            pdf.set_text_color(0, 120, 0)
            pdf.multi_cell(0, 5, safe("   Fix      : " + rec))
            pdf.set_text_color(30, 30, 30)

        pdf.ln(3)

    # --- Disclaimer ---
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.multi_cell(0, 5, safe(
        "Disclaimer: This tool is for educational and authorized security testing only. "
        "Unauthorized scanning is illegal under IT Act 2000 (India). "
        "This report was generated as part of a BCA Final Year Project."
    ))

    pdf.output(output_path)
    return output_path
