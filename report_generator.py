"""
report_generator.py
--------------------
Builds a one-page PDF security report from an analyzer.py result dict.

The report never includes the actual password - only a masked version
(first + last character, rest asterisked) so the document is safe to
save, print, or attach to an internship submission without leaking a
real credential.
"""

from datetime import datetime
from fpdf import FPDF

# Brand palette (kept close to the web UI's teal/navy scheme)
COLOR_INK = (17, 24, 39)
COLOR_MUTED = (100, 110, 130)
COLOR_STRONG = (26, 163, 132)
COLOR_FAIR = (217, 155, 26)
COLOR_WEAK = (204, 70, 70)
COLOR_LINE = (222, 227, 235)

SCORE_COLORS = {
    "Very Strong": COLOR_STRONG,
    "Strong": COLOR_STRONG,
    "Fair": COLOR_FAIR,
    "Weak": COLOR_WEAK,
    "Very Weak": COLOR_WEAK,
}


def _pdf_safe(text: str) -> str:
    """The PDF core fonts only support latin-1. Swap the handful of
    typographic characters used elsewhere in the project for plain-ASCII
    equivalents so report generation never breaks on an em dash or a
    curly apostrophe."""
    replacements = {
        "\u2014": "-", "\u2013": "-",   # em dash, en dash
        "\u2018": "'", "\u2019": "'",   # curly single quotes
        "\u201c": '"', "\u201d": '"',   # curly double quotes
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text


def _mask_password(password: str) -> str:
    if not password:
        return "(none)"
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


class _Report(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*COLOR_INK)
        self.cell(0, 10, "Password Security Report", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*COLOR_MUTED)
        self.cell(0, 6, f"Generated {datetime.now().strftime('%d %b %Y, %H:%M')} | Password Strength Analyzer & Security Awareness Tool", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*COLOR_LINE)
        self.line(10, self.get_y() + 2, 200, self.get_y() + 2)
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*COLOR_MUTED)
        self.cell(0, 10, f"Page {self.page_no()} - This report does not contain your actual password.", align="C")

    def section_title(self, text):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*COLOR_INK)
        self.ln(2)
        self.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*COLOR_LINE)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)


def generate_report(password: str, analysis: dict, output_path: str) -> str:
    """Write a PDF report to output_path and return that path."""
    pdf = _Report()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # --- Summary block ----------------------------------------------
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*COLOR_INK)
    pdf.cell(45, 7, "Password analyzed:")
    pdf.set_font("Courier", "", 10)
    pdf.cell(0, 7, _mask_password(password), new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(45, 7, "Length:")
    pdf.cell(0, 7, f"{analysis['length']} characters", new_x="LMARGIN", new_y="NEXT")

    pdf.cell(45, 7, "Estimated entropy:")
    pdf.cell(0, 7, f"{analysis['entropy_bits']} bits", new_x="LMARGIN", new_y="NEXT")

    color = SCORE_COLORS.get(analysis["label"], COLOR_INK)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(45, 8, "Strength score:")
    pdf.set_text_color(*color)
    pdf.cell(0, 8, f"{analysis['score']} / 100  -  {analysis['label']}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(*COLOR_INK)

    # Score bar
    bar_x, bar_y, bar_w, bar_h = 55, pdf.get_y() + 1, 130, 5
    pdf.set_fill_color(*COLOR_LINE)
    pdf.rect(bar_x, bar_y, bar_w, bar_h, style="F")
    pdf.set_fill_color(*color)
    pdf.rect(bar_x, bar_y, bar_w * analysis["score"] / 100, bar_h, style="F")
    pdf.ln(12)

    # --- Checklist ----------------------------------------------------
    pdf.section_title("Complexity Checklist")
    check_labels = {
        "length_ok": "At least 8 characters",
        "length_strong": "At least 12 characters (recommended)",
        "has_lowercase": "Contains lowercase letters",
        "has_uppercase": "Contains uppercase letters",
        "has_digits": "Contains numbers",
        "has_symbols": "Contains symbols",
        "not_common_password": "Not a known common/breached password",
        "no_sequential_pattern": "No sequential characters (abcd, 4321)",
        "no_repeated_pattern": "No repeated-character runs (aaa, 111)",
        "no_keyboard_walk": "No keyboard-walk patterns (qwerty, asdf)",
    }
    pdf.set_font("Helvetica", "", 10)
    for key, text in check_labels.items():
        passed = analysis["checks"].get(key, False)
        pdf.set_text_color(*(COLOR_STRONG if passed else COLOR_WEAK))
        mark = "PASS" if passed else "FAIL"
        pdf.cell(18, 6, mark)
        pdf.set_text_color(*COLOR_INK)
        pdf.cell(0, 6, text, new_x="LMARGIN", new_y="NEXT")

    # --- Crack time estimates ------------------------------------------
    if analysis.get("crack_time_estimates"):
        pdf.section_title("Estimated Time to Crack")
        pdf.set_font("Helvetica", "", 9)
        for scenario, t in analysis["crack_time_estimates"].items():
            label = scenario.split(" (")[0].replace("_", " ").title()
            detail = scenario.split(" (")[1].rstrip(")") if "(" in scenario else ""
            pdf.set_text_color(*COLOR_MUTED)
            pdf.cell(85, 6, f"{label} ({detail})")
            pdf.set_text_color(*COLOR_INK)
            pdf.cell(0, 6, t, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*COLOR_MUTED)
        pdf.multi_cell(0, 5, "These are order-of-magnitude estimates for illustration. Real-world crack speed depends heavily on how the target system stores and hashes passwords.")
        pdf.set_text_color(*COLOR_INK)

    # --- Recommendations ------------------------------------------------
    pdf.section_title("Recommendations")
    pdf.set_font("Helvetica", "", 10)
    for rec in analysis["recommendations"]:
        pdf.set_x(10)
        pdf.multi_cell(0, 6, f"-  {_pdf_safe(rec)}")
    pdf.ln(1)

    # --- General awareness tips ------------------------------------------
    from analyzer import SECURITY_AWARENESS_TIPS
    pdf.section_title("General Security Awareness")
    pdf.set_font("Helvetica", "", 10)
    for tip in SECURITY_AWARENESS_TIPS:
        pdf.set_x(10)
        pdf.multi_cell(0, 6, f"-  {_pdf_safe(tip)}")

    pdf.output(output_path)
    return output_path


if __name__ == "__main__":
    from analyzer import analyze_password
    pw = "Summer2024!"
    result = analyze_password(pw)
    generate_report(pw, result, "/tmp/sample_report.pdf")
    print("Sample report written to /tmp/sample_report.pdf")
