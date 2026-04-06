"""PDF report generation."""

from datetime import datetime
from pathlib import Path

from fpdf import FPDF

from web_scanner.utils import count_by_severity

SEVERITY_LABELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEV_COLORS = {
    "CRITICAL": (248, 81, 73),
    "HIGH": (240, 136, 62),
    "MEDIUM": (210, 153, 34),
    "LOW": (88, 166, 255),
    "INFO": (139, 148, 158),
}


def _sanitize(text: str) -> str:
    """Replace unsupported characters for PDF Latin-1 encoding."""
    return text.replace("\u2014", "-").replace("\u2013", "-").replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"').replace("\u2026", "...").replace("\u2022", "-").replace("\u25bc", "")


class ReportPDF(FPDF):
    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(255, 255, 255)
        self.set_fill_color(13, 17, 23)
        self.cell(0, 12, f"  Web Vulnerability Scanner Report", new_x="LMARGIN", new_y="NEXT", fill=True)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(139, 148, 158)
        self.cell(0, 5, f"Target: {self.target}", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 5, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(80)
        self.cell(0, 1, "", new_x="LMARGIN", new_y="NEXT", border="B")
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(139, 148, 158)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def title_section(self, text: str):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(30, 30, 30)
        self.cell(0, 10, text, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)

    def severity_summary(self, by_severity: dict):
        self.title_section("Severity Summary")
        self.set_font("Helvetica", "", 10)
        counts = [(s, by_severity.get(s, 0)) for s in SEVERITY_LABELS]
        width = 35
        for sev, cnt in counts:
            if cnt > 0:
                r, g, b = SEV_COLORS.get(sev, (128, 128, 128))
                self.set_fill_color(r, g, b)
                self.set_text_color(255, 255, 255)
                self.set_font("Helvetica", "B", 9)
                self.cell(width, 7, f"  {sev}")
                self.set_text_color(255, 255, 255)
                self.set_font("Helvetica", "B", 10)
                self.cell(20, 7, str(cnt), align="C", fill=True)
                self.set_text_color(80)
                self.cell(0, 7, new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

    def add_finding(self, idx: int, severity: str, title: str, detail: str):
        r, g, b = SEV_COLORS.get(severity, (128, 128, 128))
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.cell(15, 6, f"  {severity}", fill=True, border="L")
        self.set_draw_color(r, g, b)
        self.set_text_color(30, 30, 30)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 6, f"  [{idx}] {_sanitize(title[:100])}", fill=True, border="R", new_x="LMARGIN", new_y="NEXT")

        self.set_font("Helvetica", "", 9)
        self.set_text_color(80, 80, 80)
        y_start = self.get_y()
        self.multi_cell(0, 5, f"      {_sanitize(detail[:200])}", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(230, 230, 230)
        if self.get_y() > 250:
            self.add_page()
        self.cell(0, 8, "", border="B", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)


def generate_pdf(findings: list[dict], target: str, filename: str | None = None):
    """Generate a PDF report."""
    target = _sanitize(target)
    pdf = ReportPDF(target)
    pdf.alias_nb_pages()
    pdf.add_page()

    by_severity = count_by_severity(findings)

    pdf.title_section(f"Scan Report - {target}")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80)
    pdf.cell(0, 6, f"Total findings: {len(findings)}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Severity summary
    pdf.severity_summary(by_severity)
    pdf.ln(3)

    # Findings
    pdf.title_section("Detailed Findings")
    for i, f in enumerate(findings, 1):
        pdf.add_finding(i, f.get("severity", "INFO"), f.get("title", ""), f.get("detail", ""))

    output_path = filename or f"scan_{target.replace('://', '_').replace('/', '_') or 'report'}.pdf"
    pdf.output(output_path)
    return output_path
