"""PDF report renderer for ReconX.

Generates standards-compliant, multi-page PDF documents directly from ReportModel
using pure Python standard library (zero external dependencies) per Implementation.md Section 26.
"""

from __future__ import annotations

import io
from typing import Sequence

from reconx.reporting.model import ReportModel


def _escape_pdf_text(text: str) -> str:
    """Escape special characters for PDF text string literals."""
    # Convert non-ascii to ascii representation to ensure Type1 font compatibility
    clean = text.encode("ascii", errors="replace").decode("ascii")
    clean = clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return clean


def _wrap_text(text: str, max_chars: int) -> list[str]:
    """Wrap a block of text into lines not exceeding max_chars."""
    if not text:
        return []
    lines: list[str] = []
    for paragraph in text.split("\n"):
        if not paragraph.strip():
            lines.append("")
            continue
        words = paragraph.split()
        curr_line: list[str] = []
        curr_len = 0
        for w in words:
            if curr_len + len(w) + (1 if curr_line else 0) <= max_chars:
                curr_line.append(w)
                curr_len += len(w) + (1 if len(curr_line) > 1 else 0)
            else:
                if curr_line:
                    lines.append(" ".join(curr_line))
                curr_line = [w]
                curr_len = len(w)
        if curr_line:
            lines.append(" ".join(curr_line))
    return lines


class _PDFPage:
    """Represents a single canvas page with a command stream."""

    def __init__(self, page_num: int, width: float = 612.0, height: float = 792.0) -> None:
        self.page_num = page_num
        self.width = width
        self.height = height
        self.commands: list[str] = []

    def draw_text(self, text: str, x: float, y: float, font: str = "F1", size: float = 10.0, r: float = 0.0, g: float = 0.0, b: float = 0.0) -> None:
        """Add text command to stream."""
        escaped = _escape_pdf_text(text)
        self.commands.append(
            f"q {r:.2f} {g:.2f} {b:.2f} rg BT /{font} {size:.1f} Tf {x:.2f} {y:.2f} Td ({escaped}) Tj ET Q"
        )

    def draw_line(self, x1: float, y1: float, x2: float, y2: float, width: float = 0.5, r: float = 0.7, g: float = 0.7, b: float = 0.7) -> None:
        """Add line drawing command."""
        self.commands.append(
            f"q {r:.2f} {g:.2f} {b:.2f} RG {width:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S Q"
        )

    def draw_rect(self, x: float, y: float, w: float, h: float, fill_r: float = 0.9, fill_g: float = 0.9, fill_b: float = 0.9, stroke: bool = False, stroke_r: float = 0.5, stroke_g: float = 0.5, stroke_b: float = 0.5) -> None:
        """Draw filled/stroked rectangle."""
        if stroke:
            self.commands.append(
                f"q {stroke_r:.2f} {stroke_g:.2f} {stroke_b:.2f} RG {fill_r:.2f} {fill_g:.2f} {fill_b:.2f} rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re B Q"
            )
        else:
            self.commands.append(
                f"q {fill_r:.2f} {fill_g:.2f} {fill_b:.2f} rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f Q"
            )

    def to_stream(self) -> bytes:
        """Compile page commands into content stream bytes."""
        return "\n".join(self.commands).encode("ascii", errors="replace")


class PDFReportRenderer:
    """Renders a ReportModel into a standard-compliant PDF document."""

    PAGE_WIDTH = 612.0   # Letter width (points)
    PAGE_HEIGHT = 792.0  # Letter height (points)
    MARGIN_LEFT = 50.0
    MARGIN_RIGHT = 50.0
    MARGIN_TOP = 50.0
    MARGIN_BOTTOM = 50.0

    def __init__(self) -> None:
        self.printable_width = self.PAGE_WIDTH - self.MARGIN_LEFT - self.MARGIN_RIGHT

    def render(self, model: ReportModel) -> bytes:
        """Render ReportModel as valid binary PDF bytes."""
        pages: list[_PDFPage] = []
        curr_page = _PDFPage(page_num=1, width=self.PAGE_WIDTH, height=self.PAGE_HEIGHT)
        pages.append(curr_page)

        curr_y = self.PAGE_HEIGHT - self.MARGIN_TOP

        def new_page() -> None:
            nonlocal curr_page, curr_y
            # Draw header & footer on current page before rotating
            self._draw_header_footer(curr_page, model.target)
            curr_page = _PDFPage(page_num=len(pages) + 1, width=self.PAGE_WIDTH, height=self.PAGE_HEIGHT)
            pages.append(curr_page)
            curr_y = self.PAGE_HEIGHT - self.MARGIN_TOP - 30.0

        def ensure_space(points_needed: float) -> None:
            nonlocal curr_y
            if curr_y - points_needed < self.MARGIN_BOTTOM + 35.0:
                new_page()

        # 1. Title Section
        curr_page.draw_rect(self.MARGIN_LEFT, curr_y - 45.0, self.printable_width, 50.0, fill_r=0.07, fill_g=0.15, fill_b=0.30)
        curr_page.draw_text("ReconX Security Assessment Report", self.MARGIN_LEFT + 15.0, curr_y - 20.0, font="F2", size=16.0, r=1.0, g=1.0, b=1.0)
        curr_page.draw_text(f"Target: {model.target}", self.MARGIN_LEFT + 15.0, curr_y - 36.0, font="F1", size=10.0, r=0.8, g=0.9, b=1.0)
        curr_y -= 65.0

        # Scan Meta Subheader
        curr_page.draw_text(f"Scan ID: {model.scan_id}", self.MARGIN_LEFT, curr_y, font="F3", size=8.5, r=0.3, g=0.3, b=0.3)
        curr_page.draw_text(f"Generated: {model.generated_at}", self.MARGIN_LEFT + 250.0, curr_y, font="F1", size=8.5, r=0.3, g=0.3, b=0.3)
        curr_y -= 15.0
        curr_page.draw_line(self.MARGIN_LEFT, curr_y, self.MARGIN_LEFT + self.printable_width, curr_y, width=1.0, r=0.2, g=0.2, b=0.2)
        curr_y -= 20.0

        # 2. Executive Summary
        ensure_space(110.0)
        curr_page.draw_text("1. Executive Summary", self.MARGIN_LEFT, curr_y, font="F2", size=13.0, r=0.1, g=0.1, b=0.1)
        curr_y -= 18.0

        exec_rows = [
            ("Target Evaluated:", model.executive_summary.target),
            ("Execution Duration:", f"{model.executive_summary.duration_seconds:.2f} seconds"),
            ("Authorized Scope:", model.executive_summary.scope_summary),
            ("Total Assets Discovered:", str(model.executive_summary.total_assets)),
            ("Total Security Findings:", str(model.executive_summary.total_findings)),
            ("Overall Risk Assessment:", model.executive_summary.risk_score_summary),
        ]

        for label, val in exec_rows:
            ensure_space(15.0)
            curr_page.draw_text(label, self.MARGIN_LEFT + 10.0, curr_y, font="F2", size=9.0, r=0.2, g=0.2, b=0.2)
            curr_page.draw_text(val, self.MARGIN_LEFT + 170.0, curr_y, font="F1", size=9.0, r=0.0, g=0.0, b=0.0)
            curr_y -= 14.0

        curr_y -= 10.0

        # Severity Distribution Table
        ensure_space(60.0)
        curr_page.draw_text("Severity Breakdown:", self.MARGIN_LEFT + 10.0, curr_y, font="F2", size=9.5, r=0.1, g=0.1, b=0.1)
        curr_y -= 16.0

        col_w = self.printable_width / 5.0
        sev_counts = model.executive_summary.severity_distribution

        sev_colors = {
            "CRITICAL": (0.85, 0.20, 0.20),
            "HIGH": (0.95, 0.45, 0.10),
            "MEDIUM": (0.90, 0.65, 0.05),
            "LOW": (0.10, 0.60, 0.80),
            "INFO": (0.45, 0.50, 0.55),
        }

        for idx, sname in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]):
            box_x = self.MARGIN_LEFT + (idx * col_w)
            c_r, c_g, c_b = sev_colors[sname]
            curr_page.draw_rect(box_x, curr_y - 25.0, col_w - 6.0, 30.0, fill_r=0.96, fill_g=0.96, fill_b=0.97, stroke=True, stroke_r=c_r, stroke_g=c_g, stroke_b=c_b)
            curr_page.draw_text(sname, box_x + 8.0, curr_y - 6.0, font="F2", size=8.0, r=c_r, g=c_g, b=c_b)
            curr_page.draw_text(str(sev_counts.get(sname, 0)), box_x + 8.0, curr_y - 20.0, font="F2", size=12.0, r=0.1, g=0.1, b=0.1)

        curr_y -= 40.0

        # 3. Attack Surface Summary
        ensure_space(80.0)
        curr_page.draw_text("2. Attack Surface Inventory", self.MARGIN_LEFT, curr_y, font="F2", size=13.0, r=0.1, g=0.1, b=0.1)
        curr_y -= 16.0

        surface_lines = [
            f"- Discovered Domains / Hostnames ({len(model.attack_surface.domains)}): " + (", ".join(model.attack_surface.domains[:8]) or "None"),
            f"- IP Addresses ({len(model.attack_surface.ip_addresses)}): " + (", ".join(model.attack_surface.ip_addresses[:8]) or "None"),
            f"- Open Ports & Services ({len(model.attack_surface.ports)}): " + (", ".join(model.attack_surface.ports[:10]) or "None"),
            f"- Discovered Endpoints / URLs ({len(model.attack_surface.endpoints)}): " + (f"{len(model.attack_surface.endpoints)} endpoints cataloged"),
        ]

        if model.attack_surface.technologies:
            surface_lines.append("- Technologies Detected: " + ", ".join(model.attack_surface.technologies[:10]))

        for sline in surface_lines:
            wrapped = _wrap_text(sline, max_chars=85)
            for wl in wrapped:
                ensure_space(14.0)
                curr_page.draw_text(wl, self.MARGIN_LEFT + 10.0, curr_y, font="F1", size=8.5, r=0.2, g=0.2, b=0.2)
                curr_y -= 13.0

        curr_y -= 15.0

        # 4. Detailed Findings
        ensure_space(40.0)
        curr_page.draw_text(f"3. Vulnerability Findings ({len(model.findings)})", self.MARGIN_LEFT, curr_y, font="F2", size=13.0, r=0.1, g=0.1, b=0.1)
        curr_y -= 18.0

        if not model.findings:
            ensure_space(20.0)
            curr_page.draw_text("No security findings were identified during this assessment.", self.MARGIN_LEFT + 10.0, curr_y, font="F1", size=9.0, r=0.3, g=0.3, b=0.3)
            curr_y -= 20.0
        else:
            for idx, f in enumerate(model.findings, start=1):
                ensure_space(80.0)

                # Finding Card Header
                c_r, c_g, c_b = sev_colors.get(f.severity, (0.4, 0.4, 0.4))
                curr_page.draw_rect(self.MARGIN_LEFT, curr_y - 18.0, self.printable_width, 22.0, fill_r=0.94, fill_g=0.95, fill_b=0.98, stroke=True, stroke_r=c_r, stroke_g=c_g, stroke_b=c_b)
                curr_page.draw_text(f"[{f.severity}] #{idx}. {f.title[:65]}", self.MARGIN_LEFT + 8.0, curr_y - 6.0, font="F2", size=9.5, r=c_r, g=c_g, b=c_b)

                cvss_str = f"CVSS {f.cvss_version or '3.1'}: {f.cvss_score:.1f}" if f.cvss_score is not None else "CVSS: Review Required"
                curr_page.draw_text(cvss_str, self.MARGIN_LEFT + self.printable_width - 130.0, curr_y - 6.0, font="F2", size=8.5, r=0.2, g=0.2, b=0.2)
                curr_y -= 26.0

                # Meta Attributes
                meta_line = f"Asset: {f.affected_asset}  |  Confidence: {f.confidence:.2f} ({f.confidence_level})  |  Status: {f.cvss_status}"
                if f.endpoint:
                    meta_line += f"  |  Endpoint: {f.endpoint}"
                for ml in _wrap_text(meta_line, max_chars=85):
                    ensure_space(13.0)
                    curr_page.draw_text(ml, self.MARGIN_LEFT + 8.0, curr_y, font="F1", size=8.0, r=0.35, g=0.35, b=0.35)
                    curr_y -= 12.0

                if f.cvss_vector:
                    ensure_space(13.0)
                    curr_page.draw_text(f"Vector: {f.cvss_vector}", self.MARGIN_LEFT + 8.0, curr_y, font="F3", size=7.5, r=0.2, g=0.3, b=0.5)
                    curr_y -= 13.0

                # Description
                if f.description:
                    ensure_space(15.0)
                    curr_page.draw_text("Description:", self.MARGIN_LEFT + 8.0, curr_y, font="F2", size=8.0, r=0.1, g=0.1, b=0.1)
                    curr_y -= 11.0
                    for dline in _wrap_text(f.description, max_chars=88):
                        ensure_space(12.0)
                        curr_page.draw_text(dline, self.MARGIN_LEFT + 15.0, curr_y, font="F1", size=8.0, r=0.1, g=0.1, b=0.1)
                        curr_y -= 11.0

                # Evidence
                if f.evidence:
                    ensure_space(15.0)
                    curr_page.draw_text("Supporting Evidence:", self.MARGIN_LEFT + 8.0, curr_y, font="F2", size=8.0, r=0.1, g=0.1, b=0.1)
                    curr_y -= 11.0
                    for ev in f.evidence[:5]:
                        for ev_line in _wrap_text(ev, max_chars=85):
                            ensure_space(11.0)
                            curr_page.draw_text(ev_line, self.MARGIN_LEFT + 15.0, curr_y, font="F3", size=7.5, r=0.2, g=0.2, b=0.3)
                            curr_y -= 10.0

                # Remediation
                if f.remediation:
                    ensure_space(15.0)
                    curr_page.draw_text("Remediation Guidance:", self.MARGIN_LEFT + 8.0, curr_y, font="F2", size=8.0, r=0.1, g=0.1, b=0.1)
                    curr_y -= 11.0
                    for rline in _wrap_text(f.remediation, max_chars=88):
                        ensure_space(12.0)
                        curr_page.draw_text(rline, self.MARGIN_LEFT + 15.0, curr_y, font="F1", size=8.0, r=0.1, g=0.3, b=0.1)
                        curr_y -= 11.0

                curr_y -= 12.0

        # 5. Technical Appendix
        ensure_space(80.0)
        curr_page.draw_text("4. Technical Appendix", self.MARGIN_LEFT, curr_y, font="F2", size=13.0, r=0.1, g=0.1, b=0.1)
        curr_y -= 16.0

        appendix_items = [
            f"ReconX Framework Version: {model.appendix.reconx_version}",
            f"Executed Modules: {', '.join(model.appendix.executed_modules) or 'None'}",
        ]
        if model.appendix.tool_versions:
            tvers = ", ".join(f"{t}: {v}" for t, v in sorted(model.appendix.tool_versions.items()))
            appendix_items.append(f"Tool Versions: {tvers}")
        if model.appendix.errors:
            appendix_items.append(f"Diagnostic Errors ({len(model.appendix.errors)}): {'; '.join(model.appendix.errors[:3])}")

        for aitem in appendix_items:
            for al in _wrap_text(aitem, max_chars=85):
                ensure_space(13.0)
                curr_page.draw_text(al, self.MARGIN_LEFT + 10.0, curr_y, font="F1", size=8.0, r=0.3, g=0.3, b=0.3)
                curr_y -= 12.0

        # Draw header/footer for the final page
        self._draw_header_footer(curr_page, model.target)

        # Assemble final PDF binary structure
        return self._build_pdf_binary(pages)

    def _draw_header_footer(self, page: _PDFPage, target: str) -> None:
        """Add running header and footer text and separator lines."""
        # Top running header
        page.draw_text(f"ReconX Security Report -- {target}", self.MARGIN_LEFT, self.PAGE_HEIGHT - 35.0, font="F1", size=7.5, r=0.5, g=0.5, b=0.5)
        page.draw_line(self.MARGIN_LEFT, self.PAGE_HEIGHT - 38.0, self.MARGIN_LEFT + self.printable_width, self.PAGE_HEIGHT - 38.0, width=0.5, r=0.8, g=0.8, b=0.8)

        # Bottom running footer
        page.draw_line(self.MARGIN_LEFT, 40.0, self.MARGIN_LEFT + self.printable_width, 40.0, width=0.5, r=0.8, g=0.8, b=0.8)
        page.draw_text("CONFIDENTIAL -- FOR AUTHORIZED AUDIT USE ONLY", self.MARGIN_LEFT, 28.0, font="F1", size=7.0, r=0.5, g=0.5, b=0.5)
        page.draw_text(f"Page {page.page_num}", self.MARGIN_LEFT + self.printable_width - 40.0, 28.0, font="F1", size=7.5, r=0.4, g=0.4, b=0.4)

    def _build_pdf_binary(self, pages: Sequence[_PDFPage]) -> bytes:
        """Serialize pages and PDF document tree into valid PDF 1.4 binary data."""
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        # Objects list: each element is bytes of the object definition
        objects: list[bytes] = []

        def add_obj(b: bytes) -> int:
            objects.append(b)
            return len(objects)

        # 1. Catalog Object (Obj 1)
        add_obj(b"<< /Type /Catalog /Pages 2 0 R >>")

        # 2. Pages Object (Obj 2) - placeholder, will fill kids after page allocation
        total_pages = len(pages)
        # We will need page objects and stream objects:
        # For each page:
        # page_obj_id = 3 + (i * 2)
        # stream_obj_id = 4 + (i * 2)
        page_obj_ids = [3 + (i * 2) for i in range(total_pages)]
        kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
        pages_dict = f"<< /Type /Pages /Kids [{kids_str}] /Count {total_pages} >>".encode("ascii")
        add_obj(pages_dict)

        # Fonts definition IDs
        # Place fonts at the end
        font_f1_id = 3 + (total_pages * 2)
        font_f2_id = font_f1_id + 1
        font_f3_id = font_f1_id + 2

        # 3. Add each page and its content stream
        for i, page in enumerate(pages):
            stream_data = page.to_stream()
            stream_id = page_obj_ids[i] + 1

            page_def = (
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {page.width:.1f} {page.height:.1f}] "
                f"/Contents {stream_id} 0 R "
                f"/Resources << /Font << "
                f"/F1 {font_f1_id} 0 R "
                f"/F2 {font_f2_id} 0 R "
                f"/F3 {font_f3_id} 0 R >> >> >>"
            ).encode("ascii")
            add_obj(page_def)

            stream_def = (
                f"<< /Length {len(stream_data)} >>\nstream\n".encode("ascii")
                + stream_data
                + b"\nendstream"
            )
            add_obj(stream_def)

        # 4. Standard 14 Type1 Fonts
        add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        # 5. Write body objects and record xref offsets
        offsets: list[int] = [0]
        for idx, obj_bytes in enumerate(objects, start=1):
            offsets.append(out.tell())
            out.write(f"{idx} 0 obj\n".encode("ascii"))
            out.write(obj_bytes)
            out.write(b"\nendobj\n")

        # 6. Cross-reference table (xref)
        xref_offset = out.tell()
        num_objects = len(objects) + 1
        out.write(f"xref\n0 {num_objects}\n0000000000 65535 f \n".encode("ascii"))
        for off in offsets[1:]:
            out.write(f"{off:010d} 00000 n \n".encode("ascii"))

        # 7. Trailer and EOF
        trailer = (
            f"trailer\n<< /Size {num_objects} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
        out.write(trailer)

        return out.getvalue()
