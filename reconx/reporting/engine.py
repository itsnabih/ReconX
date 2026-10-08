"""Reporting engine orchestrator for ReconX.

Integrates all four report renderers (JSON, Markdown, HTML, PDF) to guarantee
that all output formats originate from the single canonical ReportModel per
Implementation.md Phase 11.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from reconx.reporting.html_renderer import HTMLReportRenderer
from reconx.reporting.json_renderer import JSONReportRenderer
from reconx.reporting.markdown_renderer import MarkdownReportRenderer
from reconx.reporting.model import ReportModel
from reconx.reporting.pdf_renderer import PDFReportRenderer

ReportFormat = Literal["json", "markdown", "md", "html", "pdf"]


class ReportingEngine:
    """Unified engine to render and export security reports across all supported formats."""

    def __init__(self) -> None:
        self.json_renderer = JSONReportRenderer()
        self.markdown_renderer = MarkdownReportRenderer()
        self.html_renderer = HTMLReportRenderer()
        self.pdf_renderer = PDFReportRenderer()

    def render_json(self, model: ReportModel, indent: int = 2) -> str:
        """Render ReportModel as canonical JSON."""
        return self.json_renderer.render(model, indent=indent)

    def render_markdown(self, model: ReportModel) -> str:
        """Render ReportModel as Markdown."""
        return self.markdown_renderer.render(model)

    def render_html(self, model: ReportModel) -> str:
        """Render ReportModel as responsive standalone HTML5."""
        return self.html_renderer.render(model)

    def render_pdf(self, model: ReportModel) -> bytes:
        """Render ReportModel as binary PDF bytes."""
        return self.pdf_renderer.render(model)

    def render(self, model: ReportModel, format: str) -> str | bytes:
        """Render ReportModel in the requested format."""
        fmt = format.strip().lower()
        if fmt == "json":
            return self.render_json(model)
        elif fmt in ("markdown", "md"):
            return self.render_markdown(model)
        elif fmt in ("html", "htm"):
            return self.render_html(model)
        elif fmt == "pdf":
            return self.render_pdf(model)
        else:
            raise ValueError(
                f"Unsupported report format '{format}'. Supported formats: 'json', 'markdown', 'html', 'pdf'"
            )

    def export(
        self,
        model: ReportModel,
        output_path: str | Path,
        format: str | None = None,
    ) -> Path:
        """Render and save report to disk at output_path.

        If format is omitted, it is inferred from the output file extension.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Infer format from extension if not given
        if format is None:
            ext = path.suffix.lower().lstrip(".")
            if ext in ("json", "md", "markdown", "html", "htm", "pdf"):
                fmt = ext
            else:
                raise ValueError(
                    f"Cannot infer report format from file extension '{path.suffix}'. "
                    "Please specify format explicitly ('json', 'markdown', 'html', 'pdf')."
                )
        else:
            fmt = format

        rendered = self.render(model, format=fmt)

        if isinstance(rendered, bytes):
            path.write_bytes(rendered)
        else:
            path.write_text(rendered, encoding="utf-8")

        # Enforce secure file permissions per Section 33 requirement #11
        try:
            import os
            os.chmod(path, 0o640)
        except OSError:
            pass

        return path
