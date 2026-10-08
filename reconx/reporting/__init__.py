"""ReconX Reporting Module.

Provides normalized ReportModel and multi-format renderers (JSON, Markdown, HTML, PDF)
with automated secret redaction.
"""

from __future__ import annotations

from reconx.reporting.engine import ReportingEngine
from reconx.reporting.html_renderer import HTMLReportRenderer
from reconx.reporting.json_renderer import JSONReportRenderer
from reconx.reporting.markdown_renderer import MarkdownReportRenderer
from reconx.reporting.model import (
    AttackSurfaceSummary,
    ExecutiveSummary,
    ReportAppendix,
    ReportFinding,
    ReportModel,
)
from reconx.reporting.pdf_renderer import PDFReportRenderer
from reconx.reporting.redaction import SecretRedactor
from reconx.reporting.validation import (
    ReportValidationError,
    ReportValidator,
    ValidationResult,
)

__all__ = [
    "AttackSurfaceSummary",
    "ExecutiveSummary",
    "HTMLReportRenderer",
    "JSONReportRenderer",
    "MarkdownReportRenderer",
    "PDFReportRenderer",
    "ReportAppendix",
    "ReportFinding",
    "ReportModel",
    "ReportValidationError",
    "ReportValidator",
    "ReportingEngine",
    "SecretRedactor",
    "ValidationResult",
]
