"""JSON report renderer for ReconX.

Produces canonical machine-readable JSON security report per Implementation.md Section 26.
"""

from __future__ import annotations

import json

from reconx.reporting.model import ReportModel


class JSONReportRenderer:
    """Renders a ReportModel into formatted JSON."""

    def render(self, model: ReportModel, indent: int = 2) -> str:
        """Render ReportModel as an indented JSON string."""
        return json.dumps(model.to_dict(), indent=indent, ensure_ascii=False)
