"""ReconX Risk Engine and CVSS scoring module.

Provides CVSS 3.1 and CVSS 4.0 calculators, deterministic vulnerability
scoring archetypes, and explicit manual review status tracking.
"""

from __future__ import annotations

from reconx.risk.cvss31 import (
    CVSS31Calculator,
    CVSS31Metrics,
    round_up,
    score_to_severity as score_to_severity_31,
)
from reconx.risk.cvss40 import (
    CVSS40Calculator,
    CVSS40Metrics,
    score_to_severity as score_to_severity_40,
)
from reconx.risk.scoring import (
    ReviewStatus,
    RiskAssessment,
    RiskEngine,
)

__all__ = [
    "CVSS31Calculator",
    "CVSS31Metrics",
    "round_up",
    "score_to_severity_31",
    "CVSS40Calculator",
    "CVSS40Metrics",
    "score_to_severity_40",
    "ReviewStatus",
    "RiskAssessment",
    "RiskEngine",
]
