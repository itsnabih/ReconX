"""ReconX finding intelligence and correlation engine package."""

from reconx.engine.classification import (
    ClassificationResult,
    VulnerabilityCategory,
    VulnerabilityClassifier,
)
from reconx.engine.confidence import (
    DEFAULT_TOOL_WEIGHTS,
    ConfidenceAssessment,
    ConfidenceScorer,
)
from reconx.engine.correlation import (
    CorrelationResult,
    FindingCorrelator,
)
from reconx.engine.deduplication import (
    DeduplicationFingerprint,
    VulnerabilityDeduplicator,
    extract_url_path,
    normalize_parameter,
    normalize_url,
)
from reconx.engine.discovery import (
    DiscoveredEndpointSummary,
    DiscoveredServiceSummary,
    DiscoveryEngine,
    DiscoveryInventory,
)

__all__ = [
    "ClassificationResult",
    "ConfidenceAssessment",
    "ConfidenceScorer",
    "CorrelationResult",
    "DEFAULT_TOOL_WEIGHTS",
    "DeduplicationFingerprint",
    "DiscoveredEndpointSummary",
    "DiscoveredServiceSummary",
    "DiscoveryEngine",
    "DiscoveryInventory",
    "FindingCorrelator",
    "VulnerabilityCategory",
    "VulnerabilityClassifier",
    "VulnerabilityDeduplicator",
    "extract_url_path",
    "normalize_parameter",
    "normalize_url",
]
