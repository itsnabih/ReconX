"""Confidence scoring engine for ReconX findings.

Computes multi-source corroborative confidence scores (0.0 to 1.0) based on:
- Source tool reliability and detection methodology
- Verification status and technical evidence presence
- Multi-tool independent corroboration
- Intra-tool repeated observation reinforcement
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from reconx.models.evidence import Evidence
from reconx.models.observation import Observation


# Baseline tool reliability weights (0.0 to 1.0)
DEFAULT_TOOL_WEIGHTS: dict[str, float] = {
    # Active parameter testing and exploitation verification engines
    "sqlmap": 0.85,
    # Direct cryptographic and transport layer inspection
    "openssl": 0.80,
    # Direct active HTTP client with precise header/body inspection
    "curl": 0.75,
    "wget": 0.70,
    # Active port scanning and service banner probe
    "nmap": 0.75,
    # High-performance directory brute-force with response validation
    "gobuster": 0.70,
    "ffuf": 0.70,
    "dirb": 0.65,
    # Broad signature-based heuristic web vulnerability scanner
    "nikto": 0.50,
    # Network host discovery
    "ping": 0.60,
    # Passive DNS resolvers
    "dig": 0.60,
    "host": 0.60,
    "nslookup": 0.55,
    "whois": 0.55,
}

_DEFAULT_GENERIC_WEIGHT = 0.45


@dataclass(frozen=True)
class ConfidenceAssessment:
    """Detailed result of confidence evaluation for a cluster of observations."""

    score: float
    confidence_level: str  # "LOW", "MODERATE", "HIGH", "CONFIRMED"
    rationale: str
    sources: tuple[str, ...]
    observation_count: int
    independent_tool_count: int


class ConfidenceScorer:
    """Computes corroborative confidence scores for findings."""

    def __init__(self, tool_weights: dict[str, float] | None = None) -> None:
        self._tool_weights = dict(tool_weights or DEFAULT_TOOL_WEIGHTS)

    def get_tool_weight(self, tool_name: str) -> float:
        """Get the base reliability weight for a tool."""
        return self._tool_weights.get(tool_name.lower(), _DEFAULT_GENERIC_WEIGHT)

    def score_single(
        self,
        observation: Observation,
        evidence: Sequence[Evidence] = (),
    ) -> float:
        """Calculate confidence score for a single observation."""
        tool = (observation.source or "").lower()
        base = self.get_tool_weight(tool)

        data = observation.data or {}
        modifiers = 0.0

        # Modifiers based on observation attributes
        if data.get("parameter"):
            modifiers += 0.05
        if data.get("injection_type"):
            modifiers += 0.05
        if data.get("cve"):
            modifiers += 0.03

        # Active vs safe vs passive mode
        mode = data.get("execution_mode")
        if mode == "active":
            modifiers += 0.04
        elif mode == "passive":
            modifiers -= 0.05

        # Check supporting evidence if linked
        matching_evidence = [
            e for e in evidence
            if (observation.task_id and e.task_id == observation.task_id) or (e.tool.lower() == tool)
        ]
        for ev in matching_evidence:
            if ev.exit_code == 0 and not ev.timed_out:
                modifiers += 0.03
                break

        score = max(0.10, min(0.95, base + modifiers))
        return round(score, 2)

    def evaluate(
        self,
        observations: Sequence[Observation],
        evidence: Sequence[Evidence] = (),
    ) -> ConfidenceAssessment:
        """Evaluate corroborative confidence score for multiple observations."""
        if not observations:
            return ConfidenceAssessment(
                score=0.10,
                confidence_level="LOW",
                rationale="No supporting observations provided.",
                sources=(),
                observation_count=0,
                independent_tool_count=0,
            )

        # Map scores per observation and group by tool
        tool_obs_map: dict[str, list[tuple[Observation, float]]] = {}
        for obs in observations:
            tool = (obs.source or "unknown").lower()
            score = self.score_single(obs, evidence)
            tool_obs_map.setdefault(tool, []).append((obs, score))

        distinct_tools = tuple(sorted(tool_obs_map.keys()))
        independent_tool_count = len(distinct_tools)
        observation_count = len(observations)

        # Calculate best score per distinct tool
        tool_best_scores: dict[str, float] = {}
        for tool, scored_list in tool_obs_map.items():
            best = max(s for _, s in scored_list)
            # Small intra-tool reinforcement for multiple observations from the same tool
            intra_count = len(scored_list)
            if intra_count > 1:
                boost = min(0.06, (intra_count - 1) * 0.03)
                best = min(0.95, best + boost)
            tool_best_scores[tool] = best

        # Multi-tool corroboration combining independent failure rates (1 - c_i)
        if independent_tool_count == 1:
            combined_score = list(tool_best_scores.values())[0]
        else:
            # Independent corroboration: P(true) = 1 - Prod(1 - c_tool)
            prob_all_false = 1.0
            for tool_score in tool_best_scores.values():
                prob_all_false *= (1.0 - tool_score)
            combined_score = 1.0 - prob_all_false

        # Clamp and round
        final_score = round(max(0.10, min(0.99, combined_score)), 2)

        # Determine confidence level string
        if final_score >= 0.90:
            confidence_level = "CONFIRMED"
        elif final_score >= 0.70:
            confidence_level = "HIGH"
        elif final_score >= 0.45:
            confidence_level = "MODERATE"
        else:
            confidence_level = "LOW"

        # Build informative rationale
        rationale_parts: list[str] = []
        if independent_tool_count > 1:
            tool_contributions = ", ".join(f"{t}: {tool_best_scores[t]:.2f}" for t in distinct_tools)
            rationale_parts.append(
                f"Multi-tool corroboration across {independent_tool_count} independent tools ({tool_contributions}) "
                f"elevated confidence to {final_score:.2f}."
            )
        else:
            single_tool = distinct_tools[0]
            rationale_parts.append(
                f"Single-source detection by {single_tool} (base score: {tool_best_scores[single_tool]:.2f})."
            )

        if observation_count > independent_tool_count:
            rationale_parts.append(
                f"Supported by {observation_count} total observations."
            )

        rationale = " ".join(rationale_parts)

        return ConfidenceAssessment(
            score=final_score,
            confidence_level=confidence_level,
            rationale=rationale,
            sources=distinct_tools,
            observation_count=observation_count,
            independent_tool_count=independent_tool_count,
        )
