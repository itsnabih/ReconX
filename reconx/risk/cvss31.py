"""CVSS v3.1 Base Score Calculator and Vector Generator.

Complies strictly with the FIRST.org Common Vulnerability Scoring System v3.1 specification:
https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re

from reconx.models.finding import Severity


# Numerical weights for CVSS 3.1 Base Metrics
_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

_VALID_METRICS = {
    "AV": set(_AV_WEIGHTS.keys()),
    "AC": set(_AC_WEIGHTS.keys()),
    "PR": set(_PR_WEIGHTS_UNCHANGED.keys()),
    "UI": set(_UI_WEIGHTS.keys()),
    "S": {"U", "C"},
    "C": set(_CIA_WEIGHTS.keys()),
    "I": set(_CIA_WEIGHTS.keys()),
    "A": set(_CIA_WEIGHTS.keys()),
}

_VECTOR_REGEX = re.compile(
    r"^CVSS:3\.1/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/S:(?P<S>[UC])/C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])$"
)


def round_up(val: float) -> float:
    """Official CVSS v3.1 round_up function (Section 7.4).

    Rounds to the nearest 0.1 with precision tolerance.
    """
    int_input = round(val * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def score_to_severity(score: float) -> Severity:
    """Map CVSS base score (0.0 to 10.0) to standard Severity."""
    if score <= 0.0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


@dataclass(frozen=True)
class CVSS31Metrics:
    """Typed container for CVSS 3.1 Base Metrics."""

    attack_vector: str  # N, A, L, P
    attack_complexity: str  # L, H
    privileges_required: str  # N, L, H
    user_interaction: str  # N, R
    scope: str  # U, C
    confidentiality: str  # N, L, H
    integrity: str  # N, L, H
    availability: str  # N, L, H

    def __post_init__(self) -> None:
        metrics = {
            "AV": self.attack_vector.upper(),
            "AC": self.attack_complexity.upper(),
            "PR": self.privileges_required.upper(),
            "UI": self.user_interaction.upper(),
            "S": self.scope.upper(),
            "C": self.confidentiality.upper(),
            "I": self.integrity.upper(),
            "A": self.availability.upper(),
        }
        for metric_name, valid_values in _VALID_METRICS.items():
            val = metrics[metric_name]
            if val not in valid_values:
                raise ValueError(
                    f"Invalid CVSS 3.1 value '{val}' for {metric_name}. "
                    f"Must be one of: {sorted(valid_values)}"
                )
        # Re-assign normalized uppercase values
        object.__setattr__(self, "attack_vector", metrics["AV"])
        object.__setattr__(self, "attack_complexity", metrics["AC"])
        object.__setattr__(self, "privileges_required", metrics["PR"])
        object.__setattr__(self, "user_interaction", metrics["UI"])
        object.__setattr__(self, "scope", metrics["S"])
        object.__setattr__(self, "confidentiality", metrics["C"])
        object.__setattr__(self, "integrity", metrics["I"])
        object.__setattr__(self, "availability", metrics["A"])

    def to_vector(self) -> str:
        """Render metrics as canonical CVSS 3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/"
            f"I:{self.integrity}/A:{self.availability}"
        )


class CVSS31Calculator:
    """Calculates CVSS 3.1 Base Scores according to FIRST.org specification."""

    def calculate(self, metrics: CVSS31Metrics) -> float:
        """Compute the CVSS 3.1 Base Score from metrics."""
        av = _AV_WEIGHTS[metrics.attack_vector]
        ac = _AC_WEIGHTS[metrics.attack_complexity]
        ui = _UI_WEIGHTS[metrics.user_interaction]

        scope_changed = metrics.scope == "C"
        if scope_changed:
            pr = _PR_WEIGHTS_CHANGED[metrics.privileges_required]
        else:
            pr = _PR_WEIGHTS_UNCHANGED[metrics.privileges_required]

        c = _CIA_WEIGHTS[metrics.confidentiality]
        i = _CIA_WEIGHTS[metrics.integrity]
        a = _CIA_WEIGHTS[metrics.availability]

        # Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # Impact
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Base Score calculation
        if impact <= 0:
            return 0.0

        if scope_changed:
            score = round_up(min(1.08 * (impact + exploitability), 10.0))
        else:
            score = round_up(min(impact + exploitability, 10.0))

        return score

    def parse_vector(self, vector_str: str) -> CVSS31Metrics:
        """Parse and validate a CVSS 3.1 vector string."""
        clean = vector_str.strip()
        match = _VECTOR_REGEX.match(clean)
        if not match:
            # Allow unordered metric segments if prefix is valid
            if not clean.startswith("CVSS:3.1/"):
                raise ValueError(f"Vector does not start with 'CVSS:3.1/': {clean!r}")
            parts = clean[len("CVSS:3.1/"):].split("/")
            metrics_dict: dict[str, str] = {}
            for part in parts:
                if ":" not in part:
                    raise ValueError(f"Malformed metric segment '{part}' in vector '{clean}'")
                k, v = part.split(":", 1)
                metrics_dict[k.upper()] = v.upper()

            missing = set(_VALID_METRICS.keys()) - set(metrics_dict.keys())
            if missing:
                raise ValueError(f"Missing required CVSS 3.1 metrics: {sorted(missing)}")

            return CVSS31Metrics(
                attack_vector=metrics_dict["AV"],
                attack_complexity=metrics_dict["AC"],
                privileges_required=metrics_dict["PR"],
                user_interaction=metrics_dict["UI"],
                scope=metrics_dict["S"],
                confidentiality=metrics_dict["C"],
                integrity=metrics_dict["I"],
                availability=metrics_dict["A"],
            )

        groups = match.groupdict()
        return CVSS31Metrics(
            attack_vector=groups["AV"],
            attack_complexity=groups["AC"],
            privileges_required=groups["PR"],
            user_interaction=groups["UI"],
            scope=groups["S"],
            confidentiality=groups["C"],
            integrity=groups["I"],
            availability=groups["A"],
        )

    def calculate_from_vector(self, vector_str: str) -> tuple[float, CVSS31Metrics]:
        """Parse vector and compute base score."""
        metrics = self.parse_vector(vector_str)
        score = self.calculate(metrics)
        return score, metrics
