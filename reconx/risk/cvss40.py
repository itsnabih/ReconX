"""CVSS v4.0 Base Score Calculator and Vector Generator.

Complies with the FIRST.org Common Vulnerability Scoring System v4.0 specification:
https://www.first.org/cvss/v4.0/specification-document
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
import math
from typing import Any

from reconx.models.finding import Severity


# Numerical levels for metric distance evaluation
AV_LEVELS = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
PR_LEVELS = {"N": 0.0, "L": 0.1, "H": 0.2}
UI_LEVELS = {"N": 0.0, "P": 0.1, "A": 0.2}

AC_LEVELS = {"L": 0.0, "H": 0.1}
AT_LEVELS = {"N": 0.0, "P": 0.1}

VC_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
VI_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
VA_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}

SC_LEVELS = {"H": 0.1, "L": 0.2, "N": 0.3}
SI_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
SA_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}

CR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
IR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
AR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}

EPSILON = 1e-6

_VALID_METRICS = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "AT": {"N", "P"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "P", "A"},
    "VC": {"H", "L", "N"},
    "VI": {"H", "L", "N"},
    "VA": {"H", "L", "N"},
    "SC": {"H", "L", "N"},
    "SI": {"S", "H", "L", "N"},
    "SA": {"S", "H", "L", "N"},
}

MAX_SEVERITY: dict[str, Any] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {
        0: {0: 7, 1: 6},
        1: {0: 8, 1: 8},
        2: {1: 10},
    },
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

MAX_COMPOSED: dict[str, dict[str, Any]] = {
    "eq1": {
        "0": ["AV:N/PR:N/UI:N/"],
        "1": ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        "2": ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        "0": ["AC:L/AT:N/"],
        "1": ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq3": {
        "0": {
            "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            "1": [
                "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
                "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
            ],
        },
        "1": {
            "0": [
                "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
                "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
            ],
            "1": [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        "2": {
            "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
        },
    },
    "eq4": {
        "0": ["SC:H/SI:S/SA:S/"],
        "1": ["SC:H/SI:H/SA:H/"],
        "2": ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        "0": ["E:A/"],
        "1": ["E:P/"],
        "2": ["E:U/"],
    },
}

CVSS_LOOKUP_GLOBAL: dict[str, float] = {
    "000000": 10,
    "000001": 9.9,
    "000010": 9.8,
    "000011": 9.5,
    "000020": 9.5,
    "000021": 9.2,
    "000100": 10,
    "000101": 9.6,
    "000110": 9.3,
    "000111": 8.7,
    "000120": 9.1,
    "000121": 8.1,
    "000200": 9.3,
    "000201": 9,
    "000210": 8.9,
    "000211": 8,
    "000220": 8.1,
    "000221": 6.8,
    "001000": 9.8,
    "001001": 9.5,
    "001010": 9.5,
    "001011": 9.2,
    "001020": 9,
    "001021": 8.4,
    "001100": 9.3,
    "001101": 9.2,
    "001110": 8.9,
    "001111": 8.1,
    "001120": 8.1,
    "001121": 6.5,
    "001200": 8.8,
    "001201": 8,
    "001210": 7.8,
    "001211": 7,
    "001220": 6.9,
    "001221": 4.8,
    "002001": 9.2,
    "002011": 8.2,
    "002021": 7.2,
    "002101": 7.9,
    "002111": 6.9,
    "002121": 5,
    "002201": 6.9,
    "002211": 5.5,
    "002221": 2.7,
    "010000": 9.9,
    "010001": 9.7,
    "010010": 9.5,
    "010011": 9.2,
    "010020": 9.2,
    "010021": 8.5,
    "010100": 9.5,
    "010101": 9.1,
    "010110": 9,
    "010111": 8.3,
    "010120": 8.4,
    "010121": 7.1,
    "010200": 9.2,
    "010201": 8.1,
    "010210": 8.2,
    "010211": 7.1,
    "010220": 7.2,
    "010221": 5.3,
    "011000": 9.5,
    "011001": 9.3,
    "011010": 9.2,
    "011011": 8.5,
    "011020": 8.5,
    "011021": 7.3,
    "011100": 9.2,
    "011101": 8.2,
    "011110": 8,
    "011111": 7.2,
    "011120": 7,
    "011121": 5.9,
    "011200": 8.4,
    "011201": 7,
    "011210": 7.1,
    "011211": 5.2,
    "011220": 5,
    "011221": 3,
    "012001": 8.6,
    "012011": 7.5,
    "012021": 5.2,
    "012101": 7.1,
    "012111": 5.2,
    "012121": 2.9,
    "012201": 6.3,
    "012211": 2.9,
    "012221": 1.7,
    "100000": 9.8,
    "100001": 9.5,
    "100010": 9.4,
    "100011": 8.7,
    "100020": 9.1,
    "100021": 8.1,
    "100100": 9.4,
    "100101": 8.9,
    "100110": 8.6,
    "100111": 7.4,
    "100120": 7.7,
    "100121": 6.4,
    "100200": 8.7,
    "100201": 7.5,
    "100210": 7.4,
    "100211": 6.3,
    "100220": 6.3,
    "100221": 4.9,
    "101000": 9.4,
    "101001": 8.9,
    "101010": 8.8,
    "101011": 7.7,
    "101020": 7.6,
    "101021": 6.7,
    "101100": 8.6,
    "101101": 7.6,
    "101110": 7.4,
    "101111": 5.8,
    "101120": 5.9,
    "101121": 5,
    "101200": 7.2,
    "101201": 5.7,
    "101210": 5.7,
    "101211": 5.2,
    "101220": 5.2,
    "101221": 2.5,
    "102001": 8.3,
    "102011": 7,
    "102021": 5.4,
    "102101": 6.5,
    "102111": 5.8,
    "102121": 2.6,
    "102201": 5.3,
    "102211": 2.1,
    "102221": 1.3,
    "110000": 9.5,
    "110001": 9,
    "110010": 8.8,
    "110011": 7.6,
    "110020": 7.6,
    "110021": 7,
    "110100": 9,
    "110101": 7.7,
    "110110": 7.5,
    "110111": 6.2,
    "110120": 6.1,
    "110121": 5.3,
    "110200": 7.7,
    "110201": 6.6,
    "110210": 6.8,
    "110211": 5.9,
    "110220": 5.2,
    "110221": 3,
    "111000": 8.9,
    "111001": 7.8,
    "111010": 7.6,
    "111011": 6.7,
    "111020": 6.2,
    "111021": 5.8,
    "111100": 7.4,
    "111101": 5.9,
    "111110": 5.7,
    "111111": 5.7,
    "111120": 4.7,
    "111121": 2.3,
    "111200": 6.1,
    "111201": 5.2,
    "111210": 5.7,
    "111211": 2.9,
    "111220": 2.4,
    "111221": 1.6,
    "112001": 7.1,
    "112011": 5.9,
    "112021": 3,
    "112101": 5.8,
    "112111": 2.6,
    "112121": 1.5,
    "112201": 2.3,
    "112211": 1.3,
    "112221": 0.6,
    "200000": 9.3,
    "200001": 8.7,
    "200010": 8.6,
    "200011": 7.2,
    "200020": 7.5,
    "200021": 5.8,
    "200100": 8.6,
    "200101": 7.4,
    "200110": 7.4,
    "200111": 6.1,
    "200120": 5.6,
    "200121": 3.4,
    "200200": 7,
    "200201": 5.4,
    "200210": 5.2,
    "200211": 4,
    "200220": 4,
    "200221": 2.2,
    "201000": 8.5,
    "201001": 7.5,
    "201010": 7.4,
    "201011": 5.5,
    "201020": 6.2,
    "201021": 5.1,
    "201100": 7.2,
    "201101": 5.7,
    "201110": 5.5,
    "201111": 4.1,
    "201120": 4.6,
    "201121": 1.9,
    "201200": 5.3,
    "201201": 3.6,
    "201210": 3.4,
    "201211": 1.9,
    "201220": 1.9,
    "201221": 0.8,
    "202001": 6.4,
    "202011": 5.1,
    "202021": 2,
    "202101": 4.7,
    "202111": 2.1,
    "202121": 1.1,
    "202201": 2.4,
    "202211": 0.9,
    "202221": 0.4,
    "210000": 8.8,
    "210001": 7.5,
    "210010": 7.3,
    "210011": 5.3,
    "210020": 6,
    "210021": 5,
    "210100": 7.3,
    "210101": 5.5,
    "210110": 5.9,
    "210111": 4,
    "210120": 4.1,
    "210121": 2,
    "210200": 5.4,
    "210201": 4.3,
    "210210": 4.5,
    "210211": 2.2,
    "210220": 2,
    "210221": 1.1,
    "211000": 7.5,
    "211001": 5.5,
    "211010": 5.8,
    "211011": 4.5,
    "211020": 4,
    "211021": 2.1,
    "211100": 6.1,
    "211101": 5.1,
    "211110": 4.8,
    "211111": 1.8,
    "211120": 2,
    "211121": 0.9,
    "211200": 4.6,
    "211201": 1.8,
    "211210": 1.7,
    "211211": 0.7,
    "211220": 0.8,
    "211221": 0.2,
    "212001": 5.3,
    "212011": 2.4,
    "212021": 1.4,
    "212101": 2.4,
    "212111": 1.2,
    "212121": 0.5,
    "212201": 1,
    "212211": 0.3,
    "212221": 0.1,
}


def final_rounding(x: float) -> float:
    """Round to one decimal place using round-half-up with float epsilon tolerance."""
    return float(Decimal(str(x + EPSILON)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def score_to_severity(score: float) -> Severity:
    """Map CVSS 4.0 base score (0.0 to 10.0) to standard Severity."""
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
class CVSS40Metrics:
    """Container for CVSS 4.0 Base Metrics."""

    attack_vector: str  # N, A, L, P
    attack_complexity: str  # L, H
    attack_requirements: str  # N, P
    privileges_required: str  # N, L, H
    user_interaction: str  # N, P, A
    vuln_confidentiality: str  # H, L, N
    vuln_integrity: str  # H, L, N
    vuln_availability: str  # H, L, N
    sub_confidentiality: str  # H, L, N
    sub_integrity: str  # S, H, L, N
    sub_availability: str  # S, H, L, N

    def __post_init__(self) -> None:
        metrics = {
            "AV": self.attack_vector.upper(),
            "AC": self.attack_complexity.upper(),
            "AT": self.attack_requirements.upper(),
            "PR": self.privileges_required.upper(),
            "UI": self.user_interaction.upper(),
            "VC": self.vuln_confidentiality.upper(),
            "VI": self.vuln_integrity.upper(),
            "VA": self.vuln_availability.upper(),
            "SC": self.sub_confidentiality.upper(),
            "SI": self.sub_integrity.upper(),
            "SA": self.sub_availability.upper(),
        }
        for metric_name, valid_values in _VALID_METRICS.items():
            val = metrics[metric_name]
            if val not in valid_values:
                raise ValueError(
                    f"Invalid CVSS 4.0 value '{val}' for {metric_name}. "
                    f"Must be one of: {sorted(valid_values)}"
                )
        object.__setattr__(self, "attack_vector", metrics["AV"])
        object.__setattr__(self, "attack_complexity", metrics["AC"])
        object.__setattr__(self, "attack_requirements", metrics["AT"])
        object.__setattr__(self, "privileges_required", metrics["PR"])
        object.__setattr__(self, "user_interaction", metrics["UI"])
        object.__setattr__(self, "vuln_confidentiality", metrics["VC"])
        object.__setattr__(self, "vuln_integrity", metrics["VI"])
        object.__setattr__(self, "vuln_availability", metrics["VA"])
        object.__setattr__(self, "sub_confidentiality", metrics["SC"])
        object.__setattr__(self, "sub_integrity", metrics["SI"])
        object.__setattr__(self, "sub_availability", metrics["SA"])

    def to_vector(self) -> str:
        """Render metrics as canonical CVSS 4.0 vector string."""
        return (
            f"CVSS:4.0/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"AT:{self.attack_requirements}/PR:{self.privileges_required}/"
            f"UI:{self.user_interaction}/VC:{self.vuln_confidentiality}/"
            f"VI:{self.vuln_integrity}/VA:{self.vuln_availability}/"
            f"SC:{self.sub_confidentiality}/SI:{self.sub_integrity}/"
            f"SA:{self.sub_availability}"
        )


class CVSS40Calculator:
    """Calculates CVSS 4.0 Base Scores according to FIRST.org specification."""

    def macro_vector(self, m: CVSS40Metrics) -> str:
        """Derive the 6-character MacroVector string."""
        # EQ1: Exploitability (AV, PR, UI)
        if m.attack_vector == "N" and m.privileges_required == "N" and m.user_interaction == "N":
            eq1 = "0"
        elif (
            (m.attack_vector == "N" or m.privileges_required == "N" or m.user_interaction == "N")
            and not (m.attack_vector == "N" and m.privileges_required == "N" and m.user_interaction == "N")
            and m.attack_vector != "P"
        ):
            eq1 = "1"
        else:
            eq1 = "2"

        # EQ2: Complexity (AC, AT)
        if m.attack_complexity == "L" and m.attack_requirements == "N":
            eq2 = "0"
        else:
            eq2 = "1"

        # EQ3: Vulnerable System Impact (VC, VI, VA)
        if m.vuln_confidentiality == "H" and m.vuln_integrity == "H":
            eq3 = "0"
        elif (
            m.vuln_confidentiality == "H"
            or m.vuln_integrity == "H"
            or m.vuln_availability == "H"
        ):
            eq3 = "1"
        else:
            eq3 = "2"

        # EQ4: Subsequent System Impact (SC, SI, SA)
        if m.sub_integrity == "S" or m.sub_availability == "S":
            eq4 = "0"
        elif m.sub_confidentiality == "H" or m.sub_integrity == "H" or m.sub_availability == "H":
            eq4 = "1"
        else:
            eq4 = "2"

        # EQ5: Exploit maturity (for Base score default is Attacked/A)
        eq5 = "0"

        # EQ6: Impact / Requirements context (default CR:H, IR:H, AR:H)
        if (
            m.vuln_confidentiality == "H"
            or m.vuln_integrity == "H"
            or m.vuln_availability == "H"
        ):
            eq6 = "0"
        else:
            eq6 = "1"

        return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"

    def calculate(self, metrics: CVSS40Metrics) -> float:
        """Compute CVSS 4.0 Base Score."""
        # Shortcut: If no impact on vulnerable or subsequent systems
        if all(
            v == "N"
            for v in [
                metrics.vuln_confidentiality,
                metrics.vuln_integrity,
                metrics.vuln_availability,
                metrics.sub_confidentiality,
                metrics.sub_integrity,
                metrics.sub_availability,
            ]
        ):
            return 0.0

        macro = self.macro_vector(metrics)
        value = CVSS_LOOKUP_GLOBAL.get(macro, 0.0)

        eq1_val = int(macro[0])
        eq2_val = int(macro[1])
        eq3_val = int(macro[2])
        eq4_val = int(macro[3])
        eq5_val = int(macro[4])
        eq6_val = int(macro[5])

        eq1_next_lower = f"{eq1_val + 1}{eq2_val}{eq3_val}{eq4_val}{eq5_val}{eq6_val}"
        eq2_next_lower = f"{eq1_val}{eq2_val + 1}{eq3_val}{eq4_val}{eq5_val}{eq6_val}"

        if eq3_val == 1 and eq6_val == 1:
            eq3eq6_next_lower = f"{eq1_val}{eq2_val}{eq3_val + 1}{eq4_val}{eq5_val}{eq6_val}"
        elif eq3_val == 0 and eq6_val == 1:
            eq3eq6_next_lower = f"{eq1_val}{eq2_val}{eq3_val + 1}{eq4_val}{eq5_val}{eq6_val}"
        elif eq3_val == 1 and eq6_val == 0:
            eq3eq6_next_lower = f"{eq1_val}{eq2_val}{eq3_val}{eq4_val}{eq5_val}{eq6_val + 1}"
        elif eq3_val == 0 and eq6_val == 0:
            eq3eq6_left = f"{eq1_val}{eq2_val}{eq3_val}{eq4_val}{eq5_val}{eq6_val + 1}"
            eq3eq6_right = f"{eq1_val}{eq2_val}{eq3_val + 1}{eq4_val}{eq5_val}{eq6_val}"
            score_left = CVSS_LOOKUP_GLOBAL.get(eq3eq6_left, float("nan"))
            score_right = CVSS_LOOKUP_GLOBAL.get(eq3eq6_right, float("nan"))
            score_eq3eq6_next = max(score_left, score_right)
            eq3eq6_next_lower = None
        else:
            eq3eq6_next_lower = f"{eq1_val}{eq2_val}{eq3_val + 1}{eq4_val}{eq5_val}{eq6_val + 1}"

        score_eq1_next = CVSS_LOOKUP_GLOBAL.get(eq1_next_lower, float("nan"))
        score_eq2_next = CVSS_LOOKUP_GLOBAL.get(eq2_next_lower, float("nan"))
        if eq3_val != 0 or eq6_val != 0:
            score_eq3eq6_next = CVSS_LOOKUP_GLOBAL.get(eq3eq6_next_lower, float("nan"))

        eq4_next_lower = f"{eq1_val}{eq2_val}{eq3_val}{eq4_val + 1}{eq5_val}{eq6_val}"
        eq5_next_lower = f"{eq1_val}{eq2_val}{eq3_val}{eq4_val}{eq5_val + 1}{eq6_val}"
        score_eq4_next = CVSS_LOOKUP_GLOBAL.get(eq4_next_lower, float("nan"))
        score_eq5_next = CVSS_LOOKUP_GLOBAL.get(eq5_next_lower, float("nan"))

        # Find max vector severity distances
        eq1_maxes = MAX_COMPOSED["eq1"][str(macro[0])]
        eq2_maxes = MAX_COMPOSED["eq2"][str(macro[1])]
        eq3_eq6_maxes = MAX_COMPOSED["eq3"][str(macro[2])][str(macro[5])]
        eq4_maxes = MAX_COMPOSED["eq4"][str(macro[3])]
        eq5_maxes = MAX_COMPOSED["eq5"][str(macro[4])]

        max_vectors: list[str] = []
        for e1 in eq1_maxes:
            for e2 in eq2_maxes:
                for e36 in eq3_eq6_maxes:
                    for e4 in eq4_maxes:
                        for e5 in eq5_maxes:
                            max_vectors.append(e1 + e2 + e36 + e4 + e5)

        def extract_val(metric: str, s: str) -> str:
            idx = s.index(metric) + len(metric) + 1
            extracted = s[idx:]
            return extracted[: extracted.index("/")] if "/" in extracted else extracted

        severity_distance_AV = 0.0
        severity_distance_PR = 0.0
        severity_distance_UI = 0.0
        severity_distance_AC = 0.0
        severity_distance_AT = 0.0
        severity_distance_VC = 0.0
        severity_distance_VI = 0.0
        severity_distance_VA = 0.0
        severity_distance_SC = 0.0
        severity_distance_SI = 0.0
        severity_distance_SA = 0.0

        for max_vector in max_vectors:
            s_AV = AV_LEVELS[metrics.attack_vector] - AV_LEVELS[extract_val("AV", max_vector)]
            s_PR = PR_LEVELS[metrics.privileges_required] - PR_LEVELS[extract_val("PR", max_vector)]
            s_UI = UI_LEVELS[metrics.user_interaction] - UI_LEVELS[extract_val("UI", max_vector)]
            s_AC = AC_LEVELS[metrics.attack_complexity] - AC_LEVELS[extract_val("AC", max_vector)]
            s_AT = AT_LEVELS[metrics.attack_requirements] - AT_LEVELS[extract_val("AT", max_vector)]
            s_VC = VC_LEVELS[metrics.vuln_confidentiality] - VC_LEVELS[extract_val("VC", max_vector)]
            s_VI = VI_LEVELS[metrics.vuln_integrity] - VI_LEVELS[extract_val("VI", max_vector)]
            s_VA = VA_LEVELS[metrics.vuln_availability] - VA_LEVELS[extract_val("VA", max_vector)]
            s_SC = SC_LEVELS[metrics.sub_confidentiality] - SC_LEVELS[extract_val("SC", max_vector)]
            s_SI = SI_LEVELS[metrics.sub_integrity] - SI_LEVELS[extract_val("SI", max_vector)]
            s_SA = SA_LEVELS[metrics.sub_availability] - SA_LEVELS[extract_val("SA", max_vector)]

            if any(dist < 0 for dist in [s_AV, s_PR, s_UI, s_AC, s_AT, s_VC, s_VI, s_VA, s_SC, s_SI, s_SA]):
                continue

            severity_distance_AV = s_AV
            severity_distance_PR = s_PR
            severity_distance_UI = s_UI
            severity_distance_AC = s_AC
            severity_distance_AT = s_AT
            severity_distance_VC = s_VC
            severity_distance_VI = s_VI
            severity_distance_VA = s_VA
            severity_distance_SC = s_SC
            severity_distance_SI = s_SI
            severity_distance_SA = s_SA
            break

        current_dist_eq1 = severity_distance_AV + severity_distance_PR + severity_distance_UI
        current_dist_eq2 = severity_distance_AC + severity_distance_AT
        current_dist_eq3eq6 = severity_distance_VC + severity_distance_VI + severity_distance_VA
        current_dist_eq4 = severity_distance_SC + severity_distance_SI + severity_distance_SA

        step = 0.1
        avail_dist_eq1 = value - score_eq1_next
        avail_dist_eq2 = value - score_eq2_next
        avail_dist_eq3eq6 = value - score_eq3eq6_next
        avail_dist_eq4 = value - score_eq4_next
        avail_dist_eq5 = value - score_eq5_next

        n_existing = 0
        norm_sev_eq1 = 0.0
        norm_sev_eq2 = 0.0
        norm_sev_eq3eq6 = 0.0
        norm_sev_eq4 = 0.0
        norm_sev_eq5 = 0.0

        max_sev_eq1 = MAX_SEVERITY["eq1"][eq1_val] * step
        max_sev_eq2 = MAX_SEVERITY["eq2"][eq2_val] * step
        max_sev_eq3eq6 = MAX_SEVERITY["eq3eq6"][eq3_val][eq6_val] * step
        max_sev_eq4 = MAX_SEVERITY["eq4"][eq4_val] * step

        if not math.isnan(avail_dist_eq1) and avail_dist_eq1 >= 0:
            n_existing += 1
            norm_sev_eq1 = avail_dist_eq1 * (current_dist_eq1 / max_sev_eq1)

        if not math.isnan(avail_dist_eq2) and avail_dist_eq2 >= 0:
            n_existing += 1
            norm_sev_eq2 = avail_dist_eq2 * (current_dist_eq2 / max_sev_eq2)

        if not math.isnan(avail_dist_eq3eq6) and avail_dist_eq3eq6 >= 0:
            n_existing += 1
            norm_sev_eq3eq6 = avail_dist_eq3eq6 * (current_dist_eq3eq6 / max_sev_eq3eq6)

        if not math.isnan(avail_dist_eq4) and avail_dist_eq4 >= 0:
            n_existing += 1
            norm_sev_eq4 = avail_dist_eq4 * (current_dist_eq4 / max_sev_eq4)

        if not math.isnan(avail_dist_eq5) and avail_dist_eq5 >= 0:
            n_existing += 1
            norm_sev_eq5 = 0.0

        mean_distance = (
            0.0
            if n_existing == 0
            else (norm_sev_eq1 + norm_sev_eq2 + norm_sev_eq3eq6 + norm_sev_eq4 + norm_sev_eq5) / n_existing
        )

        score = value - mean_distance
        return max(0.0, min(10.0, final_rounding(score)))

    def parse_vector(self, vector_str: str) -> CVSS40Metrics:
        """Parse and validate CVSS 4.0 vector string."""
        clean = vector_str.strip()
        if not clean.startswith("CVSS:4.0/"):
            raise ValueError(f"Vector does not start with 'CVSS:4.0/': {clean!r}")

        parts = clean[len("CVSS:4.0/"):].split("/")
        metrics_dict: dict[str, str] = {}
        for part in parts:
            if ":" not in part:
                raise ValueError(f"Malformed metric segment '{part}' in vector '{clean}'")
            k, v = part.split(":", 1)
            metrics_dict[k.upper()] = v.upper()

        required = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
        missing = [r for r in required if r not in metrics_dict]
        if missing:
            raise ValueError(f"Missing required CVSS 4.0 metrics: {missing}")

        return CVSS40Metrics(
            attack_vector=metrics_dict["AV"],
            attack_complexity=metrics_dict["AC"],
            attack_requirements=metrics_dict["AT"],
            privileges_required=metrics_dict["PR"],
            user_interaction=metrics_dict["UI"],
            vuln_confidentiality=metrics_dict["VC"],
            vuln_integrity=metrics_dict["VI"],
            vuln_availability=metrics_dict["VA"],
            sub_confidentiality=metrics_dict["SC"],
            sub_integrity=metrics_dict["SI"],
            sub_availability=metrics_dict["SA"],
        )

    def calculate_from_vector(self, vector_str: str) -> tuple[float, CVSS40Metrics]:
        """Parse vector and calculate CVSS 4.0 base score."""
        metrics = self.parse_vector(vector_str)
        score = self.calculate(metrics)
        return score, metrics
