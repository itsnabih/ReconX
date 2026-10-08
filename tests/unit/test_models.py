"""Validation of Phase 3 domain models."""

import math
import re
import unittest
from datetime import datetime, timezone

from reconx.models import (
    Asset,
    AssetKind,
    AssetOrigin,
    Evidence,
    Finding,
    Observation,
    Scan,
    ScanStatus,
    Severity,
    new_scan_id,
)
from reconx.scope import ScopePolicy

POLICY = ScopePolicy(allowed_domains=("example.com",))


class TestScan(unittest.TestCase):
    def test_scan_id_format_and_uniqueness(self) -> None:
        moment = datetime(2026, 10, 5, 9, 42, 11, tzinfo=timezone.utc)
        self.assertRegex(new_scan_id(moment), r"^scan-20261005-094211-[0-9a-f]{4}$")
        ids = {new_scan_id(moment) for _ in range(50)}
        self.assertGreater(len(ids), 1)

    def test_defaults(self) -> None:
        scan = Scan(targets=["example.com"], scope=POLICY)
        self.assertEqual(scan.targets, ("example.com",))
        self.assertEqual(scan.status, ScanStatus.PENDING)
        self.assertTrue(re.match(r"^scan-\d{8}-\d{6}-[0-9a-f]{4}$", scan.id))

    def test_rejects_missing_targets(self) -> None:
        for targets in ((), ("",)):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                Scan(targets=targets, scope=POLICY)
        with self.assertRaises(TypeError):
            Scan(targets="example.com", scope=POLICY)

    def test_rejects_invalid_scope(self) -> None:
        with self.assertRaises(ValueError):
            Scan(targets=("example.com",), scope=ScopePolicy())
        with self.assertRaises(ValueError):
            Scan(targets=("example.com",), scope=ScopePolicy(allowed_ips=("10.0.0.5/8",)))

    def test_rejects_unknown_status(self) -> None:
        with self.assertRaises(ValueError):
            Scan(targets=("example.com",), scope=POLICY, status="DONE")

    def test_scope_policy_rejects_bare_string(self) -> None:
        with self.assertRaises(TypeError):
            ScopePolicy(allowed_domains="example.com")


class TestAsset(unittest.TestCase):
    def test_ip_is_normalized(self) -> None:
        asset = Asset(AssetKind.IP, "2001:DB8:0:0::1", AssetOrigin.DISCOVERED, in_scope=False)
        self.assertEqual(asset.value, "2001:db8::1")

    def test_invalid_values_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Asset(AssetKind.IP, "999.1.1.1", AssetOrigin.DISCOVERED, in_scope=False)
        with self.assertRaises(ValueError):
            Asset(AssetKind.DOMAIN, "", AssetOrigin.USER_PROVIDED, in_scope=True)
        with self.assertRaises(ValueError):
            Asset("HOST", "example.com", AssetOrigin.USER_PROVIDED, in_scope=True)


class TestObservationAndEvidence(unittest.TestCase):
    def test_observation_requires_fields(self) -> None:
        with self.assertRaises(ValueError):
            Observation(type="", asset_id="a", source="dig")

    def test_evidence_command_must_be_sequence(self) -> None:
        with self.assertRaises(TypeError):
            Evidence(tool="dig", target="example.com", command="dig example.com")
        self.assertEqual(Evidence(tool="dig", target="x", command=["dig", "x"]).command, ("dig", "x"))

    def test_evidence_requires_tool_and_target(self) -> None:
        with self.assertRaises(ValueError):
            Evidence(tool="", target="example.com")


class TestFinding(unittest.TestCase):
    def make(self, **overrides) -> Finding:
        values = dict(
            finding_type="missing_header", title="Missing CSP", asset_id="a",
            severity=Severity.LOW, confidence=0.9,
        )
        values.update(overrides)
        return Finding(**values)

    def test_confidence_is_independent_of_severity(self) -> None:
        finding = self.make(severity="CRITICAL", confidence=0.2)
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.confidence, 0.2)

    def test_confidence_bounds(self) -> None:
        for value in (-0.01, 1.01, math.nan, math.inf):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.make(confidence=value)

    def test_duplicate_links_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.make(evidence_ids=("e1", "e1"))

    def test_unknown_severity_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.make(severity="SEVERE")


if __name__ == "__main__":
    unittest.main()
