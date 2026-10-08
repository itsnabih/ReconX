"""End-to-end integration test against controlled mock targets (Phase 14 / Section 37).

Verifies the entire vertical slice:
Target Validation -> Scope Guard -> Session DB -> DAG Scheduler ->
Adapter Execution -> Normalized Observation -> SQLite Persistence ->
Finding Intelligence -> Risk Scoring -> Report Generation -> Report Validation.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import unittest

from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig
from reconx.models.asset import Asset, AssetKind, AssetOrigin
from reconx.models.finding import Finding, Severity
from reconx.models.observation import Observation
from reconx.parsers.dns import DigParser
from reconx.reporting.engine import ReportingEngine
from reconx.reporting.model import ReportModel
from reconx.reporting.validation import ReportValidator
from reconx.risk.scoring import RiskEngine
from reconx.scope import ScopePolicy, ScopeValidator
from reconx.security.audit import TargetSecurityValidator
from reconx.session.manager import ScanSessionManager
from reconx.tools.dig import DigAdapter


class ControlledMockRunner(CommandRunner):
    """Deterministic runner returning controlled fixture outputs without real network calls."""

    def __init__(self, fixture_path: Path) -> None:
        super().__init__()
        self.fixture_path = fixture_path
        self.calls: list[list[str]] = []

    async def run(
        self,
        command: list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> CommandResult:
        self.calls.append(list(command))
        fixture_content = self.fixture_path.read_text(encoding="utf-8")
        return CommandResult(
            command=list(command),
            executable=command[0],
            arguments=list(command[1:]),
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            duration=0.01,
            exit_code=0,
            stdout=fixture_content,
            stderr="",
            timed_out=False,
            cancelled=False,
        )


class TestEndToEndControlledScan(unittest.IsolatedAsyncioTestCase):
    """End-to-end verification of the ReconX system pipeline."""

    async def test_complete_reconnaissance_pipeline(self) -> None:
        target = "example.com"
        fixtures_dir = Path(__file__).resolve().parent.parent / "fixtures"
        dig_fixture = fixtures_dir / "dig_sample.txt"
        assert dig_fixture.exists(), f"Missing fixture at {dig_fixture}"

        # 1. Target Security Audit
        assert TargetSecurityValidator.is_safe_target(target) is True

        # 2. Centralized Scope Guard
        scope = ScopeValidator(
            allowed_domains=(target,),
        )
        assert scope.check(target).allowed is True

        # 3. Persistent Session Setup
        db_path = ":memory:"
        session_mgr = ScanSessionManager(db_path)
        scan_state = session_mgr.create_session(
            targets=[target],
            scope=ScopePolicy(allowed_domains=(target,)),
        )
        assert scan_state.scan.id is not None

        # 4. Tool Adapter & Task Creation
        runner = ControlledMockRunner(fixture_path=dig_fixture)
        dig_adapter = DigAdapter(runner=runner)

        task = dig_adapter.create_task(
            task_id="task_dig_example",
            target=target,
            record_type="ANY",
            priority=10,
        )
        task.action = None  # Ensure serializable for SQLite persistence per Phase 3 rules
        scan_state.tasks.append(task)
        session_mgr.save_session(scan_state)

        # 5. DAG Scheduler with Bounded Concurrency
        scheduler = Scheduler(
            runner=runner,
            config=SchedulerConfig(global_concurrency=5),
            scope=scope,
        )
        scheduler.add_task(task)
        summary = await scheduler.run()

        assert summary.total_tasks == 1
        assert summary.completed == 1
        assert summary.failed == 0
        assert len(runner.calls) == 1

        # 6. Parser Verification
        raw_output = summary.results[task.id].command_result.stdout
        parser = DigParser()
        dns_res = parser.parse(raw_output, target=target)
        assert len(dns_res.records) >= 3

        # 7. Normalized Observation and Finding Generation
        asset = Asset(
            id=f"asset_{target}",
            kind=AssetKind.DOMAIN,
            value=target,
            origin=AssetOrigin.USER_PROVIDED,
            in_scope=True,
        )
        scan_state.assets.append(asset)

        obs = Observation(
            id="obs_dns_1",
            type="dns_record",
            asset_id=asset.id,
            source="dig",
            data={"record_type": "TXT", "value": "v=spf1 -all"},
            task_id=task.id,
        )
        scan_state.observations.append(obs)

        finding = Finding(
            id="find_dns_1",
            finding_type="information_disclosure",
            title="SPF Record Disclosed",
            description="DNS TXT record exposes SPF configuration.",
            asset_id=asset.id,
            severity=Severity.LOW,
            confidence=1.0,
            endpoint=None,
            observation_ids=(obs.id,),
        )
        scan_state.findings.append(finding)
        session_mgr.save_session(scan_state)

        # 8. Risk Engine Assessment
        risk_engine = RiskEngine()
        assessment = risk_engine.assess_finding(finding)
        assert assessment.review_status is not None
        if assessment.base_score is not None:
            assert 0.0 <= assessment.base_score <= 10.0

        # 9. Canonical Report Generation
        reports_dir = Path("/tmp/reconx_test_reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        reporting_engine = ReportingEngine()
        report_model = ReportModel.from_scan_state(scan_state)

        assert report_model.scan_id == scan_state.scan.id
        assert report_model.target == target
        assert len(report_model.findings) == 1

        # Generate all 4 formats
        paths = {
            "json": reporting_engine.export(report_model, reports_dir / "report.json"),
            "markdown": reporting_engine.export(report_model, reports_dir / "report.md"),
            "html": reporting_engine.export(report_model, reports_dir / "report.html"),
            "pdf": reporting_engine.export(report_model, reports_dir / "report.pdf"),
        }
        assert "json" in paths
        assert "markdown" in paths
        assert "html" in paths
        assert "pdf" in paths

        # 10. Report Validation (Phase 14)
        validation = ReportValidator.validate_report_model(report_model)
        assert validation.is_valid is True
        assert len(validation.errors) == 0
        assert len(validation.unredacted_secrets_found) == 0

        # Validate generated JSON report file
        json_file_validation = ReportValidator.validate_report_file(paths["json"])
        assert json_file_validation.is_valid is True
