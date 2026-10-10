#!/usr/bin/env python3
"""
Unit and Integration Test Suite for Amazon Aurora Benchmark Execution Runner
Strictly offline; mocks all external subprocess, kubectl, and cluster boundaries.
Validates:
1. Execution argument validation & collision detection.
2. Fail-closed preflight abort gate.
3. Telemetry startup handshake failure abort gate.
4. Workload failure & partial evidence preservation.
5. Transaction accounting reconciliation mismatch detection.
6. End-to-end successful orchestration lifecycle using mocks.
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import subprocess
from unittest.mock import patch, MagicMock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
AURORA_BENCHMARK_DIR = os.path.join(REPO_ROOT, "benchmark", "scripts", "aurora")
if AURORA_BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, AURORA_BENCHMARK_DIR)

from orchestrate_aurora import AuroraBenchmarkOrchestrator


class TestAuroraExecutionRunner(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.test_dir, "results")
        os.makedirs(self.output_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_execution_argument_validation_and_collision(self):
        """Must fail closed on directory collision and invalid run-id format."""
        orch = AuroraBenchmarkOrchestrator(config={
            "output_dir": self.output_dir,
            "warmup_seconds": 1,
            "measurement_seconds": 1,
            "cooldown_seconds": 1,
        })
        run_id = "test-aurora-r01"
        existing_run_dir = os.path.join(self.output_dir, run_id)
        os.makedirs(existing_run_dir, exist_ok=True)

        with self.assertRaises(FileExistsError) as ctx:
            orch.execute_run(run_id=run_id)
        self.assertIn("already exists", str(ctx.exception))

    @patch.object(AuroraBenchmarkOrchestrator, "run_preflight_audit", return_value=False)
    def test_02_fail_closed_preflight(self, mock_preflight):
        """Must abort execution immediately when preflight audit fails."""
        orch = AuroraBenchmarkOrchestrator(config={
            "output_dir": self.output_dir,
            "warmup_seconds": 1,
            "measurement_seconds": 1,
            "cooldown_seconds": 1,
        })
        run_id = "test-fail-preflight"
        with self.assertRaises(RuntimeError) as ctx:
            orch.execute_run(run_id=run_id)
        self.assertIn("preflight audit failed", str(ctx.exception).lower())
        # Ensure run directory was not created or was left aborted
        run_dir = os.path.join(self.output_dir, run_id)
        self.assertFalse(os.path.exists(os.path.join(run_dir, f"{run_id}-warmup.txt")))

    @patch.object(AuroraBenchmarkOrchestrator, "run_preflight_audit", return_value=True)
    @patch.object(AuroraBenchmarkOrchestrator, "get_database_snapshot")
    @patch.object(AuroraBenchmarkOrchestrator, "_run_kubectl")
    @patch.object(AuroraBenchmarkOrchestrator, "_run_psql")
    def test_03_telemetry_handshake_failure(self, mock_psql, mock_kubectl, mock_snapshot, mock_preflight):
        """Must abort workload launch if telemetry handshake fails or returns error."""
        # S0 snapshot valid
        mock_snapshot.return_value = {
            "phase": "S0_Initial",
            "database": "benchdb",
            "user": "postgres",
            "is_recovery": False,
            "accounts_count": 5000000,
            "accounts_balance": 0,
            "branches_count": 50,
            "branches_balance": 0,
            "tellers_count": 500,
            "tellers_balance": 0,
            "history_count": 0,
            "wal_lsn": "WAL_UNAVAILABLE_WAL_LEVEL_replica",
            "transaction_id": 67000,
            "raw_output": "benchdb,postgres,f,5000000,0,50,0,500,0,0,WAL_UNAVAILABLE_WAL_LEVEL_replica,67000",
        }
        # Warm-up subprocess succeeds
        mock_kubectl.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Telemetry query fails with error
        mock_psql.return_value = MagicMock(returncode=1, stdout="ERROR: connection refused", stderr="server closed")

        orch = AuroraBenchmarkOrchestrator(config={
            "output_dir": self.output_dir,
            "warmup_seconds": 1,
            "measurement_seconds": 1,
            "cooldown_seconds": 1,
        })
        run_id = "test-handshake-failure"

        with patch("subprocess.run") as mock_subproc:
            mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                orch.execute_run(run_id=run_id)
            self.assertIn("Telemetry handshake failed", str(ctx.exception))

        run_dir = os.path.join(self.output_dir, run_id)
        # Verify measurement was NOT executed
        self.assertFalse(os.path.exists(os.path.join(run_dir, f"{run_id}-measurement.txt")))

    @patch.object(AuroraBenchmarkOrchestrator, "run_preflight_audit", return_value=True)
    @patch.object(AuroraBenchmarkOrchestrator, "get_database_snapshot")
    @patch.object(AuroraBenchmarkOrchestrator, "_run_kubectl")
    @patch.object(AuroraBenchmarkOrchestrator, "_run_psql")
    def test_04_workload_failure_and_partial_evidence_preservation(self, mock_psql, mock_kubectl, mock_snapshot, mock_preflight):
        """Must preserve failure metadata and partial logs when pgbench exits non-zero."""
        mock_snapshot.return_value = {
            "phase": "S0_Initial",
            "database": "benchdb",
            "user": "postgres",
            "is_recovery": False,
            "accounts_count": 5000000,
            "accounts_balance": 0,
            "branches_count": 50,
            "branches_balance": 0,
            "tellers_count": 500,
            "tellers_balance": 0,
            "history_count": 0,
            "wal_lsn": "WAL_UNAVAILABLE_WAL_LEVEL_replica",
            "transaction_id": 67000,
            "raw_output": "benchdb,postgres,f,5000000,0,50,0,500,0,0,WAL_UNAVAILABLE_WAL_LEVEL_replica,67000",
        }
        mock_kubectl.return_value = MagicMock(returncode=0, stdout="", stderr="")
        # Telemetry returns OK sample
        mock_psql.return_value = MagicMock(returncode=0, stdout="20,100,0,50,50,10,10,0,0,0,0,0,0,0", stderr="")

        orch = AuroraBenchmarkOrchestrator(config={
            "output_dir": self.output_dir,
            "warmup_seconds": 1,
            "measurement_seconds": 1,
            "cooldown_seconds": 1,
        })
        run_id = "test-workload-fail"

        # Mock subprocess.run: warm-up succeeds (retcode 0), measurement fails (retcode 2)
        def subproc_side_effect(cmd, *args, **kwargs):
            if any("pgbench" in str(c) for c in cmd):
                if "-l" in cmd:
                    return MagicMock(returncode=2, stdout="pgbench error: connection to server was lost", stderr="")
                return MagicMock(returncode=0, stdout="warmup ok", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=subproc_side_effect):
            with self.assertRaises(RuntimeError) as ctx:
                orch.execute_run(run_id=run_id)
            self.assertIn("pgbench measurement failed with exit code 2", str(ctx.exception))

        run_dir = os.path.join(self.output_dir, run_id)
        # Verify partial failure artifact was preserved
        fail_json = os.path.join(run_dir, f"{run_id}-failure.json")
        self.assertTrue(os.path.exists(fail_json), "Failure artifact must be saved")
        with open(fail_json, "r", encoding="utf-8") as f:
            fail_data = json.load(f)
        self.assertEqual(fail_data["status"], "FAILED")
        self.assertIn("pgbench measurement failed", fail_data["error"])

    @patch.object(AuroraBenchmarkOrchestrator, "run_preflight_audit", return_value=True)
    @patch.object(AuroraBenchmarkOrchestrator, "get_database_snapshot")
    @patch.object(AuroraBenchmarkOrchestrator, "_run_kubectl")
    @patch.object(AuroraBenchmarkOrchestrator, "_run_psql")
    def test_05_transaction_reconciliation_mismatch(self, mock_psql, mock_kubectl, mock_snapshot, mock_preflight):
        """Must fail closed when delta_history != committed transactions or balance drifts."""
        # Setup snapshot sequence: S0, S1, S2, S3
        snap_s0 = {
            "phase": "S0_Initial", "database": "benchdb", "user": "postgres", "is_recovery": False,
            "accounts_count": 5000000, "accounts_balance": 0, "branches_count": 50, "branches_balance": 0,
            "tellers_count": 500, "tellers_balance": 0, "history_count": 0,
            "wal_lsn": "WAL_UNAVAILABLE_WAL_LEVEL_replica", "transaction_id": 67000, "raw_output": "",
        }
        snap_s1 = dict(snap_s0, phase="S1_PreMeasurement", history_count=500, transaction_id=67500)
        # S2 has 1500 history rows (delta = 1000)
        snap_s2 = dict(snap_s0, phase="S2_PostMeasurement", history_count=1500, transaction_id=68500)
        snap_s3 = dict(snap_s2, phase="S3_PostRecovery")

        mock_snapshot.side_effect = [snap_s0, snap_s1, snap_s2, snap_s3]
        mock_kubectl.return_value = MagicMock(returncode=0, stdout="", stderr="")
        mock_psql.return_value = MagicMock(returncode=0, stdout="20,100,0,50,50,10,10,0,0,0,0,0,0,0", stderr="")

        orch = AuroraBenchmarkOrchestrator(config={
            "output_dir": self.output_dir,
            "warmup_seconds": 1,
            "measurement_seconds": 1,
            "cooldown_seconds": 1,
        })
        run_id = "test-reconciliation-mismatch"

        # Mock analyze_pgbench_logs returning numeric_records = 995 (mismatch: 1000 != 995)
        mock_parsed = {
            "ok": True,
            "numeric_records": 995,  # 5 lost commits!
            "failed_records": 5,
            "total_retries": 0,
            "retried_records": 0,
            "p50_ms": 12.3,
            "p95_ms": 25.4,
            "p99_ms": 40.1,
            "errors": [],
        }

        with patch.object(AuroraBenchmarkOrchestrator, "_copy_logs_from_pod", return_value={"test.log": "hash123"}), \
             patch("subprocess.run") as mock_subproc, \
             patch("orchestrate_aurora.analyze_pgbench_logs", return_value=mock_parsed):
            mock_subproc.return_value = MagicMock(returncode=0, stdout="number of transactions actually processed: 1000\nlatency average = 15.0 ms\n", stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                orch.execute_run(run_id=run_id)
            self.assertIn("FAIL-CLOSED AUDIT FAILED: delta_history", str(ctx.exception))

        run_dir = os.path.join(self.output_dir, run_id)
        rec_json = os.path.join(run_dir, f"{run_id}-reconciliation.json")
        self.assertTrue(os.path.exists(rec_json), "Reconciliation report must be written even on mismatch")
        with open(rec_json, "r", encoding="utf-8") as f:
            rec_data = json.load(f)
        self.assertEqual(rec_data["reconciliation_verdict"], "FAILED — RECONCILIATION MISMATCH")
        self.assertEqual(rec_data["durability_accounting"]["unaccounted_discrepancy"], 5)

    @patch.object(AuroraBenchmarkOrchestrator, "run_preflight_audit", return_value=True)
    @patch.object(AuroraBenchmarkOrchestrator, "get_database_snapshot")
    @patch.object(AuroraBenchmarkOrchestrator, "_run_kubectl")
    @patch.object(AuroraBenchmarkOrchestrator, "_run_psql")
    def test_06_successful_orchestration_using_mocks(self, mock_psql, mock_kubectl, mock_snapshot, mock_preflight):
        """Must execute complete benchmark lifecycle and output all reports and telemetry."""
        snap_s0 = {
            "phase": "S0_Initial", "database": "benchdb", "user": "postgres", "is_recovery": False,
            "accounts_count": 5000000, "accounts_balance": 0, "branches_count": 50, "branches_balance": 0,
            "tellers_count": 500, "tellers_balance": 0, "history_count": 0,
            "wal_lsn": "WAL_UNAVAILABLE_WAL_LEVEL_replica", "transaction_id": 67000, "raw_output": "",
        }
        snap_s1 = dict(snap_s0, phase="S1_PreMeasurement", history_count=500, transaction_id=67500)
        snap_s2 = dict(snap_s0, phase="S2_PostMeasurement", history_count=2500, transaction_id=69500)
        snap_s3 = dict(snap_s2, phase="S3_PostRecovery")

        mock_snapshot.side_effect = [snap_s0, snap_s1, snap_s2, snap_s3]
        mock_kubectl.return_value = MagicMock(returncode=0, stdout="", stderr="")
        mock_psql.return_value = MagicMock(returncode=0, stdout="20,100,0,50,50,10,10,0,0,0,0,0,0,0", stderr="")

        orch = AuroraBenchmarkOrchestrator(config={
            "output_dir": self.output_dir,
            "warmup_seconds": 1,
            "measurement_seconds": 1,
            "cooldown_seconds": 1,
        })
        run_id = "test-aurora-success"

        mock_parsed = {
            "ok": True,
            "numeric_records": 2000,  # Exact match: 2500 - 500 = 2000
            "failed_records": 0,
            "total_retries": 0,
            "retried_records": 0,
            "p50_ms": 14.125,
            "p95_ms": 28.500,
            "p99_ms": 45.250,
            "errors": [],
        }

        pgbench_stdout = (
            "number of transactions actually processed: 2000\n"
            "number of failed transactions: 0 (0.000%)\n"
            "latency average = 14.500 ms\n"
            "tps = 850.123456 (including connections establishing)\n"
            "tps = 850.567890 (excluding connections establishing)\n"
        )

        with patch.object(AuroraBenchmarkOrchestrator, "_copy_logs_from_pod", return_value={"test.log": "hash123"}), \
             patch("subprocess.run") as mock_subproc, \
             patch("orchestrate_aurora.analyze_pgbench_logs", return_value=mock_parsed):
            mock_subproc.return_value = MagicMock(returncode=0, stdout=pgbench_stdout, stderr="")
            res = orch.execute_run(run_id=run_id)
            self.assertTrue(res)

        run_dir = os.path.join(self.output_dir, run_id)
        # Verify all mandatory evidence files are generated
        self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-warmup.txt")))
        self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-measurement.txt")))
        self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-telemetry.csv")))
        self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-recovery-telemetry.csv")))
        self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-reconciliation.json")))
        self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-phase-timeline.json")))
        self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-summary.json")))
        self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-summary.md")))

        # Check reconciliation content
        with open(os.path.join(run_dir, f"{run_id}-reconciliation.json"), "r", encoding="utf-8") as f:
            rec = json.load(f)
        self.assertEqual(rec["reconciliation_verdict"], "VERIFIED — EXACT MATCH")
        self.assertEqual(rec["durability_accounting"]["delta_history_measurement"], 2000)
        self.assertEqual(rec["durability_accounting"]["parser_numeric_records_committed"], 2000)
        self.assertEqual(rec["durability_accounting"]["unaccounted_discrepancy"], 0)
        self.assertTrue(rec["financial_conservation"]["conservation_verified"])

        # Check summary content
        with open(os.path.join(run_dir, f"{run_id}-summary.json"), "r", encoding="utf-8") as f:
            sum_data = json.load(f)
        self.assertEqual(sum_data["reconciliation_status"], "VERIFIED")
        self.assertEqual(sum_data["committed_transactions"], 2000)
        self.assertEqual(sum_data["p50_ms"], 14.125)
        self.assertEqual(sum_data["p95_ms"], 28.5)
        self.assertEqual(sum_data["p99_ms"], 45.25)


if __name__ == "__main__":
    unittest.main(verbosity=2)
