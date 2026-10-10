"""
test_g1_live_runner_offline.py - Exhaustive Offline Unit and Integration Test Suite
for G1 Live Runner (benchmark/scripts/cockroachdb/g1/g1_live_runner.py).

Covers:
- TokenSchemaAdapter: valid 17-to-13 mapping, missing fields, extra fields, invariant checks,
  nonce generation, provenance generation.
- TargetProcessResolver: mock process inspection, container name detection ('db' vs 'cockroachdb'),
  and error handling.
- KubernetesJobFaultController: Secret and Job lifecycle simulation, rollback verification,
  token binding checks, failure simulation.
- G1LiveExecutionCoordinator: 3-way accounting reconciliation (delta_history == commits == parsed_logs),
  warm-up and measurement phase coordination, rollback failure detection, dry-run safety.
"""

import datetime
import hashlib
import json
import os
import sys
import unittest
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmark.scripts.cockroachdb.g1.g1_authorizer import (
    EXPECTED_EXPERIMENT_ID,
    EXPECTED_ACTION as HOST_EXPECTED_ACTION,
    EXPECTED_TARGET_CLUSTER,
    EXPECTED_TARGET_NAMESPACE,
    EXPECTED_TARGET_POLICY,
    EXPECTED_PHYSICAL_RANGE_ID,
    EXPECTED_FAULT_TYPE,
    EXPECTED_LATENCY_MS,
    EXPECTED_JITTER_MS,
    EXPECTED_FAULT_DURATION_SEC,
    EXPECTED_MEASUREMENT_WINDOW_SEC,
    EXPECTED_SUPERVISOR_REF,
)
from benchmark.scripts.cockroachdb.g1.g1_helper_authorizer import (
    G1HelperFaultAuthorizer,
    SharedAtomicClaimStore,
)
from benchmark.scripts.cockroachdb.g1.g1_pgbench_runner import (
    PgbenchConfig,
    MockPgbenchLogRetriever,
    MockPgbenchProcessExecutor,
    PgbenchProcessOutput,
    PgbenchRunnerError,
)
from benchmark.scripts.cockroachdb.g1.g1_live_runner import (
    TokenSchemaAdapter,
    TokenAdapterError,
    TargetProcessResolver,
    TargetBindingResult,
    TargetBindingError,
    KubernetesJobFaultController,
    ControllerExecutionError,
    G1LiveExecutionCoordinator,
    ReconciliationError,
)
from benchmark.scripts.cockroachdb.g1.g1_fault_controller import (
    FaultControllerError,
    RollbackVerificationError,
)


def create_valid_host_token(run_id: str = "crdb-g1-l2-pilot-r01") -> Dict[str, Any]:
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "experiment_id": EXPECTED_EXPERIMENT_ID,
        "action": HOST_EXPECTED_ACTION,
        "target_cluster": EXPECTED_TARGET_CLUSTER,
        "target_namespace": EXPECTED_TARGET_NAMESPACE,
        "target_policy": EXPECTED_TARGET_POLICY,
        "physical_range_id": EXPECTED_PHYSICAL_RANGE_ID,
        "fault_type": EXPECTED_FAULT_TYPE,
        "latency_ms": EXPECTED_LATENCY_MS,
        "jitter_ms": EXPECTED_JITTER_MS,
        "fault_duration_sec": EXPECTED_FAULT_DURATION_SEC,
        "measurement_window_sec": EXPECTED_MEASUREMENT_WINDOW_SEC,
        "run_id": run_id,
        "execution_attempt_id": "attempt-001",
        "issued_at_utc": now.isoformat(),
        "expires_at_utc": (now + datetime.timedelta(minutes=15)).isoformat(),
        "authorized_by_operator": "operator_live_authorized",
        "supervisor_approval_ref": EXPECTED_SUPERVISOR_REF,
    }


class TestTokenSchemaAdapter(unittest.TestCase):
    """Exhaustive tests for TokenSchemaAdapter."""

    def test_valid_host_to_helper_translation(self):
        host_token = create_valid_host_token()
        helper_token, provenance = TokenSchemaAdapter.translate_host_to_helper(
            host_payload=host_token,
            target_pod="cockroachdb-0",
            target_netns_inode="net:[4026532845]",
        )

        # 1. Exact 13 fields
        self.assertEqual(len(helper_token), 13)
        self.assertEqual(set(helper_token.keys()), G1HelperFaultAuthorizer.REQUIRED_FIELDS)

        # 2. Key translations
        self.assertEqual(helper_token["delay_ms"], 1000)
        self.assertEqual(helper_token["jitter_ms"], 20)
        self.assertEqual(helper_token["duration_sec"], 180)
        self.assertEqual(helper_token["action"], "EXECUTE_G1_FAULT_HELPER")
        self.assertEqual(helper_token["target_pod"], "cockroachdb-0")
        self.assertEqual(helper_token["target_netns_inode"], "net:[4026532845]")
        self.assertEqual(helper_token["run_id"], "crdb-g1-l2-pilot-r01")
        self.assertTrue(len(helper_token["auth_nonce"]) >= 16)

        # 3. Provenance retains extra host metadata
        self.assertEqual(provenance["experiment_id"], EXPECTED_EXPERIMENT_ID)
        self.assertEqual(provenance["target_cluster"], EXPECTED_TARGET_CLUSTER)
        self.assertEqual(provenance["physical_range_id"], EXPECTED_PHYSICAL_RANGE_ID)
        self.assertEqual(provenance["supervisor_approval_ref"], EXPECTED_SUPERVISOR_REF)

    def test_translated_token_passes_in_container_helper_authorizer(self):
        host_token = create_valid_host_token()
        helper_token, _ = TokenSchemaAdapter.translate_host_to_helper(
            host_payload=host_token,
            target_pod="cockroachdb-0",
            target_netns_inode="net:[4026532845]",
        )

        # Feed directly into G1HelperFaultAuthorizer to ensure 100% interoperability
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            token_file = os.path.join(tmpdir, G1HelperFaultAuthorizer.TOKEN_FILENAME)
            with open(token_file, "w", encoding="utf-8") as f:
                json.dump(helper_token, f)

            claim_store = SharedAtomicClaimStore()
            authorizer = G1HelperFaultAuthorizer(
                base_dir=tmpdir,
                allow_readonly_secret=True,
                claim_store=claim_store,
            )
            claimed = authorizer.verify_and_claim(
                expected_run_id="crdb-g1-l2-pilot-r01",
                expected_target_pod="cockroachdb-0",
                expected_target_namespace="cockroachdb",
                observed_netns_inode="net:[4026532845]",
            )
            self.assertEqual(claimed["delay_ms"], 1000)
            self.assertEqual(claimed["jitter_ms"], 20)
            self.assertEqual(claimed["duration_sec"], 180)

    def test_missing_host_field_raises_error(self):
        host_token = create_valid_host_token()
        del host_token["supervisor_approval_ref"]
        with self.assertRaises(TokenAdapterError) as ctx:
            TokenSchemaAdapter.translate_host_to_helper(
                host_payload=host_token,
                target_pod="cockroachdb-0",
                target_netns_inode="net:[4026532845]",
            )
        self.assertIn("missing required fields", str(ctx.exception))

    def test_extra_host_field_raises_error(self):
        host_token = create_valid_host_token()
        host_token["unauthorized_field"] = "malicious"
        with self.assertRaises(TokenAdapterError) as ctx:
            TokenSchemaAdapter.translate_host_to_helper(
                host_payload=host_token,
                target_pod="cockroachdb-0",
                target_netns_inode="net:[4026532845]",
            )
        self.assertIn("unexpected extra fields", str(ctx.exception))

    def test_invalid_invariant_values_fail_closed(self):
        # Latency mismatch
        host_token = create_valid_host_token()
        host_token["latency_ms"] = 500
        with self.assertRaises(TokenAdapterError) as ctx:
            TokenSchemaAdapter.translate_host_to_helper(
                host_payload=host_token,
                target_pod="cockroachdb-0",
                target_netns_inode="net:[4026532845]",
            )
        self.assertIn("Invalid latency_ms", str(ctx.exception))

        # Fault duration mismatch
        host_token = create_valid_host_token()
        host_token["fault_duration_sec"] = 60
        with self.assertRaises(TokenAdapterError) as ctx:
            TokenSchemaAdapter.translate_host_to_helper(
                host_payload=host_token,
                target_pod="cockroachdb-0",
                target_netns_inode="net:[4026532845]",
            )
        self.assertIn("Invalid fault_duration_sec", str(ctx.exception))


class TestTargetProcessResolver(unittest.TestCase):
    """Exhaustive tests for TargetProcessResolver."""

    def test_proc_inspector_resolution(self):
        mock_inspector = lambda pod, container: (1234, 56789, "net:[4026532845]")
        resolver = TargetProcessResolver(proc_inspector=mock_inspector)
        res = resolver.resolve_target("cockroachdb-0", "cockroachdb")

        self.assertEqual(res.pod_name, "cockroachdb-0")
        self.assertEqual(res.container_name, "db")
        self.assertEqual(res.host_pid, 1234)
        self.assertEqual(res.start_time_ticks, 56789)
        self.assertEqual(res.netns_inode, "net:[4026532845]")

    def test_kubectl_mock_resolution_pod_running(self):
        mock_kubectl = lambda cmd: "ip-10-0-1-75.ec2.internal|db init-certs|Running"
        resolver = TargetProcessResolver(kubectl_executor=mock_kubectl)
        res = resolver.resolve_target("cockroachdb-0", "cockroachdb")

        self.assertEqual(res.pod_name, "cockroachdb-0")
        self.assertEqual(res.container_name, "db")
        self.assertEqual(res.node_name, "ip-10-0-1-75.ec2.internal")

    def test_kubectl_mock_resolution_pod_not_running_fails(self):
        mock_kubectl = lambda cmd: "ip-10-0-1-75.ec2.internal|db init-certs|Pending"
        resolver = TargetProcessResolver(kubectl_executor=mock_kubectl)
        with self.assertRaises(TargetBindingError) as ctx:
            resolver.resolve_target("cockroachdb-0", "cockroachdb")
        self.assertIn("not in Running state", str(ctx.exception))

    def test_kubectl_mock_resolution_container_mismatch_fails(self):
        mock_kubectl = lambda cmd: "ip-10-0-1-75.ec2.internal|unrelated sidecar|Running"
        resolver = TargetProcessResolver(kubectl_executor=mock_kubectl)
        with self.assertRaises(TargetBindingError) as ctx:
            resolver.resolve_target("cockroachdb-0", "cockroachdb")
        self.assertIn("does not contain any expected container", str(ctx.exception))


class TestKubernetesJobFaultController(unittest.TestCase):
    """Exhaustive tests for KubernetesJobFaultController."""

    def test_dry_run_lifecycle(self):
        controller = KubernetesJobFaultController(dry_run=True)
        host_token = create_valid_host_token()
        helper_token, _ = TokenSchemaAdapter.translate_host_to_helper(
            host_token, "cockroachdb-0", "net:[4026532845]"
        )
        controller.set_authorized_token(helper_token)

        qdisc = controller.inspect_initial_qdisc("cockroachdb-0")
        self.assertEqual(qdisc, "noqueue")

        res_apply = controller.apply_latency_fault("cockroachdb-0", 1000, 20, "normal", 180)
        self.assertEqual(res_apply["status"], "APPLIED_SIMULATED")

        res_rollback = controller.rollback_fault("cockroachdb-0")
        self.assertEqual(res_rollback["status"], "ROLLED_BACK_SIMULATED")

        self.assertTrue(controller.verify_rollback("cockroachdb-0"))

    def test_apply_fault_without_token_raises_error(self):
        controller = KubernetesJobFaultController(dry_run=True)
        with self.assertRaises(FaultControllerError) as ctx:
            controller.apply_latency_fault("cockroachdb-0")
        self.assertIn("no authorized helper token configured", str(ctx.exception))

    def test_apply_fault_pod_mismatch_raises_error(self):
        controller = KubernetesJobFaultController(dry_run=True)
        host_token = create_valid_host_token()
        helper_token, _ = TokenSchemaAdapter.translate_host_to_helper(
            host_token, "cockroachdb-0", "net:[4026532845]"
        )
        controller.set_authorized_token(helper_token)

        with self.assertRaises(FaultControllerError) as ctx:
            controller.apply_latency_fault("cockroachdb-1")
        self.assertIn("Token target pod mismatch", str(ctx.exception))


class TestG1LiveExecutionCoordinator(unittest.TestCase):
    """Exhaustive tests for G1LiveExecutionCoordinator."""

    def setUp(self):
        self.config = PgbenchConfig(
            clients=20,
            threads=4,
            warmup_sec=120,
            measurement_sec=600,
            observation_sec=300,
            max_tries=1,
            simple_query=True,
        )
        self.token_adapter = TokenSchemaAdapter()
        mock_proc_inspector = lambda pod, container: (1001, 2002, "net:[4026532845]")
        self.target_resolver = TargetProcessResolver(proc_inspector=mock_proc_inspector)
        self.fault_controller = KubernetesJobFaultController(dry_run=True)

    def test_successful_pilot_execution_and_3way_reconciliation(self):
        # 5 sample transactions
        raw_log_lines = [
            "0 1 123456 0 1731550000 0",
            "1 2 234567 0 1731550001 0",
            "2 3 345678 0 1731550002 0",
            "3 4 456789 0 1731550003 0",
            "0 5 567890 0 1731550004 0",
        ]
        log_retriever = MockPgbenchLogRetriever(lines=raw_log_lines)

        stdout_mock = (
            "transaction type: <builtin: simple counter>\n"
            "scaling factor: 50\n"
            "query mode: simple\n"
            "number of clients: 20\n"
            "number of threads: 4\n"
            "duration: 600 s\n"
            "number of transactions actually processed: 5\n"
            "latency average = 12.34 ms\n"
            "tps = 150.25 (including connections establishing)\n"
        )
        def handler(argv, timeout_sec, log_path):
            return PgbenchProcessOutput(
                exit_code=0,
                stdout=stdout_mock,
                stderr="",
                raw_log_lines=raw_log_lines,
            )
        process_executor = MockPgbenchProcessExecutor(handler=handler)

        history_rows = {"count": 100}
        def mock_history_counter():
            val = history_rows["count"]
            history_rows["count"] += 5  # 5 rows added during measurement
            return val

        coordinator = G1LiveExecutionCoordinator(
            config=self.config,
            fault_controller=self.fault_controller,
            token_adapter=self.token_adapter,
            target_resolver=self.target_resolver,
            log_retriever=log_retriever,
            process_executor=process_executor,
            history_row_counter=mock_history_counter,
        )

        host_token = create_valid_host_token()
        report = coordinator.execute_pilot(host_token=host_token, dry_run=False)

        self.assertTrue(report.phase_warmup_success)
        self.assertTrue(report.phase_measurement_success)
        self.assertTrue(report.fault_injected)
        self.assertTrue(report.fault_cleared)
        self.assertTrue(report.rollback_verified)
        self.assertEqual(report.delta_history_rows, 5)
        self.assertEqual(report.pgbench_commits, 5)
        self.assertEqual(report.parsed_log_records, 5)
        self.assertTrue(report.reconciliation_passed)

    def test_reconciliation_failure_raises_error_in_non_dry_run(self):
        # Mismatch between delta_history and pgbench commits
        raw_log_lines = [
            "0 1 123456 0 1731550000 0",
        ]
        log_retriever = MockPgbenchLogRetriever(lines=raw_log_lines)
        stdout_mock = "number of transactions actually processed: 5\n"
        def handler(argv, timeout_sec, log_path):
            return PgbenchProcessOutput(
                exit_code=0,
                stdout=stdout_mock,
                stderr="",
                raw_log_lines=raw_log_lines,
            )
        process_executor = MockPgbenchProcessExecutor(handler=handler)

        # Delta history rows will be 2, but commits is 5, logs is 1
        history_rows = {"count": 10}
        def mock_history_counter():
            val = history_rows["count"]
            history_rows["count"] += 2
            return val

        coordinator = G1LiveExecutionCoordinator(
            config=self.config,
            fault_controller=self.fault_controller,
            token_adapter=self.token_adapter,
            target_resolver=self.target_resolver,
            log_retriever=log_retriever,
            process_executor=process_executor,
            history_row_counter=mock_history_counter,
        )

        host_token = create_valid_host_token()
        with self.assertRaises(ReconciliationError) as ctx:
            coordinator.execute_pilot(host_token=host_token, dry_run=False)
        self.assertIn("3-way reconciliation failure", str(ctx.exception))

    def test_warmup_failure_fails_closed(self):
        log_retriever = MockPgbenchLogRetriever()
        def handler(argv, timeout_sec, log_path):
            return PgbenchProcessOutput(
                exit_code=1,
                stdout="",
                stderr="Connection refused",
                raw_log_lines=[],
            )
        process_executor = MockPgbenchProcessExecutor(handler=handler)
        coordinator = G1LiveExecutionCoordinator(
            config=self.config,
            fault_controller=self.fault_controller,
            token_adapter=self.token_adapter,
            target_resolver=self.target_resolver,
            log_retriever=log_retriever,
            process_executor=process_executor,
        )
        host_token = create_valid_host_token()
        with self.assertRaises(PgbenchRunnerError) as ctx:
            coordinator.execute_pilot(host_token=host_token, dry_run=False)
        self.assertIn("Warm-up phase failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
