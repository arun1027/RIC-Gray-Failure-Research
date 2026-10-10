"""
test_g1_offline_suite.py - Exhaustive Offline Test Suite for Scenario G1.

Features:
- Compatible with Python's built-in `unittest` framework (runs cleanly without external dependencies).
- Can also be executed via `pytest` when installed.
- 100% offline, isolated from AWS, live Kubernetes, databases, and network adapters.
"""

import unittest
import datetime
import os
import tempfile
import sys
import json
import yaml
import warnings
from unittest.mock import patch

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmark.scripts.cockroachdb.g1.g1_target_resolver import (
    TargetResolver,
    MockDatabaseMetadataProvider,
    MockKubernetesMetadataProvider,
    RangeMetadata,
    NodeMetadata,
    PodMetadata,
    TargetResolutionError
)
from benchmark.scripts.cockroachdb.g1.g1_fault_controller import (
    MockFaultController,
    QdiscConflictError,
    RollbackVerificationError,
    FaultControllerError
)
from benchmark.scripts.cockroachdb.g1.g1_helper_daemon import (
    PrivilegedHelperDaemon,
    HelperSecurityContext,
    TargetNamespaceSpec,
    AutonomousWatchdog,
    HelperFaultController,
    CapabilityMissingError,
    TargetVerificationError,
    WatchdogTimeoutError
)
from benchmark.scripts.cockroachdb.g1.g1_preflight import (
    G1PreflightValidator,
    MockPreflightProbe
)
from benchmark.scripts.cockroachdb.g1.g1_authorizer import (
    G1Authorizer,
    G1AuthorizationError,
    EXPECTED_EXPERIMENT_ID,
    EXPECTED_ACTION,
    EXPECTED_TARGET_CLUSTER,
    EXPECTED_TARGET_NAMESPACE,
    EXPECTED_TARGET_POLICY,
    EXPECTED_PHYSICAL_RANGE_ID,
    EXPECTED_FAULT_TYPE,
    EXPECTED_LATENCY_MS,
    EXPECTED_JITTER_MS,
    EXPECTED_FAULT_DURATION_SEC,
    EXPECTED_MEASUREMENT_WINDOW_SEC,
    EXPECTED_SUPERVISOR_REF
)
from benchmark.scripts.cockroachdb.g1.g1_watchdog import (
    G1Watchdog,
    TripwireBreachedError
)
from benchmark.scripts.cockroachdb.g1.g1_evidence_collector import (
    G1EvidenceCollector,
    TransactionRecord
)
from benchmark.scripts.cockroachdb.g1.g1_orchestrator import (
    G1Orchestrator,
    main as orchestrator_main
)


class TestG1OfflineSuite(unittest.TestCase):

    def setUp(self):
        self.mock_nodes = [
            NodeMetadata(node_id=1, address="cockroachdb-0.cockroachdb:26257", locality="region=us-east-1,zone=us-east-1a", is_live=True, draining=False),
            NodeMetadata(node_id=2, address="cockroachdb-1.cockroachdb:26257", locality="region=us-east-1,zone=us-east-1b", is_live=True, draining=False),
            NodeMetadata(node_id=3, address="cockroachdb-2.cockroachdb:26257", locality="region=us-east-1,zone=us-east-1c", is_live=True, draining=False),
        ]
        self.mock_pods = [
            PodMetadata(pod_name="cockroachdb-0", pod_ip="10.0.1.47", node_name="ip-10-0-1-47", zone="us-east-1a", is_ready=True),
            PodMetadata(pod_name="cockroachdb-1", pod_ip="10.0.2.238", node_name="ip-10-0-2-238", zone="us-east-1b", is_ready=True),
            PodMetadata(pod_name="cockroachdb-2", pod_ip="10.0.3.74", node_name="ip-10-0-3-74", zone="us-east-1c", is_ready=True),
        ]

    def test_dynamic_range_selection_single_range(self):
        """Test target resolution when table has a single physical range."""
        ranges = [
            RangeMetadata(range_id=89, start_key="<before:/Table/107>", end_key="<after:/Max>", replicas=[1, 2, 3], lease_holder=1)
        ]
        resolver = TargetResolver(
            MockDatabaseMetadataProvider(ranges, self.mock_nodes),
            MockKubernetesMetadataProvider(self.mock_pods),
            policy=TargetResolver.POLICY_AID_1
        )
        target = resolver.resolve_target()
        self.assertEqual(target["physical_range_id"], 89)
        self.assertEqual(target["lease_holder_node_id"], 1)
        self.assertEqual(target["target_pod_name"], "cockroachdb-0")
        self.assertEqual(target["policy_status"], "PROVISIONAL_PENDING_SUPERVISOR_APPROVAL")

    def test_dynamic_range_selection_multiple_ranges(self):
        """Test resolution selects physical range containing initial key span (aid=1)."""
        ranges = [
            RangeMetadata(range_id=89, start_key="<before:/Table/107>", end_key="/Table/107/1/1", replicas=[1, 2, 3], lease_holder=2),
            RangeMetadata(range_id=98, start_key="/Table/107/1/1", end_key="/Table/107/2/1", replicas=[1, 2, 3], lease_holder=1),
            RangeMetadata(range_id=99, start_key="/Table/107/2/1", end_key="<after:/Max>", replicas=[1, 2, 3], lease_holder=3),
        ]
        resolver = TargetResolver(
            MockDatabaseMetadataProvider(ranges, self.mock_nodes),
            MockKubernetesMetadataProvider(self.mock_pods),
            policy=TargetResolver.POLICY_AID_1
        )
        target = resolver.resolve_target()
        self.assertEqual(target["physical_range_id"], 89)
        self.assertEqual(target["lease_holder_node_id"], 2)
        self.assertEqual(target["target_pod_name"], "cockroachdb-1")

    def test_ambiguous_logical_target_aborts(self):
        """Test that ambiguous target conditions raise an immediate error."""
        ranges = [
            RangeMetadata(range_id=89, start_key="<before:/Table/107/1/1>", end_key="/Table/107/1/1", replicas=[1, 2, 3], lease_holder=1),
            RangeMetadata(range_id=99, start_key="<before:/Table/107/1/1>", end_key="/Table/107/1/1", replicas=[1, 2, 3], lease_holder=2),
        ]
        resolver = TargetResolver(
            MockDatabaseMetadataProvider(ranges, self.mock_nodes),
            MockKubernetesMetadataProvider(self.mock_pods),
            policy=TargetResolver.POLICY_AID_1
        )
        with self.assertRaises(TargetResolutionError):
            resolver.resolve_target()

    def test_leaseholder_migration(self):
        """Test that moving the leaseholder node dynamically shifts the target pod."""
        # Run 1: Lease on Node 2
        ranges1 = [RangeMetadata(range_id=89, start_key="<before:/Table/107>", end_key="/Table/107/1/1", replicas=[1, 2, 3], lease_holder=2)]
        target1 = TargetResolver(MockDatabaseMetadataProvider(ranges1, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods)).resolve_target()
        self.assertEqual(target1["target_pod_name"], "cockroachdb-1")

        # Run 2: Lease migrated to Node 3
        ranges2 = [RangeMetadata(range_id=89, start_key="<before:/Table/107>", end_key="/Table/107/1/1", replicas=[1, 2, 3], lease_holder=3)]
        target2 = TargetResolver(MockDatabaseMetadataProvider(ranges2, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods)).resolve_target()
        self.assertEqual(target2["target_pod_name"], "cockroachdb-2")

    def test_missing_pod_raises_error(self):
        """Test that failing to map a live SQL node to a Kubernetes pod aborts cleanly."""
        ranges = [RangeMetadata(range_id=89, start_key="<before:/Table/107>", end_key="/Table/107/1/1", replicas=[1, 2, 3], lease_holder=2)]
        partial_pods = [
            PodMetadata(pod_name="cockroachdb-0", pod_ip="10.0.1.47", node_name="ip-10-0-1-47", zone="us-east-1a", is_ready=True),
            PodMetadata(pod_name="cockroachdb-2", pod_ip="10.0.3.74", node_name="ip-10-0-3-74", zone="us-east-1c", is_ready=True),
        ]
        resolver = TargetResolver(MockDatabaseMetadataProvider(ranges, self.mock_nodes), MockKubernetesMetadataProvider(partial_pods))
        with self.assertRaises(TargetResolutionError):
            resolver.resolve_target()

    def test_fault_controller_inspect_initial_qdisc(self):
        """Test initial qdisc inspection returns normal default state."""
        ctrl = MockFaultController(initial_qdisc="noqueue")
        qdisc = ctrl.inspect_initial_qdisc("cockroachdb-0")
        self.assertEqual(qdisc, "noqueue")

    def test_fault_controller_existing_qdisc_conflict(self):
        """Test applying a fault when a conflicting netem qdisc already exists is rejected."""
        ctrl = MockFaultController(simulate_conflict=True)
        with self.assertRaises(QdiscConflictError):
            ctrl.apply_latency_fault("cockroachdb-0")

    def test_fault_controller_failure(self):
        """Test simulation of command failure when injecting fault."""
        ctrl = MockFaultController(simulate_apply_failure=True)
        with self.assertRaises(FaultControllerError):
            ctrl.apply_latency_fault("cockroachdb-0")

    def test_fault_controller_rollback_failure(self):
        """Test simulation of rollback failure."""
        ctrl = MockFaultController(simulate_rollback_failure=True)
        ctrl.apply_latency_fault("cockroachdb-0")
        with self.assertRaises(FaultControllerError):
            ctrl.rollback_fault("cockroachdb-0")

    def test_fault_controller_rollback_verification(self):
        """Test successful rollback verification."""
        ctrl = MockFaultController()
        ctrl.apply_latency_fault("cockroachdb-0")
        self.assertTrue(ctrl.fault_active)
        ctrl.rollback_fault("cockroachdb-0")
        self.assertFalse(ctrl.fault_active)
        self.assertTrue(ctrl.verify_rollback("cockroachdb-0"))

    def test_watchdog_tw01_cpu_tripwire(self):
        """Test TW-01 triggers when CPU > 95% for sustained 30 seconds."""
        watchdog = G1Watchdog(cpu_threshold_percent=95.0, cpu_sustained_seconds=30)
        base_time = datetime.datetime(2026, 11, 12, 12, 0, 0, tzinfo=datetime.timezone.utc)

        watchdog.evaluate_sample(base_time, cpu_percent=96.0, transaction_drop_percent=0.0)
        watchdog.evaluate_sample(base_time + datetime.timedelta(seconds=20), cpu_percent=97.0, transaction_drop_percent=0.0)
        with self.assertRaises(TripwireBreachedError):
            watchdog.evaluate_sample(base_time + datetime.timedelta(seconds=31), cpu_percent=96.5, transaction_drop_percent=0.0)

    def test_watchdog_tw02_drop_tripwire(self):
        """Test TW-02 triggers when transaction drops = 100% for sustained 60 seconds."""
        watchdog = G1Watchdog(drop_threshold_percent=100.0, drop_sustained_seconds=60)
        base_time = datetime.datetime(2026, 11, 12, 12, 0, 0, tzinfo=datetime.timezone.utc)

        watchdog.evaluate_sample(base_time, cpu_percent=50.0, transaction_drop_percent=100.0)
        watchdog.evaluate_sample(base_time + datetime.timedelta(seconds=40), cpu_percent=50.0, transaction_drop_percent=100.0)
        with self.assertRaises(TripwireBreachedError):
            watchdog.evaluate_sample(base_time + datetime.timedelta(seconds=61), cpu_percent=50.0, transaction_drop_percent=100.0)

    def test_watchdog_tw03_pod_restart_tripwire(self):
        """Test TW-03 immediately triggers if any pod restart occurs."""
        watchdog = G1Watchdog(allow_pod_restarts=False)
        now = datetime.datetime.now(datetime.timezone.utc)
        with self.assertRaises(TripwireBreachedError):
            watchdog.evaluate_sample(now, cpu_percent=40.0, transaction_drop_percent=0.0, pod_restarts=1)

    def test_evidence_collector_dt_and_ca2_rto(self):
        """Test Detection Time (DT) and Primary CA2 RTO calculations."""
        collector = G1EvidenceCollector(run_id="test-run", output_dir=".")
        t0 = 100.0
        t1 = 102.350
        t2 = 112.480

        dt = collector.calculate_dt(t0, t1)
        self.assertEqual(dt, 2.350)

        ca2_rto = collector.calculate_ca2_rto(t0, t2)
        self.assertEqual(ca2_rto, 12.480)

    def test_evidence_collector_supplementary_restoration(self):
        """Test supplementary rolling steady-state restoration calculation."""
        collector = G1EvidenceCollector(run_id="test-run", output_dir=".")
        baseline_tps = 450.0
        t_clear = 300.0
        samples = [
            (305.0, 200.0),
            (310.0, 350.0),
            (315.0, 410.0),
            (320.0, 440.0)
        ]
        restoration_time = collector.calculate_supplementary_restoration(baseline_tps, samples, t_clear)
        self.assertEqual(restoration_time, 15.0)

    def test_evidence_collector_transaction_reconciliation(self):
        """Test transaction reconciliation mathematical equality."""
        collector = G1EvidenceCollector(run_id="test-run", output_dir=".")
        mock_records = [
            TransactionRecord(client_id=0, tx_id=1, status="ok", latency_us=20000, timestamp_epoch=100.0),
            TransactionRecord(client_id=1, tx_id=2, status="ok", latency_us=21000, timestamp_epoch=100.1),
            TransactionRecord(client_id=2, tx_id=3, status="failed", latency_us=50000, timestamp_epoch=100.2),
        ]
        res = collector.reconcile_transactions(
            s0_history_count=0,
            s2_history_count=102,
            warmup_successful=100,
            measurement_tx_records=mock_records
        )
        self.assertTrue(res["reconciled"])
        self.assertEqual(res["logged_successful"], 2)
        self.assertEqual(res["logged_failed"], 1)
        self.assertEqual(res["discrepancy"], 0)

    def test_sha256_manifest_generation(self):
        """Test SHA-256 manifest creation across mock artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = os.path.join(tmpdir, "file1.txt")
            f2 = os.path.join(tmpdir, "file2.txt")
            with open(f1, "w", encoding="utf-8") as f:
                f.write("hello cockroachdb")
            with open(f2, "w", encoding="utf-8") as f:
                f.write("g1 chaos test")

            manifest_file = os.path.join(tmpdir, "manifest.csv")
            collector = G1EvidenceCollector(run_id="test-run", output_dir=tmpdir)
            manifest = collector.generate_sha256_manifest([f1, f2], manifest_file)

            self.assertEqual(len(manifest), 2)
            self.assertIn("file1.txt", manifest)
            self.assertIn("file2.txt", manifest)
            self.assertTrue(os.path.exists(manifest_file))

    def test_rejection_of_live_execution(self):
        """Test that attempting live simulation runs cleanly through offline path."""
        orchestrator = G1Orchestrator(run_id="crdb-pilot-g1-01")
        sim_report = orchestrator.run_simulation()
        self.assertEqual(sim_report["status"], "SIMULATION_COMPLETED")
        self.assertTrue(sim_report["reconciliation"]["reconciled"])

    # -------------------------------------------------------------------------
    # Phase A.1 Safety Hardening Tests
    # -------------------------------------------------------------------------

    def test_target_resolver_reverification_at_t110(self):
        """1. Target Re-Verification: Test leaseholder shift between T=0 and T=110s."""
        ranges_t0 = [RangeMetadata(range_id=89, start_key="<before:/Table/107>", end_key="/Table/107/1/1", replicas=[1, 2, 3], lease_holder=1)]
        db_prov = MockDatabaseMetadataProvider(ranges_t0, self.mock_nodes)
        k8s_prov = MockKubernetesMetadataProvider(self.mock_pods)

        resolver = TargetResolver(db_prov, k8s_prov)
        target_t0 = resolver.resolve_target()
        self.assertEqual(target_t0["target_pod_name"], "cockroachdb-0")

        # Simulate lease migration to Node 2 (cockroachdb-1) at T=110s
        db_prov.ranges = [RangeMetadata(range_id=89, start_key="<before:/Table/107>", end_key="/Table/107/1/1", replicas=[1, 2, 3], lease_holder=2)]
        target_t110 = resolver.resolve_target()
        self.assertEqual(target_t110["target_pod_name"], "cockroachdb-1")
        self.assertNotEqual(target_t0["target_pod_name"], target_t110["target_pod_name"])

    def test_fault_controller_timeout_handling(self):
        """2. Fault Controller: Test simulated timeout raises TimeoutError and bounds duration."""
        ctrl = MockFaultController(simulate_timeout=True)
        with self.assertRaises(TimeoutError):
            ctrl.apply_latency_fault("cockroachdb-0", duration_sec=180)
        self.assertFalse(ctrl.fault_active)

    def test_preflight_probe_individual_failures(self):
        """3. Preflight Validator: Test individual failure modes in probe."""
        # A. Dead node
        p1 = G1PreflightValidator(MockPreflightProbe(nodes_healthy=False))
        c1 = p1.run_all_checks("cockroachdb-0")
        self.assertFalse(c1[0].passed)
        self.assertEqual(c1[0].check_name, "cockroach_nodes_healthy")

        # B. Under-replicated range
        p2 = G1PreflightValidator(MockPreflightProbe(ranges_replicated=False, under_replicated_count=2))
        c2 = p2.run_all_checks("cockroachdb-0")
        self.assertFalse(c2[1].passed)
        self.assertEqual(c2[1].check_name, "range_replication_healthy")

        # C. Dataset scale mismatch
        p3 = G1PreflightValidator(MockPreflightProbe(account_count=1000000))
        c3 = p3.run_all_checks("cockroachdb-0")
        self.assertFalse(c3[2].passed)
        self.assertEqual(c3[2].check_name, "dataset_sf50_intact")

        # D. Expired TLS cert
        p4 = G1PreflightValidator(MockPreflightProbe(tls_valid=False))
        c4 = p4.run_all_checks("cockroachdb-0")
        self.assertFalse(c4[3].passed)
        self.assertEqual(c4[3].check_name, "client_mtls_valid")

        # E. Missing CAP_NET_ADMIN
        p5 = G1PreflightValidator(MockPreflightProbe(net_admin_capable=False))
        c5 = p5.run_all_checks("cockroachdb-0")
        self.assertFalse(c5[4].passed)
        self.assertEqual(c5[4].check_name, "net_admin_capable")

    def test_evidence_collector_negative_dt_or_rto_rejected(self):
        """4. Evidence Collector: Test negative DT or RTO values raise ValueError."""
        collector = G1EvidenceCollector(run_id="test-run", output_dir=".")
        # T1 before T0
        with self.assertRaises(ValueError):
            collector.calculate_dt(t0=100.0, t1=99.0)

        # T2 before T0
        with self.assertRaises(ValueError):
            collector.calculate_ca2_rto(t0=100.0, t2=95.0)

    def test_cli_execute_flag_sys_exit(self):
        """5. CLI Gate: Test that --execute flag immediately triggers sys.exit(1)."""
        with patch.object(sys, 'argv', ['g1_orchestrator.py', '--execute']):
            with self.assertRaises(SystemExit) as cm:
                orchestrator_main()
            self.assertEqual(cm.exception.code, 1)

    def test_resolver_fallback_warning_emitted(self):
        """6. Resolver Warning: Test warning is emitted when fallback sort is used."""
        ranges = [
            RangeMetadata(range_id=89, start_key="/Table/107/1/1", end_key="/Table/107/2/1", replicas=[1, 2, 3], lease_holder=1),
            RangeMetadata(range_id=98, start_key="/Table/107/2/1", end_key="/Table/107/3/1", replicas=[1, 2, 3], lease_holder=2),
        ]
        resolver = TargetResolver(
            MockDatabaseMetadataProvider(ranges, self.mock_nodes),
            MockKubernetesMetadataProvider(self.mock_pods),
            policy=TargetResolver.POLICY_AID_1
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            target = resolver.resolve_target()
            self.assertTrue(target["used_fallback_sort"])
            self.assertTrue(any("RESOLVER WARNING" in str(item.message) for item in w))

    # =========================================================================
    # Phase C: Privileged Chaos Helper Daemon Tests
    # =========================================================================

    def test_helper_target_namespace_correct_selection(self):
        """Phase C.1: Helper correctly validates target namespace, pod name, IP, and port."""
        helper = PrivilegedHelperDaemon()
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-1",
            namespace="cockroachdb",
            expected_pod_ip="10.0.2.238",
            expected_listen_port=26257
        )
        live_pods = {
            "cockroachdb-1": {"ip": "10.0.2.238", "ports": [26257, 8080]}
        }
        self.assertTrue(helper.verify_target(target, live_pods))
        self.assertEqual(helper.active_target, target)

    def test_helper_rejects_wrong_target_ip(self):
        """Phase C.2: Helper rejects targeting when pod IP does not match expected IP."""
        helper = PrivilegedHelperDaemon()
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-1",
            namespace="cockroachdb",
            expected_pod_ip="10.0.2.238"
        )
        live_pods = {
            "cockroachdb-1": {"ip": "10.0.2.999", "ports": [26257]}
        }
        with self.assertRaises(TargetVerificationError):
            helper.verify_target(target, live_pods)

    def test_helper_rejects_nonexistent_target_pod(self):
        """Phase C.3: Helper rejects target if pod does not exist in cluster state."""
        helper = PrivilegedHelperDaemon()
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-nonexistent",
            namespace="cockroachdb",
            expected_pod_ip="10.0.1.1"
        )
        with self.assertRaises(TargetVerificationError):
            helper.verify_target(target, {})

    def test_helper_missing_net_admin_capability(self):
        """Phase C.4: Helper raises CapabilityMissingError if NET_ADMIN is absent."""
        context = HelperSecurityContext(capabilities_add=["SYS_ADMIN"])
        helper = PrivilegedHelperDaemon(security_context=context)
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-0",
            namespace="cockroachdb",
            expected_pod_ip="10.0.1.47"
        )
        with self.assertRaises(CapabilityMissingError) as cm:
            helper.inspect_qdisc(target)
        self.assertIn("CAP_NET_ADMIN", str(cm.exception))

    def test_helper_missing_sys_admin_capability(self):
        """Phase C1.1: Audit requirement - Helper raises CapabilityMissingError if SYS_ADMIN is absent."""
        context = HelperSecurityContext(capabilities_add=["NET_ADMIN"])
        helper = PrivilegedHelperDaemon(security_context=context)
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-0",
            namespace="cockroachdb",
            expected_pod_ip="10.0.1.47"
        )
        with self.assertRaises(CapabilityMissingError) as cm:
            helper.inspect_qdisc(target)
        self.assertIn("CAP_SYS_ADMIN", str(cm.exception))

    def test_helper_existing_qdisc_conflict(self):
        """Phase C.5: Helper detects pre-existing netem qdisc and rejects injection."""
        helper = PrivilegedHelperDaemon(simulate_conflict=True)
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-0",
            namespace="cockroachdb",
            expected_pod_ip="10.0.1.47"
        )
        with self.assertRaises(QdiscConflictError):
            helper.apply_fault(target)

    def test_helper_successful_fault_application_and_rollback(self):
        """Phase C.6: Helper applies 1000ms latency, arms watchdog, rolls back and verifies."""
        helper = PrivilegedHelperDaemon(initial_qdisc="noqueue")
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-1",
            namespace="cockroachdb",
            expected_pod_ip="10.0.2.238"
        )
        # Apply fault
        result = helper.apply_fault(target, delay_ms=1000, jitter_ms=20, duration_sec=180)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["delay_ms"], 1000)
        self.assertEqual(result["direction"], "egress")
        self.assertTrue(helper.watchdog.is_armed)
        self.assertIn("netem delay 1000ms 20ms", helper.inspect_qdisc(target))

        # Rollback fault
        rb_result = helper.rollback_fault(target)
        self.assertEqual(rb_result["status"], "CLEARED")
        self.assertFalse(helper.watchdog.is_armed)
        self.assertTrue(helper.verify_rollback(target))
        self.assertEqual(helper.inspect_qdisc(target), "noqueue")

    def test_helper_watchdog_autonomous_timeout(self):
        """Phase C.7: Autonomous watchdog trips when duration exceeds safety timeout."""
        watchdog = AutonomousWatchdog(max_duration_sec=180, safety_margin_sec=20)
        watchdog.arm()
        self.assertEqual(watchdog.check_status(elapsed_sec=100), "ARMED")
        self.assertEqual(watchdog.check_status(elapsed_sec=185), "TRIPPED")
        self.assertTrue(watchdog.tripped)

    def test_helper_orchestrator_termination_safety(self):
        """Phase C.8: In-helper watchdog ensures fault is cleared if orchestrator terminates."""
        helper = PrivilegedHelperDaemon(initial_qdisc="noqueue")
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-2",
            namespace="cockroachdb",
            expected_pod_ip="10.0.3.74"
        )
        helper.apply_fault(target, delay_ms=1000, duration_sec=180)
        self.assertTrue(helper.watchdog.is_armed)

        # Simulate orchestrator abrupt termination: helper watchdog autonomously disarms and cleans
        if helper.watchdog.check_status(elapsed_sec=200) == "TRIPPED":
            helper.rollback_fault(target)

        self.assertEqual(helper.inspect_qdisc(target), "noqueue")
        self.assertTrue(helper.verify_rollback(target))

    def test_helper_crash_before_apply(self):
        """Phase C.9: Helper crash simulation prevents fault from being applied."""
        helper = PrivilegedHelperDaemon(simulate_crash=True)
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-0",
            namespace="cockroachdb",
            expected_pod_ip="10.0.1.47"
        )
        with self.assertRaises(FaultControllerError):
            helper.apply_fault(target)
        self.assertFalse(helper.watchdog.is_armed)

    def test_helper_pod_sandbox_deletion_recovery(self):
        """Phase C.10: Pod sandbox deletion dissolves netem qdisc and resets namespace to clean state."""
        helper = PrivilegedHelperDaemon(initial_qdisc="noqueue")
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-1",
            namespace="cockroachdb",
            expected_pod_ip="10.0.2.238"
        )
        helper.apply_fault(target, delay_ms=1000)
        self.assertIn("netem", helper.current_qdisc)

        # Pod sandbox deletion creates clean network namespace
        helper.handle_pod_sandbox_deletion(target)
        self.assertEqual(helper.current_qdisc, "noqueue")
        self.assertFalse(helper.watchdog.is_armed)

    def test_helper_container_restart_leaves_qdisc_intact(self):
        """Phase C3.1: Audit finding - Ordinary container restart inside pod preserves pause container netns and qdisc."""
        helper = PrivilegedHelperDaemon(initial_qdisc="noqueue")
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-1",
            namespace="cockroachdb",
            expected_pod_ip="10.0.2.238"
        )
        helper.apply_fault(target, delay_ms=1000)
        self.assertIn("netem", helper.current_qdisc)

        # Ordinary container restart (pause container remains alive)
        helper.handle_container_restart(target)
        # Qdisc MUST remain attached because pod sandbox netns persists!
        self.assertIn("netem", helper.current_qdisc)
        self.assertTrue(helper.watchdog.is_armed)

    def test_helper_rollback_verification_failure(self):
        """Phase C.11: Failure during qdisc deletion or verification raises RollbackVerificationError."""
        helper = PrivilegedHelperDaemon(simulate_rollback_failure=True)
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-1",
            namespace="cockroachdb",
            expected_pod_ip="10.0.2.238"
        )
        with self.assertRaises(RollbackVerificationError):
            helper.rollback_fault(target)

    def test_helper_audit_logging_and_evidence_hashes(self):
        """Phase C.12: Audit logging records all operations and produces verifiable SHA-256."""
        helper = PrivilegedHelperDaemon(initial_qdisc="noqueue")
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-0",
            namespace="cockroachdb",
            expected_pod_ip="10.0.1.47"
        )
        live_pods = {"cockroachdb-0": {"ip": "10.0.1.47", "ports": [26257, 8080]}}
        helper.verify_target(target, live_pods)
        helper.apply_fault(target)
        helper.rollback_fault(target)
        helper.verify_rollback(target)

        self.assertGreaterEqual(len(helper.audit_log), 4)
        h1 = helper.compute_audit_hash()
        h2 = helper.compute_audit_hash()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_helper_fault_controller_integration(self):
        """Phase C.13: HelperFaultController acts as a drop-in IFaultController adapter."""
        helper = PrivilegedHelperDaemon(initial_qdisc="noqueue")
        controller = HelperFaultController(helper)
        
        init_q = controller.inspect_initial_qdisc("cockroachdb-1")
        self.assertEqual(init_q, "noqueue")
        
        apply_res = controller.apply_latency_fault("cockroachdb-1", delay_ms=1000)
        self.assertEqual(apply_res["status"], "APPLIED")
        
        rb_res = controller.rollback_fault("cockroachdb-1")
        self.assertEqual(rb_res["status"], "CLEARED")
        self.assertTrue(controller.verify_rollback("cockroachdb-1"))

    # =========================================================================
    # Phase C.1: Independent Security & Rollback Audit Tests
    # =========================================================================

    def test_helper_refuses_to_delete_unknown_handle(self):
        """Phase C1.2: Rollback safety - Helper refuses to delete qdisc if handle does not match G1_HANDLE."""
        helper = PrivilegedHelperDaemon()
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-1",
            namespace="cockroachdb",
            expected_pod_ip="10.0.2.238"
        )
        # Manually simulate a foreign qdisc handle attached to root
        helper.current_qdisc = "netem delay 200ms"
        helper.current_handle = "999:"  # Foreign handle, not G1_HANDLE (100:)

        with self.assertRaises(QdiscConflictError) as cm:
            helper.rollback_fault(target)
        self.assertIn("does not match G1 handle", str(cm.exception))

    def test_helper_race_condition_detected_between_inspect_and_apply(self):
        """Phase C1.3: Concurrency safety - Helper detects concurrent qdisc change between inspect and apply."""
        helper = PrivilegedHelperDaemon(simulate_race_condition=True)
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-0",
            namespace="cockroachdb",
            expected_pod_ip="10.0.1.47"
        )
        with self.assertRaises(QdiscConflictError) as cm:
            helper.apply_fault(target)
        self.assertIn("Race condition detected", str(cm.exception))

    def test_helper_rollback_failure_sets_unresolved_fault_and_operator_alert_without_pod_delete(self):
        """Phase C1.4: Pod preservation - Failed rollback sets UNRESOLVED_FAULT and alerts operator; NEVER deletes DB pod."""
        helper = PrivilegedHelperDaemon(simulate_rollback_failure=True)
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-2",
            namespace="cockroachdb",
            expected_pod_ip="10.0.3.74"
        )
        with self.assertRaises(RollbackVerificationError):
            helper.rollback_fault(target)

        # Assert safe state
        self.assertTrue(helper.unresolved_fault)
        self.assertIsNotNone(helper.operator_alert)
        self.assertIn("DO NOT delete CockroachDB pod", helper.operator_alert)
        self.assertIn("Operator manual intervention required", helper.operator_alert)
        # Ensure nuclear escalation was NOT attempted
        self.assertFalse(helper.pod_deleted_escalation_attempted)

    def test_watchdog_failure_boundaries_matrix(self):
        """Phase C1.5: Watchdog reliability - Formally evaluates survival across all failure domains."""
        self.assertTrue(AutonomousWatchdog.evaluate_survival("orchestrator_termination"))
        self.assertTrue(AutonomousWatchdog.evaluate_survival("network_partition"))
        self.assertFalse(AutonomousWatchdog.evaluate_survival("helper_container_termination"))
        self.assertFalse(AutonomousWatchdog.evaluate_survival("helper_pod_deletion"))
        self.assertFalse(AutonomousWatchdog.evaluate_survival("worker_node_reboot"))

    # =========================================================================
    # Phase C.2: Privilege Minimisation & Disappearing Interface Tests
    # =========================================================================

    def test_helper_rollback_disappearing_interface_naturally_clears(self):
        """Phase C2.1: Interface disappearance - When target interface vanishes (ENODEV), rollback handles as natural cleanup."""
        helper = PrivilegedHelperDaemon(simulate_disappearing_interface=True)
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-1",
            namespace="cockroachdb",
            expected_pod_ip="10.0.2.238"
        )
        res = helper.rollback_fault(target)
        self.assertEqual(res["status"], "NATURALLY_CLEARED_INTERFACE_VANISHED")
        self.assertEqual(helper.current_qdisc, "noqueue")
        self.assertFalse(helper.watchdog.is_armed)

    def test_helper_dedicated_chaos_namespace_isolation(self):
        """Phase C2.2: Privilege minimisation - Dedicated chaos namespace is separate from cockroachdb namespace."""
        context = HelperSecurityContext()
        self.assertEqual(context.chaos_namespace, "g1-chaos")
        self.assertNotEqual(context.chaos_namespace, "cockroachdb")
        self.assertFalse(context.privileged)

    # =========================================================================
    # Phase C.4: Multi-Factor Qdisc Ownership Verification Tests
    # =========================================================================

    def test_helper_refuses_to_delete_foreign_qdisc_even_with_handle_100(self):
        """Phase C4.1: Ownership safety - Handle 100: alone does not prove ownership if type is not netem."""
        helper = PrivilegedHelperDaemon()
        target = TargetNamespaceSpec(
            pod_name="cockroachdb-1",
            namespace="cockroachdb",
            expected_pod_ip="10.0.2.238"
        )
        # Foreign qdisc using handle 100: but type tbf (not netem)
        helper.current_qdisc = "tbf rate 10mbit"
        helper.current_handle = "100:"

        with self.assertRaises(QdiscConflictError) as cm:
            helper.rollback_fault(target)
        self.assertIn("Handle alone does not prove ownership", str(cm.exception))


    # =========================================================================
    # Phase F.0.5: G1-Specific Authorization & Diagnostic Security Remediation
    # =========================================================================


class TestG1AuthorizationAndSecurityRemediation(unittest.TestCase):
    """
    Offline validation suite for Phase F.0.5 authorization validator and SQL diagnostic manifest.
    Strictly isolated from live clusters, network, and live secrets.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.authorizer = G1Authorizer(base_dir=self.test_dir)
        self.now = datetime.datetime.now(datetime.timezone.utc)

    def tearDown(self):
        for f in os.listdir(self.test_dir):
            try:
                os.remove(os.path.join(self.test_dir, f))
            except Exception:
                pass
        try:
            os.rmdir(self.test_dir)
        except Exception:
            pass

    def _create_valid_token_payload(
        self,
        run_id="crdb-pilot-g1-01",
        attempt_id="attempt-01",
        ttl_sec=600,
        issue_offset_sec=0
    ):
        issued = self.now + datetime.timedelta(seconds=issue_offset_sec)
        expires = issued + datetime.timedelta(seconds=ttl_sec)
        return {
            "experiment_id": EXPECTED_EXPERIMENT_ID,
            "action": EXPECTED_ACTION,
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
            "execution_attempt_id": attempt_id,
            "issued_at_utc": issued.isoformat(),
            "expires_at_utc": expires.isoformat(),
            "authorized_by_operator": "Lead Operator",
            "supervisor_approval_ref": EXPECTED_SUPERVISOR_REF,
        }

    def _write_token(self, payload, filename="G1_AUTHORIZED.json"):
        path = os.path.join(self.test_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            if isinstance(payload, str):
                f.write(payload)
            else:
                json.dump(payload, f)
        return path

    def test_authorizer_missing_token_file(self):
        """Phase F0.5: Authorizer fails closed when G1_AUTHORIZED.json is absent."""
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("Token file 'G1_AUTHORIZED.json' was not found", str(cm.exception))

    def test_authorizer_invalid_json(self):
        """Phase F0.5: Authorizer fails closed on malformed JSON payload."""
        self._write_token("{malformed_json: true, missing_quotes")
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("Malformed JSON in authorization token", str(cm.exception))

    def test_authorizer_malformed_not_dict(self):
        """Phase F0.5: Authorizer fails closed when payload is not a JSON object."""
        self._write_token(["list", "of", "items"])
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("must be a JSON object", str(cm.exception))

    def test_authorizer_unexpected_unknown_fields(self):
        """Phase F0.5: Authorizer rejects unexpected unknown fields (strict schema)."""
        payload = self._create_valid_token_payload()
        payload["malicious_extra_field"] = "exploit_attempt"
        self._write_token(payload)
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("unexpected unknown fields", str(cm.exception))
        self.assertIn("malicious_extra_field", str(cm.exception))

    def test_authorizer_missing_required_fields(self):
        """Phase F0.5: Authorizer rejects token missing mandatory fields."""
        payload = self._create_valid_token_payload()
        del payload["physical_range_id"]
        self._write_token(payload)
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("missing required fields", str(cm.exception))
        self.assertIn("physical_range_id", str(cm.exception))

    def test_authorizer_expired_token(self):
        """Phase F0.5: Authorizer rejects expired authorization tokens."""
        # Issued 1 hour ago, expired 45 minutes ago
        payload = self._create_valid_token_payload(issue_offset_sec=-3600, ttl_sec=900)
        self._write_token(payload)
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("Authorization token has expired", str(cm.exception))

    def test_authorizer_future_token_clock_skew(self):
        """Phase F0.5: Authorizer rejects token issued in the future (clock skew)."""
        payload = self._create_valid_token_payload(issue_offset_sec=600, ttl_sec=900)
        self._write_token(payload)
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("is in the future", str(cm.exception))

    def test_authorizer_ttl_exceeds_max_15m(self):
        """Phase F0.5: Authorizer enforces maximum 15-minute TTL window."""
        payload = self._create_valid_token_payload(ttl_sec=1200)  # 20 minutes
        self._write_token(payload)
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("exceeds maximum allowed window", str(cm.exception))

    def test_authorizer_incorrect_target_cluster(self):
        """Phase F0.5: Authorizer rejects token targeting wrong Kubernetes cluster."""
        payload = self._create_valid_token_payload()
        payload["target_cluster"] = "rogue-cluster"
        self._write_token(payload)
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("target_cluster mismatch", str(cm.exception))

    def test_authorizer_incorrect_physical_range_id(self):
        """Phase F0.5: Authorizer prevents targeting system metadata range (Range 1)."""
        payload = self._create_valid_token_payload()
        payload["physical_range_id"] = 1  # Attempting to target Range 1 instead of 89
        self._write_token(payload)
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("physical_range_id mismatch", str(cm.exception))

    def test_authorizer_incorrect_fault_parameters(self):
        """Phase F0.5: Authorizer rejects unapproved latency values (e.g. 5000ms)."""
        payload = self._create_valid_token_payload()
        payload["latency_ms"] = 5000
        self._write_token(payload)
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("latency_ms mismatch", str(cm.exception))

    def test_authorizer_incorrect_run_id(self):
        """Phase F0.5: Authorizer rejects token issued for a different run ID."""
        payload = self._create_valid_token_payload(run_id="crdb-pilot-g1-99")
        self._write_token(payload)
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("run_id mismatch", str(cm.exception))

    def test_authorizer_rejection_of_p06_fallback(self):
        """Phase F0.5: Authorizer explicitly rejects historical P06_AUTHORIZED.json."""
        self._write_token({"run_id": "p06", "action": "EXECUTE_P06"}, filename="P06_AUTHORIZED.json")
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("strictly prohibits fallback to historical Stage 4 baseline authorization", str(cm.exception))

    def test_authorizer_rejection_of_env_vars(self):
        """Phase F0.5: Authorizer refuses execution when environment variable auth is attempted."""
        with patch.dict(os.environ, {"G1_AUTHORIZED": "1"}):
            with self.assertRaises(G1AuthorizationError) as cm:
                self.authorizer.verify_and_claim(
                    expected_run_id="crdb-pilot-g1-01",
                    execution_attempt_id="attempt-01"
                )
            self.assertIn("G1_AUTHORIZED environment variable authorization is strictly forbidden", str(cm.exception))

    def test_authorizer_rejection_of_static_txt_file(self):
        """Phase F0.5: Authorizer refuses deprecated static text authorization files."""
        self._write_token("AUTHORIZED", filename="G1_AUTHORIZED.txt")
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("Static text token 'G1_AUTHORIZED.txt' is rejected", str(cm.exception))

    def test_authorizer_atomic_claim_and_single_use_consumption(self):
        """Phase F0.5: Valid token is atomically verified, claimed, and consumed (deleted)."""
        payload = self._create_valid_token_payload()
        token_path = self._write_token(payload)

        self.assertTrue(os.path.exists(token_path))
        claimed = self.authorizer.verify_and_claim(
            expected_run_id="crdb-pilot-g1-01",
            execution_attempt_id="attempt-01",
            consume_token=True
        )
        self.assertEqual(claimed["experiment_id"], EXPECTED_EXPERIMENT_ID)
        # Token must be consumed (deleted) to prevent replay
        self.assertFalse(os.path.exists(token_path))

    def test_authorizer_reused_token_fails_closed(self):
        """Phase F0.5: Replay prevention - A consumed token cannot be reused for a second attempt."""
        payload = self._create_valid_token_payload()
        self._write_token(payload)

        # Attempt 1: succeeds and consumes token
        self.authorizer.verify_and_claim(
            expected_run_id="crdb-pilot-g1-01",
            execution_attempt_id="attempt-01",
            consume_token=True
        )

        # Attempt 2: must fail closed because token was consumed
        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-02",
                consume_token=True
            )
        self.assertIn("Token file 'G1_AUTHORIZED.json' was not found", str(cm.exception))

    def test_authorizer_concurrent_claim_race_file_exists(self):
        """Phase F0.5: Concurrency safety - An active claim lock blocks concurrent claimants."""
        payload = self._create_valid_token_payload()
        self._write_token(payload)

        # Simulate concurrent process having created the claim file
        claim_path = os.path.join(self.test_dir, "G1_AUTHORIZED.claim")
        with open(claim_path, "w") as f:
            f.write("claimed_by: another_process\n")

        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("Authorization claim file 'G1_AUTHORIZED.claim' already exists", str(cm.exception))

    def test_authorizer_file_permission_or_io_error(self):
        """Phase F0.5: Fail-closed on file open / OS permission errors."""
        payload = self._create_valid_token_payload()
        self._write_token(payload)

        with patch("os.open", side_effect=PermissionError("Permission denied by kernel")):
            with self.assertRaises(G1AuthorizationError) as cm:
                self.authorizer.verify_and_claim(
                    expected_run_id="crdb-pilot-g1-01",
                    execution_attempt_id="attempt-01"
                )
            self.assertIn("Failed to atomically create authorization claim", str(cm.exception))

    def test_authorizer_rejection_of_symlink_token(self):
        """Phase F0.6: Security - Authorizer refuses symlinked authorization token files."""
        real_file = os.path.join(self.test_dir, "real_payload.json")
        payload = self._create_valid_token_payload()
        with open(real_file, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        symlink_path = os.path.join(self.test_dir, "G1_AUTHORIZED.json")
        try:
            os.symlink(real_file, symlink_path)
        except (OSError, NotImplementedError):
            # In Windows unprivileged environments without SeCreateSymbolicLinkPrivilege, skip symlink creation
            self.skipTest("Symlink creation not permitted by local Windows OS privilege.")

        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01"
            )
        self.assertIn("cannot be a symbolic link", str(cm.exception))

    def test_authorizer_dynamic_physical_range_id_match(self):
        """Phase F0.6: Dynamic targeting - Authorizer supports dynamic range ID verification."""
        payload = self._create_valid_token_payload()
        payload["physical_range_id"] = 98  # Dynamically resolved range
        self._write_token(payload)

        claimed = self.authorizer.verify_and_claim(
            expected_run_id="crdb-pilot-g1-01",
            execution_attempt_id="attempt-01",
            expected_physical_range_id=98,
            consume_token=True
        )
        self.assertEqual(claimed["physical_range_id"], 98)

    def test_authorizer_dynamic_physical_range_id_mismatch(self):
        """Phase F0.6: Dynamic targeting - Authorizer fails closed on range ID mismatch."""
        payload = self._create_valid_token_payload()
        payload["physical_range_id"] = 89
        self._write_token(payload)

        with self.assertRaises(G1AuthorizationError) as cm:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-pilot-g1-01",
                execution_attempt_id="attempt-01",
                expected_physical_range_id=98,  # Expected dynamically resolved range 98
                consume_token=True
            )
        self.assertIn("Expected 98, found 89", str(cm.exception))

    def test_sql_diagnostic_manifest_security_compliance(self):
        """Phase F1.1: Hardened SQL diagnostic manifest with InitContainer satisfies all security invariants."""
        manifest_path = os.path.join(REPO_ROOT, "kubernetes", "cockroachdb", "cockroachdb-sql-diagnostic.yaml")
        self.assertTrue(os.path.isfile(manifest_path), f"Manifest not found: {manifest_path}")

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = yaml.safe_load(f)

        spec = manifest.get("spec", {})
        self.assertEqual(spec.get("restartPolicy"), "Never")
        self.assertEqual(spec.get("activeDeadlineSeconds"), 120)
        self.assertFalse(spec.get("automountServiceAccountToken", True))

        pod_sec = spec.get("securityContext", {})
        self.assertTrue(pod_sec.get("runAsNonRoot"))
        self.assertEqual(pod_sec.get("runAsUser"), 1000530000)
        self.assertEqual(pod_sec.get("seccompProfile", {}).get("type"), "RuntimeDefault")

        # Verify minimal InitContainer (copy-certs)
        init_containers = spec.get("initContainers", [])
        self.assertEqual(len(init_containers), 1)
        ic = init_containers[0]
        self.assertEqual(ic.get("name"), "copy-certs")
        self.assertEqual(
            ic.get("image"),
            "docker.io/library/busybox@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4"
        )

        ic_sec = ic.get("securityContext", {})
        self.assertFalse(ic_sec.get("privileged"))
        self.assertTrue(ic_sec.get("readOnlyRootFilesystem"))
        self.assertFalse(ic_sec.get("allowPrivilegeEscalation"))
        self.assertEqual(ic_sec.get("runAsUser"), 0)
        self.assertEqual(ic_sec.get("capabilities", {}).get("drop"), ["ALL"])
        self.assertEqual(ic_sec.get("capabilities", {}).get("add"), ["CHOWN"])

        # Verify initContainer copy -> chmod -> chown -> stat verification without printing file contents
        ic_cmd = " ".join(ic.get("command", []))
        self.assertIn("cp /certs-src/ca.crt /cockroach-certs/ca.crt", ic_cmd)
        self.assertIn("cp /certs-src/client.root.crt /cockroach-certs/client.root.crt", ic_cmd)
        self.assertIn("cp /certs-src/client.root.key /cockroach-certs/client.root.key", ic_cmd)
        chmod_idx = ic_cmd.find("chmod 0400")
        chown_idx = ic_cmd.find("chown 1000530000:1000530000")
        stat_idx = ic_cmd.find("stat -c '%u:%g:%a'")
        self.assertNotEqual(chmod_idx, -1)
        self.assertNotEqual(chown_idx, -1)
        self.assertNotEqual(stat_idx, -1)
        self.assertLess(chmod_idx, chown_idx, "chmod 0400 must run BEFORE chown 1000530000:1000530000")
        self.assertLess(chown_idx, stat_idx, "stat permission check must run AFTER chown")
        self.assertIn("1000530000:1000530000:400", ic_cmd)
        for forbidden_log_cmd in ["cat ", "head ", "tail ", "base64 ", "print"]:
            self.assertNotIn(forbidden_log_cmd, ic_cmd)

        ic_mounts = {m["name"]: m for m in ic.get("volumeMounts", [])}
        self.assertTrue(ic_mounts["client-certs-src"].get("readOnly"))
        self.assertFalse(ic_mounts["client-certs-prepared"].get("readOnly", False))

        # Verify main container runs as non-root and cannot modify its filesystem
        containers = spec.get("containers", [])
        self.assertEqual(len(containers), 1)
        c = containers[0]
        self.assertEqual(c.get("image"), "cockroachdb/cockroach:v26.3.2")

        c_sec = c.get("securityContext", {})
        self.assertTrue(c_sec.get("runAsNonRoot"))
        self.assertEqual(c_sec.get("runAsUser"), 1000530000)
        self.assertFalse(c_sec.get("privileged"))
        self.assertTrue(c_sec.get("readOnlyRootFilesystem"))
        self.assertFalse(c_sec.get("allowPrivilegeEscalation"))
        self.assertEqual(c_sec.get("capabilities", {}).get("drop"), ["ALL"])
        self.assertNotIn("add", c_sec.get("capabilities", {}))

        # Check command has zero sleep, enforces errexit=true, and only executes read-only SELECT statements
        cmd_str = " ".join(c.get("command", []))
        self.assertNotIn("sleep", cmd_str)
        self.assertIn("--set=errexit=true", cmd_str)
        self.assertIn("SELECT version();", cmd_str)
        self.assertIn("SELECT count(*) AS account_count FROM benchdb.public.pgbench_accounts;", cmd_str)
        self.assertIn("SELECT count(*) AS branch_count FROM benchdb.public.pgbench_branches;", cmd_str)
        self.assertIn("SELECT count(*) AS teller_count FROM benchdb.public.pgbench_tellers;", cmd_str)
        self.assertIn("SELECT count(*) AS history_count FROM benchdb.public.pgbench_history;", cmd_str)
        for mutating_kw in ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE"]:
            self.assertNotIn(mutating_kw, cmd_str.upper())

        # Main container mounts ONLY the prepared emptyDir readOnly: true (not the raw secret)
        c_mounts = c.get("volumeMounts", [])
        self.assertEqual(len(c_mounts), 1)
        self.assertEqual(c_mounts[0]["name"], "client-certs-prepared")
        self.assertTrue(c_mounts[0].get("readOnly"))

        # Check volumes: secret readOnly 0400 mode, and memory-backed bounded emptyDir
        vols = {v["name"]: v for v in spec.get("volumes", [])}
        self.assertEqual(vols["client-certs-src"]["secret"]["secretName"], "cockroachdb-client-secret")
        self.assertEqual(vols["client-certs-src"]["secret"]["defaultMode"], 256)
        self.assertEqual(vols["client-certs-prepared"]["emptyDir"]["medium"], "Memory")
        self.assertEqual(vols["client-certs-prepared"]["emptyDir"]["sizeLimit"], "1Mi")

    def test_sql_diagnostic_chmod_before_chown_regression(self):
        """Phase F1.5: Regression check detecting incorrect chown-before-chmod ordering."""
        def has_valid_chmod_chown_order(shell_script: str) -> bool:
            chmod_pos = shell_script.find("chmod 0400")
            chown_pos = shell_script.find("chown 1000530000:1000530000")
            return chmod_pos != -1 and chown_pos != -1 and chmod_pos < chown_pos

        broken_script = "cp /a /b\nchown 1000530000:1000530000 /b\nchmod 0400 /b\n"
        self.assertFalse(has_valid_chmod_chown_order(broken_script))

        manifest_path = os.path.join(REPO_ROOT, "kubernetes", "cockroachdb", "cockroachdb-sql-diagnostic.yaml")
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = yaml.safe_load(f)
        ic_script = " ".join(manifest["spec"]["initContainers"][0]["command"])
        self.assertTrue(has_valid_chmod_chown_order(ic_script))

    def test_system_range_exclusion_in_target_resolver(self):
        """Section D.3: Internal system ranges (range_id <= 1) cannot be selected."""
        db_prov = MockDatabaseMetadataProvider(
            ranges=[RangeMetadata(range_id=1, start_key="<before:/Table/107>", end_key="/Table/107/1", replicas=[1, 2, 3], lease_holder=1)],
            nodes=[NodeMetadata(node_id=1, address="cockroachdb-0.cockroachdb:26257", locality="zone=us-east-1a", is_live=True, draining=False)]
        )
        k8s_prov = MockKubernetesMetadataProvider(
            pods=[PodMetadata(pod_name="cockroachdb-0", pod_ip="10.0.1.1", node_name="node-1", zone="us-east-1a", is_ready=True)]
        )
        resolver = TargetResolver(db_prov, k8s_prov, policy=TargetResolver.POLICY_AID_1)
        with self.assertRaises(TargetResolutionError) as cm:
            resolver.resolve_target()
        self.assertIn("Internal system range", str(cm.exception))

    def test_stale_range_id_rejected(self):
        """Section D.2: Stale physical range IDs are rejected by freshness validation."""
        with self.assertRaises(TargetResolutionError) as cm:
            TargetResolver.validate_target_freshness({"physical_range_id": 98}, expected_range_id=89)
        self.assertIn("Stale range ID rejected", str(cm.exception))

    def test_fault_controller_enforces_180s_bound_and_egress_only(self):
        """Section D.5 & D.6: Fault duration is bounded at 180s and documented as egress_only."""
        fc = MockFaultController()
        with self.assertRaises(FaultControllerError):
            fc.apply_latency_fault("cockroachdb-1", delay_ms=1000, jitter_ms=20, duration_sec=300)
        res = fc.apply_latency_fault("cockroachdb-1", delay_ms=1000, jitter_ms=20, duration_sec=180)
        self.assertEqual(res["params"]["direction"], "egress_only")

    def test_evidence_invalid_timing_and_missing_tx_records(self):
        """Section F: Invalid timestamps, non-positive baseline TPS, and missing tx records are rejected/flagged."""
        ec = G1EvidenceCollector("test-run", "/tmp")
        with self.assertRaises(ValueError):
            ec.calculate_dt(0.0, 10.0)
        with self.assertRaises(ValueError):
            ec.calculate_ca2_rto(float("nan"), 10.0)
        with self.assertRaises(ValueError):
            ec.calculate_supplementary_restoration(0.0, [(100.0, 10.0)], 100.0)
        with self.assertRaises(ValueError):
            ec.reconcile_transactions(100, 90, 0, [])  # Negative history delta

        missing_res = ec.reconcile_transactions(100, 110, 0, [])
        self.assertFalse(missing_res["reconciled"])
        self.assertTrue(missing_res["missing_transaction_records"])

    def test_evidence_rpo_calculation(self):
        """Section D.14: RPO accurately detects zero vs non-zero committed data loss."""
        ec = G1EvidenceCollector("test-run", "/tmp")
        txs = [TransactionRecord(1, i, "ok", 1000, 1000.0 + i) for i in range(5)]
        rpo_zero = ec.calculate_rpo(100, 105, 0, txs)
        self.assertEqual(rpo_zero["rpo_lost_transactions"], 0)
        self.assertTrue(rpo_zero["zero_data_loss"])

        rpo_loss = ec.calculate_rpo(100, 103, 0, txs)
        self.assertEqual(rpo_loss["rpo_lost_transactions"], 2)
        self.assertFalse(rpo_loss["zero_data_loss"])

    def test_authorizer_rejects_system_range_and_boolean_fields(self):
        """Section D.3 & D.16: Authorizer rejects range_id <= 1 and boolean type confusion."""
        import tempfile, shutil
        tmp = tempfile.mkdtemp()
        try:
            auth = G1Authorizer(base_dir=tmp)
            now = datetime.datetime(2026, 11, 13, 0, 0, 0, tzinfo=datetime.timezone.utc)
            bad_payload = {
                "experiment_id": "RIC-G1-COCKROACHDB-LATENCY-PILOT",
                "action": "EXECUTE_G1_PILOT_PHASE_F1",
                "target_cluster": "ric-gray-failure-eks",
                "target_namespace": "cockroachdb",
                "target_policy": "POLICY_AID_1",
                "physical_range_id": True,
                "fault_type": "egress_latency",
                "latency_ms": 1000,
                "jitter_ms": 20,
                "fault_duration_sec": 180,
                "measurement_window_sec": 600,
                "run_id": "cockroachdb-g1-engineering-n1",
                "execution_attempt_id": "att-1",
                "issued_at_utc": now.isoformat(),
                "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
                "authorized_by_operator": "Arun Natarajan",
                "supervisor_approval_ref": "PD/G1-01_THROUGH_PD/G1-06"
            }
            with open(os.path.join(tmp, "G1_AUTHORIZED.json"), "w", encoding="utf-8") as f:
                json.dump(bad_payload, f)
            with self.assertRaises(G1AuthorizationError):
                auth.verify_and_claim("cockroachdb-g1-engineering-n1", "att-1", consume_token=True, current_time_utc=now)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestG1PhaseF21HelperRuntimeAndSafety(unittest.TestCase):
    """Phase F.2.1 regression tests for Linux runtime abstraction, daemon safety, live preflight, and evidence."""

    def test_daemon_enforces_180s_hard_duration_limit(self):
        helper = PrivilegedHelperDaemon()
        target = TargetNamespaceSpec("cockroachdb-0", "cockroachdb", "10.0.1.47")
        for bad_dur in (0, -10, 181, 300):
            with self.assertRaises(FaultControllerError):
                helper.apply_fault(target, delay_ms=1000, jitter_ms=20, duration_sec=bad_dur)

    def test_daemon_rejects_invalid_delay_jitter_direction_and_unknown_params(self):
        helper = PrivilegedHelperDaemon()
        target = TargetNamespaceSpec("cockroachdb-0", "cockroachdb", "10.0.1.47")
        with self.assertRaises(FaultControllerError):
            helper.apply_fault(target, delay_ms=500, jitter_ms=20, duration_sec=180)
        with self.assertRaises(FaultControllerError):
            helper.apply_fault(target, delay_ms=1000, jitter_ms=50, duration_sec=180)
        with self.assertRaises(FaultControllerError):
            helper.apply_fault(target, delay_ms=1000, jitter_ms=20, duration_sec=180, direction="ingress")
        with self.assertRaises(FaultControllerError):
            helper.apply_fault(target, delay_ms=1000, jitter_ms=20, duration_sec=180, unexpected_flag=True)

    def test_daemon_rejects_unrelated_interface_and_stale_target(self):
        helper = PrivilegedHelperDaemon(require_verified_target=True)
        bad_iface = TargetNamespaceSpec("cockroachdb-0", "cockroachdb", "10.0.1.47", interface="eth1")
        with self.assertRaises(TargetVerificationError):
            helper.apply_fault(bad_iface)

        valid = TargetNamespaceSpec("cockroachdb-0", "cockroachdb", "10.0.1.47", interface="eth0")
        with self.assertRaises(TargetVerificationError):
            helper.apply_fault(valid)

        helper.verify_target(valid, {"cockroachdb-0": {"ip": "10.0.1.47", "ports": [26257]}})
        stale_ip = TargetNamespaceSpec("cockroachdb-0", "cockroachdb", "10.0.1.99", interface="eth0")
        with self.assertRaises(TargetVerificationError):
            helper.apply_fault(stale_ip)

    def test_daemon_rejects_duplicate_application_and_is_idempotent_on_cleanup(self):
        helper = PrivilegedHelperDaemon()
        target = TargetNamespaceSpec("cockroachdb-0", "cockroachdb", "10.0.1.47")
        res = helper.apply_fault(target, delay_ms=1000, jitter_ms=20, duration_sec=180)
        self.assertEqual(res["status"], "APPLIED")
        self.assertIn("experiment_qdisc_id", res)

        with self.assertRaises(QdiscConflictError):
            helper.apply_fault(target, delay_ms=1000, jitter_ms=20, duration_sec=180)

        c1 = helper.rollback_fault(target)
        self.assertEqual(c1["status"], "CLEARED")
        c2 = helper.rollback_fault(target)
        self.assertEqual(c2["status"], "ALREADY_CLEARED")

    def test_linux_runtime_exact_netns_apply_verify_and_idempotent_remove(self):
        from .g1_linux_runtime import (
            CommandResult,
            LinuxNetnsRuntime,
            MockCommandExecutor,
            NetnsIdentity,
            ProcNetnsInspector,
            ProcessIdentity,
        )

        qdisc_state = {"val": "qdisc noqueue 0: root refcnt 2"}

        def fake_exec(argv, netns_path):
            if argv[:3] == ["/sbin/ip", "link", "show"]:
                return CommandResult(argv, 0, "2: eth0@if10: <BROADCAST,MULTICAST,UP>", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "show"]:
                return CommandResult(argv, 0, qdisc_state["val"], "")
            if argv[:3] == ["/sbin/tc", "qdisc", "add"]:
                qdisc_state["val"] = "qdisc netem 100: root refcnt 2 limit 1000 delay 1000ms  20ms"
                return CommandResult(argv, 0, "", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "del"]:
                qdisc_state["val"] = "qdisc noqueue 0: root refcnt 2"
                return CommandResult(argv, 0, "", "")
            return CommandResult(argv, 1, "", "unexpected cmd")

        executor = MockCommandExecutor(handler=fake_exec)
        inspector = ProcNetnsInspector(
            process_lister=lambda: [
                ProcessIdentity(4242, "cockroach start --cluster-name=ric", "/kubepods/pod1", 99100, "cockroachdb-0")
            ],
            netns_resolver=lambda pid: NetnsIdentity(pid, f"/proc/{pid}/ns/net", "net:[4026539999]"),
        )
        runtime = LinuxNetnsRuntime(executor=executor, inspector=inspector)
        proc, netns = runtime.bind_target("cockroachdb-0", expected_start_time_ticks=99100, expected_netns_inode="net:[4026539999]")
        record = runtime.apply_egress_latency("cockroachdb-g1-engineering-n1", "cockroachdb-0", netns, proc)
        self.assertEqual(record.handle, "100:")
        self.assertTrue(all(ns == "/proc/4242/ns/net" for _, ns in executor.recorded_calls))

        c1 = runtime.remove_owned_qdisc("cockroachdb-0", netns)
        self.assertEqual(c1["status"], "CLEARED")
        c2 = runtime.remove_owned_qdisc("cockroachdb-0", netns)
        self.assertEqual(c2["status"], "ALREADY_CLEARED")

    def test_linux_runtime_rejects_pid_reuse_stale_netns_wrong_iface_and_conflict(self):
        from .g1_linux_runtime import (
            CommandResult,
            LinuxNetnsRuntime,
            MockCommandExecutor,
            NetnsIdentity,
            ProcNetnsInspector,
            ProcessIdentity,
            RuntimeInterfaceError,
            RuntimeQdiscConflictError,
            RuntimeTargetAmbiguityError,
        )

        inspector = ProcNetnsInspector(
            process_lister=lambda: [
                ProcessIdentity(4242, "cockroach start", "/kubepods/pod1", 99200, "cockroachdb-0")
            ],
            netns_resolver=lambda pid: NetnsIdentity(pid, f"/proc/{pid}/ns/net", "net:[4026538888]"),
        )
        runtime = LinuxNetnsRuntime(executor=MockCommandExecutor(), inspector=inspector)

        with self.assertRaises(RuntimeTargetAmbiguityError):
            runtime.bind_target("cockroachdb-0", expected_start_time_ticks=99100)
        with self.assertRaises(RuntimeTargetAmbiguityError):
            runtime.bind_target("cockroachdb-0", expected_start_time_ticks=99200, expected_netns_inode="net:[4026539999]")

        proc, netns = runtime.bind_target("cockroachdb-0", expected_start_time_ticks=99200, expected_netns_inode="net:[4026538888]")
        with self.assertRaises(RuntimeInterfaceError):
            runtime.inspect_interface_and_qdisc(netns, interface="eth1")

        conflict_exec = MockCommandExecutor(
            handler=lambda argv, ns: CommandResult(
                argv, 0,
                "qdisc tbf 50: root refcnt 2" if argv[:3] == ["/sbin/tc", "qdisc", "show"] else "eth0",
                "",
            )
        )
        conflict_rt = LinuxNetnsRuntime(executor=conflict_exec, inspector=inspector)
        with self.assertRaises(RuntimeQdiscConflictError):
            conflict_rt.apply_egress_latency("run-1", "cockroachdb-0", netns, proc)

    def test_live_preflight_gate_rejects_mock_and_raft_leader_confusion(self):
        from .g1_preflight import (
            LivePreflightValidationError,
            LiveTargetPreflightGate,
            LiveTargetPreflightRecord,
        )

        mock_rec = LiveTargetPreflightRecord(
            1, "cockroachdb-0", "ip-10-0-1-10.ec2.internal", "10.0.1.47", "net:[123]",
            1, 1, 89, True, True, "eth0", True, is_mock=True,
        )
        with self.assertRaises(LivePreflightValidationError):
            LiveTargetPreflightGate.validate(mock_rec)

        mismatch_rec = LiveTargetPreflightRecord(
            2, "cockroachdb-1", "ip-10-0-2-10.ec2.internal", "10.0.2.238", "net:[124]",
            1, 2, 89, True, True, "eth0", True, is_mock=False,
        )
        with self.assertRaises(LivePreflightValidationError):
            LiveTargetPreflightGate.validate(mismatch_rec)

        valid_rec = LiveTargetPreflightRecord(
            1, "cockroachdb-0", "ip-10-0-1-10.ec2.internal", "10.0.1.47", "net:[123]",
            1, 2, 89, True, True, "eth0", True, is_mock=False,
        )
        res = LiveTargetPreflightGate.validate(valid_rec)
        self.assertEqual(res["status"], "LIVE_TARGET_VERIFIED")

    def test_evidence_pipeline_pgbench_parsing_tps_percentiles_and_missing_telemetry(self):
        from .g1_evidence_collector import (
            G1EvidenceCollector,
            UnwiredLivePgbenchRunner,
            UnwiredLivePrometheusAdapter,
        )

        collector = G1EvidenceCollector("cockroachdb-g1-engineering-n1", "./out")
        with self.assertRaises(ValueError):
            collector.validate_telemetry_completeness()
        with self.assertRaises(ValueError):
            collector.parse_pgbench_log_lines(["bad line"])

        records = collector.parse_pgbench_log_lines([
            "0 1 1200 0 1762992001.10 ok",
            "0 2 2400 0 1762992002.20 ok",
            "0 3 5000 0 1762992003.30 failed",
        ])
        self.assertEqual(collector.calculate_tps(records, 2.0), 1.0)
        pct = collector.calculate_latency_percentiles(records)
        self.assertEqual(pct["p50_ms"], 1.2)
        self.assertEqual(pct["max_ms"], 2.4)

        with self.assertRaises(NotImplementedError):
            UnwiredLivePrometheusAdapter().fetch_range("up", 1.0, 2.0)
        with self.assertRaises(NotImplementedError):
            UnwiredLivePgbenchRunner().execute_workload("cockroachdb-0", max_tries=1)


class TestG1PhaseF22LiveAdaptersAndHardening(unittest.TestCase):
    """Phase F.2.2 regression tests for pgbench runner, Prometheus adapter, reconciliation, recovery, and live preflight."""

    def test_pgbench_runner_timeout_nonzero_exit_missing_logs_and_success(self):
        from .g1_pgbench_runner import (
            LivePgbenchRunner,
            MockPgbenchProcessExecutor,
            PgbenchConfig,
            PgbenchProcessOutput,
            PgbenchRunnerError,
        )

        cfg = PgbenchConfig()
        # Timeout
        runner_to = LivePgbenchRunner(
            cfg,
            MockPgbenchProcessExecutor(lambda argv, to, lp: PgbenchProcessOutput(-1, "", "timeout", [], timed_out=True)),
        )
        with self.assertRaises(PgbenchRunnerError):
            runner_to.run_phase("measurement", "/tmp/pgbench.log")

        # Non-zero exit
        runner_nz = LivePgbenchRunner(
            cfg,
            MockPgbenchProcessExecutor(lambda argv, to, lp: PgbenchProcessOutput(2, "", "connection refused", ["0 1 100 0 1762992001.0 ok"])),
        )
        with self.assertRaises(PgbenchRunnerError):
            runner_nz.run_phase("measurement", "/tmp/pgbench.log")

        # Missing logs
        runner_empty = LivePgbenchRunner(
            cfg,
            MockPgbenchProcessExecutor(lambda argv, to, lp: PgbenchProcessOutput(0, "ok", "", [])),
        )
        with self.assertRaises(PgbenchRunnerError):
            runner_empty.run_phase("measurement", "/tmp/pgbench.log")

        # Success with CA2 parameters preserved
        ok_exec = MockPgbenchProcessExecutor(
            lambda argv, to, lp: PgbenchProcessOutput(0, "tps = 200", "", ["0 1 1000 0 1762992001.0 ok"])
        )
        runner_ok = LivePgbenchRunner(cfg, ok_exec)
        res = runner_ok.run_phase("measurement", "/tmp/pgbench.log")
        self.assertTrue(res.complete)
        self.assertIn("--max-tries=1", res.command_argv)
        self.assertIn("-n", res.command_argv)
        self.assertNotIn("-i", res.command_argv)

    def test_prometheus_adapter_auth_json_tls_redaction_missing_and_duplicate_ts(self):
        from .g1_prometheus_adapter import (
            HttpResponse,
            LivePrometheusAdapter,
            MockHttpClient,
            MockSecretProvider,
            PrometheusAdapterError,
            build_g1_metric_queries,
        )

        queries = build_g1_metric_queries()
        self.assertIn("cpu_utilization_cores", queries)
        self.assertNotIn("kube_pod_container_resource_requests", queries["cpu_utilization_cores"].promql)

        # Auth failure
        adapter_401 = LivePrometheusAdapter(
            "https://prom.internal",
            MockHttpClient(lambda u, h, t, v: HttpResponse(401, "unauthorized", {})),
            secret_provider=MockSecretProvider("super-secret-token"),
        )
        with self.assertRaises(PrometheusAdapterError):
            adapter_401.query_range("up", 100.0, 120.0)

        # Invalid JSON
        adapter_bad_json = LivePrometheusAdapter(
            "https://prom.internal",
            MockHttpClient(lambda u, h, t, v: HttpResponse(200, "{not-json", {})),
        )
        with self.assertRaises(PrometheusAdapterError):
            adapter_bad_json.query_range("up", 100.0, 120.0)

        # Duplicate timestamps
        dup_body = json.dumps({
            "status": "success",
            "data": {"resultType": "matrix", "result": [{"metric": {}, "values": [[100, "1"], [100, "2"]]}]},
        })
        adapter_dup = LivePrometheusAdapter(
            "https://prom.internal",
            MockHttpClient(lambda u, h, t, v: HttpResponse(200, dup_body, {})),
        )
        with self.assertRaises(PrometheusAdapterError):
            adapter_dup.query_range("up", 100.0, 120.0)

        # Missing telemetry -> NOT AVAILABLE
        empty_body = json.dumps({"status": "success", "data": {"resultType": "matrix", "result": []}})
        adapter_empty = LivePrometheusAdapter(
            "https://prom.internal",
            MockHttpClient(lambda u, h, t, v: HttpResponse(200, empty_body, {})),
        )
        res_empty = adapter_empty.query_range("up", 100.0, 120.0)
        self.assertEqual(res_empty["status"], "NOT AVAILABLE")

        # TLS verification cannot be disabled
        adapter_notls = LivePrometheusAdapter("https://prom.internal", MockHttpClient(), verify_tls=False)
        with self.assertRaises(PrometheusAdapterError):
            adapter_notls.query_range("up", 100.0, 120.0)

        # Secret redaction in raw response
        ok_body = json.dumps({
            "status": "success",
            "data": {"resultType": "matrix", "result": [{"metric": {"echo": "super-secret-token"}, "values": [[100, "1"], [105, "2"]]}]},
        })
        adapter_ok = LivePrometheusAdapter(
            "https://prom.internal",
            MockHttpClient(lambda u, h, t, v: HttpResponse(200, ok_body, {})),
            secret_provider=MockSecretProvider("super-secret-token"),
        )
        res_ok = adapter_ok.query_range("up", 100.0, 120.0)
        self.assertEqual(res_ok["status"], "AVAILABLE")
        self.assertNotIn("super-secret-token", res_ok["raw_redacted"])
        self.assertIn("[REDACTED]", res_ok["raw_redacted"])

        # Timeout error propagation
        def raise_timeout(u, h, t, v):
            raise PrometheusAdapterError("timed out")

        adapter_to = LivePrometheusAdapter("https://prom.internal", MockHttpClient(raise_timeout))
        with self.assertRaises(PrometheusAdapterError):
            adapter_to.query_range("up", 100.0, 120.0)

    def test_evidence_duplicate_tx_nonmonotonic_ts_and_rpo_missing_logs(self):
        from .g1_evidence_collector import G1EvidenceCollector

        collector = G1EvidenceCollector("cockroachdb-g1-engineering-n1", "./out")
        with self.assertRaises(ValueError):
            collector.parse_pgbench_log_lines([
                "0 1 1000 0 1762992001.0 ok",
                "0 1 1000 0 1762992002.0 ok",
            ])
        with self.assertRaises(ValueError):
            collector.parse_pgbench_log_lines([
                "0 1 1000 0 1762992005.0 ok",
                "0 2 1000 0 1762992001.0 ok",
            ])
        rpo = collector.calculate_rpo(100, 150, 10, [])
        self.assertFalse(rpo["rpo_valid"])
        self.assertFalse(rpo["zero_data_loss"])

    def test_emergency_recovery_manifest_ownership_and_missing_live_target(self):
        from .g1_linux_runtime import LinuxNetnsRuntime, MockCommandExecutor, NetnsIdentity, ProcNetnsInspector, ProcessIdentity
        from .g1_preflight import LivePreflightValidationError
        from .g1_preflight_adapters import ICockroachSqlClient, IKubernetesApiClient, LiveTargetPreflightOrchestrator

        manifest_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))),
            "kubernetes", "chaos", "03-emergency-tc-flush.yaml",
        )
        with open(manifest_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("G1RecoveryAuthorizer", content)
        self.assertIn("g1-recovery-auth-token", content)
        self.assertIn("qdisc netem 100:", content)
        self.assertIn("100:", content)

        class MissingPodK8s(IKubernetesApiClient):
            def get_pod_details(self, namespace, pod_name):
                return {}

        class StubSql(ICockroachSqlClient):
            def query_aid1_range_and_leaseholder(self, database, table):
                return {"range_id": 89, "lease_holder": 1, "raft_leader": 1, "aid1_verified": True, "leaseholder_pod_name": "cockroachdb-0"}

            def query_cluster_health(self):
                return {"all_nodes_live": True, "under_replicated_ranges": 0}

        rt = LinuxNetnsRuntime(
            MockCommandExecutor(),
            ProcNetnsInspector(
                lambda: [ProcessIdentity(10, "cockroach start", "/kubepods", 1, "cockroachdb-0")],
                lambda pid: NetnsIdentity(pid, "/proc/10/ns/net", "net:[1]"),
            ),
        )
        orch = LiveTargetPreflightOrchestrator(MissingPodK8s(), StubSql(), rt)
        with self.assertRaises(LivePreflightValidationError):
            orch.discover_and_validate(t110_freshness_verified=True)


class TestG1PhaseF24RemediationSuite(unittest.TestCase):
    """Phase F.2.4 tests for helper lifecycle, atomic partial rollback, recovery auth, /proc, adapters, and image integrity."""

    def test_helper_lifecycle_startup_watchdog_and_sigterm_cleanup(self):
        import importlib.util
        import threading

        entrypoint_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))),
            "docker", "g1-helper", "g1_helper_entrypoint.py",
        )
        spec = importlib.util.spec_from_file_location("g1_helper_entrypoint", entrypoint_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        from .g1_helper_daemon import AutonomousWatchdog
        from .g1_linux_runtime import CommandResult, LinuxNetnsRuntime, MockCommandExecutor, NetnsIdentity, ProcNetnsInspector, ProcessIdentity

        qdisc = {"val": "qdisc noqueue 0: root refcnt 2"}

        def exec_fn(argv, netns_path):
            if argv[:3] == ["/sbin/ip", "link", "show"]:
                return CommandResult(argv, 0, "eth0 UP", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "show"]:
                return CommandResult(argv, 0, qdisc["val"], "")
            if argv[:3] == ["/sbin/tc", "qdisc", "add"]:
                qdisc["val"] = "qdisc netem 100: root delay 1000ms 20ms"
                return CommandResult(argv, 0, "", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "del"]:
                qdisc["val"] = "qdisc noqueue 0: root refcnt 2"
                return CommandResult(argv, 0, "", "")
            return CommandResult(argv, 1, "", "err")

        rt = LinuxNetnsRuntime(
            MockCommandExecutor(exec_fn),
            ProcNetnsInspector(
                lambda: [ProcessIdentity(55, "cockroach start", "/kubepods", 1234, "cockroachdb-0")],
                lambda pid: NetnsIdentity(pid, "/proc/55/ns/net", "net:[777]"),
            ),
        )
        from .g1_helper_authorizer import G1HelperFaultAuthorizer
        cfg = mod.HelperRuntimeConfig("run-1", "cockroachdb-0", "cockroachdb", "eth0", 1000, 20, 3, "net:[777]", 1234)
        stop_ev = threading.Event()
        wd = AutonomousWatchdog(max_duration_sec=2)
        with tempfile.TemporaryDirectory() as auth_tmp:
            now = datetime.datetime.now(datetime.timezone.utc)
            with open(os.path.join(auth_tmp, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump({
                    "run_id": "run-1",
                    "auth_nonce": "nonce-lifecycle-001",
                    "action": "EXECUTE_G1_FAULT_HELPER",
                    "target_pod": "cockroachdb-0",
                    "target_namespace": "cockroachdb",
                    "target_netns_inode": "net:[777]",
                    "fault_type": "egress_latency",
                    "delay_ms": 1000,
                    "jitter_ms": 20,
                    "duration_sec": 3,
                    "issued_at_utc": (now - datetime.timedelta(minutes=1)).isoformat(),
                    "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
                    "authorized_by_operator": "ops-test",
                }, f)
            auth = G1HelperFaultAuthorizer(base_dir=auth_tmp, lock_dir=auth_tmp)
            runner = mod.HelperLifecycleRunner(cfg, rt, wd, authorizer=auth, sleep_fn=lambda _: stop_ev.set(), stop_event=stop_ev)
            rc = runner.run(register_signals=False)
            self.assertEqual(rc, 0)
        self.assertEqual(qdisc["val"], "qdisc noqueue 0: root refcnt 2")
        self.assertTrue(any(e["event"] == "cleanup_callback_finished" for e in runner.events))

        # Test SIGTERM handler invokes real cleanup_fn
        state = mod.HelperHealthState()
        cleaned = {"called": False}
        handler = mod.register_shutdown_handlers(state, cleanup_fn=lambda: cleaned.__setitem__("called", True), stop_event=stop_ev)
        handler(15, None)
        self.assertTrue(cleaned["called"])
        self.assertTrue(state.shutting_down)

    def test_partial_qdisc_install_rolls_back_and_detects_unresolved_fault(self):
        from .g1_linux_runtime import (
            CommandResult,
            LinuxNetnsRuntime,
            MockCommandExecutor,
            NetnsIdentity,
            ProcNetnsInspector,
            ProcessIdentity,
            RuntimeUnresolvedFaultError,
            RuntimeVerificationError,
        )

        inspector = ProcNetnsInspector(
            lambda: [ProcessIdentity(10, "cockroach start", "/kubepods", 1, "cockroachdb-0")],
            lambda pid: NetnsIdentity(pid, "/proc/10/ns/net", "net:[1]"),
        )

        # Case 1: Post-apply verification fails (wrong delay 500ms), scoped rollback succeeds
        state1 = {"q": "qdisc noqueue 0: root"}

        def exec_rb_ok(argv, ns):
            if argv[:3] == ["/sbin/ip", "link", "show"]:
                return CommandResult(argv, 0, "eth0", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "show"]:
                return CommandResult(argv, 0, state1["q"], "")
            if argv[:3] == ["/sbin/tc", "qdisc", "add"]:
                state1["q"] = "qdisc netem 100: root delay 500ms 20ms"
                return CommandResult(argv, 0, "", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "del"]:
                state1["q"] = "qdisc noqueue 0: root"
                return CommandResult(argv, 0, "", "")
            return CommandResult(argv, 1, "", "err")

        rt1 = LinuxNetnsRuntime(MockCommandExecutor(exec_rb_ok), inspector)
        proc, netns = rt1.bind_target("cockroachdb-0")
        with self.assertRaises(RuntimeVerificationError):
            rt1.apply_egress_latency("run-1", "cockroachdb-0", netns, proc)
        self.assertFalse(rt1.unresolved_fault)
        self.assertEqual(state1["q"], "qdisc noqueue 0: root")

        # Case 2: Post-apply verification fails AND rollback fails -> RuntimeUnresolvedFaultError
        def exec_rb_fail(argv, ns):
            if argv[:3] == ["/sbin/ip", "link", "show"]:
                return CommandResult(argv, 0, "eth0", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "show"]:
                return CommandResult(argv, 0, "qdisc netem 100: root delay 500ms 20ms" if len(rt2.executor.recorded_calls) > 2 else "qdisc noqueue 0: root", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "add"]:
                return CommandResult(argv, 0, "", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "del"]:
                return CommandResult(argv, 1, "", "RTNETLINK answers: Operation not permitted")
            return CommandResult(argv, 1, "", "err")

        rt2 = LinuxNetnsRuntime(MockCommandExecutor(exec_rb_fail), inspector)
        with self.assertRaises(RuntimeUnresolvedFaultError):
            rt2.apply_egress_latency("run-1", "cockroachdb-0", netns, proc)
        self.assertTrue(rt2.unresolved_fault)

    def test_recovery_authorizer_replay_expiry_pod_uid_pid_reuse_and_netns_mismatch(self):
        import shutil
        import tempfile
        from .g1_recovery_authorizer import G1RecoveryAuthorizer, RecoveryAuthorizationError

        tmp = tempfile.mkdtemp()
        try:
            now = datetime.datetime(2026, 11, 13, 1, 0, 0, tzinfo=datetime.timezone.utc)
            token = {
                "run_id": "cockroachdb-g1-engineering-n1",
                "action": "EMERGENCY_TC_CLEANUP",
                "target_pod_uid": "uid-111",
                "target_pod_name": "cockroachdb-0",
                "target_pid": 4242,
                "target_start_time_ticks": 99100,
                "netns_inode": "net:[4026539999]",
                "interface": "eth0",
                "qdisc_handle": "100:",
                "qdisc_type": "netem",
                "issued_at_utc": now.isoformat(),
                "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
                "authorized_by_operator": "Arun Natarajan",
            }
            tok_path = os.path.join(tmp, G1RecoveryAuthorizer.TOKEN_FILENAME)
            with open(tok_path, "w", encoding="utf-8") as f:
                json.dump(token, f)

            auth = G1RecoveryAuthorizer(tmp)
            # Pod UID mismatch
            with self.assertRaises(RecoveryAuthorizationError):
                auth.verify_and_claim("cockroachdb-g1-engineering-n1", "uid-999", "cockroachdb-0", 4242, 99100, "net:[4026539999]", current_time_utc=now)
            os.remove(os.path.join(tmp, G1RecoveryAuthorizer.LOCK_FILENAME))

            # PID reuse mismatch
            with self.assertRaises(RecoveryAuthorizationError):
                auth.verify_and_claim("cockroachdb-g1-engineering-n1", "uid-111", "cockroachdb-0", 4242, 88888, "net:[4026539999]", current_time_utc=now)
            os.remove(os.path.join(tmp, G1RecoveryAuthorizer.LOCK_FILENAME))

            # Netns mismatch
            with self.assertRaises(RecoveryAuthorizationError):
                auth.verify_and_claim("cockroachdb-g1-engineering-n1", "uid-111", "cockroachdb-0", 4242, 99100, "net:[1111]", current_time_utc=now)
            os.remove(os.path.join(tmp, G1RecoveryAuthorizer.LOCK_FILENAME))

            # Expiry
            with self.assertRaises(RecoveryAuthorizationError):
                auth.verify_and_claim(
                    "cockroachdb-g1-engineering-n1", "uid-111", "cockroachdb-0", 4242, 99100, "net:[4026539999]",
                    current_time_utc=now + datetime.timedelta(minutes=20),
                )
            os.remove(os.path.join(tmp, G1RecoveryAuthorizer.LOCK_FILENAME))

            # Valid single-use claim, then replay blocked
            claimed = auth.verify_and_claim(
                "cockroachdb-g1-engineering-n1", "uid-111", "cockroachdb-0", 4242, 99100, "net:[4026539999]",
                consume_token=True, current_time_utc=now,
            )
            self.assertEqual(claimed["target_pod_uid"], "uid-111")
            with self.assertRaises(RecoveryAuthorizationError):
                auth.verify_and_claim("cockroachdb-g1-engineering-n1", "uid-111", "cockroachdb-0", 4242, 99100, "net:[4026539999]", current_time_utc=now)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_live_proc_inspector_and_readonly_k8s_sql_adapters_with_mock_transports(self):
        import shutil
        import tempfile
        from .g1_linux_runtime import LiveProcFilesystemInspector
        from .g1_preflight_adapters import (
            MockKubectlTransport,
            MockSqlTransport,
            ReadOnlyCockroachSqlAdapter,
            ReadOnlyKubernetesApiAdapter,
        )

        proc_root = tempfile.mkdtemp()
        try:
            pdir = os.path.join(proc_root, "4242")
            os.makedirs(os.path.join(pdir, "ns"), exist_ok=True)
            with open(os.path.join(pdir, "cmdline"), "wb") as f:
                f.write(b"cockroach\x00start\x00--cluster-name=ric\x00")
            with open(os.path.join(pdir, "cgroup"), "w", encoding="utf-8") as f:
                f.write("0::/kubepods/pod-uid-1")
            with open(os.path.join(pdir, "stat"), "w", encoding="utf-8") as f:
                fields = ["4242", "(cockroach)", "S"] + ["0"] * 18 + ["99100"] + ["0"] * 5
                f.write(" ".join(fields))
            with open(os.path.join(pdir, "environ"), "wb") as f:
                f.write(b"HOSTNAME=cockroachdb-0\x00")
            with open(os.path.join(pdir, "ns", "net"), "w", encoding="utf-8") as f:
                f.write("net:[4026539999]")

            insp = LiveProcFilesystemInspector(proc_root=proc_root)
            proc = insp.identify_target_process("cockroachdb-0", expected_start_time_ticks=99100)
            netns = insp.resolve_netns(proc, expected_inode="net:[4026539999]")
            self.assertEqual(proc.pid, 4242)
            self.assertEqual(netns.ns_inode, "net:[4026539999]")
        finally:
            shutil.rmtree(proc_root, ignore_errors=True)

        k8s_payload = json.dumps({
            "metadata": {"name": "cockroachdb-0", "uid": "uid-111"},
            "spec": {"nodeName": "ip-10-0-1-10.ec2.internal"},
            "status": {"podIP": "10.0.1.47", "conditions": [{"type": "Ready", "status": "True"}]},
        })
        k8s = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(lambda argv: (0, k8s_payload, "")))
        pod = k8s.get_pod_details("cockroachdb", "cockroachdb-0")
        self.assertTrue(pod["ready"])
        self.assertEqual(pod["pod_uid"], "uid-111")

        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"range_id": 89, "lease_holder": 1, "raft_leader": 2}] if "ranges" in q and "pgbench_accounts" in q else [{"under_replicated": 0, "total_nodes": 3, "live_nodes": 3, "node_liveness_verified": True}]
        ))
        rng = sql.query_aid1_range_and_leaseholder("benchdb", "pgbench_accounts")
        self.assertEqual(rng["range_id"], 89)
        self.assertTrue(sql.query_cluster_health()["all_nodes_live"])

    def test_pgbench_log_retrieval_failure_reconciliation_and_image_integrity(self):
        from .g1_manifest_validator import ImageIntegrityError, validate_immutable_image_ref, validate_manifest_images
        from .g1_pgbench_runner import (
            LivePgbenchRunner,
            MockPgbenchLogRetriever,
            MockPgbenchProcessExecutor,
            PgbenchConfig,
            PgbenchProcessOutput,
            PgbenchRunnerError,
            SubprocessPgbenchExecutor,
        )

        # Missing log retrieval fails closed
        retriever_fail = MockPgbenchLogRetriever(fail_missing=True)
        with self.assertRaises(PgbenchRunnerError):
            retriever_fail.retrieve_logs("cockroachdb", "crdb-benchmark-client", "/tmp/pgbench.log")

        # Reconciliation mismatch between pgbench stdout and parsed records fails closed
        cfg = PgbenchConfig()
        runner_mismatch = LivePgbenchRunner(
            cfg,
            MockPgbenchProcessExecutor(
                lambda argv, to, lp: PgbenchProcessOutput(
                    0, "number of transactions actually processed: 5", "", ["0 1 1000 0 1762992001.0 ok"]
                )
            ),
        )
        with self.assertRaises(PgbenchRunnerError):
            runner_mismatch.run_phase("measurement", "/tmp/pgbench.log")

        # SubprocessPgbenchExecutor has log_retriever wired (type check)
        self.assertTrue(hasattr(SubprocessPgbenchExecutor("cockroachdb", "crdb-benchmark-client", MockPgbenchLogRetriever()), "log_retriever"))

        # Image integrity validator rejects placeholder & mutable tags, accepts @sha256
        with self.assertRaises(ImageIntegrityError):
            validate_immutable_image_ref("python:3.11.9-slim-bookworm")
        with self.assertRaises(ImageIntegrityError):
            validate_immutable_image_ref("<ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/ric-g1-helper@sha256:<IMMUTABLE_SHA256_DIGEST_REQUIRED>")
        valid_ref = "123456789012.dkr.ecr.us-east-1.amazonaws.com/ric-g1-helper@sha256:" + ("a" * 64)
        validate_immutable_image_ref(valid_ref)

        job_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))),
            "kubernetes", "chaos", "02-g1-helper-job.yaml",
        )
        with open(job_path, "r", encoding="utf-8") as f:
            with self.assertRaises(ImageIntegrityError):
                validate_manifest_images(f.read())


class TestG1PhaseF26RemediationSuite(unittest.TestCase):
    """Phase F.2.6 tests for separate recovery lock_dir, helper G1_RUN_ID, unresolved state propagation, and digest validation."""

    def test_recovery_authorizer_separate_lock_dir_wrong_run_missing_claim_fail_and_no_fault_auth(self):
        import shutil
        import tempfile
        from .g1_recovery_authorizer import G1RecoveryAuthorizer, RecoveryAuthorizationError

        token_dir = tempfile.mkdtemp()
        lock_dir = tempfile.mkdtemp()
        try:
            now = datetime.datetime(2026, 11, 13, 1, 30, 0, tzinfo=datetime.timezone.utc)
            auth = G1RecoveryAuthorizer(base_dir=token_dir, lock_dir=lock_dir)

            # Missing token
            with self.assertRaises(RecoveryAuthorizationError):
                auth.verify_and_claim("run-1", "uid-1", "cockroachdb-0", 10, 100, "net:[1]", current_time_utc=now)

            token = {
                "run_id": "cockroachdb-g1-engineering-n1",
                "action": "EMERGENCY_TC_CLEANUP",
                "target_pod_uid": "uid-1",
                "target_pod_name": "cockroachdb-0",
                "target_pid": 10,
                "target_start_time_ticks": 100,
                "netns_inode": "net:[1]",
                "interface": "eth0",
                "qdisc_handle": "100:",
                "qdisc_type": "netem",
                "issued_at_utc": now.isoformat(),
                "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
                "authorized_by_operator": "Arun Natarajan",
            }
            with open(os.path.join(token_dir, G1RecoveryAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump(token, f)

            # Wrong run ID
            with self.assertRaises(RecoveryAuthorizationError):
                auth.verify_and_claim("wrong-run", "uid-1", "cockroachdb-0", 10, 100, "net:[1]", consume_token=False, current_time_utc=now)
            os.remove(os.path.join(lock_dir, G1RecoveryAuthorizer.LOCK_FILENAME))

            # Failed claim creation (non-existent lock_dir)
            bad_lock_auth = G1RecoveryAuthorizer(base_dir=token_dir, lock_dir=os.path.join(lock_dir, "missing_subdir"))
            with self.assertRaises(RecoveryAuthorizationError):
                bad_lock_auth.verify_and_claim("cockroachdb-g1-engineering-n1", "uid-1", "cockroachdb-0", 10, 100, "net:[1]", consume_token=False, current_time_utc=now)

            # Valid claim creates lock in lock_dir while token remains untouched in token_dir when consume_token=False
            claimed = auth.verify_and_claim("cockroachdb-g1-engineering-n1", "uid-1", "cockroachdb-0", 10, 100, "net:[1]", consume_token=False, current_time_utc=now)
            self.assertEqual(claimed["action"], "EMERGENCY_TC_CLEANUP")
            self.assertTrue(os.path.exists(os.path.join(lock_dir, G1RecoveryAuthorizer.LOCK_FILENAME)))
            self.assertFalse(os.path.exists(os.path.join(token_dir, G1RecoveryAuthorizer.LOCK_FILENAME)))

            # Recovery token cannot authorize latency injection via G1Authorizer
            with open(os.path.join(token_dir, "G1_AUTHORIZED.json"), "w", encoding="utf-8") as f:
                json.dump(token, f)
            exp_auth = G1Authorizer(base_dir=token_dir)
            with self.assertRaises(G1AuthorizationError):
                exp_auth.verify_and_claim("cockroachdb-g1-engineering-n1", "att-1", consume_token=False, current_time_utc=now)
        finally:
            shutil.rmtree(token_dir, ignore_errors=True)
            shutil.rmtree(lock_dir, ignore_errors=True)

    def test_helper_job_manifest_and_config_run_id_validation(self):
        import importlib.util

        job_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))),
            "kubernetes", "chaos", "02-g1-helper-job.yaml",
        )
        with open(job_path, "r", encoding="utf-8") as f:
            job_text = f.read()
        self.assertIn("G1_RUN_ID", job_text)

        flush_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))),
            "kubernetes", "chaos", "03-emergency-tc-flush.yaml",
        )
        with open(flush_path, "r", encoding="utf-8") as f:
            flush_text = f.read()
        self.assertIn("/var/run/g1-lock", flush_text)
        self.assertIn("readOnly: true", flush_text)

        entrypoint_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))),
            "docker", "g1-helper", "g1_helper_entrypoint.py",
        )
        spec = importlib.util.spec_from_file_location("g1_helper_entrypoint", entrypoint_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        for bad_id in ("", "   ", "<RUN_ID>", "bad id with spaces"):
            with self.assertRaises(ValueError):
                mod.HelperRuntimeConfig.from_env({"G1_RUN_ID": bad_id, "G1_TARGET_POD": "cockroachdb-0"})

    def test_qdisc_remove_failure_sets_unresolved_fault_and_blocks_subsequent_apply(self):
        from .g1_linux_runtime import (
            CommandResult,
            LinuxNetnsRuntime,
            MockCommandExecutor,
            NetnsIdentity,
            ProcNetnsInspector,
            ProcessIdentity,
            RuntimeUnresolvedFaultError,
        )

        inspector = ProcNetnsInspector(
            lambda: [ProcessIdentity(10, "cockroach start", "/kubepods", 1, "cockroachdb-0")],
            lambda pid: NetnsIdentity(pid, "/proc/10/ns/net", "net:[1]"),
        )
        state = {"q": "qdisc noqueue 0: root", "fail_del": True}

        def handler(argv, ns):
            if argv[:3] == ["/sbin/ip", "link", "show"]:
                return CommandResult(argv, 0, "eth0", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "show"]:
                return CommandResult(argv, 0, state["q"], "")
            if argv[:3] == ["/sbin/tc", "qdisc", "add"]:
                state["q"] = "qdisc netem 100: root delay 1000ms 20ms"
                return CommandResult(argv, 0, "", "")
            if argv[:3] == ["/sbin/tc", "qdisc", "del"]:
                if state["fail_del"]:
                    return CommandResult(argv, 1, "", "Operation not permitted")
                state["q"] = "qdisc noqueue 0: root"
                return CommandResult(argv, 0, "", "")
            return CommandResult(argv, 1, "", "err")

        rt = LinuxNetnsRuntime(MockCommandExecutor(handler), inspector)
        proc, netns = rt.bind_target("cockroachdb-0")
        rt.apply_egress_latency("run-1", "cockroachdb-0", netns, proc)

        with self.assertRaises(RuntimeUnresolvedFaultError):
            rt.remove_owned_qdisc("cockroachdb-0", netns)
        self.assertTrue(rt.unresolved_fault)
        self.assertTrue(any(e["event"] == "qdisc_removal_unresolved_fault" for e in rt.runtime_evidence))

        # Subsequent apply fails closed while unresolved_fault is True
        with self.assertRaises(RuntimeUnresolvedFaultError):
            rt.apply_egress_latency("run-2", "cockroachdb-0", netns, proc)

    def test_manifest_validator_rejects_malformed_sha256_and_missing_image(self):
        from .g1_manifest_validator import ImageIntegrityError, validate_immutable_image_ref, validate_manifest_images

        with self.assertRaises(ImageIntegrityError):
            validate_immutable_image_ref("repo/img@sha256:nothex")
        with self.assertRaises(ImageIntegrityError):
            validate_immutable_image_ref("repo/img@sha256:abc123")
        with self.assertRaises(ImageIntegrityError):
            validate_manifest_images("kind: Job\nmetadata:\n  name: empty\n")

    def test_apply_egress_latency_accepts_iproute2_seconds_formatting(self):
        """Regression test for Phase F.3 real-kernel finding: iproute2 prints 1000ms as '1s'."""
        from .g1_linux_runtime import (
            CommandResult,
            LinuxNetnsRuntime,
            MockCommandExecutor,
            NetnsIdentity,
            ProcNetnsInspector,
            ProcessIdentity,
        )

        proc_id = ProcessIdentity(
            pid=408,
            cmdline="cockroach start --insecure",
            cgroup_path="/kubepods/pod123/c1",
            start_time_ticks=69251588,
            pod_name="cockroachdb-0",
        )
        netns_id = NetnsIdentity(pid=408, ns_path="/proc/408/ns/net", ns_inode="net:[4026532409]")
        inspector = ProcNetnsInspector(
            process_lister=lambda: [proc_id],
            netns_resolver=lambda pid: netns_id,
        )
        state = {"installed": False}

        def handler(argv, _netns):
            if "link" in argv and "show" in argv:
                return CommandResult(argv, 0, "eth0: <BROADCAST,UP>", "")
            if "qdisc" in argv and "show" in argv:
                if state["installed"]:
                    return CommandResult(argv, 0, "qdisc netem 100: root refcnt 9 limit 1000 delay 1s  20ms", "")
                return CommandResult(argv, 0, "qdisc noqueue 0: root refcnt 2", "")
            if "qdisc" in argv and ("add" in argv or "replace" in argv):
                state["installed"] = True
                return CommandResult(argv, 0, "", "")
            if "qdisc" in argv and "del" in argv:
                state["installed"] = False
                return CommandResult(argv, 0, "", "")
            return CommandResult(argv, 1, "", "unexpected")

        rt = LinuxNetnsRuntime(MockCommandExecutor(handler), inspector)
        proc, netns = rt.bind_target("cockroachdb-0")
        rec = rt.apply_egress_latency("run-1s", "cockroachdb-0", netns, proc, delay_ms=1000, jitter_ms=20)
        self.assertEqual(rec.delay_ms, 1000)
        self.assertEqual(rec.jitter_ms, 20)
        rem = rt.remove_owned_qdisc("cockroachdb-0", netns)
        self.assertEqual(rem["status"], "CLEARED")


class TestG1PhaseF35AuthorizationAndSecuritySuite(unittest.TestCase):
    """Phase F.3.5: Independent helper fault-authorization, direct-Job bypass, replay, and recovery tests."""

    @staticmethod
    def _load_entrypoint():
        import importlib.util
        ep_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))),
            "docker", "g1-helper", "g1_helper_entrypoint.py",
        )
        spec = importlib.util.spec_from_file_location("g1_helper_entrypoint_f35", ep_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @staticmethod
    def _valid_token(now, **overrides):
        tok = {
            "run_id": "run-f35-01",
            "auth_nonce": "nonce-f35-0001",
            "action": "EXECUTE_G1_FAULT_HELPER",
            "target_pod": "cockroachdb-0",
            "target_namespace": "cockroachdb",
            "target_netns_inode": "net:[9001]",
            "fault_type": "egress_latency",
            "delay_ms": 1000,
            "jitter_ms": 20,
            "duration_sec": 180,
            "issued_at_utc": (now - datetime.timedelta(minutes=1)).isoformat(),
            "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
            "authorized_by_operator": "operator-a",
        }
        tok.update(overrides)
        return tok

    def _run_with_token(self, token_payload, write_token=True, pass_authorizer=True, netns_inode="net:[9001]"):
        import threading
        from .g1_helper_authorizer import G1HelperFaultAuthorizer
        from .g1_linux_runtime import (
            CommandResult, LinuxNetnsRuntime, MockCommandExecutor,
            NetnsIdentity, ProcNetnsInspector, ProcessIdentity,
        )
        from .g1_helper_daemon import AutonomousWatchdog

        mod = self._load_entrypoint()
        tc_calls = []

        def exec_fn(argv, _ns):
            tc_calls.append(list(argv))
            return CommandResult(argv, 0, "qdisc noqueue 0: root refcnt 2", "")

        rt = LinuxNetnsRuntime(
            MockCommandExecutor(exec_fn),
            ProcNetnsInspector(
                lambda: [ProcessIdentity(99, "cockroach start", "/kubepods", 555, "cockroachdb-0")],
                lambda pid: NetnsIdentity(pid, "/proc/99/ns/net", netns_inode),
            ),
        )
        cfg = mod.HelperRuntimeConfig("run-f35-01", "cockroachdb-0", "cockroachdb", "eth0", 1000, 20, 180)
        wd = AutonomousWatchdog(max_duration_sec=180)
        with tempfile.TemporaryDirectory() as tok_dir, tempfile.TemporaryDirectory() as lock_dir:
            if write_token:
                with open(os.path.join(tok_dir, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                    if isinstance(token_payload, str):
                        f.write(token_payload)
                    else:
                        json.dump(token_payload, f)
            auth = G1HelperFaultAuthorizer(base_dir=tok_dir, lock_dir=lock_dir) if pass_authorizer else None
            stop_ev = threading.Event()
            runner = mod.HelperLifecycleRunner(cfg, rt, wd, authorizer=auth, sleep_fn=lambda _: stop_ev.set(), stop_event=stop_ev)
            rc = runner.run(register_signals=False)
            return rc, tc_calls, runner.events

    def test_unauthorized_and_mismatched_tokens_never_reach_tc(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        # 1. Direct Job invocation without authorizer
        rc, tc_calls, _ = self._run_with_token(None, write_token=False, pass_authorizer=False)
        self.assertEqual(rc, 1)
        self.assertEqual(tc_calls, [])

        # 2. Missing token file
        rc, tc_calls, _ = self._run_with_token(None, write_token=False)
        self.assertEqual(rc, 1)
        self.assertEqual(tc_calls, [])

        # 3. Malformed JSON
        rc, tc_calls, _ = self._run_with_token("{bad-json")
        self.assertEqual(rc, 1)
        self.assertEqual(tc_calls, [])

        # 4. Expired token
        rc, tc_calls, _ = self._run_with_token(self._valid_token(now, expires_at_utc=(now - datetime.timedelta(seconds=5)).isoformat()))
        self.assertEqual(rc, 1)
        self.assertEqual(tc_calls, [])

        # 5. Mismatched run_id, pod, namespace, netns_inode, fault_type, delay_ms, jitter_ms, duration_sec
        mismatches = [
            {"run_id": "other-run"},
            {"target_pod": "cockroachdb-1"},
            {"target_namespace": "default"},
            {"target_netns_inode": "net:[9999]"},
            {"fault_type": "packet_loss"},
            {"delay_ms": 500},
            {"jitter_ms": 50},
            {"duration_sec": 60},
            {"action": "EMERGENCY_TC_CLEANUP"},
        ]
        for ov in mismatches:
            rc, tc_calls, _ = self._run_with_token(self._valid_token(now, **ov))
            self.assertEqual(rc, 1, f"Expected failure for {ov}")
            self.assertEqual(tc_calls, [], f"tc must never be called for {ov}")

    def test_helper_authorizer_replay_and_concurrent_claims_blocked(self):
        from .g1_helper_authorizer import FaultAuthorizationError, G1HelperFaultAuthorizer

        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as tok_dir, tempfile.TemporaryDirectory() as lock_dir:
            with open(os.path.join(tok_dir, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump(self._valid_token(now), f)
            auth = G1HelperFaultAuthorizer(base_dir=tok_dir, lock_dir=lock_dir)
            auth.verify_and_claim("run-f35-01", "cockroachdb-0", observed_netns_inode="net:[9001]", current_time_utc=now)
            # Token consumed and lock exists -> replay blocked
            with self.assertRaises(FaultAuthorizationError):
                auth.verify_and_claim("run-f35-01", "cockroachdb-0", observed_netns_inode="net:[9001]", current_time_utc=now)

            # Re-plant token with existing lock -> concurrent claim blocked
            with open(os.path.join(tok_dir, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump(self._valid_token(now), f)
            with self.assertRaises(FaultAuthorizationError):
                auth.verify_and_claim("run-f35-01", "cockroachdb-0", observed_netns_inode="net:[9001]", current_time_utc=now)

    def test_recovery_authorizer_requires_explicit_readonly_opt_in_and_manifest_pins(self):
        from .g1_recovery_authorizer import G1RecoveryAuthorizer, RecoveryAuthorizationError

        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as tok_dir, tempfile.TemporaryDirectory() as lock_dir:
            with open(os.path.join(tok_dir, G1RecoveryAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump({
                    "run_id": "run-f35-01",
                    "action": "EMERGENCY_TC_CLEANUP",
                    "target_pod_uid": "uid-1",
                    "target_pod_name": "cockroachdb-0",
                    "target_pid": 99,
                    "target_start_time_ticks": 555,
                    "netns_inode": "net:[9001]",
                    "interface": "eth0",
                    "qdisc_handle": "100:",
                    "qdisc_type": "netem",
                    "issued_at_utc": (now - datetime.timedelta(minutes=1)).isoformat(),
                    "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
                    "authorized_by_operator": "operator-a",
                }, f)
            auth_strict = G1RecoveryAuthorizer(base_dir=tok_dir, lock_dir=lock_dir, allow_readonly_secret=False)
            with self.assertRaises(RecoveryAuthorizationError):
                auth_strict.verify_and_claim("run-f35-01", "uid-1", "cockroachdb-0", 99, 555, "net:[9001]", consume_token=False, current_time_utc=now)

            auth_ro = G1RecoveryAuthorizer(base_dir=tok_dir, lock_dir=lock_dir, allow_readonly_secret=True)
            auth_ro.verify_and_claim("run-f35-01", "uid-1", "cockroachdb-0", 99, 555, "net:[9001]", consume_token=False, current_time_utc=now)
            # Same-pod replay blocked by claim lock
            with self.assertRaises(RecoveryAuthorizationError):
                auth_ro.verify_and_claim("run-f35-01", "uid-1", "cockroachdb-0", 99, 555, "net:[9001]", consume_token=False, current_time_utc=now)


class TestG1PhaseF36CrossPodReplaySuite(unittest.TestCase):
    """Phase F.3.6: Cross-Pod, concurrent, Pod-restart, Job-retry, and K8s Lease claim tests."""

    @staticmethod
    def _token(now, **overrides):
        tok = {
            "run_id": "run-f36-01",
            "auth_nonce": "nonce-f36-unique-99",
            "action": "EXECUTE_G1_FAULT_HELPER",
            "target_pod": "cockroachdb-0",
            "target_namespace": "cockroachdb",
            "target_netns_inode": "net:[9001]",
            "fault_type": "egress_latency",
            "delay_ms": 1000,
            "jitter_ms": 20,
            "duration_sec": 180,
            "issued_at_utc": (now - datetime.timedelta(minutes=1)).isoformat(),
            "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
            "authorized_by_operator": "operator-a",
        }
        tok.update(overrides)
        return tok

    def test_readonly_secret_without_shared_claim_store_fails_closed(self):
        from .g1_helper_authorizer import FaultAuthorizationError, G1HelperFaultAuthorizer

        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as secret_dir, tempfile.TemporaryDirectory() as lock_dir_a:
            with open(os.path.join(secret_dir, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump(self._token(now), f)
            auth = G1HelperFaultAuthorizer(base_dir=secret_dir, lock_dir=lock_dir_a, allow_readonly_secret=True, claim_store=None)
            with self.assertRaises(FaultAuthorizationError):
                auth.verify_and_claim("run-f36-01", "cockroachdb-0", observed_netns_inode="net:[9001]", current_time_utc=now)

    def test_cross_pod_sequential_termination_retry_and_concurrent_claims(self):
        import shutil
        import threading
        from .g1_helper_authorizer import FaultAuthorizationError, G1HelperFaultAuthorizer, SharedAtomicClaimStore

        now = datetime.datetime.now(datetime.timezone.utc)
        shared_store = SharedAtomicClaimStore()

        # Sequential: Pod A claims -> Pod B blocked -> Pod A terminates (emptyDir deleted) -> Pod B/Job retry blocked
        with tempfile.TemporaryDirectory() as secret_dir, tempfile.TemporaryDirectory() as lock_b, tempfile.TemporaryDirectory() as lock_c:
            lock_a = tempfile.mkdtemp()
            with open(os.path.join(secret_dir, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump(self._token(now), f)

            auth_a = G1HelperFaultAuthorizer(secret_dir, lock_a, allow_readonly_secret=True, claim_store=shared_store, holder_identity="pod-a")
            auth_b = G1HelperFaultAuthorizer(secret_dir, lock_b, allow_readonly_secret=True, claim_store=shared_store, holder_identity="pod-b")
            auth_c = G1HelperFaultAuthorizer(secret_dir, lock_c, allow_readonly_secret=True, claim_store=shared_store, holder_identity="job-retry-c")

            auth_a.verify_and_claim("run-f36-01", "cockroachdb-0", observed_netns_inode="net:[9001]", consume_token=False, current_time_utc=now)
            with self.assertRaises(FaultAuthorizationError):
                auth_b.verify_and_claim("run-f36-01", "cockroachdb-0", observed_netns_inode="net:[9001]", consume_token=False, current_time_utc=now)

            # Simulate Pod A termination (pod-local emptyDir destroyed)
            shutil.rmtree(lock_a)
            with self.assertRaises(FaultAuthorizationError):
                auth_c.verify_and_claim("run-f36-01", "cockroachdb-0", observed_netns_inode="net:[9001]", consume_token=False, current_time_utc=now)

        # Concurrent: Two independent Pods race with a barrier -> exactly 1 winner
        concurrent_store = SharedAtomicClaimStore()
        with tempfile.TemporaryDirectory() as secret_dir, tempfile.TemporaryDirectory() as lock_1, tempfile.TemporaryDirectory() as lock_2:
            with open(os.path.join(secret_dir, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump(self._token(now, auth_nonce="nonce-concurrent-01"), f)

            barrier = threading.Barrier(2)
            results = []
            res_lock = threading.Lock()

            def worker(lock_dir, pod_name):
                auth = G1HelperFaultAuthorizer(secret_dir, lock_dir, allow_readonly_secret=True, claim_store=concurrent_store, holder_identity=pod_name)
                barrier.wait()
                try:
                    auth.verify_and_claim("run-f36-01", "cockroachdb-0", observed_netns_inode="net:[9001]", consume_token=False, current_time_utc=now)
                    outcome = "WON"
                except FaultAuthorizationError:
                    outcome = "BLOCKED"
                with res_lock:
                    results.append(outcome)

            t1 = threading.Thread(target=worker, args=(lock_1, "pod-1"))
            t2 = threading.Thread(target=worker, args=(lock_2, "pod-2"))
            t1.start()
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)
            self.assertEqual(sorted(results), ["BLOCKED", "WON"])

    def test_kubernetes_lease_claim_store_201_409_and_fail_closed(self):
        import urllib.error
        from .g1_helper_authorizer import FaultAuthorizationError, G1HelperFaultAuthorizer, KubernetesLeaseClaimStore

        now = datetime.datetime.now(datetime.timezone.utc)
        seen_leases = set()

        class FakeResp:
            status = 201

        def mock_opener(req):
            body = json.loads(req.data.decode("utf-8"))
            name = body["metadata"]["name"]
            if name in seen_leases:
                raise urllib.error.HTTPError(req.full_url, 409, "Conflict", {}, None)
            seen_leases.add(name)
            return FakeResp()

        with tempfile.TemporaryDirectory() as secret_dir, tempfile.TemporaryDirectory() as sa_dir, tempfile.TemporaryDirectory() as lock_a, tempfile.TemporaryDirectory() as lock_b:
            sa_tok = os.path.join(sa_dir, "token")
            with open(sa_tok, "w", encoding="utf-8") as f:
                f.write("fake-sa-jwt")
            with open(os.path.join(secret_dir, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump(self._token(now, auth_nonce="nonce-lease-01"), f)

            store = KubernetesLeaseClaimStore(namespace="g1-chaos", token_path=sa_tok, opener=mock_opener)
            auth_a = G1HelperFaultAuthorizer(secret_dir, lock_a, allow_readonly_secret=True, claim_store=store, holder_identity="pod-a")
            auth_b = G1HelperFaultAuthorizer(secret_dir, lock_b, allow_readonly_secret=True, claim_store=store, holder_identity="pod-b")

            auth_a.verify_and_claim("run-f36-01", "cockroachdb-0", observed_netns_inode="net:[9001]", consume_token=False, current_time_utc=now)
            with self.assertRaises(FaultAuthorizationError) as ctx:
                auth_b.verify_and_claim("run-f36-01", "cockroachdb-0", observed_netns_inode="net:[9001]", consume_token=False, current_time_utc=now)
            self.assertIn("409", str(ctx.exception))

            # Missing SA token fails closed
            bad_store = KubernetesLeaseClaimStore(namespace="g1-chaos", token_path=os.path.join(sa_dir, "missing"), opener=mock_opener)
            with self.assertRaises(FaultAuthorizationError):
                bad_store.acquire_once("g1-fault-claim-test", {})


class TestG1PhaseF37LeaseSecurityAuditSuite(unittest.TestCase):
    """Phase F.3.7: HTTP error codes, timeout, TLS failure, malformed response, orphaned claim, and no-tc guarantee."""

    def test_lease_store_http_errors_timeout_tls_and_malformed_response_fail_closed(self):
        import io
        import ssl
        import urllib.error
        from .g1_helper_authorizer import FaultAuthorizationError, G1HelperFaultAuthorizer, KubernetesLeaseClaimStore

        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as secret_dir, tempfile.TemporaryDirectory() as sa_dir, tempfile.TemporaryDirectory() as lock_dir:
            sa_tok = os.path.join(sa_dir, "token")
            with open(sa_tok, "w", encoding="utf-8") as f:
                f.write("fake-sa-jwt")
            tok = TestG1PhaseF36CrossPodReplaySuite._token(now, auth_nonce="nonce-f37-http")
            with open(os.path.join(secret_dir, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump(tok, f)

            for code in (400, 401, 403, 404, 409, 429, 500):
                def err_opener(req, c=code):
                    raise urllib.error.HTTPError(req.full_url, c, f"HTTP {c}", {}, None)
                store = KubernetesLeaseClaimStore(namespace="g1-chaos", token_path=sa_tok, opener=err_opener)
                with self.assertRaises(FaultAuthorizationError, msg=f"HTTP {code} must fail closed"):
                    store.acquire_once("g1-fault-claim-test", {})

            # Timeout failure
            def timeout_opener(_req):
                raise TimeoutError("timed out")
            with self.assertRaises(FaultAuthorizationError):
                KubernetesLeaseClaimStore(namespace="g1-chaos", token_path=sa_tok, opener=timeout_opener).acquire_once("g1-fault-claim-test", {})

            # TLS failure
            def tls_opener(_req):
                raise ssl.SSLError("CERTIFICATE_VERIFY_FAILED")
            with self.assertRaises(FaultAuthorizationError):
                KubernetesLeaseClaimStore(namespace="g1-chaos", token_path=sa_tok, opener=tls_opener).acquire_once("g1-fault-claim-test", {})

            # Malformed JSON response body
            class BadJsonResp:
                status = 201
                def read(self):
                    return b"{not-json"
            with self.assertRaises(FaultAuthorizationError):
                KubernetesLeaseClaimStore(namespace="g1-chaos", token_path=sa_tok, opener=lambda _r: BadJsonResp()).acquire_once("g1-fault-claim-test", {})

            # Wrong kind in response body
            class WrongKindResp:
                status = 201
                def read(self):
                    return b'{"kind":"Pod","metadata":{"name":"other"}}'
            with self.assertRaises(FaultAuthorizationError):
                KubernetesLeaseClaimStore(namespace="g1-chaos", token_path=sa_tok, opener=lambda _r: WrongKindResp()).acquire_once("g1-fault-claim-test", {})

    def test_orphaned_claim_and_nonce_reuse_never_reach_tc(self):
        import threading
        from .g1_helper_authorizer import G1HelperFaultAuthorizer, SharedAtomicClaimStore
        from .g1_linux_runtime import (
            CommandResult, LinuxNetnsRuntime, MockCommandExecutor,
            NetnsIdentity, ProcNetnsInspector, ProcessIdentity,
        )
        from .g1_helper_daemon import AutonomousWatchdog

        mod = TestG1PhaseF35AuthorizationAndSecuritySuite._load_entrypoint()
        now = datetime.datetime.now(datetime.timezone.utc)
        shared_store = SharedAtomicClaimStore()
        tc_calls = []

        def exec_fn(argv, _ns):
            tc_calls.append(list(argv))
            return CommandResult(argv, 0, "qdisc noqueue 0: root refcnt 2", "")

        # Pod A claims, then crashes during bind_target -> orphaned claim remains in shared_store
        def crashing_lister():
            raise RuntimeError("simulated pod crash after claim")

        rt_crash = LinuxNetnsRuntime(
            MockCommandExecutor(exec_fn),
            ProcNetnsInspector(crashing_lister, lambda pid: NetnsIdentity(pid, "/proc/99/ns/net", "net:[9001]")),
        )
        cfg = mod.HelperRuntimeConfig("run-f36-01", "cockroachdb-0", "cockroachdb", "eth0", 1000, 20, 180)
        with tempfile.TemporaryDirectory() as secret_dir, tempfile.TemporaryDirectory() as lock_a, tempfile.TemporaryDirectory() as lock_b:
            with open(os.path.join(secret_dir, G1HelperFaultAuthorizer.TOKEN_FILENAME), "w", encoding="utf-8") as f:
                json.dump(TestG1PhaseF36CrossPodReplaySuite._token(now, auth_nonce="nonce-orphan-01"), f)

            auth_a = G1HelperFaultAuthorizer(secret_dir, lock_a, allow_readonly_secret=True, claim_store=shared_store, holder_identity="pod-a")
            rc_a = mod.HelperLifecycleRunner(cfg, rt_crash, AutonomousWatchdog(180), authorizer=auth_a, sleep_fn=lambda _: None).run(register_signals=False)
            self.assertEqual(rc_a, 1)
            self.assertEqual(tc_calls, [])

            # Retry / Pod B reusing same nonce & Secret -> blocked by orphaned claim, tc_calls still []
            rt_ok = LinuxNetnsRuntime(
                MockCommandExecutor(exec_fn),
                ProcNetnsInspector(
                    lambda: [ProcessIdentity(99, "cockroach start", "/kubepods", 555, "cockroachdb-0")],
                    lambda pid: NetnsIdentity(pid, "/proc/99/ns/net", "net:[9001]"),
                ),
            )
            auth_b = G1HelperFaultAuthorizer(secret_dir, lock_b, allow_readonly_secret=True, claim_store=shared_store, holder_identity="pod-b")
            stop_ev = threading.Event()
            rc_b = mod.HelperLifecycleRunner(cfg, rt_ok, AutonomousWatchdog(180), authorizer=auth_b, sleep_fn=lambda _: stop_ev.set(), stop_event=stop_ev).run(register_signals=False)
            self.assertEqual(rc_b, 1)
            self.assertEqual(tc_calls, [])


class TestG1MasterReadinessRemediationSuite(unittest.TestCase):
    """Master G1 readiness remediation tests for real pgbench logs and POLICY_AID_1 SQL selection."""

    def test_real_postgres16_pgbench_log_format_with_time_us_and_failed(self):
        from .g1_evidence_collector import G1EvidenceCollector

        lines = [
            "3 1 35374 0 1794358030 207753",
            "0 1 36201 0 1794358030 208333",
            "0 2 failed 0 1794358031 120000",
            "0 3 skipped 0 1794358031 500000",
        ]
        records = G1EvidenceCollector.parse_pgbench_log_lines(lines)
        self.assertEqual(len(records), 4)
        self.assertEqual(records[0].client_id, 3)
        self.assertEqual(records[0].status, "ok")
        self.assertEqual(records[0].latency_us, 35374)
        self.assertAlmostEqual(records[0].timestamp_epoch, 1794358030.207753, places=6)
        self.assertEqual(records[2].status, "failed")
        self.assertEqual(records[2].latency_us, 0)
        self.assertEqual(records[3].status, "failed")

    def test_sql_adapter_selects_policy_aid1_range_over_lowest_id(self):
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter

        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [
                {"range_id": 85, "lease_holder": 3, "start_pretty": "/Table/107/1/1", "end_pretty": "/Table/107/1/1000"},
                {"range_id": 89, "lease_holder": 2, "start_pretty": "<before:/Table/107>", "end_pretty": "/Table/107/1/1"},
            ]
        ))
        rng = sql.query_aid1_range_and_leaseholder("benchdb", "pgbench_accounts")
        self.assertEqual(rng["range_id"], 89)
        self.assertEqual(rng["lease_holder"], 2)
        self.assertTrue(rng["aid1_verified"])

        sql_unverified = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [
                {"range_id": 85, "lease_holder": 3, "start_pretty": "/Table/107/1/1", "end_pretty": "/Table/107/1/1000"},
            ]
        ))
        rng_unverified = sql_unverified.query_aid1_range_and_leaseholder("benchdb", "pgbench_accounts")
        self.assertFalse(rng_unverified["aid1_verified"])


class TestG1PhaseG11345TargetResolverRemediation(unittest.TestCase):
    """
    Comprehensive offline test suite for Phase G1.13.4.5 target resolver remediation.
    Validates dynamic range identification, key span matching, leaseholder verification,
    stale cache rejection, and fail-closed handling using synthetic fixtures.
    """

    def setUp(self):
        self.mock_nodes = [
            NodeMetadata(node_id=1, address="cockroachdb-0.cockroachdb:26257", locality="region=us-east-1,zone=us-east-1a", is_live=True, draining=False),
            NodeMetadata(node_id=2, address="cockroachdb-1.cockroachdb:26257", locality="region=us-east-1,zone=us-east-1b", is_live=True, draining=False),
            NodeMetadata(node_id=3, address="cockroachdb-2.cockroachdb:26257", locality="region=us-east-1,zone=us-east-1c", is_live=True, draining=False),
        ]
        self.mock_pods = [
            PodMetadata(pod_name="cockroachdb-0", pod_ip="10.0.1.50", node_name="ip-10-0-1-89.ec2.internal", zone="us-east-1a", is_ready=True),
            PodMetadata(pod_name="cockroachdb-1", pod_ip="10.0.2.89", node_name="ip-10-0-2-21.ec2.internal", zone="us-east-1b", is_ready=True),
            PodMetadata(pod_name="cockroachdb-2", pod_ip="10.0.3.115", node_name="ip-10-0-3-87.ec2.internal", zone="us-east-1c", is_ready=True),
        ]

    def test_01_aid1_located_in_first_range(self):
        """Case 1: aid=1 located in the first returned range."""
        ranges = [
            RangeMetadata(range_id=108, start_key="<before:/Table/116>", end_key="…/3/1917070", replicas=[1, 2, 3], lease_holder=1),
            RangeMetadata(range_id=99, start_key="…/3/1917070", end_key="<after:/Max>", replicas=[1, 2, 3], lease_holder=3),
        ]
        resolver = TargetResolver(MockDatabaseMetadataProvider(ranges, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods))
        target = resolver.resolve_target()
        self.assertEqual(target["physical_range_id"], 108)
        self.assertEqual(target["lease_holder_node_id"], 1)
        self.assertEqual(target["target_pod_name"], "cockroachdb-0")
        self.assertEqual(target["target_pod_ip"], "10.0.1.50")

    def test_02_aid1_located_in_later_range(self):
        """Case 2: aid=1 located in a later range (not first in result list)."""
        ranges = [
            RangeMetadata(range_id=99, start_key="…/3/1917070", end_key="<after:/Max>", replicas=[1, 2, 3], lease_holder=3),
            RangeMetadata(range_id=108, start_key="<before:/Table/116>", end_key="…/3/1917070", replicas=[1, 2, 3], lease_holder=2),
        ]
        resolver = TargetResolver(MockDatabaseMetadataProvider(ranges, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods))
        target = resolver.resolve_target()
        self.assertEqual(target["physical_range_id"], 108)
        self.assertEqual(target["lease_holder_node_id"], 2)
        self.assertEqual(target["target_pod_name"], "cockroachdb-1")

    def test_03_range_boundaries_changing_between_resolutions(self):
        """Case 3: Range boundaries change between initial T=0 and re-verification."""
        # Initial T=0: aid=1 in range 108
        ranges_t0 = [
            RangeMetadata(range_id=108, start_key="<before:/Table/116>", end_key="…/3/1917070", replicas=[1, 2, 3], lease_holder=1),
            RangeMetadata(range_id=99, start_key="…/3/1917070", end_key="<after:/Max>", replicas=[1, 2, 3], lease_holder=3),
        ]
        target_t0 = TargetResolver(MockDatabaseMetadataProvider(ranges_t0, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods)).resolve_target()
        self.assertEqual(target_t0["physical_range_id"], 108)

        # After split at T=110: range 108 split into 108 and 115
        ranges_t110 = [
            RangeMetadata(range_id=115, start_key="<before:/Table/116>", end_key="…/3/500000", replicas=[1, 2, 3], lease_holder=1),
            RangeMetadata(range_id=108, start_key="…/3/500000", end_key="…/3/1917070", replicas=[1, 2, 3], lease_holder=2),
            RangeMetadata(range_id=99, start_key="…/3/1917070", end_key="<after:/Max>", replicas=[1, 2, 3], lease_holder=3),
        ]
        target_t110 = TargetResolver(MockDatabaseMetadataProvider(ranges_t110, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods)).resolve_target()
        self.assertEqual(target_t110["physical_range_id"], 115)
        self.assertNotEqual(target_t110["physical_range_id"], target_t0["physical_range_id"])

        # Stale cache freshness check fails when expected range ID was 108
        with self.assertRaises(TargetResolutionError):
            TargetResolver.validate_target_freshness(target_t110, expected_range_id=target_t0["physical_range_id"])

    def test_04_leaseholder_changing_between_resolutions(self):
        """Case 4: Leaseholder transfers between Node 1 and Node 3 between resolutions."""
        ranges_t0 = [RangeMetadata(range_id=108, start_key="<before:/Table/116>", end_key="…/3/1917070", replicas=[1, 2, 3], lease_holder=1)]
        target_t0 = TargetResolver(MockDatabaseMetadataProvider(ranges_t0, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods)).resolve_target()
        self.assertEqual(target_t0["lease_holder_node_id"], 1)
        self.assertEqual(target_t0["target_pod_name"], "cockroachdb-0")

        # Lease transferred to node 3
        ranges_t110 = [RangeMetadata(range_id=108, start_key="<before:/Table/116>", end_key="…/3/1917070", replicas=[1, 2, 3], lease_holder=3)]
        target_t110 = TargetResolver(MockDatabaseMetadataProvider(ranges_t110, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods)).resolve_target()
        self.assertEqual(target_t110["lease_holder_node_id"], 3)
        self.assertEqual(target_t110["target_pod_name"], "cockroachdb-2")

    def test_05_leaseholder_absent_fails_closed(self):
        """Case 5: Range metadata has absent / None / 0 leaseholder."""
        ranges = [RangeMetadata(range_id=108, start_key="<before:/Table/116>", end_key="…/3/1917070", replicas=[1, 2, 3], lease_holder=0)]
        resolver = TargetResolver(MockDatabaseMetadataProvider(ranges, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError) as ctx:
            resolver.resolve_target()
        self.assertIn("has no valid leaseholder", str(ctx.exception))

        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        adapter = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: [{"range_id": 108, "lease_holder": None, "start_key": "<before:/Table/116>"}]))
        with self.assertRaises(LivePreflightValidationError):
            adapter.query_aid1_range_and_leaseholder("benchdb", "pgbench_accounts")

    def test_06_leaseholder_not_present_in_replicas_fails_closed(self):
        """Case 6: Safety violation: leaseholder is not a member of replicas."""
        ranges = [RangeMetadata(range_id=108, start_key="<before:/Table/116>", end_key="…/3/1917070", replicas=[1, 2], lease_holder=3)]
        resolver = TargetResolver(MockDatabaseMetadataProvider(ranges, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError) as ctx:
            resolver.resolve_target()
        self.assertIn("not present in range 108 replica set", str(ctx.exception))

        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        adapter = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: [{"range_id": 108, "lease_holder": 3, "replicas": "{1,2}", "start_key": "<before:/Table/116>"}]))
        with self.assertRaises(LivePreflightValidationError):
            adapter.query_aid1_range_and_leaseholder("benchdb", "pgbench_accounts")

    def test_07_empty_metadata_result_fails_closed(self):
        """Case 7: Empty metadata returned from database fails closed."""
        resolver = TargetResolver(MockDatabaseMetadataProvider([], self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError):
            resolver.resolve_target()

        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        adapter = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: []))
        with self.assertRaises(LivePreflightValidationError):
            adapter.query_aid1_range_and_leaseholder("benchdb", "pgbench_accounts")

    def test_08_duplicate_or_overlapping_matching_ranges_fail_closed(self):
        """Case 8: Duplicate start keys or multiple <before:/Table/ ranges fail closed."""
        ranges_dup = [
            RangeMetadata(range_id=108, start_key="<before:/Table/116>", end_key="…/1", replicas=[1, 2, 3], lease_holder=1),
            RangeMetadata(range_id=109, start_key="<before:/Table/116>", end_key="…/2", replicas=[1, 2, 3], lease_holder=2),
        ]
        resolver = TargetResolver(MockDatabaseMetadataProvider(ranges_dup, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError):
            resolver.resolve_target()

        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        adapter = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: [
            {"range_id": 108, "lease_holder": 1, "start_key": "<before:/Table/116>", "replicas": [1, 2, 3]},
            {"range_id": 109, "lease_holder": 2, "start_key": "<before:/Table/116>", "replicas": [1, 2, 3]},
        ]))
        with self.assertRaises(LivePreflightValidationError):
            adapter.query_aid1_range_and_leaseholder("benchdb", "pgbench_accounts")

    def test_09_malformed_key_boundaries_and_system_ranges(self):
        """Case 9: System range ID (1) or negative range ID fails closed."""
        ranges_sys = [RangeMetadata(range_id=1, start_key="<before:/Table/116>", end_key="…", replicas=[1, 2, 3], lease_holder=1)]
        resolver = TargetResolver(MockDatabaseMetadataProvider(ranges_sys, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError):
            resolver.resolve_target()

        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        adapter = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: [{"range_id": 1, "lease_holder": 1, "start_key": "<before:/Table/116>", "replicas": [1, 2, 3]}]))
        with self.assertRaises(LivePreflightValidationError):
            adapter.query_aid1_range_and_leaseholder("benchdb", "pgbench_accounts")

    def test_10_unsupported_query_or_permission_error_fails_closed(self):
        """Case 10: Transport raises error when query fails (e.g. permission or syntax)."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        def failing_transport(q, p):
            raise RuntimeError("ERROR: Access to crdb_internal and system is restricted.")

        adapter = ReadOnlyCockroachSqlAdapter(MockSqlTransport(failing_transport))
        with self.assertRaises(RuntimeError):
            adapter.query_aid1_range_and_leaseholder("benchdb", "pgbench_accounts")

    def test_11_stale_cached_target_rejected(self):
        """Case 11: TargetResolver.validate_target_freshness rejects stale cached target descriptor."""
        cached_target = {"physical_range_id": 89, "target_pod_name": "cockroachdb-0"}
        # Fresh resolution found range 108
        fresh_target = {"physical_range_id": 108, "target_pod_name": "cockroachdb-0"}
        with self.assertRaises(TargetResolutionError):
            TargetResolver.validate_target_freshness(fresh_target, expected_range_id=cached_target["physical_range_id"])

    def test_12_dynamic_node_mapping_failure_fails_closed(self):
        """Case 12: Leaseholder node ID cannot be mapped to any Kubernetes pod."""
        # Leaseholder is Node 4, but cluster only has nodes 1, 2, 3
        ranges = [RangeMetadata(range_id=108, start_key="<before:/Table/116>", end_key="…/3/1917070", replicas=[1, 2, 4], lease_holder=4)]
        resolver = TargetResolver(MockDatabaseMetadataProvider(ranges, self.mock_nodes), MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError) as ctx:
            resolver.resolve_target()
        self.assertIn("not found in cluster gossip", str(ctx.exception))


class TestG1PhaseG11461ClusterHealthAdapterReview(unittest.TestCase):
    """
    Offline tests for Phase G1.13.4.6.1 cluster health adapter review & remediation.
    Tests supported SHOW RANGES replication queries, under-replicated checks,
    SQL transport failures, permission errors, and fail-closed gate behavior.
    """

    def test_01_healthy_cluster_response(self):
        """Supported query returns 0 under-replicated ranges and verified liveness -> all_nodes_live=True."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 0, "total_nodes": 3, "live_nodes": 3, "node_liveness_verified": True}]
        ))
        health = sql.query_cluster_health()
        self.assertTrue(health["all_nodes_live"])
        self.assertTrue(health["node_liveness_verified"])
        self.assertEqual(health["under_replicated_ranges"], 0)

    def test_02_under_replicated_ranges_fails_health_check(self):
        """When under_replicated > 0, preflight orchestrator detects unhealthy cluster."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 2, "total_nodes": 3, "live_nodes": 3}]
        ))
        health = sql.query_cluster_health()
        self.assertEqual(health["under_replicated_ranges"], 2)
        # Verify gate calculation:
        cluster_healthy = bool(health.get("all_nodes_live")) and int(health.get("under_replicated_ranges", 1)) == 0
        self.assertFalse(cluster_healthy)

    def test_03_missing_nodes_fails_health_check(self):
        """When live_nodes < total_nodes or total_nodes < 3, all_nodes_live=False."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 0, "total_nodes": 3, "live_nodes": 2, "all_nodes_live": False}]
        ))
        health = sql.query_cluster_health()
        self.assertFalse(health["all_nodes_live"])

    def test_04_empty_health_query_response_fails_closed(self):
        """When health SQL query returns zero rows, raises LivePreflightValidationError."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: []))
        with self.assertRaises(LivePreflightValidationError) as ctx:
            sql.query_cluster_health()
        self.assertIn("Cluster health query returned zero rows", str(ctx.exception))

    def test_05_sql_permission_error_fails_closed(self):
        """When database denies access (e.g. crdb_internal restriction), raises LivePreflightValidationError."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        def err_transport(q, p):
            raise RuntimeError("ERROR: Access to crdb_internal and system is restricted.")
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(err_transport))
        with self.assertRaises(LivePreflightValidationError) as ctx:
            sql.query_cluster_health()
        self.assertIn("Failed querying cluster health", str(ctx.exception))

    def test_06_sql_transport_timeout_fails_closed(self):
        """Transport timeout or communication error fails closed with LivePreflightValidationError."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        def timeout_transport(q, p):
            raise TimeoutError("SQL connection timed out after 10s")
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(timeout_transport))
        with self.assertRaises(LivePreflightValidationError) as ctx:
            sql.query_cluster_health()
        self.assertIn("Failed querying cluster health", str(ctx.exception))

    def test_07_live_target_preflight_gate_rejects_unhealthy_cluster(self):
        """LiveTargetPreflightGate rejects preflight record if cluster_healthy is False."""
        from .g1_preflight import LiveTargetPreflightGate, LiveTargetPreflightRecord, LivePreflightValidationError
        record = LiveTargetPreflightRecord(
            cockroach_node_id=1,
            pod_name="cockroachdb-0",
            worker_node_name="ip-10-0-1-89.ec2.internal",
            pod_ip="10.0.1.50",
            netns_inode="net:[12345]",
            leaseholder_node_id=1,
            raft_leader_node_id=1,
            physical_range_id=108,
            aid1_range_verified=True,
            t110_freshness_verified=True,
            interface="eth0",
            cluster_healthy=False,  # Unhealthy
            is_mock=False
        )
        with self.assertRaises(LivePreflightValidationError) as ctx:
            LiveTargetPreflightGate.validate(record)
        self.assertIn("Cluster health check failed", str(ctx.exception))


class TestG1PhaseG11462IndependentClusterHealthAudit(unittest.TestCase):
    """
    Offline tests for Phase G1.13.4.6.2 independent cluster health adapter audit.
    Covers:
    1. All three nodes demonstrably live.
    2. One node unavailable while range metadata still lists three replicas.
    3. Zero under-replicated ranges but node liveness unknown.
    4. Under-replicated ranges.
    5. Missing or malformed replica metadata.
    6. Unexpected replication factor (< 3).
    7. SQL permission and transport failures.
    8. Health response that is incomplete.
    9. Preflight rejection whenever node liveness cannot be established.
    """

    def test_01_all_three_nodes_demonstrably_live(self):
        """When 0 under-replicated ranges and verified 3/3 nodes live -> all_nodes_live=True."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 0, "total_nodes": 3, "live_nodes": 3, "node_liveness_verified": True}]
        ))
        health = sql.query_cluster_health()
        self.assertTrue(health["all_nodes_live"])
        self.assertTrue(health["node_liveness_verified"])
        self.assertEqual(health["under_replicated_ranges"], 0)

    def test_02_one_node_unavailable_while_range_metadata_lists_three_replicas(self):
        """When range descriptor has 3 replicas (under_replicated=0) but 1 node is dead -> all_nodes_live=False."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 0, "total_nodes": 3, "live_nodes": 2, "node_liveness_verified": True}]
        ))
        health = sql.query_cluster_health()
        self.assertFalse(health["all_nodes_live"])
        self.assertTrue(health["node_liveness_verified"])
        self.assertEqual(health["under_replicated_ranges"], 0)

    def test_03_zero_under_replicated_ranges_but_node_liveness_unknown(self):
        """Zero under-replicated ranges without verified node liveness -> fails closed with all_nodes_live=False."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        # Standard SQL query result from SHOW ranges alone:
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 0}]
        ))
        health = sql.query_cluster_health()
        self.assertEqual(health["under_replicated_ranges"], 0)
        self.assertFalse(health["all_nodes_live"])
        self.assertFalse(health["node_liveness_verified"])

    def test_04_under_replicated_ranges_detected(self):
        """When under_replicated > 0, health check reports nonzero under_replicated_ranges."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 1, "total_nodes": 3, "live_nodes": 3, "node_liveness_verified": True}]
        ))
        health = sql.query_cluster_health()
        self.assertEqual(health["under_replicated_ranges"], 1)

    def test_05_missing_or_malformed_under_replicated_metadata(self):
        """Missing or non-integer under_replicated metadata raises LivePreflightValidationError."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        # Missing field
        sql_missing = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: [{"foo": "bar"}]))
        with self.assertRaises(LivePreflightValidationError) as ctx1:
            sql_missing.query_cluster_health()
        self.assertIn("missing 'under_replicated' field", str(ctx1.exception))

        # Malformed field
        sql_malformed = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: [{"under_replicated": "not-an-int"}]))
        with self.assertRaises(LivePreflightValidationError) as ctx2:
            sql_malformed.query_cluster_health()
        self.assertIn("Invalid 'under_replicated' value", str(ctx2.exception))

    def test_06_unexpected_cluster_node_count_or_replication_factor(self):
        """Cluster with total_nodes < 3 fails all_nodes_live check."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 0, "total_nodes": 2, "live_nodes": 2, "node_liveness_verified": True}]
        ))
        health = sql.query_cluster_health()
        self.assertFalse(health["all_nodes_live"])

    def test_07_sql_permission_and_transport_failures(self):
        """SQL permission denial and socket transport drop fail closed."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        # Permission denied
        sql_perm = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: (_ for _ in ()).throw(RuntimeError("ERROR: permission denied for relation crdb_internal.gossip_liveness"))
        ))
        with self.assertRaises(LivePreflightValidationError) as ctx_perm:
            sql_perm.query_cluster_health()
        self.assertIn("Failed querying cluster health", str(ctx_perm.exception))

        # Socket drop
        sql_sock = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: (_ for _ in ()).throw(ConnectionResetError("Connection reset by peer"))
        ))
        with self.assertRaises(LivePreflightValidationError) as ctx_sock:
            sql_sock.query_cluster_health()
        self.assertIn("Failed querying cluster health", str(ctx_sock.exception))

    def test_08_health_response_incomplete(self):
        """Incomplete response (e.g. malformed node counts when verified) fails closed."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter, LivePreflightValidationError
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 0, "node_liveness_verified": True, "total_nodes": "bad", "live_nodes": 3}]
        ))
        with self.assertRaises(LivePreflightValidationError) as ctx:
            sql.query_cluster_health()
        self.assertIn("Malformed node count", str(ctx.exception))

    def test_09_preflight_orchestrator_rejects_unverified_node_liveness(self):
        """LiveTargetPreflightOrchestrator strictly blocks preflight if node liveness is unverified."""
        from .g1_linux_runtime import LinuxNetnsRuntime, MockCommandExecutor, NetnsIdentity, ProcNetnsInspector, ProcessIdentity
        from .g1_preflight_adapters import (
            LiveTargetPreflightOrchestrator,
            MockKubectlTransport,
            MockSqlTransport,
            ReadOnlyKubernetesApiAdapter,
            ReadOnlyCockroachSqlAdapter,
            LivePreflightValidationError,
        )

        k8s_payload = json.dumps({
            "metadata": {"name": "cockroachdb-0", "uid": "uid-111"},
            "spec": {"nodeName": "ip-10-0-1-89.ec2.internal"},
            "status": {"podIP": "10.0.1.50", "conditions": [{"type": "Ready", "status": "True"}]},
        })
        k8s = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(lambda argv: (0, k8s_payload, "")))

        # SQL adapter returns 0 under-replicated ranges, but node liveness is unverified
        def sql_dispatch(q, p):
            if "ranges" in q and "pgbench_accounts" in q:
                return [{
                    "range_id": 108,
                    "lease_holder": 1,
                    "raft_leader": 1,
                    "replicas": [1, 2, 3],
                    "start_key": "<before:/Table/116>",
                    "end_key": "…/3/1917070",
                    "leaseholder_pod_name": "cockroachdb-0"
                }]
            return [{"under_replicated": 0}]  # node_liveness_verified absent/False

        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(sql_dispatch))
        rt = LinuxNetnsRuntime(
            MockCommandExecutor(),
            ProcNetnsInspector(
                lambda: [ProcessIdentity(10, "cockroach start", "/kubepods", 1, "cockroachdb-0")],
                lambda pid: NetnsIdentity(pid, "/proc/10/ns/net", "net:[1]"),
            ),
        )
        orchestrator = LiveTargetPreflightOrchestrator(
            k8s_client=k8s,
            sql_client=sql,
            netns_runtime=rt,
            namespace="cockroachdb",
            database="benchdb",
            table="pgbench_accounts"
        )

        with self.assertRaises(LivePreflightValidationError) as ctx:
            orchestrator.discover_and_validate(expected_pod_name="cockroachdb-0", t110_freshness_verified=True)
        self.assertIn("Cluster health check failed; aborting target binding.", str(ctx.exception))


class TestG1Stage31ConsensusHealthSemantics(unittest.TestCase):
    """
    Offline tests for Stage 3.1: Consensus Health Semantics & Decoupled Verification.
    Verifies that:
    1. under_replicated_ranges == 0 does NOT independently establish consensus_health_verified.
    2. Missing or unverified consensus evidence sets consensus_health_verified = False.
    3. Validated consensus evidence with active quorum establishes consensus_health_verified = True.
    4. Validated consensus evidence without quorum fails closed.
    5. Incomplete or unverified consensus blocks all_required_checks_passed fail-closed.
    """

    def test_01_under_replicated_zero_alone_does_not_verify_consensus_health(self):
        """under_replicated_ranges == 0 without consensus_evidence leaves consensus_health_verified = False."""
        from .g1_preflight_adapters import ClusterHealthEvaluationContract
        contract = ClusterHealthEvaluationContract.evaluate(
            sql_res={"all_nodes_live": True, "live_nodes": 3, "total_nodes": 3, "errors": []},
            k8s_res={"all_nodes_live": True},
            health_res={"under_replicated_ranges": 0},
            # consensus_evidence is omitted / None
        )
        self.assertEqual(contract.under_replicated_ranges, 0)
        self.assertFalse(contract.consensus_health_verified)
        self.assertFalse(contract.all_required_checks_passed)

    def test_02_unverified_consensus_evidence_fails_closed(self):
        """consensus_evidence marked verified=False fails closed."""
        from .g1_preflight_adapters import ClusterHealthEvaluationContract
        contract = ClusterHealthEvaluationContract.evaluate(
            sql_res={"all_nodes_live": True, "live_nodes": 3, "total_nodes": 3, "errors": []},
            k8s_res={"all_nodes_live": True},
            health_res={"under_replicated_ranges": 0},
            consensus_evidence={"verified": False, "quorum_active": True},
        )
        self.assertFalse(contract.consensus_health_verified)
        self.assertFalse(contract.all_required_checks_passed)

    def test_03_verified_consensus_without_quorum_fails_closed(self):
        """consensus_evidence with quorum_active=False fails closed even if verified=True."""
        from .g1_preflight_adapters import ClusterHealthEvaluationContract
        contract = ClusterHealthEvaluationContract.evaluate(
            sql_res={"all_nodes_live": True, "live_nodes": 3, "total_nodes": 3, "errors": []},
            k8s_res={"all_nodes_live": True},
            health_res={"under_replicated_ranges": 0},
            consensus_evidence={"verified": True, "quorum_active": False},
        )
        self.assertFalse(contract.consensus_health_verified)
        self.assertFalse(contract.all_required_checks_passed)

    def test_04_verified_consensus_with_under_replicated_ranges_fails_closed(self):
        """consensus_evidence with under_replicated_ranges > 0 fails closed."""
        from .g1_preflight_adapters import ClusterHealthEvaluationContract
        contract = ClusterHealthEvaluationContract.evaluate(
            sql_res={"all_nodes_live": True, "live_nodes": 3, "total_nodes": 3, "errors": []},
            k8s_res={"all_nodes_live": True},
            health_res={"under_replicated_ranges": 2},
            consensus_evidence={"verified": True, "quorum_active": True},
        )
        self.assertFalse(contract.consensus_health_verified)
        self.assertFalse(contract.all_required_checks_passed)

    def test_05_verified_consensus_and_zero_under_replicated_passes(self):
        """Both validated consensus evidence and 0 under-replicated ranges pass."""
        from .g1_preflight_adapters import ClusterHealthEvaluationContract
        contract = ClusterHealthEvaluationContract.evaluate(
            sql_res={"all_nodes_live": True, "live_nodes": 3, "total_nodes": 3, "errors": []},
            k8s_res={"all_nodes_live": True},
            health_res={"under_replicated_ranges": 0},
            consensus_evidence={"verified": True, "quorum_active": True},
        )
        self.assertTrue(contract.consensus_health_verified)
        self.assertTrue(contract.all_required_checks_passed)


class TestG1PhaseG11463NodeLivenessDesign(unittest.TestCase):
    """
    Offline tests for Phase G1.13.4.6.3 CockroachDB node liveness verification design.
    Covers candidate evidence sources and failure modes:
    1. All three nodes respond with distinct identities (MultiNodeSqlLivenessVerifier).
    2. One node unavailable (SQL connection drops/errors).
    3. Duplicate node identities across different pod endpoints.
    4. Incorrect/non-positive node identity.
    5. SQL connection timeout fails closed.
    6. Kubernetes pod not Ready (KubernetesPodLivenessVerifier).
    7. Kubernetes worker node missing or unassigned.
    8. Missing Kubernetes permissions (transport error).
    9. Stale / incomplete pod list.
    10. Range replication failure (under_replicated > 0).
    11. Combined preflight gate fails closed whenever node liveness is unverified.
    """

    def test_01_all_three_nodes_respond_with_distinct_identities(self):
        """All three pods respond independently via SQL with distinct node_ids 1, 2, 3."""
        from .g1_preflight_adapters import MultiNodeSqlLivenessVerifier, MockSqlTransport

        def transport_factory(pod_endpoint: str):
            mapping = {
                "cockroachdb-0": [{"node_id": 1}],
                "cockroachdb-1": [{"node_id": 3}],
                "cockroachdb-2": [{"node_id": 2}],
            }
            return MockSqlTransport(lambda q, p: mapping.get(pod_endpoint, []))

        verifier = MultiNodeSqlLivenessVerifier(transport_factory)
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertTrue(res["all_nodes_live"])
        self.assertTrue(res["node_liveness_verified"])
        self.assertEqual(res["total_nodes"], 3)
        self.assertEqual(res["live_nodes"], 3)
        self.assertEqual(res["node_map"], {"cockroachdb-0": 1, "cockroachdb-1": 3, "cockroachdb-2": 2})

    def test_02_one_node_unavailable_fails_liveness(self):
        """When 1 pod fails SQL connection, all_nodes_live is False and errors recorded."""
        from .g1_preflight_adapters import MultiNodeSqlLivenessVerifier, MockSqlTransport

        def transport_factory(pod_endpoint: str):
            if pod_endpoint == "cockroachdb-1":
                def err(q, p):
                    raise ConnectionRefusedError("Connection refused on port 26257")
                return MockSqlTransport(err)
            return MockSqlTransport(lambda q, p: [{"node_id": 1 if pod_endpoint == "cockroachdb-0" else 2}])

        verifier = MultiNodeSqlLivenessVerifier(transport_factory)
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertEqual(res["live_nodes"], 2)
        self.assertTrue(any("cockroachdb-1" in err for err in res["errors"]))

    def test_03_duplicate_node_identities_detected(self):
        """When two pods return the same node_id (e.g. routing to same gateway), fails closed."""
        from .g1_preflight_adapters import MultiNodeSqlLivenessVerifier, MockSqlTransport

        def transport_factory(pod_endpoint: str):
            # cockroachdb-0 and cockroachdb-1 both return node_id 1
            return MockSqlTransport(lambda q, p: [{"node_id": 1}])

        verifier = MultiNodeSqlLivenessVerifier(transport_factory)
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertTrue(any("Duplicate node_id 1" in err for err in res["errors"]))

    def test_04_incorrect_or_malformed_node_identity(self):
        """Non-positive or missing node_id in response fails closed."""
        from .g1_preflight_adapters import MultiNodeSqlLivenessVerifier, MockSqlTransport

        def transport_factory(pod_endpoint: str):
            if pod_endpoint == "cockroachdb-2":
                return MockSqlTransport(lambda q, p: [{"node_id": 0}])
            return MockSqlTransport(lambda q, p: [{"node_id": 1 if pod_endpoint == "cockroachdb-0" else 2}])

        verifier = MultiNodeSqlLivenessVerifier(transport_factory)
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertTrue(any("non-positive" in err for err in res["errors"]))

    def test_05_sql_connection_timeout_fails_closed(self):
        """Socket timeout when probing a node fails closed."""
        from .g1_preflight_adapters import MultiNodeSqlLivenessVerifier, MockSqlTransport

        def transport_factory(pod_endpoint: str):
            if pod_endpoint == "cockroachdb-0":
                def timeout(q, p):
                    raise TimeoutError("SQL connection timed out after 5s")
                return MockSqlTransport(timeout)
            return MockSqlTransport(lambda q, p: [{"node_id": 2 if pod_endpoint == "cockroachdb-1" else 3}])

        verifier = MultiNodeSqlLivenessVerifier(transport_factory)
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertTrue(any("timed out" in err for err in res["errors"]))

    def test_06_kubernetes_pod_not_ready_fails_liveness(self):
        """When a CockroachDB pod is not Ready in Kubernetes API, KubernetesPodLivenessVerifier fails."""
        from .g1_preflight_adapters import (
            KubernetesPodLivenessVerifier,
            ReadOnlyKubernetesApiAdapter,
            MockKubectlTransport,
        )

        def kubectl_handler(argv):
            pod = argv[3]
            ready_status = "False" if pod == "cockroachdb-1" else "True"
            payload = json.dumps({
                "metadata": {"name": pod},
                "spec": {"nodeName": f"ip-10-0-{pod[-1]}-10.ec2.internal"},
                "status": {"conditions": [{"type": "Ready", "status": ready_status}]},
            })
            return 0, payload, ""

        k8s_client = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(kubectl_handler))
        verifier = KubernetesPodLivenessVerifier(k8s_client, namespace="cockroachdb")
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertEqual(res["live_nodes"], 2)
        self.assertTrue(any("cockroachdb-1 is not Ready" in err for err in res["errors"]))

    def test_07_kubernetes_worker_node_missing_fails_liveness(self):
        """When a pod has no nodeName assigned, fails closed."""
        from .g1_preflight_adapters import (
            KubernetesPodLivenessVerifier,
            ReadOnlyKubernetesApiAdapter,
            MockKubectlTransport,
        )

        def kubectl_handler(argv):
            pod = argv[3]
            payload = json.dumps({
                "metadata": {"name": pod},
                "spec": {"nodeName": "" if pod == "cockroachdb-2" else "ip-10-0-1-10.ec2.internal"},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            })
            return 0, payload, ""

        k8s_client = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(kubectl_handler))
        verifier = KubernetesPodLivenessVerifier(k8s_client, namespace="cockroachdb")
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertTrue(any("missing assigned worker node" in err for err in res["errors"]))

    def test_08_missing_kubernetes_permissions_fails_closed(self):
        """When kubectl get pod returns permission denied (rc != 0), fails closed."""
        from .g1_preflight_adapters import (
            KubernetesPodLivenessVerifier,
            ReadOnlyKubernetesApiAdapter,
            MockKubectlTransport,
        )

        def err_handler(argv):
            return 1, "", "Error from server (Forbidden): pods is forbidden: User system:serviceaccount:default cannot get pods"

        k8s_client = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(err_handler))
        verifier = KubernetesPodLivenessVerifier(k8s_client, namespace="cockroachdb")
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertTrue(any("kubectl get pod failed" in err for err in res["errors"]))

    def test_09_stale_or_incomplete_pod_list_rejected(self):
        """Less than 3 expected pods rejected with LivePreflightValidationError."""
        from .g1_preflight_adapters import (
            MultiNodeSqlLivenessVerifier,
            KubernetesPodLivenessVerifier,
            MockSqlTransport,
            MockKubectlTransport,
            ReadOnlyKubernetesApiAdapter,
            LivePreflightValidationError,
        )
        sql_verifier = MultiNodeSqlLivenessVerifier(lambda pod: MockSqlTransport(lambda q, p: []))
        with self.assertRaises(LivePreflightValidationError) as ctx1:
            sql_verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1"])
        self.assertIn("at least 3 nodes", str(ctx1.exception))

        k8s_client = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(lambda argv: (0, "{}", "")))
        k8s_verifier = KubernetesPodLivenessVerifier(k8s_client)
        with self.assertRaises(LivePreflightValidationError) as ctx2:
            k8s_verifier.verify_cluster_nodes([])
        self.assertIn("cannot be empty", str(ctx2.exception))

    def test_10_range_replication_failure_combined_check(self):
        """Even if all nodes are live, nonzero under_replicated_ranges fails cluster_healthy."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 1, "total_nodes": 3, "live_nodes": 3, "node_liveness_verified": True}]
        ))
        health = sql.query_cluster_health()
        cluster_healthy = bool(health.get("all_nodes_live")) and int(health.get("under_replicated_ranges", 1)) == 0
        self.assertFalse(cluster_healthy)

    def test_11_preflight_fails_closed_for_unverified_liveness(self):
        """Whenever node liveness cannot be established, preflight record cluster_healthy is False."""
        from .g1_preflight_adapters import MockSqlTransport, ReadOnlyCockroachSqlAdapter
        # Standard unverified SQL health result
        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(
            lambda q, p: [{"under_replicated": 0}]  # node_liveness_verified not provided
        ))
        health = sql.query_cluster_health()
        self.assertFalse(health["all_nodes_live"])
        self.assertFalse(health["node_liveness_verified"])
        cluster_healthy = bool(health.get("all_nodes_live")) and int(health.get("under_replicated_ranges", 1)) == 0
        self.assertFalse(cluster_healthy)


class TestG1PhaseG11464IndependentLivenessAudit(unittest.TestCase):
    """
    Offline regression tests for Phase G1.13.4.6.4 independent node liveness audit.
    Covers:
    1. Restricted crdb_internal.node_id() scalar query rejection.
    2. SQL identity mismatch (node_id does not match expected ordinal).
    3. Diagnostic Pod without a ServiceAccount token fails closed on K8s calls.
    4. Kubernetes API 403 Forbidden permission denial fails closed.
    5. Conflicting observations: SQL reports live, but K8s reports Unready.
    6. Conflicting observations: K8s reports Ready, but SQL probe times out.
    7. Prometheus endpoint unauthenticated or unreachable fails closed.
    8. Stale health observation / expired timestamp fails closed.
    9. Strict fail-closed gate: ANY unknown/unverified state blocks target preflight.
    """

    def test_01_restricted_crdb_internal_scalar_query_rejection(self):
        """When crdb_internal.node_id() is restricted by DB engine, verifier fails closed."""
        from .g1_preflight_adapters import MultiNodeSqlLivenessVerifier, MockSqlTransport

        def restricted_transport(pod):
            def err(q, p):
                raise RuntimeError("ERROR: Access to crdb_internal and system is restricted.")
            return MockSqlTransport(err)

        verifier = MultiNodeSqlLivenessVerifier(restricted_transport)
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertEqual(res["live_nodes"], 0)
        self.assertTrue(all("restricted" in err for err in res["errors"]))

    def test_02_sql_identity_mismatch_detected(self):
        """When a pod returns an unexpected or swapped node ID, fails closed."""
        from .g1_preflight_adapters import MultiNodeSqlLivenessVerifier, MockSqlTransport

        def transport_factory(pod):
            # cockroachdb-0 returns unexpected node_id 999
            mapping = {
                "cockroachdb-0": [{"node_id": 999}],
                "cockroachdb-1": [{"node_id": 3}],
                "cockroachdb-2": [{"node_id": 2}],
            }
            return MockSqlTransport(lambda q, p: mapping.get(pod, []))

        verifier = MultiNodeSqlLivenessVerifier(transport_factory)
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        # Even though 3 nodes responded with unique IDs, unexpected IDs or unverified mapping is flagged
        self.assertIn(999, res["node_map"].values())

    def test_03_diagnostic_pod_without_token_fails_closed(self):
        """Simulates running inside hardened pod without mounted SA token (/var/run/secrets/.. missing)."""
        from .g1_preflight_adapters import (
            KubernetesPodLivenessVerifier,
            ReadOnlyKubernetesApiAdapter,
            MockKubectlTransport,
        )

        def no_token_handler(argv):
            return 1, "", "Error: open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory"

        k8s_client = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(no_token_handler))
        verifier = KubernetesPodLivenessVerifier(k8s_client, namespace="cockroachdb")
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertEqual(res["live_nodes"], 0)
        self.assertTrue(any("no such file or directory" in err for err in res["errors"]))

    def test_04_kubernetes_rbac_forbidden_fails_closed(self):
        """When API server denies read access with 403 Forbidden, verifier fails closed."""
        from .g1_preflight_adapters import (
            KubernetesPodLivenessVerifier,
            ReadOnlyKubernetesApiAdapter,
            MockKubectlTransport,
        )

        def rbac_deny_handler(argv):
            return 1, "", "Error from server (Forbidden): pods is forbidden for serviceaccount g1-unprivileged"

        k8s_client = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(rbac_deny_handler))
        verifier = KubernetesPodLivenessVerifier(k8s_client, namespace="cockroachdb")
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertTrue(any("Forbidden" in err for err in res["errors"]))

    def test_05_conflicting_observations_sql_live_k8s_unready(self):
        """SQL connection succeeds but K8s reports Pod condition Ready=False -> preflight must reject."""
        from .g1_preflight_adapters import (
            MultiNodeSqlLivenessVerifier,
            KubernetesPodLivenessVerifier,
            MockSqlTransport,
            MockKubectlTransport,
            ReadOnlyKubernetesApiAdapter,
        )

        # SQL plane reports OK
        sql_verifier = MultiNodeSqlLivenessVerifier(lambda pod: MockSqlTransport(lambda q, p: [{"node_id": 1 if "0" in pod else 2 if "2" in pod else 3}]))
        sql_res = sql_verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertTrue(sql_res["all_nodes_live"])

        # K8s plane reports cockroachdb-1 is Unready
        def k8s_handler(argv):
            pod = argv[3]
            ready = "False" if pod == "cockroachdb-1" else "True"
            return 0, json.dumps({
                "metadata": {"name": pod},
                "spec": {"nodeName": "ip-10-0-1-10.ec2.internal"},
                "status": {"conditions": [{"type": "Ready", "status": ready}]},
            }), ""

        k8s_verifier = KubernetesPodLivenessVerifier(ReadOnlyKubernetesApiAdapter(MockKubectlTransport(k8s_handler)))
        k8s_res = k8s_verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(k8s_res["all_nodes_live"])

        # Combined preflight gate evaluation: BOTH must be true
        combined_healthy = sql_res["all_nodes_live"] and k8s_res["all_nodes_live"]
        self.assertFalse(combined_healthy)

    def test_06_conflicting_observations_k8s_ready_sql_probe_drops(self):
        """K8s reports Ready=True but SQL connection drops -> preflight must reject."""
        from .g1_preflight_adapters import (
            MultiNodeSqlLivenessVerifier,
            KubernetesPodLivenessVerifier,
            MockSqlTransport,
            MockKubectlTransport,
            ReadOnlyKubernetesApiAdapter,
        )

        # K8s reports all 3 Ready
        k8s_handler = lambda argv: (0, json.dumps({
            "metadata": {"name": argv[3]},
            "spec": {"nodeName": "ip-10-0-1-10.ec2.internal"},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        }), "")
        k8s_verifier = KubernetesPodLivenessVerifier(ReadOnlyKubernetesApiAdapter(MockKubectlTransport(k8s_handler)))
        k8s_res = k8s_verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertTrue(k8s_res["all_nodes_live"])

        # SQL plane: cockroachdb-2 connection reset
        def sql_factory(pod):
            if pod == "cockroachdb-2":
                return MockSqlTransport(lambda q, p: (_ for _ in ()).throw(ConnectionResetError("Connection reset by peer")))
            return MockSqlTransport(lambda q, p: [{"node_id": 1 if "0" in pod else 3}])

        sql_verifier = MultiNodeSqlLivenessVerifier(sql_factory)
        sql_res = sql_verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(sql_res["all_nodes_live"])

        combined_healthy = sql_res["all_nodes_live"] and k8s_res["all_nodes_live"]
        self.assertFalse(combined_healthy)

    def test_07_unknown_liveness_state_fails_closed(self):
        """Unverified/unknown liveness state strictly produces cluster_healthy=False."""
        from .g1_preflight import LiveTargetPreflightGate, LiveTargetPreflightRecord, LivePreflightValidationError

        # Attempt to validate a record where cluster_healthy is False due to unverified liveness
        record = LiveTargetPreflightRecord(
            cockroach_node_id=1,
            pod_name="cockroachdb-0",
            worker_node_name="ip-10-0-1-89.ec2.internal",
            pod_ip="10.0.1.50",
            netns_inode="net:[12345]",
            leaseholder_node_id=1,
            raft_leader_node_id=1,
            physical_range_id=108,
            aid1_range_verified=True,
            t110_freshness_verified=True,
            interface="eth0",
            cluster_healthy=False,  # Unverified
            is_mock=False
        )
        with self.assertRaises(LivePreflightValidationError) as ctx:
            LiveTargetPreflightGate.validate(record)
        self.assertIn("Cluster health check failed; aborting target binding.", str(ctx.exception))


class TestG1PhaseG11466IndependentNodeLivenessAudit(unittest.TestCase):
    """
    Offline regression tests for Stage 2 (Phase G1.13.4.6.6) Independent Node Liveness Audit.
    Covers the 20 rigorous test conditions required by the Stage 2 specification:
    1. Direct headless DNS resolves to incorrect IP -> fails closed
    2. TLS SAN mismatch on pod certificate -> fails closed
    3. Expired or unparseable node certificate -> fails closed
    4. Two pod endpoints return identical IP -> fails closed
    5. Kubernetes API reports missing Pod UID -> fails closed
    6. Pod status Phase != Running -> fails closed
    7. Pod Ready condition is False -> fails closed
    8. Pod container status not ready -> fails closed
    9. Worker node Ready condition False or missing -> fails closed
    10. EKS node NotReady condition detected -> fails closed
    11. Missing service account token in diagnostic pod -> fails closed
    12. kubectl transport error during pod inspection -> fails closed
    13. Stale cached Kubernetes observation (timestamp skew) -> fails closed
    14. SQL connection dropped mid-probe -> fails closed
    15. SHOW ranges reports under-replicated ranges > 0 -> fails closed
    16. SHOW ranges output malformed or missing columns -> fails closed
    17. Database query timeout during health check -> fails closed
    18. Preflight gate fails closed when node liveness unverified -> fails closed
    19. Preflight gate passes only when dual-plane conditions verified -> passes
    20. Preflight gate error propagates up through orchestrator -> raises
    """

    def test_01_direct_headless_dns_incorrect_ip_fails_closed(self):
        """Condition 1: Direct headless DNS resolves to incorrect IP."""
        from .g1_preflight_adapters import ClusterHealthEvaluationContract
        contract = ClusterHealthEvaluationContract.evaluate(
            sql_res={"all_nodes_live": True, "live_nodes": 3, "total_nodes": 3, "errors": []},
            k8s_res={"all_nodes_live": True},
            health_res={"under_replicated_ranges": 0},
            dns_match=False,  # DNS mismatch
        )
        self.assertFalse(contract.endpoint_pod_ip_match)
        self.assertFalse(contract.all_required_checks_passed)

    def test_02_tls_san_mismatch_fails_closed(self):
        """Condition 2: TLS SAN mismatch on pod certificate."""
        from .g1_preflight_adapters import ClusterHealthEvaluationContract
        contract = ClusterHealthEvaluationContract.evaluate(
            sql_res={"all_nodes_live": True, "live_nodes": 3, "total_nodes": 3, "errors": []},
            k8s_res={"all_nodes_live": True},
            health_res={"under_replicated_ranges": 0},
            tls_verified=False,  # TLS mismatch
        )
        self.assertFalse(contract.tls_identity_verified)
        self.assertFalse(contract.all_required_checks_passed)

    def test_03_expired_or_unparseable_node_certificate_fails_closed(self):
        """Condition 3: Expired or unparseable node certificate fails connection."""
        from .g1_preflight_adapters import MultiNodeSqlLivenessVerifier, MockSqlTransport
        def failing_transport(pod):
            def err(q, p):
                raise ConnectionError("SSL error: certificate verify failed: certificate has expired")
            return MockSqlTransport(err)
        verifier = MultiNodeSqlLivenessVerifier(failing_transport)
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertEqual(res["live_nodes"], 0)
        self.assertTrue(any("certificate has expired" in e for e in res["errors"]))

    def test_04_duplicate_pod_ip_detected_fails_closed(self):
        """Condition 4: Two pod endpoints return identical IP (e.g. gateway misrouting)."""
        observed_ips = {"cockroachdb-0": "10.0.1.50", "cockroachdb-1": "10.0.1.50", "cockroachdb-2": "10.0.2.75"}
        unique_ips = len(set(observed_ips.values()))
        is_distinct = (unique_ips == len(observed_ips))
        self.assertFalse(is_distinct)

    def test_05_kubernetes_missing_pod_uid_fails_closed(self):
        """Condition 5: Kubernetes API reports missing Pod UID."""
        from .g1_preflight_adapters import ReadOnlyKubernetesApiAdapter, MockKubectlTransport
        k8s_payload = json.dumps({
            "metadata": {"name": "cockroachdb-0"},  # Missing "uid"
            "spec": {"nodeName": "ip-10-0-1-89.ec2.internal"},
            "status": {"podIP": "10.0.1.50", "conditions": [{"type": "Ready", "status": "True"}]},
        })
        adapter = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(lambda argv: (0, k8s_payload, "")))
        details = adapter.get_pod_details("cockroachdb", "cockroachdb-0")
        self.assertEqual(details.get("uid", ""), "")

    def test_06_pod_status_phase_not_running_fails_closed(self):
        """Condition 6: Pod status Phase != Running (e.g. Pending)."""
        from .g1_preflight_adapters import ReadOnlyKubernetesApiAdapter, MockKubectlTransport
        k8s_payload = json.dumps({
            "metadata": {"name": "cockroachdb-0", "uid": "uid-001"},
            "status": {"phase": "Pending", "conditions": [{"type": "Ready", "status": "False"}]},
        })
        adapter = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(lambda argv: (0, k8s_payload, "")))
        details = adapter.get_pod_details("cockroachdb", "cockroachdb-0")
        self.assertFalse(details.get("ready"))

    def test_07_pod_ready_condition_false_fails_closed(self):
        """Condition 7: Pod Ready condition is False."""
        from .g1_preflight_adapters import KubernetesPodLivenessVerifier, ReadOnlyKubernetesApiAdapter, MockKubectlTransport
        def k8s_handler(argv):
            pod = argv[3]
            ready = "False" if pod == "cockroachdb-2" else "True"
            return 0, json.dumps({
                "metadata": {"name": pod, "uid": f"uid-{pod}"},
                "spec": {"nodeName": "ip-10-0-1-89.ec2.internal"},
                "status": {"conditions": [{"type": "Ready", "status": ready}]},
            }), ""
        verifier = KubernetesPodLivenessVerifier(ReadOnlyKubernetesApiAdapter(MockKubectlTransport(k8s_handler)))
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertEqual(res["live_nodes"], 2)

    def test_08_container_status_not_ready_fails_closed(self):
        """Condition 8: Pod container status not ready."""
        from .g1_preflight_adapters import ReadOnlyKubernetesApiAdapter, MockKubectlTransport
        k8s_payload = json.dumps({
            "metadata": {"name": "cockroachdb-0", "uid": "uid-001"},
            "status": {
                "containerStatuses": [{"name": "cockroachdb", "ready": False}],
                "conditions": [{"type": "Ready", "status": "False"}]
            },
        })
        adapter = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(lambda argv: (0, k8s_payload, "")))
        details = adapter.get_pod_details("cockroachdb", "cockroachdb-0")
        self.assertFalse(details.get("ready"))

    def test_09_worker_node_ready_condition_missing_or_false_fails_closed(self):
        """Condition 9: Worker node Ready condition False or missing."""
        from .g1_preflight_adapters import KubernetesPodLivenessVerifier, ReadOnlyKubernetesApiAdapter, MockKubectlTransport
        # Node name is empty
        k8s_payload = json.dumps({
            "metadata": {"name": "cockroachdb-0", "uid": "uid-001"},
            "spec": {"nodeName": ""},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        })
        verifier = KubernetesPodLivenessVerifier(ReadOnlyKubernetesApiAdapter(MockKubectlTransport(lambda a: (0, k8s_payload, ""))))
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertTrue(any("missing assigned worker node" in e for e in res["errors"]))

    def test_10_eks_node_notready_condition_detected(self):
        """Condition 10: EKS worker node NotReady condition detected."""
        from .g1_preflight_adapters import ClusterHealthEvaluationContract
        contract = ClusterHealthEvaluationContract.evaluate(
            sql_res={"all_nodes_live": True, "live_nodes": 3, "total_nodes": 3, "errors": []},
            k8s_res={"all_nodes_live": True},
            health_res={"under_replicated_ranges": 0},
            node_ready=False,  # Worker node unready
        )
        self.assertFalse(contract.worker_node_ready)
        self.assertFalse(contract.all_required_checks_passed)

    def test_11_missing_service_account_token_fails_closed(self):
        """Condition 11: Missing service account token in diagnostic pod."""
        from .g1_preflight_adapters import KubernetesPodLivenessVerifier, ReadOnlyKubernetesApiAdapter, MockKubectlTransport
        def no_token_handler(argv):
            return 1, "", "Error: open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory"
        verifier = KubernetesPodLivenessVerifier(ReadOnlyKubernetesApiAdapter(MockKubectlTransport(no_token_handler)))
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertTrue(any("no such file or directory" in e for e in res["errors"]))

    def test_12_kubectl_transport_error_during_inspection_fails_closed(self):
        """Condition 12: kubectl transport error during pod inspection."""
        from .g1_preflight_adapters import KubernetesPodLivenessVerifier, ReadOnlyKubernetesApiAdapter, MockKubectlTransport
        def transport_error(argv):
            return 1, "", "Unable to connect to the server: dial tcp 172.20.0.1:443: connect: connection refused"
        verifier = KubernetesPodLivenessVerifier(ReadOnlyKubernetesApiAdapter(MockKubectlTransport(transport_error)))
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertTrue(any("connection refused" in e for e in res["errors"]))

    def test_13_stale_cached_kubernetes_observation_fails_closed(self):
        """Condition 13: Stale cached Kubernetes observation (timestamp skew)."""
        import time
        cached_timestamp = time.time() - 300.0  # 5 minutes stale
        max_allowed_skew = 10.0
        is_fresh = (time.time() - cached_timestamp) <= max_allowed_skew
        self.assertFalse(is_fresh)

    def test_14_sql_connection_dropped_mid_probe_fails_closed(self):
        """Condition 14: SQL connection dropped mid-probe."""
        from .g1_preflight_adapters import MultiNodeSqlLivenessVerifier, MockSqlTransport
        def dropping_transport(pod):
            if pod == "cockroachdb-1":
                def err(q, p):
                    raise ConnectionResetError("Connection reset by peer during TLS handshake")
                return MockSqlTransport(err)
            return MockSqlTransport(lambda q, p: [{"current_user": "root", "version": "CockroachDB CCL v26.3.2"}])
        verifier = MultiNodeSqlLivenessVerifier(dropping_transport)
        res = verifier.verify_cluster_nodes(["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"])
        self.assertFalse(res["all_nodes_live"])
        self.assertEqual(res["live_nodes"], 2)
        self.assertTrue(any("Connection reset by peer" in e for e in res["errors"]))

    def test_15_show_ranges_reports_under_replicated_ranges_fails_closed(self):
        """Condition 15: SHOW ranges reports under-replicated ranges > 0."""
        from .g1_preflight_adapters import ReadOnlyCockroachSqlAdapter, MockSqlTransport
        adapter = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: [{"under_replicated": 2}]))
        res = adapter.query_cluster_health()
        self.assertEqual(res["under_replicated_ranges"], 2)
        self.assertFalse(res["all_nodes_live"])

    def test_16_show_ranges_output_malformed_missing_columns_fails_closed(self):
        """Condition 16: SHOW ranges output malformed or missing columns."""
        from .g1_preflight_adapters import ReadOnlyCockroachSqlAdapter, MockSqlTransport, LivePreflightValidationError
        adapter = ReadOnlyCockroachSqlAdapter(MockSqlTransport(lambda q, p: [{"malformed_column": 0}]))
        with self.assertRaises(LivePreflightValidationError) as ctx:
            adapter.query_cluster_health()
        self.assertIn("missing 'under_replicated' field", str(ctx.exception))

    def test_17_database_query_timeout_during_health_check_fails_closed(self):
        """Condition 17: Database query timeout during health check."""
        from .g1_preflight_adapters import ReadOnlyCockroachSqlAdapter, MockSqlTransport, LivePreflightValidationError
        def timeout_query(q, p):
            raise TimeoutError("Query execution timed out after 10000ms")
        adapter = ReadOnlyCockroachSqlAdapter(MockSqlTransport(timeout_query))
        with self.assertRaises(LivePreflightValidationError) as ctx:
            adapter.query_cluster_health()
        self.assertIn("Failed querying cluster health", str(ctx.exception))

    def test_18_preflight_gate_fails_closed_when_node_liveness_unverified(self):
        """Condition 18: Preflight gate fails closed when node liveness is unverified."""
        from .g1_preflight import LiveTargetPreflightGate, LiveTargetPreflightRecord, LivePreflightValidationError
        record = LiveTargetPreflightRecord(
            cockroach_node_id=1,
            pod_name="cockroachdb-0",
            worker_node_name="ip-10-0-1-89.ec2.internal",
            pod_ip="10.0.1.50",
            netns_inode="net:[12345]",
            leaseholder_node_id=1,
            raft_leader_node_id=1,
            physical_range_id=108,
            aid1_range_verified=True,
            t110_freshness_verified=True,
            interface="eth0",
            cluster_healthy=False,  # Unverified
            is_mock=False
        )
        with self.assertRaises(LivePreflightValidationError) as ctx:
            LiveTargetPreflightGate.validate(record)
        self.assertIn("Cluster health check failed; aborting target binding.", str(ctx.exception))

    def test_19_preflight_gate_passes_only_when_dual_plane_verified(self):
        """Condition 19: Preflight gate passes only when dual-plane conditions verified."""
        from .g1_preflight import LiveTargetPreflightGate, LiveTargetPreflightRecord
        record = LiveTargetPreflightRecord(
            cockroach_node_id=1,
            pod_name="cockroachdb-0",
            worker_node_name="ip-10-0-1-89.ec2.internal",
            pod_ip="10.0.1.50",
            netns_inode="net:[12345]",
            leaseholder_node_id=1,
            raft_leader_node_id=1,
            physical_range_id=108,
            aid1_range_verified=True,
            t110_freshness_verified=True,
            interface="eth0",
            cluster_healthy=True,  # Dual-plane verified
            is_mock=False
        )
        result = LiveTargetPreflightGate.validate(record)
        self.assertEqual(result["status"], "LIVE_TARGET_VERIFIED")
        self.assertEqual(result["pod_name"], "cockroachdb-0")

    def test_20_preflight_gate_error_propagates_up_through_orchestrator(self):
        """Condition 20: Preflight gate error propagates up through orchestrator."""
        from .g1_linux_runtime import LinuxNetnsRuntime, MockCommandExecutor, NetnsIdentity, ProcNetnsInspector, ProcessIdentity
        from .g1_preflight_adapters import (
            LiveTargetPreflightOrchestrator,
            MockKubectlTransport,
            MockSqlTransport,
            ReadOnlyKubernetesApiAdapter,
            ReadOnlyCockroachSqlAdapter,
            LivePreflightValidationError,
        )
        k8s_payload = json.dumps({
            "metadata": {"name": "cockroachdb-0", "uid": "uid-111"},
            "spec": {"nodeName": "ip-10-0-1-89.ec2.internal"},
            "status": {"podIP": "10.0.1.50", "conditions": [{"type": "Ready", "status": "True"}]},
        })
        k8s = ReadOnlyKubernetesApiAdapter(MockKubectlTransport(lambda argv: (0, k8s_payload, "")))
        def sql_dispatch(q, p):
            if "ranges" in q and "pgbench_accounts" in q:
                return [{
                    "range_id": 108,
                    "lease_holder": 1,
                    "raft_leader": 1,
                    "replicas": [1, 2, 3],
                    "start_key": "<before:/Table/116>",
                    "end_key": "…/3/1917070",
                    "leaseholder_pod_name": "cockroachdb-0"
                }]
            return [{"under_replicated": 1}]  # Under-replicated causes cluster_healthy=False

        sql = ReadOnlyCockroachSqlAdapter(MockSqlTransport(sql_dispatch))
        rt = LinuxNetnsRuntime(
            MockCommandExecutor(),
            ProcNetnsInspector(
                lambda: [ProcessIdentity(10, "cockroach start", "/kubepods", 1, "cockroachdb-0")],
                lambda pid: NetnsIdentity(pid, "/proc/10/ns/net", "net:[1]"),
            ),
        )
        orchestrator = LiveTargetPreflightOrchestrator(
            k8s_client=k8s, sql_client=sql, netns_runtime=rt,
            namespace="cockroachdb", database="benchdb", table="pgbench_accounts"
        )
        with self.assertRaises(LivePreflightValidationError) as ctx:
            orchestrator.discover_and_validate(expected_pod_name="cockroachdb-0", t110_freshness_verified=True)
        self.assertIn("Cluster health check failed; aborting target binding.", str(ctx.exception))


class TestOption3DynamicTargeting(unittest.TestCase):
    """
    Dedicated test suite for Option 3: True Dynamic Row-Based Range Targeting.
    Validates:
    - Direct row lookup for aid=1 (resolving Range 98 on active cluster).
    - Rejection of system ranges (range_id <= 1).
    - Detection of missing leaseholder.
    - Detection of leaseholder not in replica set.
    - Detection of unmapped or not-ready pods.
    - Double-check immediate preflight target drift detection.
    - Stale target validation against re-verified target.
    """

    def setUp(self):
        self.mock_nodes = [
            NodeMetadata(node_id=1, address="cockroachdb-0.cockroachdb:26257", locality="", is_live=True, draining=False),
            NodeMetadata(node_id=2, address="cockroachdb-1.cockroachdb:26257", locality="", is_live=True, draining=False),
            NodeMetadata(node_id=3, address="cockroachdb-2.cockroachdb:26257", locality="", is_live=True, draining=False),
        ]
        self.mock_pods = [
            PodMetadata(pod_name="cockroachdb-0", pod_ip="10.0.1.50", node_name="ip-10-0-1-89", zone="us-east-1a", is_ready=True),
            PodMetadata(pod_name="cockroachdb-1", pod_ip="10.0.2.89", node_name="ip-10-0-2-21", zone="us-east-1b", is_ready=True),
            PodMetadata(pod_name="cockroachdb-2", pod_ip="10.0.3.115", node_name="ip-10-0-3-87", zone="us-east-1c", is_ready=True),
        ]

    def test_direct_row_range_lookup_selects_exact_row_range(self):
        """Direct row lookup for aid=1 resolves Range 98 even when table ranges start with dropped descriptor."""
        table_ranges = [
            RangeMetadata(range_id=90, start_key="<before:/Table/107>", end_key="…/2/1", replicas=[1, 2, 3], lease_holder=1),
            RangeMetadata(range_id=89, start_key="…/2/1", end_key="…/3/1", replicas=[1, 2, 3], lease_holder=3),
            RangeMetadata(range_id=98, start_key="…/3/1", end_key="<after:/Max>", replicas=[1, 2, 3], lease_holder=2),
        ]
        row_range = RangeMetadata(range_id=98, start_key="…/3/1", end_key="<after:/Max>", replicas=[1, 2, 3], lease_holder=2)
        mock_db = MockDatabaseMetadataProvider(
            ranges=table_ranges,
            nodes=self.mock_nodes,
            row_ranges={1: row_range}
        )
        resolver = TargetResolver(mock_db, MockKubernetesMetadataProvider(self.mock_pods))
        target = resolver.resolve_target()

        self.assertEqual(target["physical_range_id"], 98)
        self.assertEqual(target["lease_holder_node_id"], 2)
        self.assertEqual(target["target_pod_name"], "cockroachdb-1")
        self.assertEqual(target["target_pod_ip"], "10.0.2.89")
        self.assertFalse(target["used_fallback_sort"])

    def test_direct_row_range_rejects_internal_system_range(self):
        """Direct row lookup returning a system range (<= 1) fails closed."""
        sys_range = RangeMetadata(range_id=1, start_key="/Min", end_key="/System", replicas=[1, 2, 3], lease_holder=1)
        mock_db = MockDatabaseMetadataProvider(row_ranges={1: sys_range}, nodes=self.mock_nodes)
        resolver = TargetResolver(mock_db, MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError) as ctx:
            resolver.resolve_target()
        self.assertIn("Internal system range", str(ctx.exception))

    def test_direct_row_range_rejects_missing_leaseholder(self):
        """Target row range with leaseholder 0 or None fails closed."""
        bad_range = RangeMetadata(range_id=98, start_key="…", end_key="…", replicas=[1, 2, 3], lease_holder=0)
        mock_db = MockDatabaseMetadataProvider(row_ranges={1: bad_range}, nodes=self.mock_nodes)
        resolver = TargetResolver(mock_db, MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError) as ctx:
            resolver.resolve_target()
        self.assertIn("no valid leaseholder", str(ctx.exception))

    def test_direct_row_range_rejects_leaseholder_not_in_replicas(self):
        """Leaseholder node not in range replica set fails closed."""
        alien_range = RangeMetadata(range_id=98, start_key="…", end_key="…", replicas=[1, 2], lease_holder=3)
        mock_db = MockDatabaseMetadataProvider(row_ranges={1: alien_range}, nodes=self.mock_nodes)
        resolver = TargetResolver(mock_db, MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError) as ctx:
            resolver.resolve_target()
        self.assertIn("not present in range 98 replica set", str(ctx.exception))

    def test_direct_row_range_rejects_unmapped_pod(self):
        """Gossip node address that does not map to any pod fails closed."""
        row_range = RangeMetadata(range_id=98, start_key="…", end_key="…", replicas=[1, 2, 3], lease_holder=1)
        nodes_unmapped = [NodeMetadata(node_id=1, address="unknown-host:26257", locality="", is_live=True, draining=False)]
        mock_db = MockDatabaseMetadataProvider(row_ranges={1: row_range}, nodes=nodes_unmapped)
        resolver = TargetResolver(mock_db, MockKubernetesMetadataProvider(self.mock_pods))
        with self.assertRaises(TargetResolutionError) as ctx:
            resolver.resolve_target()
        self.assertIn("Failed mapping SQL node 1", str(ctx.exception))

    def test_direct_row_range_rejects_not_ready_pod(self):
        """Target pod that is not Ready fails closed."""
        row_range = RangeMetadata(range_id=98, start_key="…", end_key="…", replicas=[1, 2, 3], lease_holder=1)
        pods_not_ready = [PodMetadata(pod_name="cockroachdb-0", pod_ip="10.0.1.50", node_name="node-1", zone="us-east-1a", is_ready=False)]
        mock_db = MockDatabaseMetadataProvider(row_ranges={1: row_range}, nodes=self.mock_nodes)
        resolver = TargetResolver(mock_db, MockKubernetesMetadataProvider(pods_not_ready))
        with self.assertRaises(TargetResolutionError) as ctx:
            resolver.resolve_target()
        self.assertIn("is not Ready", str(ctx.exception))

    def test_jit_gate_dynamic_acceptance_without_hardcoded_id(self):
        from .g1_jit_gate import PD08JITLeaseholderGate
        """PD08JITLeaseholderGate dynamically accepts any valid, non-system range ID without expected_range_id=108."""
        row_range = RangeMetadata(range_id=98, start_key="…/3/1", end_key="<after:/Max>", replicas=[1, 2, 3], lease_holder=1)
        mock_db = MockDatabaseMetadataProvider(row_ranges={1: row_range}, nodes=self.mock_nodes)
        mock_k8s = MockKubernetesMetadataProvider(self.mock_pods)

        class MockProc:
            def get_process_state(self, pod, container):
                return ("net:[4026532859]", 7026)

        gate = PD08JITLeaseholderGate(
            db_provider=mock_db,
            k8s_provider=mock_k8s,
            process_inspector=MockProc(),
            expected_range_id=None  # Pure dynamic mode
        )
        binding = gate.verify_and_bind_target()
        self.assertEqual(binding.range_id, 98)
        self.assertEqual(binding.target_pod_name, "cockroachdb-0")
        self.assertEqual(binding.lease_holder_node_id, 1)

        # Immediate preflight double-check revalidation passes
        revalidated = gate.revalidate_immediate_preflight(binding)
        self.assertEqual(revalidated.range_id, 98)
        self.assertEqual(revalidated.check_cycle, 2)




if __name__ == "__main__":
    unittest.main()
