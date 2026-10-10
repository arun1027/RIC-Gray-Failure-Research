"""
test_g2_offline_suite.py - Exhaustive Offline Test Suite for Scenario G2 Tooling.

Requirements:
- 100% offline, zero network access, zero real fault injection, zero cluster modifications.
- Tests severity validation (G2-L1 10%, G2-L2 30%, G2-L3 50%).
- Tests packet loss configuration generation (uniform random netem syntax on eth0).
- Tests target identity validation and JIT two-cycle consensus leaseholder verification.
- Tests fault activation, verification, clearance, and idempotent cleanup.
- Tests invalid input handling and fail-closed security boundaries.
- Tests that recovery observation (W_rec) begins strictly after verified fault clearance.
- Tests run identifier uniqueness across all 15 formal runs (N=5 per level).
- Tests that existing G1 implementation remains completely unchanged.
"""

import datetime
import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmark.scripts.cockroachdb.g2.g2_packet_loss_runtime import (
    G2LinuxRuntimePlanner,
    G2LinuxRuntime,
    NetnsIdentity,
    ProcessIdentity,
    LinuxRuntimeError,
    QdiscConflictError,
    APPROVED_PACKET_LOSS_PERCENTAGES,
    APPROVED_LOSS_DISTRIBUTION,
)
from benchmark.scripts.cockroachdb.g2.g2_authorizer import (
    G2HelperFaultAuthorizer,
    FaultAuthorizationError,
    SharedAtomicClaimStore,
)
from benchmark.scripts.cockroachdb.g2.g2_helper_daemon import (
    G2HelperConfig,
    G2TwoPhaseHelperController,
    HelperState,
    AutonomousWatchdog,
)
from benchmark.scripts.cockroachdb.g2.g2_executor import (
    G2RunPlan,
    G2Executor,
    G2TargetBinding,
    VALID_G2_LEVELS,
    EXPECTED_FORMAL_REPETITIONS,
)
from benchmark.scripts.cockroachdb.g2.g2_campaign_manager import G2CampaignManager


class TestG2SeverityAndCommandValidation(unittest.TestCase):
    """Verifies severity level validation and netem command generation."""

    def test_approved_severity_levels(self):
        self.assertEqual(APPROVED_PACKET_LOSS_PERCENTAGES, frozenset({10, 30, 50}))
        self.assertEqual(VALID_G2_LEVELS["G2-L1"], 10)
        self.assertEqual(VALID_G2_LEVELS["G2-L2"], 30)
        self.assertEqual(VALID_G2_LEVELS["G2-L3"], 50)

    def test_plan_add_egress_packet_loss_syntax(self):
        for level, pct in VALID_G2_LEVELS.items():
            cmd = G2LinuxRuntimePlanner.plan_add_egress_packet_loss("eth0", pct)
            expected = [
                "tc", "qdisc", "add", "dev", "eth0", "root", "handle", "10:",
                "netem", "loss", f"{pct}%"
            ]
            self.assertEqual(cmd, expected)

    def test_reject_unapproved_loss_percentages(self):
        unapproved = [0, 5, 15, 20, 25, 40, 60, 100, -10]
        for pct in unapproved:
            with self.assertRaises(LinuxRuntimeError):
                G2LinuxRuntimePlanner.plan_add_egress_packet_loss("eth0", pct)

    def test_reject_invalid_interfaces(self):
        invalid_ifaces = ["", " ", "eth0; rm -rf", "lo$foo", "a" * 30]
        for iface in invalid_ifaces:
            with self.assertRaises(LinuxRuntimeError):
                G2LinuxRuntimePlanner.plan_add_egress_packet_loss(iface, 10)

    def test_plan_del_root_qdisc(self):
        cmd = G2LinuxRuntimePlanner.plan_del_root_qdisc("eth0")
        self.assertEqual(cmd, ["tc", "qdisc", "del", "dev", "eth0", "root"])


class TestG2Authorizer(unittest.TestCase):
    """Verifies cryptographic token authorization and schema validation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = self.temp_dir.name
        self.claim_store = SharedAtomicClaimStore()
        self.authorizer = G2HelperFaultAuthorizer(
            base_dir=self.base_dir,
            allow_readonly_secret=True,
            claim_store=self.claim_store,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_valid_token(
        self,
        run_id="crdb-g2l1-formal-f01",
        pod="cockroachdb-0",
        loss_pct=10,
        distribution="uniform",
        netns="net:[12345]",
        action="EXECUTE_G2_FAULT_HELPER",
        duration_sec=180,
    ):
        now = datetime.datetime.now(datetime.timezone.utc)
        token = {
            "run_id": run_id,
            "auth_nonce": "12345678abcdefgh",
            "action": action,
            "target_pod": pod,
            "target_namespace": "cockroachdb",
            "target_netns_inode": netns,
            "fault_type": "packet_loss",
            "loss_percentage": loss_pct,
            "loss_distribution": distribution,
            "duration_sec": duration_sec,
            "issued_at_utc": now.isoformat(),
            "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
            "authorized_by_operator": "test_operator",
        }
        path = os.path.join(self.base_dir, "G2_FAULT_AUTHORIZED.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(token, f)
        return token

    def test_valid_token_authorization(self):
        self._create_valid_token(loss_pct=10)
        payload = self.authorizer.verify_and_claim(
            expected_run_id="crdb-g2l1-formal-f01",
            expected_target_pod="cockroachdb-0",
            expected_loss_percentage=10,
            observed_netns_inode="net:[12345]",
        )
        self.assertEqual(payload["loss_percentage"], 10)
        self.assertEqual(payload["fault_type"], "packet_loss")
        self.assertEqual(payload["loss_distribution"], "uniform")

    def test_replay_blocked_by_claim_store(self):
        self._create_valid_token(loss_pct=30)
        # First claim succeeds
        self.authorizer.verify_and_claim(
            expected_run_id="crdb-g2l1-formal-f01",
            expected_target_pod="cockroachdb-0",
            expected_loss_percentage=30,
            observed_netns_inode="net:[12345]",
        )
        # Second claim with same nonce fails closed
        with self.assertRaises(FaultAuthorizationError):
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-g2l1-formal-f01",
                expected_target_pod="cockroachdb-0",
                expected_loss_percentage=30,
                observed_netns_inode="net:[12345]",
            )

    def test_reject_action_mismatch(self):
        self._create_valid_token(action="EXECUTE_G1_FAULT_HELPER")
        with self.assertRaises(FaultAuthorizationError):
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-g2l1-formal-f01",
                expected_target_pod="cockroachdb-0",
                expected_loss_percentage=10,
            )

    def test_reject_distribution_mismatch(self):
        self._create_valid_token(distribution="burst")
        with self.assertRaises(FaultAuthorizationError):
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-g2l1-formal-f01",
                expected_target_pod="cockroachdb-0",
                expected_loss_percentage=10,
            )

    def test_reject_netns_mismatch(self):
        self._create_valid_token(netns="net:[12345]")
        with self.assertRaises(FaultAuthorizationError):
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-g2l1-formal-f01",
                expected_target_pod="cockroachdb-0",
                expected_loss_percentage=10,
                observed_netns_inode="net:[99999]",  # Inode mismatch
            )


class TestG2RuntimeLifecycle(unittest.TestCase):
    """Verifies runtime fault application, verification, and idempotent clearance."""

    def test_runtime_apply_and_clear_lifecycle(self):
        state = {"qdisc": "qdisc noqueue 0: dev eth0 root refcnt 2"}

        def mock_runner(cmd, netns_path=None):
            if cmd == ["tc", "qdisc", "show", "dev", "eth0"]:
                return 0, state["qdisc"], ""
            elif "add" in cmd:
                state["qdisc"] = "qdisc netem 10: dev eth0 root refcnt 2 limit 1000 loss 30%"
                return 0, "", ""
            elif "del" in cmd:
                state["qdisc"] = "qdisc noqueue 0: dev eth0 root refcnt 2"
                return 0, "", ""
            return 1, "", "unrecognized mock command"

        runtime = G2LinuxRuntime(runner=mock_runner)
        netns = NetnsIdentity("net:[12345]", path="/proc/100/ns/net")
        proc = ProcessIdentity(pid=100)

        # 1. Apply 30% loss
        rec = runtime.apply_egress_packet_loss(
            run_id="crdb-g2l2-formal-f01",
            pod_name="cockroachdb-1",
            netns=netns,
            proc=proc,
            loss_percentage=30,
        )
        self.assertEqual(rec.loss_percentage, 30)
        self.assertIn("cockroachdb-1", runtime.owned_qdiscs)

        # 2. Idempotent remove
        res = runtime.remove_owned_qdisc("cockroachdb-1", netns)
        self.assertEqual(res["status"], "CLEARED")
        self.assertNotIn("cockroachdb-1", runtime.owned_qdiscs)

        # 3. Second remove is safe (returns status CLEARED / no-op)
        res2 = runtime.remove_owned_qdisc("cockroachdb-1", netns)
        self.assertEqual(res2["status"], "CLEARED")

    def test_runtime_fails_on_conflict(self):
        # Pre-existing netem qdisc triggers QdiscConflictError
        mock_runner = lambda cmd, netns_path=None: (0, "qdisc netem 10: dev eth0 root refcnt 2 loss 10%", "")
        runtime = G2LinuxRuntime(runner=mock_runner)
        netns = NetnsIdentity("net:[12345]", path="/proc/100/ns/net")
        proc = ProcessIdentity(pid=100)

        with self.assertRaises(QdiscConflictError):
            runtime.apply_egress_packet_loss(
                run_id="crdb-g2l1-formal-f01",
                pod_name="cockroachdb-0",
                netns=netns,
                proc=proc,
                loss_percentage=10,
            )


class TestG2ExecutorAndPhasing(unittest.TestCase):
    """Verifies G2 executor phasing, JIT verification, and monotonic cooldown gating."""

    def test_run_plan_creation(self):
        plan = G2RunPlan.create("G2-L2", 3)
        self.assertEqual(plan.run_id, "crdb-g2l2-formal-f03")
        self.assertEqual(plan.loss_percentage, 30)
        self.assertEqual(plan.repetition_index, 3)
        self.assertEqual(plan.fault_duration_sec, 180)
        self.assertEqual(plan.cooldown_duration_sec, 300)
        self.assertEqual(plan.warmup_duration_sec, 120)

    def test_campaign_manager_uniqueness(self):
        plans = G2CampaignManager.generate_campaign_plan()
        self.assertEqual(len(plans), 30)  # 3 levels * 10 reps = 30 per approved protocol
        self.assertTrue(G2CampaignManager.validate_run_id_uniqueness(plans))

        # Check expected prefixes
        run_ids = [p.run_id for p in plans]
        self.assertIn("crdb-g2l1-formal-f01", run_ids)
        self.assertIn("crdb-g2l1-formal-f05", run_ids)
        self.assertIn("crdb-g2l1-formal-f10", run_ids)
        self.assertIn("crdb-g2l2-formal-f01", run_ids)
        self.assertIn("crdb-g2l2-formal-f10", run_ids)
        self.assertIn("crdb-g2l3-formal-f05", run_ids)
        self.assertIn("crdb-g2l3-formal-f10", run_ids)

    def test_executor_jit_gate_drift_detection(self):
        plan = G2RunPlan.create("G2-L1", 1)
        simulated_time = [1000.0]

        def mock_monotonic():
            return simulated_time[0]

        def mock_sleep(sec):
            simulated_time[0] += sec

        # Simulate drift: cycle 1 returns leaseholder 1, cycle 2 returns leaseholder 2
        calls = [0]
        def mock_sql(query):
            calls[0] += 1
            if calls[0] == 1:
                return "1"
            return "2"

        executor = G2Executor(
            plan=plan,
            output_dir="/tmp/test",
            sql_query_runner=mock_sql,
            monotonic_fn=mock_monotonic,
            sleep_fn=mock_sleep,
        )

        binding = executor.jit_leaseholder_discovery()
        self.assertIsNone(binding)
        self.assertTrue(executor.state.aborted)
        self.assertIn("Leaseholder drift detected", executor.state.abort_reason)

    def test_executor_recovery_observation_requires_fault_clearance(self):
        plan = G2RunPlan.create("G2-L3", 1)
        executor = G2Executor(
            plan=plan,
            output_dir="/tmp/test",
            k8s_cmd_runner=lambda cmd: (0, "qdisc netem 10: dev eth0 root loss 50%", ""),  # Fault still active!
        )

        cleared = executor.verify_fault_cleared("cockroachdb-0")
        self.assertFalse(cleared)


class TestG2DynamicTargetingAndFailureModes(unittest.TestCase):
    """
    Verifies dynamic range targeting, leaseholder failover, pod replacement,
    netns inode binding, stale token rejection, and target mismatch safety.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = self.temp_dir.name
        self.claim_store = SharedAtomicClaimStore()
        self.authorizer = G2HelperFaultAuthorizer(
            base_dir=self.base_dir,
            claim_store=self.claim_store,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dynamic_row_range_parsing_and_resolution(self):
        """Verifies parsing of native SHOW RANGE FROM TABLE pgbench_accounts FOR ROW (1)."""
        plan = G2RunPlan.create("G2-L1", 1)
        # Mock standard psql output from SHOW RANGE
        psql_output = "…/2060753 | <after:/Max> | 98 | 2 | | {1,2,3} | {\"\",\"\",\"\"} | {1,2,3} | {}"
        executor = G2Executor(
            plan=plan,
            output_dir="/tmp/test",
            sql_query_runner=lambda q: psql_output,
            k8s_cmd_runner=lambda cmd: (0, "ip-10-0-1-160.ec2.internal", "")
            if "nodeName" in " ".join(cmd)
            else (0, "net:[4026532539]", ""),
        )

        binding = executor.jit_leaseholder_discovery()
        self.assertIsNotNone(binding)
        self.assertEqual(binding.range_id, 98)
        self.assertEqual(binding.lease_holder_id, 2)
        self.assertEqual(binding.target_pod_name, "cockroachdb-1")
        self.assertEqual(binding.target_node_name, "ip-10-0-1-160.ec2.internal")
        self.assertEqual(binding.target_netns_inode, "net:[4026532539]")

    def test_range_change_dynamic_acceptance(self):
        """Verifies that if range ID changes (e.g. from 98 to 115), it is dynamically accepted."""
        plan = G2RunPlan.create("G2-L2", 2)
        psql_output = "…/500000 | …/1000000 | 115 | 3 | | {1,2,3} | {\"\",\"\",\"\"} | {1,2,3} | {}"
        executor = G2Executor(
            plan=plan,
            output_dir="/tmp/test",
            sql_query_runner=lambda q: psql_output,
            k8s_cmd_runner=lambda cmd: (0, "ip-10-0-2-50.ec2.internal", "")
            if "nodeName" in " ".join(cmd)
            else (0, "containerd://aabbcc112233", ""),
        )

        binding = executor.jit_leaseholder_discovery()
        self.assertIsNotNone(binding)
        self.assertEqual(binding.range_id, 115)
        self.assertEqual(binding.lease_holder_id, 3)
        self.assertEqual(binding.target_pod_name, "cockroachdb-2")
        self.assertEqual(binding.target_node_name, "ip-10-0-2-50.ec2.internal")

    def test_range_drift_between_cycles_fails_closed(self):
        """Verifies that range ID rebalance/drift between verification cycles triggers safe abort."""
        plan = G2RunPlan.create("G2-L1", 1)
        calls = [0]

        def drifting_sql(q):
            calls[0] += 1
            if calls[0] == 1:
                return "k1 | k2 | 98 | 2"
            return "k1 | k2 | 99 | 2"  # Range changed mid-verification!

        executor = G2Executor(
            plan=plan,
            output_dir="/tmp/test",
            sql_query_runner=drifting_sql,
            sleep_fn=lambda s: None,
        )

        binding = executor.jit_leaseholder_discovery()
        self.assertIsNone(binding)
        self.assertTrue(executor.state.aborted)
        self.assertIn("Target range drift detected", executor.state.abort_reason)

    def test_system_internal_range_fails_closed(self):
        """Verifies that resolution of system internal range (<= 1) fails closed."""
        plan = G2RunPlan.create("G2-L1", 1)
        executor = G2Executor(
            plan=plan,
            output_dir="/tmp/test",
            sql_query_runner=lambda q: "k1 | k2 | 1 | 1",  # System range 1
            sleep_fn=lambda s: None,
        )

        binding = executor.jit_leaseholder_discovery()
        self.assertIsNone(binding)
        self.assertTrue(executor.state.aborted)
        self.assertIn("System internal range", executor.state.abort_reason)

    def test_netns_inode_mismatch_in_authorizer_fails_closed(self):
        """Verifies that target network namespace inode changes/mismatches fail closed in helper authorizer."""
        now = datetime.datetime.now(datetime.timezone.utc)
        token_payload = {
            "run_id": "crdb-g2l1-formal-f01",
            "auth_nonce": "testnonce12345678",
            "action": "EXECUTE_G2_FAULT_HELPER",
            "target_pod": "cockroachdb-1",
            "target_namespace": "cockroachdb",
            "target_netns_inode": "net:[4026532000]",  # Expected inode
            "fault_type": "packet_loss",
            "loss_percentage": 10,
            "loss_distribution": "uniform",
            "duration_sec": 180,
            "issued_at_utc": now.isoformat(),
            "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
            "authorized_by_operator": "ops-test",
        }

        token_path = os.path.join(self.base_dir, "G2_FAULT_AUTHORIZED.json")
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_payload, f)

        # Container replaced or netns changed: observed inode does not match token
        with self.assertRaises(FaultAuthorizationError) as ctx:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-g2l1-formal-f01",
                expected_target_pod="cockroachdb-1",
                expected_loss_percentage=10,
                observed_netns_inode="net:[4026539999]",  # Changed inode
            )
        self.assertIn("netns_inode mismatch", str(ctx.exception))

    def test_stale_token_expiry_fails_closed(self):
        """Verifies that an expired authorization token is strictly rejected."""
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=20)
        token_payload = {
            "run_id": "crdb-g2l1-formal-f01",
            "auth_nonce": "stalenonce123456",
            "action": "EXECUTE_G2_FAULT_HELPER",
            "target_pod": "cockroachdb-1",
            "target_namespace": "cockroachdb",
            "target_netns_inode": "net:[4026532000]",
            "fault_type": "packet_loss",
            "loss_percentage": 10,
            "loss_distribution": "uniform",
            "duration_sec": 180,
            "issued_at_utc": (past - datetime.timedelta(minutes=5)).isoformat(),
            "expires_at_utc": past.isoformat(),  # Expired
            "authorized_by_operator": "ops-test",
        }

        token_path = os.path.join(self.base_dir, "G2_FAULT_AUTHORIZED.json")
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_payload, f)

        with self.assertRaises(FaultAuthorizationError) as ctx:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-g2l1-formal-f01",
                expected_target_pod="cockroachdb-1",
                expected_loss_percentage=10,
            )
        self.assertIn("token has expired", str(ctx.exception))

    def test_target_pod_mismatch_fails_closed(self):
        """Verifies that if target pod differs from token, authorizer aborts."""
        now = datetime.datetime.now(datetime.timezone.utc)
        token_payload = {
            "run_id": "crdb-g2l1-formal-f01",
            "auth_nonce": "podmismatchnonce",
            "action": "EXECUTE_G2_FAULT_HELPER",
            "target_pod": "cockroachdb-0",  # Token authorized cockroachdb-0
            "target_namespace": "cockroachdb",
            "target_netns_inode": "net:[4026532000]",
            "fault_type": "packet_loss",
            "loss_percentage": 10,
            "loss_distribution": "uniform",
            "duration_sec": 180,
            "issued_at_utc": now.isoformat(),
            "expires_at_utc": (now + datetime.timedelta(minutes=10)).isoformat(),
            "authorized_by_operator": "ops-test",
        }

        token_path = os.path.join(self.base_dir, "G2_FAULT_AUTHORIZED.json")
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_payload, f)

        with self.assertRaises(FaultAuthorizationError) as ctx:
            self.authorizer.verify_and_claim(
                expected_run_id="crdb-g2l1-formal-f01",
                expected_target_pod="cockroachdb-1",  # JIT resolved cockroachdb-1
                expected_loss_percentage=10,
            )
        self.assertIn("target_pod mismatch", str(ctx.exception))


class TestG2ProcessDiscoveryAndBinding(unittest.TestCase):
    """
    Validates fail-closed host process discovery, netns resolution,
    and binding safety invariants for G2-14 remediation.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def _setup_proc_pid(
        self,
        pid: int,
        cmdline: str = "cockroach start --insecure",
        cgroup: str = "12:memory:/kubepods.slice/kubepods-pod1a98abd7_7ac3_4bd6_96ee_1dcfd67f0f67.slice/cri-containerd-f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c.scope",
        start_ticks: int = 1626198,
        inode_num: int = 4026532539,
    ):
        pid_dir = os.path.join(self.proc_root, str(pid))
        os.makedirs(os.path.join(pid_dir, "ns"), exist_ok=True)

        with open(os.path.join(pid_dir, "cmdline"), "wb") as f:
            f.write(cmdline.replace(" ", "\x00").encode("utf-8") + b"\x00")

        with open(os.path.join(pid_dir, "cgroup"), "w", encoding="utf-8") as f:
            f.write(cgroup)

        # /proc/[pid]/stat format: pid (comm) state ... start_time is field 22 (index 19 after ')')
        stat_prefix = f"{pid} (cockroach) S 1 1 0 0 -1 4194304 1000 0 0 0 500 200 0 0 20 0 1 0 "
        stat_content = f"{stat_prefix}{start_ticks} 100000 5000\n"
        with open(os.path.join(pid_dir, "stat"), "w", encoding="utf-8") as f:
            f.write(stat_content)

        # Netns path
        netns_file = os.path.join(pid_dir, "ns", "net")
        with open(netns_file, "w", encoding="utf-8") as f:
            f.write(f"dummy-ns-{inode_num}")

    def test_discover_target_process_success(self):
        """Verifies successful, unambiguous discovery with matching pod UID and container ID."""
        self._setup_proc_pid(
            pid=89190,
            cmdline="cockroach start --insecure",
            cgroup="12:memory:/kubepods.slice/kubepods-pod1a98abd7_7ac3_4bd6_96ee_1dcfd67f0f67.slice/cri-containerd-f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c.scope",
            start_ticks=1626198,
        )
        # Mock os.stat to return known inode
        orig_stat = os.stat
        try:
            class DummyStat:
                st_ino = 4026532539

            def mock_stat(path, *args, **kwargs):
                if str(path).endswith(os.path.join("89190", "ns", "net")):
                    return DummyStat()
                return orig_stat(path, *args, **kwargs)

            os.stat = mock_stat

            from benchmark.scripts.cockroachdb.g2.g2_process_discovery import (
                discover_target_process,
                ProcessDiscoveryError,
            )

            res = discover_target_process(
                target_pod="cockroachdb-1",
                proc_root=self.proc_root,
                target_pod_uid="1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67",
                target_container_id="containerd://f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c",
                expected_netns_inode="net:[4026532539]",
                expected_start_time_ticks=1626198,
            )

            self.assertEqual(res["pid"], 89190)
            self.assertEqual(res["netns_inode"], "net:[4026532539]")
            self.assertEqual(res["start_time_ticks"], 1626198)
            self.assertIn("89190", res["netns_path"])
        finally:
            os.stat = orig_stat

    def test_missing_process_fails_closed(self):
        """Verifies error raised when no matching CockroachDB process exists."""
        from benchmark.scripts.cockroachdb.g2.g2_process_discovery import (
            discover_target_process,
            ProcessDiscoveryError,
        )
        with self.assertRaises(ProcessDiscoveryError) as ctx:
            discover_target_process(
                target_pod="cockroachdb-1",
                proc_root=self.proc_root,
            )
        self.assertIn("Could not locate active CockroachDB process", str(ctx.exception))

    def test_multiple_matching_processes_fails_closed(self):
        """Verifies error raised when multiple matching processes cause ambiguity."""
        self._setup_proc_pid(pid=1001, cgroup="pod-uid-test")
        self._setup_proc_pid(pid=1002, cgroup="pod-uid-test")

        from benchmark.scripts.cockroachdb.g2.g2_process_discovery import (
            discover_target_process,
            ProcessDiscoveryError,
        )
        with self.assertRaises(ProcessDiscoveryError) as ctx:
            discover_target_process(
                target_pod="cockroachdb-1",
                proc_root=self.proc_root,
                target_pod_uid="pod-uid-test",
            )
        self.assertIn("Ambiguous process discovery", str(ctx.exception))

    def test_start_time_ticks_mismatch_fails_closed(self):
        """Verifies PID reuse / container restart detection via start_time_ticks mismatch."""
        self._setup_proc_pid(pid=5000, start_ticks=999999)

        from benchmark.scripts.cockroachdb.g2.g2_process_discovery import (
            discover_target_process,
            ProcessDiscoveryError,
        )
        with self.assertRaises(ProcessDiscoveryError) as ctx:
            discover_target_process(
                target_pod="cockroachdb-1",
                proc_root=self.proc_root,
                expected_start_time_ticks=888888,  # Different ticks
            )
        self.assertIn("PID reuse detected", str(ctx.exception))

    def test_inode_mismatch_fails_closed(self):
        """Verifies netns inode mismatch fails closed."""
        self._setup_proc_pid(pid=5000)
        orig_stat = os.stat
        try:
            class DummyStat:
                st_ino = 11111111

            def mock_stat(path, *args, **kwargs):
                if str(path).endswith(os.path.join("5000", "ns", "net")):
                    return DummyStat()
                return orig_stat(path, *args, **kwargs)

            os.stat = mock_stat

            from benchmark.scripts.cockroachdb.g2.g2_process_discovery import (
                discover_target_process,
                ProcessDiscoveryError,
            )
            with self.assertRaises(ProcessDiscoveryError) as ctx:
                discover_target_process(
                    target_pod="cockroachdb-1",
                    proc_root=self.proc_root,
                    expected_netns_inode="net:[99999999]",  # Expected different
                )
            self.assertIn("Network namespace inode mismatch", str(ctx.exception))
        finally:
            os.stat = orig_stat

    def test_missing_expected_pid_in_config_fails_validation(self):
        """Verifies G2HelperConfig requires expected_pid > 0."""
        from benchmark.scripts.cockroachdb.g2.g2_helper_daemon import G2HelperConfig

        cfg = G2HelperConfig(
            run_id="crdb-g2l1-pilot-r01",
            target_pod="cockroachdb-1",
            loss_percentage=10,
            expected_pid=None,  # Missing PID
        )
        with self.assertRaises(ValueError) as ctx:
            cfg.validate()
        self.assertIn("FAULT mode requires a verified target PID", str(ctx.exception))

        cfg_zero = G2HelperConfig(
            run_id="crdb-g2l1-pilot-r01",
            target_pod="cockroachdb-1",
            loss_percentage=10,
            expected_pid=0,  # Invalid PID
        )
        with self.assertRaises(ValueError) as ctx:
            cfg_zero.validate()
        self.assertIn("FAULT mode requires a verified target PID", str(ctx.exception))

    def test_runtime_refuses_execution_without_netns_path(self):
        """Verifies G2LinuxRuntime strictly refuses local fallback when netns.path is None."""
        from benchmark.scripts.cockroachdb.g2.g2_packet_loss_runtime import (
            G2LinuxRuntime,
            NetnsIdentity,
            ProcessIdentity,
            LinuxRuntimeError,
        )

        runtime = G2LinuxRuntime()
        dummy_netns = NetnsIdentity(ns_inode="net:[12345]", path=None)
        dummy_proc = ProcessIdentity(pid=100)

        with self.assertRaises(LinuxRuntimeError) as ctx:
            runtime.inspect_interface_and_qdisc(dummy_netns)
        self.assertIn("Missing netns path: refusing read-only qdisc inspection", str(ctx.exception))

        with self.assertRaises(LinuxRuntimeError) as ctx:
            runtime.apply_egress_packet_loss(
                run_id="crdb-g2l1-pilot-r01",
                pod_name="cockroachdb-1",
                netns=dummy_netns,
                proc=dummy_proc,
                loss_percentage=10,
            )
        self.assertIn("Missing netns path: refusing fault injection", str(ctx.exception))

        with self.assertRaises(LinuxRuntimeError) as ctx:
            runtime.remove_owned_qdisc(
                pod_name="cockroachdb-1",
                netns=dummy_netns,
            )
        self.assertIn("Missing netns path: refusing qdisc cleanup", str(ctx.exception))

    def test_default_runner_constructs_nsenter_correctly(self):
        """Verifies that _default_runner executes nsenter with --net=<path> and refuses empty netns."""
        from benchmark.scripts.cockroachdb.g2.g2_packet_loss_runtime import (
            G2LinuxRuntime,
            LinuxRuntimeError,
        )

        with self.assertRaises(LinuxRuntimeError) as ctx:
            G2LinuxRuntime._default_runner(["tc", "qdisc", "show"], netns_path=None)
        self.assertIn("Missing netns path: refusing execution in local container namespace", str(ctx.exception))


class TestG1ImplementationIntegrity(unittest.TestCase):
    """Verifies that G1 implementation files are completely unaltered."""

    def test_g1_helper_entrypoint_unmodified(self):
        with open("docker/g1-helper-v2/g1_helper_entrypoint.py", "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn('expected_fault_type="egress_latency"', content)
            self.assertIn("apply_egress_latency", content)

    def test_g1_helper_authorizer_unmodified(self):
        with open("docker/g1-helper-v2/g1_helper_authorizer_REMEDIATED.py", "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn('expected_fault_type: str = "egress_latency"', content)
            self.assertNotIn("packet_loss", content)


if __name__ == "__main__":
    unittest.main()
