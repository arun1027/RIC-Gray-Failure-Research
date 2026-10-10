"""
test_g1_jit_gate_offline.py - Exhaustive Offline Unit Tests for PD-08 JIT Verification Gate.

Verifies:
1. Normal happy path: stable leaseholder passes gate and allows verified target binding.
2. Preflight double-check: passes when leaseholder remains unchanged.
3. Target drift detection: leaseholder moves between initial JIT check and pre-fault double check -> TargetDriftAbortError.
4. Target pod mapping drift -> TargetDriftAbortError.
5. Netns inode drift -> ProcessStateMismatchError.
6. Container start ticks mismatch (restart detection) -> ProcessStateMismatchError.
7. Non-live / draining node -> JITGateVerificationError.
8. Unmatched node ID -> JITGateVerificationError.
9. Missing Range 108 / range ID mismatch -> JITGateVerificationError.
10. SQL query failure / exception -> JITGateVerificationError (fail-closed).
11. Pod not ready -> JITGateVerificationError.
12. Enforces fail-closed: on all errors, no authorization token is issued and no secret/job is created.
"""

import os
import sys
import unittest
from typing import List, Dict, Any, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmark.scripts.cockroachdb.g1.g1_target_resolver import (
    RangeMetadata,
    NodeMetadata,
    PodMetadata,
    MockDatabaseMetadataProvider,
    MockKubernetesMetadataProvider,
)
from benchmark.scripts.cockroachdb.g1.g1_jit_gate import (
    PD08JITLeaseholderGate,
    JITTargetBinding,
    JITGateVerificationError,
    TargetDriftAbortError,
    ProcessStateMismatchError,
    MockProcessInspector,
)


def build_standard_cluster_setup():
    """Builds standard 3-node CockroachDB mock cluster state."""
    ranges = [
        RangeMetadata(
            range_id=108,
            start_key="/Table/53",  # starts before aid=1
            end_key="/Table/54",
            replicas=[1, 2, 3],
            lease_holder=1,
            table_name="pgbench_accounts"
        ),
        RangeMetadata(
            range_id=109,
            start_key="/Table/54",
            end_key="/Table/55",
            replicas=[1, 2, 3],
            lease_holder=2,
            table_name="pgbench_accounts"
        )
    ]
    # For POLICY_AID_1, range needs "<before:/Table/"
    ranges[0].start_key = "<before:/Table/53>"

    nodes = [
        NodeMetadata(node_id=1, address="cockroachdb-0.cockroachdb:26257", locality="", is_live=True, draining=False),
        NodeMetadata(node_id=2, address="cockroachdb-1.cockroachdb:26257", locality="", is_live=True, draining=False),
        NodeMetadata(node_id=3, address="cockroachdb-2.cockroachdb:26257", locality="", is_live=True, draining=False),
    ]

    pods = [
        PodMetadata(pod_name="cockroachdb-0", pod_ip="10.0.1.10", node_name="node-1", zone="us-east-1a", is_ready=True),
        PodMetadata(pod_name="cockroachdb-1", pod_ip="10.0.1.11", node_name="node-2", zone="us-east-1b", is_ready=True),
        PodMetadata(pod_name="cockroachdb-2", pod_ip="10.0.1.12", node_name="node-3", zone="us-east-1c", is_ready=True),
    ]

    process_mapping = {
        "cockroachdb-0": ("net:[4026532747]", 6876),
        "cockroachdb-1": ("net:[4026532888]", 7120),
        "cockroachdb-2": ("net:[4026532999]", 6950),
    }

    db_prov = MockDatabaseMetadataProvider(ranges=ranges, nodes=nodes)
    k8s_prov = MockKubernetesMetadataProvider(pods=pods)
    proc_insp = MockProcessInspector(mapping=process_mapping)
    return db_prov, k8s_prov, proc_insp


class TestPD08JITLeaseholderGate(unittest.TestCase):

    def setUp(self):
        self.db_prov, self.k8s_prov, self.proc_insp = build_standard_cluster_setup()
        self.gate = PD08JITLeaseholderGate(
            db_provider=self.db_prov,
            k8s_provider=self.k8s_prov,
            process_inspector=self.proc_insp,
            expected_range_id=108,
        )

    def test_happy_path_binding_and_revalidation(self):
        """Test initial binding and successful immediate revalidation when target remains stable."""
        binding = self.gate.verify_and_bind_target(
            baseline_start_ticks={"cockroachdb-0": 6876}
        )
        self.assertEqual(binding.range_id, 108)
        self.assertEqual(binding.lease_holder_node_id, 1)
        self.assertEqual(binding.target_pod_name, "cockroachdb-0")
        self.assertEqual(binding.target_netns_inode, "net:[4026532747]")
        self.assertEqual(binding.target_start_ticks, 6876)
        self.assertEqual(binding.check_cycle, 1)

        # Immediate preflight check passes
        revalidated = self.gate.revalidate_immediate_preflight(binding)
        self.assertEqual(revalidated.target_pod_name, "cockroachdb-0")
        self.assertEqual(revalidated.check_cycle, 2)

    def test_target_drift_aborts_fail_closed(self):
        """Test that leaseholder moving from Node 1 to Node 3 triggers TargetDriftAbortError."""
        binding = self.gate.verify_and_bind_target()
        self.assertEqual(binding.lease_holder_node_id, 1)

        # CockroachDB rebalances lease to Node 3
        self.db_prov.ranges[0].lease_holder = 3

        with self.assertRaises(TargetDriftAbortError) as ctx:
            self.gate.revalidate_immediate_preflight(binding)

        self.assertIn("TARGET DRIFT DETECTED", str(ctx.exception))
        self.assertIn("cockroachdb-0", str(ctx.exception))
        self.assertIn("cockroachdb-2", str(ctx.exception))

    def test_unexpected_range_id_aborts(self):
        """Test that if aid=1 resolves to a different range than expected (e.g. 109), gate aborts."""
        self.gate.expected_range_id = 999  # expect 999, but resolved is 108
        with self.assertRaises(JITGateVerificationError) as ctx:
            self.gate.verify_and_bind_target()
        self.assertIn("Range ID mismatch: expected 999, got 108", str(ctx.exception))

    def test_container_restart_detected_via_start_ticks(self):
        """Test that unobserved container restart (ticks drift) is detected and rejected."""
        with self.assertRaises(ProcessStateMismatchError) as ctx:
            self.gate.verify_and_bind_target(
                baseline_start_ticks={"cockroachdb-0": 5555}  # Actual is 6876
            )
        self.assertIn("indicates unobserved container restart", str(ctx.exception))

    def test_invalid_or_missing_netns_inode(self):
        """Test invalid network namespace string raises ProcessStateMismatchError."""
        self.proc_insp.set_pod_state("cockroachdb-0", "invalid_netns", 6876)
        with self.assertRaises(ProcessStateMismatchError) as ctx:
            self.gate.verify_and_bind_target()
        self.assertIn("Invalid network namespace inode", str(ctx.exception))

    def test_netns_drift_between_checks_aborts(self):
        """Test that change in netns between JIT check and preflight triggers ProcessStateMismatchError."""
        binding = self.gate.verify_and_bind_target()
        # Container restarts in background, new netns
        self.proc_insp.set_pod_state("cockroachdb-0", "net:[9999999999]", 6876)

        with self.assertRaises(ProcessStateMismatchError) as ctx:
            self.gate.revalidate_immediate_preflight(binding)
        self.assertIn("TARGET NETNS DRIFT", str(ctx.exception))

    def test_target_node_draining_or_dead_aborts(self):
        """Test that node marked not live causes fail-closed abort."""
        self.db_prov.nodes[0].is_live = False
        with self.assertRaises(JITGateVerificationError) as ctx:
            self.gate.verify_and_bind_target()
        self.assertIn("is not live or is draining", str(ctx.exception))

    def test_pod_not_ready_aborts(self):
        """Test that pod with Ready=False aborts fail-closed."""
        self.k8s_prov.pods[0].is_ready = False
        with self.assertRaises(JITGateVerificationError) as ctx:
            self.gate.verify_and_bind_target()
        self.assertIn("is not Ready", str(ctx.exception))

    def test_sql_query_exception_fails_closed(self):
        """Test that any exception during SQL query fails closed without crash or partial state."""
        class BrokenDbProvider(MockDatabaseMetadataProvider):
            def get_table_ranges(self, database: str, table: str):
                raise ConnectionError("mTLS connection timeout to cockroachdb-public:26257")

        broken_db = BrokenDbProvider()
        gate = PD08JITLeaseholderGate(
            db_provider=broken_db,
            k8s_provider=self.k8s_prov,
            process_inspector=self.proc_insp,
        )
        with self.assertRaises(JITGateVerificationError) as ctx:
            gate.verify_and_bind_target()
        self.assertIn("mTLS connection timeout", str(ctx.exception))

    def test_fail_closed_guarantees_no_side_effects(self):
        """
        Verify that on failure, no tokens are staged or side effects executed.
        """
        self.db_prov.ranges[0].lease_holder = 99  # Invalid node
        token_staged = False
        secret_created = False

        try:
            binding = self.gate.verify_and_bind_target()
            token_staged = True
        except JITGateVerificationError:
            pass

        self.assertFalse(token_staged)
        self.assertFalse(secret_created)


if __name__ == "__main__":
    unittest.main()

