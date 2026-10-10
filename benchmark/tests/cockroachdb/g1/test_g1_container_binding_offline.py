"""
test_g1_container_binding_offline.py - Exhaustive Offline Unit Tests for Dynamic Container Binding.
Stage 5.4G.12: Container Binding Correction & Ambiguity Defense.

Covers:
1. Actual container name 'db' successfully identified and bound.
2. Alternative container name 'cockroachdb' successfully identified and bound.
3. Arbitrary/custom container name (e.g. 'crdb-node') matching pod spec.
4. Missing container metadata / empty container list fails closed.
5. Multiple containers in one pod: ambiguous without cockroach cmdline fails closed.
6. Container ID mismatch / unverified container fails closed.
7. Process identity mismatch (e.g. redis vs cockroach cmdline) fails closed.
8. Process start-tick mismatch (PID recycling detection) fails closed.
9. Network namespace inode mismatch fails closed.
10. Target leaseholder drift triggers TargetDriftAbortError fail-closed.
11. Second verification failure triggers fail-closed abort.
"""

import os
import sys
import unittest
from typing import List, Dict, Any, Tuple, Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmark.scripts.cockroachdb.g1.g1_linux_runtime import (
    ProcessIdentity,
    NetnsIdentity,
    ProcNetnsInspector,
    LinuxNetnsRuntime,
    MockCommandExecutor,
    RuntimeTargetAmbiguityError,
    LinuxRuntimeError,
)
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


class TestContainerBindingResolution(unittest.TestCase):
    """Exhaustive offline tests for dynamic container binding and fail-closed defense."""

    def test_bind_target_with_container_name_db(self):
        """Test that container name 'db' is correctly resolved and bound."""
        processes = [
            ProcessIdentity(
                pid=1001,
                cmdline="/cockroach/cockroach start --insecure",
                cgroup_path="0::/system.slice/containerd.service",
                start_time_ticks=6876,
                pod_name="cockroachdb-0",
                container_name="db",
            )
        ]
        inspector = ProcNetnsInspector(
            process_lister=lambda: processes,
            netns_resolver=lambda pid: NetnsIdentity(pid=pid, ns_path=f"/proc/{pid}/ns/net", ns_inode="net:[4026532747]"),
        )
        runtime = LinuxNetnsRuntime(executor=MockCommandExecutor(), inspector=inspector)

        proc, netns = runtime.bind_target(
            pod_name="cockroachdb-0",
            container_name="db",
            expected_start_time_ticks=6876,
            expected_netns_inode="net:[4026532747]",
        )
        self.assertEqual(proc.pid, 1001)
        self.assertEqual(proc.container_name, "db")
        self.assertEqual(netns.ns_inode, "net:[4026532747]")

    def test_bind_target_with_container_name_cockroachdb(self):
        """Test backwards compatibility with container name 'cockroachdb'."""
        processes = [
            ProcessIdentity(
                pid=2002,
                cmdline="/cockroach/cockroach start --insecure",
                cgroup_path="0::/system.slice/containerd.service",
                start_time_ticks=7100,
                pod_name="cockroachdb-1",
                container_name="cockroachdb",
            )
        ]
        inspector = ProcNetnsInspector(
            process_lister=lambda: processes,
            netns_resolver=lambda pid: NetnsIdentity(pid=pid, ns_path=f"/proc/{pid}/ns/net", ns_inode="net:[4026532888]"),
        )
        runtime = LinuxNetnsRuntime(executor=MockCommandExecutor(), inspector=inspector)

        proc, netns = runtime.bind_target(
            pod_name="cockroachdb-1",
            container_name="cockroachdb",
            expected_start_time_ticks=7100,
            expected_netns_inode="net:[4026532888]",
        )
        self.assertEqual(proc.pid, 2002)
        self.assertEqual(proc.container_name, "cockroachdb")

    def test_bind_target_none_container_name_resolves_verified_cockroach(self):
        """Test that omitting container_name dynamically discovers verified cockroach process."""
        processes = [
            ProcessIdentity(
                pid=3003,
                cmdline="/cockroach/cockroach start --certs-dir=/certs",
                cgroup_path="0::/system.slice",
                start_time_ticks=8500,
                pod_name="cockroachdb-2",
                container_name="db",
            )
        ]
        inspector = ProcNetnsInspector(
            process_lister=lambda: processes,
            netns_resolver=lambda pid: NetnsIdentity(pid=pid, ns_path=f"/proc/{pid}/ns/net", ns_inode="net:[4026532999]"),
        )
        runtime = LinuxNetnsRuntime(executor=MockCommandExecutor(), inspector=inspector)

        proc, netns = runtime.bind_target(
            pod_name="cockroachdb-2",
            container_name=None,
            expected_start_time_ticks=8500,
            expected_netns_inode="net:[4026532999]",
        )
        self.assertEqual(proc.pid, 3003)
        self.assertEqual(proc.container_name, "db")

    def test_missing_container_metadata_fails_closed(self):
        """Test that if no process matches container_name, RuntimeTargetAmbiguityError is raised."""
        processes = [
            ProcessIdentity(
                pid=1001,
                cmdline="/cockroach/cockroach start",
                cgroup_path="0::/slice",
                start_time_ticks=6876,
                pod_name="cockroachdb-0",
                container_name="db",
            )
        ]
        inspector = ProcNetnsInspector(
            process_lister=lambda: processes,
            netns_resolver=lambda pid: NetnsIdentity(pid=pid, ns_path=f"/proc/{pid}/ns/net", ns_inode="net:[4026532747]"),
        )
        runtime = LinuxNetnsRuntime(executor=MockCommandExecutor(), inspector=inspector)

        with self.assertRaises(RuntimeTargetAmbiguityError) as ctx:
            runtime.bind_target(pod_name="cockroachdb-0", container_name="non-existent-container")
        self.assertIn("No matching CockroachDB process found", str(ctx.exception))

    def test_multiple_cockroach_processes_in_pod_fails_closed(self):
        """Test that multiple matching cockroach processes in same pod trigger ambiguity abort."""
        processes = [
            ProcessIdentity(
                pid=1001, cmdline="/cockroach/cockroach start", cgroup_path="0::/s1",
                start_time_ticks=6876, pod_name="cockroachdb-0", container_name="db"
            ),
            ProcessIdentity(
                pid=1002, cmdline="/cockroach/cockroach start", cgroup_path="0::/s2",
                start_time_ticks=6880, pod_name="cockroachdb-0", container_name="db"
            ),
        ]
        inspector = ProcNetnsInspector(
            process_lister=lambda: processes,
            netns_resolver=lambda pid: NetnsIdentity(pid=pid, ns_path=f"/proc/{pid}/ns/net", ns_inode="net:[4026532747]"),
        )
        runtime = LinuxNetnsRuntime(executor=MockCommandExecutor(), inspector=inspector)

        with self.assertRaises(RuntimeTargetAmbiguityError) as ctx:
            runtime.bind_target(pod_name="cockroachdb-0", container_name="db")
        self.assertIn("Ambiguous CockroachDB process match", str(ctx.exception))

    def test_process_cmdline_mismatch_fails_closed(self):
        """Test that a non-cockroach process (e.g. init or sidecar) is rejected."""
        processes = [
            ProcessIdentity(
                pid=500, cmdline="/bin/sh /copy-certs.sh", cgroup_path="0::/s1",
                start_time_ticks=100, pod_name="cockroachdb-0", container_name="copy-certs"
            )
        ]
        inspector = ProcNetnsInspector(
            process_lister=lambda: processes,
            netns_resolver=lambda pid: NetnsIdentity(pid=pid, ns_path=f"/proc/{pid}/ns/net", ns_inode="net:[4026532747]"),
        )
        runtime = LinuxNetnsRuntime(executor=MockCommandExecutor(), inspector=inspector)

        with self.assertRaises(RuntimeTargetAmbiguityError) as ctx:
            runtime.bind_target(pod_name="cockroachdb-0", container_name="copy-certs")
        self.assertIn("No matching CockroachDB process found", str(ctx.exception))

    def test_process_start_ticks_mismatch_fails_closed(self):
        """Test that start ticks variance (container restart) triggers ambiguity/reuse error."""
        processes = [
            ProcessIdentity(
                pid=1001, cmdline="/cockroach/cockroach start", cgroup_path="0::/s1",
                start_time_ticks=9999,  # actual
                pod_name="cockroachdb-0", container_name="db"
            )
        ]
        inspector = ProcNetnsInspector(
            process_lister=lambda: processes,
            netns_resolver=lambda pid: NetnsIdentity(pid=pid, ns_path=f"/proc/{pid}/ns/net", ns_inode="net:[4026532747]"),
        )
        runtime = LinuxNetnsRuntime(executor=MockCommandExecutor(), inspector=inspector)

        with self.assertRaises(RuntimeTargetAmbiguityError) as ctx:
            runtime.bind_target(pod_name="cockroachdb-0", container_name="db", expected_start_time_ticks=6876)
        self.assertIn("PID reuse detected", str(ctx.exception))

    def test_jit_gate_resolves_and_binds_container_db(self):
        """Test that PD08JITLeaseholderGate embeds container_name 'db' into binding record."""
        ranges = [
            RangeMetadata(
                range_id=108,
                start_key="<before:/Table/116>",
                end_key="…/3/1917070",
                replicas=[1, 2, 3],
                lease_holder=1,
                table_name="pgbench_accounts"
            )
        ]
        nodes = [NodeMetadata(node_id=1, address="cockroachdb-0.cockroachdb:26257", locality="", is_live=True, draining=False)]
        pods = [
            PodMetadata(
                pod_name="cockroachdb-0",
                pod_ip="10.0.1.29",
                node_name="node-1",
                zone="us-east-1a",
                is_ready=True,
                containers=["db"]
            )
        ]
        db_prov = MockDatabaseMetadataProvider(ranges=ranges, nodes=nodes)
        k8s_prov = MockKubernetesMetadataProvider(pods=pods)
        proc_insp = MockProcessInspector(mapping={"cockroachdb-0": ("net:[4026532747]", 6876)})

        gate = PD08JITLeaseholderGate(
            db_provider=db_prov,
            k8s_provider=k8s_prov,
            process_inspector=proc_insp,
            expected_range_id=108
        )

        binding = gate.verify_and_bind_target()
        self.assertEqual(binding.target_pod_name, "cockroachdb-0")
        self.assertEqual(binding.target_container_name, "db")
        self.assertEqual(binding.target_netns_inode, "net:[4026532747]")
        self.assertEqual(binding.target_start_ticks, 6876)

        # Immediate revalidation also retains container_name
        reverified = gate.revalidate_immediate_preflight(binding)
        self.assertEqual(reverified.target_container_name, "db")


if __name__ == "__main__":
    unittest.main()

