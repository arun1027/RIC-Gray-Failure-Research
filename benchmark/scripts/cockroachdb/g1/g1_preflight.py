"""
g1_preflight.py - Preflight Validation Module for Scenario G1.

Features:
- Validates CockroachDB cluster health, 3-node quorum, and range replication.
- Validates SF50 dataset row counts and balance integrity.
- Validates TLS configuration and in-cluster certificates.
- Validates Linux NET_ADMIN capability / tc availability (mockable).
- Distinguishes approved research thresholds from provisional thresholds.
- Integrates with injectable providers to allow 100% offline verification.
"""

from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod


class PreflightCheckResult:
    def __init__(self, check_name: str, passed: bool, message: str, details: Optional[Dict[str, Any]] = None):
        self.check_name = check_name
        self.passed = passed
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_name": self.check_name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
        }


class TupleCheckResult:
    def __init__(self, passed: bool, message: str, details: Optional[Dict[str, Any]] = None):
        self.passed = passed
        self.message = message
        self.details = details or {}


class IPreflightProbe(ABC):
    @abstractmethod
    def check_node_health(self) -> TupleCheckResult:
        pass

    @abstractmethod
    def check_range_replication(self) -> TupleCheckResult:
        pass

    @abstractmethod
    def check_dataset_counts(self) -> TupleCheckResult:
        pass

    @abstractmethod
    def check_tls_config(self) -> TupleCheckResult:
        pass

    @abstractmethod
    def check_net_admin_capability(self, pod_name: str) -> TupleCheckResult:
        pass


class MockPreflightProbe(IPreflightProbe):
    def __init__(
        self,
        nodes_healthy: bool = True,
        ranges_replicated: bool = True,
        dataset_valid: bool = True,
        tls_valid: bool = True,
        net_admin_capable: bool = True,
        under_replicated_count: int = 0,
        account_count: int = 5000000
    ):
        self.nodes_healthy = nodes_healthy
        self.ranges_replicated = ranges_replicated
        self.dataset_valid = dataset_valid
        self.tls_valid = tls_valid
        self.net_admin_capable = net_admin_capable
        self.under_replicated_count = under_replicated_count
        self.account_count = account_count

    def check_node_health(self) -> TupleCheckResult:
        if self.nodes_healthy:
            return TupleCheckResult(True, "All 3 CockroachDB nodes live, active, and non-draining.")
        return TupleCheckResult(False, "Node health check failed: 1 or more nodes dead or draining.")

    def check_range_replication(self) -> TupleCheckResult:
        if self.ranges_replicated and self.under_replicated_count == 0:
            return TupleCheckResult(True, "100% of ranges replicated across 3 nodes (0 under-replicated).")
        return TupleCheckResult(False, f"Range replication check failed: {self.under_replicated_count} under-replicated ranges detected.")

    def check_dataset_counts(self) -> TupleCheckResult:
        if self.dataset_valid and self.account_count == 5000000:
            return TupleCheckResult(True, "Dataset verified at Scale Factor 50 (5,000,000 accounts, 50 branches, 500 tellers).")
        return TupleCheckResult(False, f"Dataset verification mismatch: found {self.account_count} accounts (expected 5,000,000).")

    def check_tls_config(self) -> TupleCheckResult:
        if self.tls_valid:
            return TupleCheckResult(True, "mTLS verify-full verified with valid certificates and root CA trust chain.")
        return TupleCheckResult(False, "TLS verification failed: certificate expired or verification error.")

    def check_net_admin_capability(self, pod_name: str) -> TupleCheckResult:
        if self.net_admin_capable:
            return TupleCheckResult(True, f"Target pod '{pod_name}' possesses CAP_NET_ADMIN / tc netem injection privileges.")
        return TupleCheckResult(False, f"Target pod '{pod_name}' lacks CAP_NET_ADMIN privileges (Operation not permitted).")


class G1PreflightValidator:
    """Orchestrates all preflight checks for G1."""

    def __init__(self, probe: IPreflightProbe):
        self.probe = probe

    def run_all_checks(self, target_pod_name: str) -> List[PreflightCheckResult]:
        checks = []

        # 1. Cluster Node Health
        r1 = self.probe.check_node_health()
        checks.append(PreflightCheckResult("cockroach_nodes_healthy", r1.passed, r1.message, r1.details))

        # 2. Range Replication
        r2 = self.probe.check_range_replication()
        checks.append(PreflightCheckResult("range_replication_healthy", r2.passed, r2.message, r2.details))

        # 3. Dataset Invariants
        r3 = self.probe.check_dataset_counts()
        checks.append(PreflightCheckResult("dataset_sf50_intact", r3.passed, r3.message, r3.details))

        # 4. TLS Configuration
        r4 = self.probe.check_tls_config()
        checks.append(PreflightCheckResult("client_mtls_valid", r4.passed, r4.message, r4.details))

        # 5. Linux Capability Check (Mockable)
        r5 = self.probe.check_net_admin_capability(target_pod_name)
        checks.append(PreflightCheckResult("net_admin_capable", r5.passed, r5.message, r5.details))

        return checks


class LivePreflightValidationError(Exception):
    """Raised when live target preflight validation fails or is ambiguous/stale."""
    pass


class LiveTargetPreflightRecord:
    """
    Captures all 10 live target identities required before fault injection.
    Explicitly distinguishes CockroachDB leaseholder from Raft leader.
    """

    def __init__(
        self,
        cockroach_node_id: int,
        pod_name: str,
        worker_node_name: str,
        pod_ip: str,
        netns_inode: str,
        leaseholder_node_id: int,
        raft_leader_node_id: Optional[int],
        physical_range_id: int,
        aid1_range_verified: bool,
        t110_freshness_verified: bool,
        interface: str,
        cluster_healthy: bool,
        is_mock: bool = False,
    ):
        self.cockroach_node_id = cockroach_node_id
        self.pod_name = pod_name
        self.worker_node_name = worker_node_name
        self.pod_ip = pod_ip
        self.netns_inode = netns_inode
        self.leaseholder_node_id = leaseholder_node_id
        self.raft_leader_node_id = raft_leader_node_id
        self.physical_range_id = physical_range_id
        self.aid1_range_verified = aid1_range_verified
        self.t110_freshness_verified = t110_freshness_verified
        self.interface = interface
        self.cluster_healthy = cluster_healthy
        self.is_mock = is_mock


class LiveTargetPreflightGate:
    """
    Fail-closed live target preflight validator.
    Never treats an offline mock record as live verification.
    """

    @staticmethod
    def validate(record: LiveTargetPreflightRecord) -> Dict[str, Any]:
        if record.is_mock:
            raise LivePreflightValidationError(
                "Offline mock record cannot satisfy live target preflight verification."
            )
        if not record.cluster_healthy:
            raise LivePreflightValidationError("Cluster health check failed; aborting target binding.")
        if record.physical_range_id <= 1 or not record.aid1_range_verified:
            raise LivePreflightValidationError(
                f"Invalid physical range_id={record.physical_range_id} or aid=1 span not verified."
            )
        if record.cockroach_node_id != record.leaseholder_node_id:
            raise LivePreflightValidationError(
                f"Target node_id={record.cockroach_node_id} does not match current leaseholder={record.leaseholder_node_id} "
                f"(note: raft_leader={record.raft_leader_node_id} is distinct from leaseholder)."
            )
        if not record.pod_name or not record.worker_node_name or not record.pod_ip or not record.netns_inode:
            raise LivePreflightValidationError("Incomplete pod/node/IP/netns identity; refusing ambiguous target.")
        if record.interface != "eth0":
            raise LivePreflightValidationError(f"Unapproved target interface '{record.interface}'; expected 'eth0'.")
        if not record.t110_freshness_verified:
            raise LivePreflightValidationError("T=110s target freshness check failed or expired.")
        return {
            "status": "LIVE_TARGET_VERIFIED",
            "cockroach_node_id": record.cockroach_node_id,
            "leaseholder_node_id": record.leaseholder_node_id,
            "raft_leader_node_id": record.raft_leader_node_id,
            "pod_name": record.pod_name,
            "worker_node_name": record.worker_node_name,
            "pod_ip": record.pod_ip,
            "netns_inode": record.netns_inode,
            "physical_range_id": record.physical_range_id,
            "interface": record.interface,
        }


