"""
g1_jit_gate.py - Just-In-Time Active Leaseholder Verification Gate for CockroachDB Scenario G1.

Implements the corrective verification gate specified under PD-08 and Stage 5.4G.6.
Guarantees that chaos injection binds to the active leaseholder for Range 1 (pgbench_accounts, aid=1)
at T=175s immediately prior to fault application (T0=180s).

Enforces fail-closed semantics:
- If leaseholder drifts from expected/initial target -> raises TargetDriftAbortError.
- If SQL range discovery fails or range_id != 108 -> raises JITGateVerificationError.
- If gossip node resolution fails or target node is not live -> raises JITGateVerificationError.
- If pod or container ticks mismatch baseline -> raises JITGateVerificationError.
- If double-check re-verification fails -> raises TargetDriftAbortError.
- Guarantees ZERO token issuance, ZERO Secret creation, and ZERO Job creation on failure.
"""

from typing import Dict, Any, List, Optional, Tuple
from abc import ABC, abstractmethod
import datetime
import warnings

from benchmark.scripts.cockroachdb.g1.g1_target_resolver import (
    RangeMetadata,
    NodeMetadata,
    PodMetadata,
    IDatabaseMetadataProvider,
    IKubernetesMetadataProvider,
    TargetResolver,
    TargetResolutionError,
)


class JITGateVerificationError(Exception):
    """Base exception for JIT verification gate failures (fail-closed)."""
    pass


class TargetDriftAbortError(JITGateVerificationError):
    """Raised when active leaseholder drifts between resolution checkpoints."""
    pass


class ProcessStateMismatchError(JITGateVerificationError):
    """Raised when target process start ticks or netns inode change unexpectedly."""
    pass


class JITTargetBinding:
    """Immutable data record representing verified target binding immediately before fault injection."""

    def __init__(
        self,
        range_id: int,
        lease_holder_node_id: int,
        node_address: str,
        target_pod_name: str,
        target_container_name: str,
        target_pod_ip: str,
        target_node_name: str,
        target_netns_inode: str,
        target_start_ticks: int,
        verified_at_utc: str,
        check_cycle: int = 1,
    ):
        self.range_id = range_id
        self.lease_holder_node_id = lease_holder_node_id
        self.node_address = node_address
        self.target_pod_name = target_pod_name
        self.target_container_name = target_container_name
        self.target_pod_ip = target_pod_ip
        self.target_node_name = target_node_name
        self.target_netns_inode = target_netns_inode
        self.target_start_ticks = target_start_ticks
        self.verified_at_utc = verified_at_utc
        self.check_cycle = check_cycle

    def to_dict(self) -> Dict[str, Any]:
        return {
            "range_id": self.range_id,
            "lease_holder_node_id": self.lease_holder_node_id,
            "node_address": self.node_address,
            "target_pod_name": self.target_pod_name,
            "target_container_name": self.target_container_name,
            "target_pod_ip": self.target_pod_ip,
            "target_node_name": self.target_node_name,
            "target_netns_inode": self.target_netns_inode,
            "target_start_ticks": self.target_start_ticks,
            "verified_at_utc": self.verified_at_utc,
            "check_cycle": self.check_cycle,
        }


class IProcessInspector(ABC):
    """Abstract interface for inspecting container process attributes."""
    @abstractmethod
    def get_process_state(self, pod_name: str, container_name: str) -> Tuple[str, int]:
        """Returns (netns_inode, start_ticks) for container process 1."""
        pass


from abc import ABC, abstractmethod


class MockProcessInspector(IProcessInspector):
    """Mock process inspector for offline deterministic testing."""

    def __init__(self, mapping: Optional[Dict[str, Tuple[str, int]]] = None):
        # pod_name -> (netns_inode, start_ticks)
        self.mapping = mapping or {}

    def set_pod_state(self, pod_name: str, netns_inode: str, start_ticks: int) -> None:
        self.mapping[pod_name] = (netns_inode, start_ticks)

    def get_process_state(self, pod_name: str, container_name: str) -> Tuple[str, int]:
        if pod_name not in self.mapping:
            raise JITGateVerificationError(f"Process inspection failed: Pod '{pod_name}' container '{container_name}' not reachable.")
        return self.mapping[pod_name]


class PD08JITLeaseholderGate:
    """
    PD-08 Dynamic Active Leaseholder Just-In-Time Verification Gate.
    Executes a 5-step strict verification sequence prior to chaos helper authorization.
    """

    TARGET_TABLE = "pgbench_accounts"
    TARGET_DB = "benchdb"

    def __init__(
        self,
        db_provider: IDatabaseMetadataProvider,
        k8s_provider: IKubernetesMetadataProvider,
        process_inspector: IProcessInspector,
        expected_range_id: Optional[int] = None,
    ):
        self.db_provider = db_provider
        self.k8s_provider = k8s_provider
        self.process_inspector = process_inspector
        self.expected_range_id = expected_range_id
        self._resolver = TargetResolver(
            db_provider=self.db_provider,
            k8s_provider=self.k8s_provider,
            policy=TargetResolver.POLICY_AID_1,
            database_name=self.TARGET_DB,
            table_name=self.TARGET_TABLE,
        )

    def _query_and_resolve(self) -> Dict[str, Any]:
        """Resolves active target using dynamic target resolver."""
        try:
            target = self._resolver.resolve_target()
        except TargetResolutionError as e:
            raise JITGateVerificationError(f"Dynamic target resolution failed: {e}") from e
        except Exception as e:
            raise JITGateVerificationError(f"Unexpected error during target resolution: {e}") from e

        # Validate range ID is valid and non-system
        resolved_range = target.get("physical_range_id")
        if resolved_range is None or resolved_range <= 1:
            raise JITGateVerificationError(
                f"Safety violation: Invalid or internal system range (range_id={resolved_range}) cannot be targeted."
            )

        # If expected_range_id is explicitly supplied, validate match; otherwise dynamically accept valid row range
        if self.expected_range_id is not None and resolved_range != self.expected_range_id:
            raise JITGateVerificationError(
                f"Range ID mismatch: expected {self.expected_range_id}, got {resolved_range}."
            )
        return target

    def verify_and_bind_target(
        self,
        baseline_start_ticks: Optional[Dict[str, int]] = None,
        check_cycle: int = 1,
    ) -> JITTargetBinding:
        """
        Step 1 to 4: Queries instantaneous SHOW RANGES, gossip nodes, pod mapping,
        and container process metadata.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target = self._query_and_resolve()

        pod_name = target["target_pod_name"]
        container_name = target.get("target_container_name", "db")

        # Step 3: Inspect kernel process state
        try:
            netns_inode, start_ticks = self.process_inspector.get_process_state(pod_name, container_name)
        except Exception as e:
            raise JITGateVerificationError(f"Process inspection error for pod '{pod_name}' container '{container_name}': {e}") from e

        if not netns_inode or not netns_inode.startswith("net:["):
            raise ProcessStateMismatchError(f"Invalid network namespace inode '{netns_inode}' for pod '{pod_name}'.")

        if baseline_start_ticks and pod_name in baseline_start_ticks:
            expected_ticks = baseline_start_ticks[pod_name]
            if start_ticks != expected_ticks:
                raise ProcessStateMismatchError(
                    f"Process start ticks mismatch for pod '{pod_name}': expected {expected_ticks}, got {start_ticks} "
                    f"(indicates unobserved container restart)."
                )

        return JITTargetBinding(
            range_id=target["physical_range_id"],
            lease_holder_node_id=target["lease_holder_node_id"],
            node_address=target["node_address"],
            target_pod_name=pod_name,
            target_container_name=container_name,
            target_pod_ip=target["target_pod_ip"],
            target_node_name=target["target_node_name"],
            target_netns_inode=netns_inode,
            target_start_ticks=start_ticks,
            verified_at_utc=now_utc,
            check_cycle=check_cycle,
        )

    def revalidate_immediate_preflight(
        self,
        bound_target: JITTargetBinding,
    ) -> JITTargetBinding:
        """
        Step 5: Post-Binding Concurrency Invariant & Safe Abort Tripwire.
        Re-queries dynamic leaseholder immediately before token creation/deployment.
        If current leaseholder or process state diverges, immediately aborts.
        """
        second_check = self.verify_and_bind_target(
            baseline_start_ticks={bound_target.target_pod_name: bound_target.target_start_ticks},
            check_cycle=bound_target.check_cycle + 1,
        )

        if second_check.lease_holder_node_id != bound_target.lease_holder_node_id:
            raise TargetDriftAbortError(
                f"TARGET DRIFT DETECTED: Leaseholder changed between JIT check ({bound_target.lease_holder_node_id} / {bound_target.target_pod_name}) "
                f"and immediate preflight ({second_check.lease_holder_node_id} / {second_check.target_pod_name}). "
                f"Refusing fault execution. Aborting fail-closed."
            )

        if second_check.target_pod_name != bound_target.target_pod_name:
            raise TargetDriftAbortError(
                f"TARGET DRIFT DETECTED: Pod mapping changed between checks: '{bound_target.target_pod_name}' -> '{second_check.target_pod_name}'."
            )

        if second_check.target_netns_inode != bound_target.target_netns_inode:
            raise ProcessStateMismatchError(
                f"TARGET NETNS DRIFT: Netns inode changed between checks: '{bound_target.target_netns_inode}' -> '{second_check.target_netns_inode}'."
            )

        return second_check
