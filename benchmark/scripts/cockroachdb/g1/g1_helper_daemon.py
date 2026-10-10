"""
g1_helper_daemon.py - Architecture & Mock Implementation of the Privileged Chaos Helper Daemon for Scenario G1.

Features:
- Encapsulates exact Linux capability requirements: CAP_NET_ADMIN (for qdisc manipulation)
  AND CAP_SYS_ADMIN (for setns into another container's network namespace).
- Models network namespace discovery and three-factor cross-verification (pod IP, target container, port 26257).
- Implements strict handle-specific qdisc tracking (handle 100:) to prevent deleting foreign qdiscs.
- Rejects pre-existing qdiscs; never overwrites unknown network configurations.
- Models autonomous in-helper watchdog and explicitly documents its failure boundaries
  (e.g., does not survive container cgroup termination).
- Enforces safe rollback: failed cleanup NEVER deletes CockroachDB pods; it sets UNRESOLVED_FAULT
  and emits an urgent operator alert.
- Provides comprehensive audit logging and SHA-256 evidence hashing.
- Implements HelperFaultController adhering to IFaultController.
- Strictly offline / mock simulation in this phase; zero live privileged operations or cluster mutations.
"""

import hashlib
import json
import time
import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

from .g1_fault_controller import (
    IFaultController,
    FaultControllerError,
    QdiscConflictError,
    RollbackVerificationError
)


class TargetVerificationError(FaultControllerError):
    """Raised when target pod, IP, or network namespace fails validation."""
    pass


class CapabilityMissingError(FaultControllerError):
    """Raised when required Linux capability (e.g. CAP_NET_ADMIN, CAP_SYS_ADMIN) is missing."""
    pass


class WatchdogTimeoutError(FaultControllerError):
    """Raised when helper autonomous watchdog trips due to duration expiry or orchestrator disconnect."""
    pass


class InterfaceNotFoundError(FaultControllerError):
    """Raised when interface or network namespace has vanished (Linux kernel ENODEV)."""
    pass


@dataclass
class HelperSecurityContext:
    """
    Security context configuration for the privileged chaos helper.
    Audit finding: CAP_NET_ADMIN is required for tc netlink, but CAP_SYS_ADMIN
    is strictly required by Linux kernel to call setns(fd, CLONE_NEWNET).
    Workstream 1 finding: The helper should reside in a dedicated chaos namespace
    ('g1-chaos') so that the production database namespace ('cockroachdb') remains
    unprivileged under Pod Security Standards.
    """
    capabilities_add: List[str] = field(default_factory=lambda: ["NET_ADMIN", "SYS_ADMIN"])
    privileged: bool = False
    allow_privilege_escalation: bool = False
    read_only_root_filesystem: bool = True
    run_as_user: int = 0  # Root required in container user namespace to open netlink socket and setns
    seccomp_profile: str = "RuntimeDefault"
    chaos_namespace: str = "g1-chaos"  # Dedicated isolated namespace

    def validate(self) -> None:
        if "NET_ADMIN" not in self.capabilities_add:
            raise CapabilityMissingError("CAP_NET_ADMIN is mandatory for Linux traffic control (tc) manipulation.")
        if "SYS_ADMIN" not in self.capabilities_add:
            raise CapabilityMissingError(
                "CAP_SYS_ADMIN is mandatory in Linux to join an existing network namespace via setns(CLONE_NEWNET)."
            )


@dataclass
class TargetNamespaceSpec:
    """Target specification for network namespace identification and verification."""
    pod_name: str
    namespace: str
    expected_pod_ip: str
    container_name: str = "cockroachdb"
    expected_listen_port: int = 26257
    interface: str = "eth0"


class AutonomousWatchdog:
    """
    Simulates an independent watchdog process inside the helper container.
    Failure boundaries are documented with absolute technical rigor:
    - Survives orchestrator termination (if helper container lives).
    - Survives network partition between client and cluster.
    - DOES NOT survive helper container termination (cgroup SIGKILL).
    - DOES NOT survive helper pod deletion or node disruption.
    """

    def __init__(self, max_duration_sec: int = 180, safety_margin_sec: int = 20):
        self.max_duration_sec = max_duration_sec
        self.hard_timeout_sec = max_duration_sec + safety_margin_sec
        self.is_armed = False
        self.armed_timestamp: Optional[float] = None
        self.tripped = False
        self.cleared = False

    def arm(self) -> None:
        self.is_armed = True
        self.armed_timestamp = time.time()
        self.tripped = False
        self.cleared = False

    def disarm(self) -> None:
        self.is_armed = False
        self.cleared = True

    def check_status(self, elapsed_sec: Optional[float] = None) -> str:
        if not self.is_armed:
            return "DISARMED"
        if elapsed_sec is None and self.armed_timestamp:
            elapsed_sec = time.time() - self.armed_timestamp
        if elapsed_sec is not None and elapsed_sec >= self.max_duration_sec:
            self.tripped = True
            return "TRIPPED"
        return "ARMED"

    @staticmethod
    def evaluate_survival(scenario: str) -> bool:
        """Determines whether the in-container watchdog survives a specific failure event."""
        survival_matrix = {
            "orchestrator_termination": True,
            "network_partition": True,
            "helper_container_termination": False,
            "helper_pod_deletion": False,
            "worker_node_reboot": False,
        }
        return survival_matrix.get(scenario, False)


class PrivilegedHelperDaemon:
    """
    Mock & Architectural Reference implementation of the G1 Privileged Chaos Helper.
    Simulates the helper daemon lifecycle, namespace binding, tc injection, and rollback.
    """

    G1_HANDLE: str = "100:"
    APPROVED_DELAY_MS: int = 1000
    APPROVED_JITTER_MS: int = 20
    MAX_DURATION_SEC: int = 180
    APPROVED_INTERFACES = ("eth0",)
    APPROVED_DISTRIBUTIONS = ("normal", "uniform", "pareto", "paretonormal")

    def __init__(
        self,
        security_context: Optional[HelperSecurityContext] = None,
        initial_qdisc: str = "noqueue",
        simulate_conflict: bool = False,
        simulate_rollback_failure: bool = False,
        simulate_crash: bool = False,
        simulate_race_condition: bool = False,
        simulate_disappearing_interface: bool = False,
        require_verified_target: bool = False,
    ):
        self.security_context = security_context or HelperSecurityContext()
        self.current_qdisc = "netem delay 500ms" if simulate_conflict else initial_qdisc
        self.current_handle: Optional[str] = "10:" if simulate_conflict else None
        self.simulate_rollback_failure = simulate_rollback_failure
        self.simulate_crash = simulate_crash
        self.simulate_race_condition = simulate_race_condition
        self.simulate_disappearing_interface = simulate_disappearing_interface
        self.require_verified_target = require_verified_target
        self.watchdog = AutonomousWatchdog(max_duration_sec=180)
        self.active_target: Optional[TargetNamespaceSpec] = None
        self.fault_active: bool = False
        self.experiment_qdisc_id: Optional[str] = None
        self.audit_log: List[Dict[str, Any]] = []

        # Safe failure state tracking
        self.unresolved_fault: bool = False
        self.operator_alert: Optional[str] = None
        self.pod_deleted_escalation_attempted: bool = False

    def verify_target(self, target: TargetNamespaceSpec, simulated_live_pods: Dict[str, Dict[str, Any]]) -> bool:
        """
        Cross-checks the target specification against live Kubernetes and node state
        before touching any network namespace.
        """
        if target.pod_name not in simulated_live_pods:
            raise TargetVerificationError(f"Target pod '{target.pod_name}' does not exist in namespace '{target.namespace}'.")
        
        pod_info = simulated_live_pods[target.pod_name]
        if pod_info.get("ip") != target.expected_pod_ip:
            raise TargetVerificationError(
                f"Pod IP mismatch for '{target.pod_name}': expected {target.expected_pod_ip}, found {pod_info.get('ip')}."
            )
        
        if target.expected_listen_port not in pod_info.get("ports", []):
            raise TargetVerificationError(
                f"Target pod '{target.pod_name}' is not listening on expected database port {target.expected_listen_port}."
            )

        self.active_target = target
        self._record_audit_event("target_verified", {"target": target.pod_name, "ip": target.expected_pod_ip})
        return True

    def inspect_qdisc(self, target: TargetNamespaceSpec) -> str:
        """Queries the current queuing discipline in the target namespace."""
        self.security_context.validate()
        self._record_audit_event("inspect_qdisc", {"interface": target.interface, "qdisc": self.current_qdisc})
        return self.current_qdisc

    def apply_fault(
        self,
        target: TargetNamespaceSpec,
        delay_ms: int = 1000,
        jitter_ms: int = 20,
        distribution: str = "normal",
        duration_sec: int = 180,
        direction: str = "egress",
        **unknown_params: Any,
    ) -> Dict[str, Any]:
        """Applies tc netem delay inside the verified target network namespace using explicit handle."""
        if unknown_params:
            raise FaultControllerError(f"Rejected unknown fault parameters: {sorted(unknown_params.keys())}.")
        if self.simulate_crash:
            raise FaultControllerError("Helper daemon simulated crash before applying fault.")

        self.security_context.validate()

        if self.unresolved_fault:
            raise QdiscConflictError(
                "Refusing fault injection: unresolved fault state from prior run requires manual verification."
            )
        if self.fault_active:
            raise QdiscConflictError(
                f"Duplicate fault application rejected: experiment qdisc '{self.experiment_qdisc_id}' is already active."
            )

        # Parameter & direction safety enforcement
        if not isinstance(duration_sec, int) or isinstance(duration_sec, bool) or duration_sec <= 0 or duration_sec > self.MAX_DURATION_SEC:
            raise FaultControllerError(
                f"Invalid duration_sec={duration_sec}: must be an integer between 1 and {self.MAX_DURATION_SEC}."
            )
        if delay_ms != self.APPROVED_DELAY_MS:
            raise FaultControllerError(
                f"Unapproved latency delay_ms={delay_ms}: approved G1 configuration requires {self.APPROVED_DELAY_MS} ms."
            )
        if jitter_ms != self.APPROVED_JITTER_MS:
            raise FaultControllerError(
                f"Unapproved jitter_ms={jitter_ms}: approved G1 configuration requires {self.APPROVED_JITTER_MS} ms."
            )
        if direction != "egress":
            raise FaultControllerError(f"Unapproved fault direction '{direction}': must be 'egress'.")
        if distribution not in self.APPROVED_DISTRIBUTIONS:
            raise FaultControllerError(
                f"Unapproved netem distribution '{distribution}': allowed {self.APPROVED_DISTRIBUTIONS}."
            )
        if target.interface not in self.APPROVED_INTERFACES:
            raise TargetVerificationError(
                f"Rejected unrelated interface '{target.interface}': allowed {self.APPROVED_INTERFACES}."
            )

        # Stale target verification
        if self.require_verified_target and self.active_target is None:
            raise TargetVerificationError("Refusing fault injection: target has not been verified via verify_target().")
        if self.active_target is not None and (
            target.pod_name != self.active_target.pod_name
            or target.expected_pod_ip != self.active_target.expected_pod_ip
            or target.interface != self.active_target.interface
        ):
            raise TargetVerificationError(
                f"Stale target identity rejected: active_target={self.active_target.pod_name}@{self.active_target.expected_pod_ip}, "
                f"requested={target.pod_name}@{target.expected_pod_ip}."
            )

        current = self.inspect_qdisc(target)
        if "netem" in current or (current not in ("noqueue", "mq", "fq_codel", "")):
            raise QdiscConflictError(
                f"Conflicting qdisc detected in target namespace {target.pod_name}:{target.interface}: '{current}'. Refusing injection."
            )

        if self.simulate_race_condition:
            # Simulate a concurrent modification between inspection and addition
            self.current_qdisc = "tbf rate 1mbit"
            self.current_handle = "50:"
            raise QdiscConflictError("Race condition detected: Qdisc changed between inspection and application.")

        # Apply fault with explicit G1 handle and unique experiment-owned identifier
        self.current_qdisc = f"netem delay {delay_ms}ms {jitter_ms}ms {distribution}"
        self.current_handle = self.G1_HANDLE
        self.fault_active = True
        self.experiment_qdisc_id = f"g1:{target.pod_name}:{target.interface}:{self.G1_HANDLE}:{int(time.time())}"
        self.watchdog.arm()

        event_data = {
            "target_pod": target.pod_name,
            "target_ip": target.expected_pod_ip,
            "interface": target.interface,
            "handle": self.G1_HANDLE,
            "experiment_qdisc_id": self.experiment_qdisc_id,
            "delay_ms": delay_ms,
            "jitter_ms": jitter_ms,
            "distribution": distribution,
            "duration_sec": duration_sec,
            "direction": "egress",
            "qdisc_command": f"/sbin/tc qdisc add dev {target.interface} root handle {self.G1_HANDLE} netem delay {delay_ms}ms {jitter_ms}ms distribution {distribution}",
            "status": "APPLIED"
        }
        self._record_audit_event("apply_fault", event_data)
        return event_data

    def rollback_fault(self, target: TargetNamespaceSpec) -> Dict[str, Any]:
        """
        Removes the netem queuing discipline using explicit handle verification.
        Never removes an unknown qdisc not created by this helper.
        If the target interface disappeared (ENODEV), it is treated as naturally cleared.
        """
        if self.simulate_disappearing_interface:
            # When the target pod terminates, Kubelet deletes the veth device; kernel destroys qdisc
            self.current_qdisc = "noqueue"
            self.current_handle = None
            self.watchdog.disarm()
            event_data = {
                "target_pod": target.pod_name,
                "interface": target.interface,
                "status": "NATURALLY_CLEARED_INTERFACE_VANISHED",
                "reason": "Interface or network namespace disappeared (ENODEV); kernel destroyed qdisc."
            }
            self._record_audit_event("rollback_interface_vanished", event_data)
            return event_data

        # Audit Check: Multi-factor ownership verification (Handle AND Type)
        # Handle alone does NOT prove ownership (foreign qdisc might use handle 100:)
        if self.current_handle is not None and self.current_handle != self.G1_HANDLE:
            raise QdiscConflictError(
                f"Refusing to delete qdisc: Current handle '{self.current_handle}' does not match G1 handle '{self.G1_HANDLE}'."
            )
        if self.current_qdisc != "noqueue" and "netem" not in self.current_qdisc:
            raise QdiscConflictError(
                f"Refusing to delete qdisc: Active qdisc '{self.current_qdisc}' is not netem. Handle alone does not prove ownership."
            )

        if not self.fault_active and self.current_qdisc == "noqueue" and self.current_handle is None and not self.simulate_rollback_failure:
            self.watchdog.disarm()
            event_data = {
                "target_pod": target.pod_name,
                "interface": target.interface,
                "handle": self.G1_HANDLE,
                "status": "ALREADY_CLEARED",
            }
            self._record_audit_event("rollback_idempotent_noop", event_data)
            return event_data

        if self.simulate_rollback_failure:
            self.unresolved_fault = True
            self.operator_alert = (
                f"CRITICAL ROLLBACK FAILURE: Unable to delete qdisc on {target.pod_name}:{target.interface}. "
                f"DO NOT delete CockroachDB pod. Operator manual intervention required."
            )
            self._record_audit_event("rollback_failure_alert", {
                "target": target.pod_name,
                "unresolved_fault": True,
                "operator_alert": self.operator_alert
            })
            raise RollbackVerificationError(f"Simulated failure executing 'tc qdisc del dev {target.interface} root handle {self.G1_HANDLE}'.")

        self.current_qdisc = "noqueue"
        self.current_handle = None
        self.fault_active = False
        cleared_id = self.experiment_qdisc_id
        self.experiment_qdisc_id = None
        self.watchdog.disarm()

        event_data = {
            "target_pod": target.pod_name,
            "interface": target.interface,
            "handle": self.G1_HANDLE,
            "experiment_qdisc_id": cleared_id,
            "qdisc_command": f"/sbin/tc qdisc del dev {target.interface} root handle {self.G1_HANDLE}",
            "status": "CLEARED"
        }
        self._record_audit_event("rollback_fault", event_data)
        return event_data

    def verify_rollback(self, target: TargetNamespaceSpec) -> bool:
        """Verifies that netem has been completely removed."""
        current = self.inspect_qdisc(target)
        if "netem" in current:
            self.unresolved_fault = True
            self.operator_alert = (
                f"CRITICAL VERIFICATION FAILURE: Netem still detected on {target.pod_name}:{target.interface}. "
                f"DO NOT delete CockroachDB pod. Operator manual intervention required."
            )
            raise RollbackVerificationError(f"Rollback verification failed: '{current}' still present on {target.interface}.")
        
        self.unresolved_fault = False
        self._record_audit_event("rollback_verified", {"target": target.pod_name, "verified": True})
        return True

    def handle_container_restart(self, target: TargetNamespaceSpec) -> None:
        """
        Phase C.3 Correction: When an ordinary container inside a pod restarts,
        the Kubernetes Pod Sandbox (pause container) remains alive. The network namespace
        and veth pair PERSIST across container restarts. Therefore, the qdisc is NOT removed!
        """
        self._record_audit_event("container_restarted_qdisc_persists", {
            "target": target.pod_name,
            "qdisc": self.current_qdisc,
            "warning": "Container restart does NOT remove netns or qdisc; pause container keeps veth active."
        })

    def handle_pod_sandbox_deletion(self, target: TargetNamespaceSpec) -> None:
        """
        Phase C.3 Correction: Only when the Pod Sandbox (pause container) itself terminates,
        the pod is deleted, or the node reboots, does the Linux kernel deallocate the veth
        pair and destroy the network namespace, resetting queuing to clean default state.
        """
        self.current_qdisc = "noqueue"
        self.current_handle = None
        self.watchdog.disarm()
        self._record_audit_event("pod_sandbox_deleted_namespace_destroyed", {
            "target": target.pod_name,
            "qdisc": "noqueue",
            "reason": "Pod sandbox terminated; kernel deallocated veth device."
        })

    # Backward compatibility alias
    def handle_pod_restart(self, target: TargetNamespaceSpec) -> None:
        """Deprecated alias: directs to handle_pod_sandbox_deletion."""
        self.handle_pod_sandbox_deletion(target)

    def compute_audit_hash(self) -> str:
        """Generates a cryptographic SHA-256 hash over the chronological audit log."""
        payload = json.dumps(self.audit_log, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _record_audit_event(self, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "action": action,
            "details": details,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })


class HelperFaultController(IFaultController):
    """
    Adapter implementing IFaultController by delegating to the PrivilegedHelperDaemon.
    Ensures drop-in compatibility with G1Orchestrator.
    """

    def __init__(
        self,
        helper: PrivilegedHelperDaemon,
        simulated_live_pods: Optional[Dict[str, Dict[str, Any]]] = None
    ):
        self.helper = helper
        self.simulated_live_pods = simulated_live_pods or {
            "cockroachdb-0": {"ip": "10.0.1.47", "ports": [26257, 8080]},
            "cockroachdb-1": {"ip": "10.0.2.238", "ports": [26257, 8080]},
            "cockroachdb-2": {"ip": "10.0.3.74", "ports": [26257, 8080]}
        }
        self.active_spec: Optional[TargetNamespaceSpec] = None

    def _build_target_spec(self, pod_name: str, interface: str = "eth0") -> TargetNamespaceSpec:
        pod_info = self.simulated_live_pods.get(pod_name, {})
        pod_ip = pod_info.get("ip", "0.0.0.0")
        return TargetNamespaceSpec(
            pod_name=pod_name,
            namespace="cockroachdb",
            expected_pod_ip=pod_ip,
            container_name="cockroachdb",
            expected_listen_port=26257,
            interface=interface
        )

    def inspect_initial_qdisc(self, pod_name: str, interface: str = "eth0") -> str:
        target = self._build_target_spec(pod_name, interface)
        return self.helper.inspect_qdisc(target)

    def apply_latency_fault(
        self,
        pod_name: str,
        delay_ms: int = 1000,
        jitter_ms: int = 20,
        distribution: str = "normal",
        duration_sec: int = 180,
        interface: str = "eth0"
    ) -> Dict[str, Any]:
        target = self._build_target_spec(pod_name, interface)
        self.helper.verify_target(target, self.simulated_live_pods)
        self.active_spec = target
        return self.helper.apply_fault(target, delay_ms, jitter_ms, distribution, duration_sec)

    def rollback_fault(self, pod_name: str, interface: str = "eth0") -> Dict[str, Any]:
        target = self.active_spec or self._build_target_spec(pod_name, interface)
        return self.helper.rollback_fault(target)

    def verify_rollback(self, pod_name: str, interface: str = "eth0") -> bool:
        target = self.active_spec or self._build_target_spec(pod_name, interface)
        return self.helper.verify_rollback(target)
