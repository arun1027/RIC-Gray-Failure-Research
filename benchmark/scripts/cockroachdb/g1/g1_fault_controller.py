"""
g1_fault_controller.py - Abstract & Mock Fault Controller Interface for Scenario G1.

Features:
- Abstract IFaultController interface defining standard contract for network latency injection.
- MockFaultController simulating:
  - Initial qdisc inspection (verifying existing qdisc).
  - Conflict detection if an existing non-default qdisc is already attached.
  - Latency injection via simulated `tc netem`.
  - Fault duration tracking.
  - Automatic and manual rollback via simulated `tc qdisc del`.
  - Independent post-rollback verification.
  - Error injection (simulating command failure, timeouts, and rollback failure).
- Strictly rejects live privileged operations in this phase.
"""

from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
import time
import datetime


class FaultControllerError(Exception):
    pass


class QdiscConflictError(FaultControllerError):
    pass


class RollbackVerificationError(FaultControllerError):
    pass


class IFaultController(ABC):
    """Abstract interface defining the fault controller lifecycle for Scenario G1."""

    @abstractmethod
    def inspect_initial_qdisc(self, pod_name: str, interface: str = "eth0") -> str:
        """Inspects existing queuing discipline on the target interface."""
        pass

    @abstractmethod
    def apply_latency_fault(
        self,
        pod_name: str,
        delay_ms: int = 1000,
        jitter_ms: int = 20,
        distribution: str = "normal",
        duration_sec: int = 180,
        interface: str = "eth0"
    ) -> Dict[str, Any]:
        """Applies netem latency fault to the target interface."""
        pass

    @abstractmethod
    def rollback_fault(self, pod_name: str, interface: str = "eth0") -> Dict[str, Any]:
        """Rolls back the fault by deleting the netem root qdisc."""
        pass

    @abstractmethod
    def verify_rollback(self, pod_name: str, interface: str = "eth0") -> bool:
        """Independently verifies that the interface has returned to normal default state."""
        pass


class MockFaultController(IFaultController):
    """
    Mock implementation of IFaultController for offline testing and dry-run execution.
    Simulates all kernel states, execution latencies, and failure modes without live operations.
    """

    def __init__(
        self,
        initial_qdisc: str = "noqueue",
        simulate_apply_failure: bool = False,
        simulate_rollback_failure: bool = False,
        simulate_timeout: bool = False,
        simulate_conflict: bool = False
    ):
        self.current_qdisc = "netem delay 500ms" if simulate_conflict else initial_qdisc
        self.initial_qdisc = self.current_qdisc
        self.simulate_apply_failure = simulate_apply_failure
        self.simulate_rollback_failure = simulate_rollback_failure
        self.simulate_timeout = simulate_timeout
        self.simulate_conflict = simulate_conflict

        self.fault_active = False
        self.active_params: Optional[Dict[str, Any]] = None
        self.t0_timestamp: Optional[str] = None
        self.t_clear_timestamp: Optional[str] = None
        self.event_log: List[Dict[str, Any]] = []

    def inspect_initial_qdisc(self, pod_name: str, interface: str = "eth0") -> str:
        self.event_log.append({
            "action": "inspect_qdisc",
            "pod": pod_name,
            "interface": interface,
            "result": self.current_qdisc,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
        return self.current_qdisc

    def apply_latency_fault(
        self,
        pod_name: str,
        delay_ms: int = 1000,
        jitter_ms: int = 20,
        distribution: str = "normal",
        duration_sec: int = 180,
        interface: str = "eth0"
    ) -> Dict[str, Any]:
        if duration_sec <= 0 or duration_sec > 180:
            raise FaultControllerError(
                f"Invalid fault duration {duration_sec}s: must be bounded between 1s and 180s."
            )
        if delay_ms <= 0 or jitter_ms < 0:
            raise FaultControllerError(
                f"Invalid latency parameters: delay_ms={delay_ms}, jitter_ms={jitter_ms}."
            )

        current = self.inspect_initial_qdisc(pod_name, interface)
        # Check for pre-existing non-default qdisc conflicts
        if "netem" in current:
            raise QdiscConflictError(
                f"Conflicting qdisc detected on {pod_name} ({interface}): '{current}'. Pre-existing fault must be cleared before applying G1."
            )

        if self.simulate_timeout:
            raise TimeoutError(f"Simulated timeout during fault injection on pod '{pod_name}'.")

        if self.simulate_apply_failure:
            raise FaultControllerError(f"Simulated execution failure executing 'tc qdisc add dev {interface} root netem'.")

        self.fault_active = True
        self.t0_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.active_params = {
            "pod_name": pod_name,
            "interface": interface,
            "direction": "egress_only",
            "delay_ms": delay_ms,
            "jitter_ms": jitter_ms,
            "distribution": distribution,
            "duration_sec": duration_sec,
            "t0_utc": self.t0_timestamp,
        }
        self.current_qdisc = f"netem delay {delay_ms}ms {jitter_ms}ms {distribution}"

        event = {
            "action": "apply_fault",
            "params": self.active_params,
            "status": "APPLIED",
            "timestamp": self.t0_timestamp
        }
        self.event_log.append(event)
        return event

    def rollback_fault(self, pod_name: str, interface: str = "eth0") -> Dict[str, Any]:
        if self.simulate_rollback_failure:
            raise FaultControllerError(f"Simulated failure executing 'tc qdisc del dev {interface} root' on pod '{pod_name}'.")

        self.fault_active = False
        self.t_clear_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.current_qdisc = "noqueue"

        event = {
            "action": "rollback_fault",
            "pod": pod_name,
            "interface": interface,
            "status": "CLEARED",
            "t_clear_utc": self.t_clear_timestamp
        }
        self.event_log.append(event)
        return event

    def verify_rollback(self, pod_name: str, interface: str = "eth0") -> bool:
        qdisc = self.inspect_initial_qdisc(pod_name, interface)
        if "netem" in qdisc:
            raise RollbackVerificationError(f"Rollback verification FAILED: Qdisc on {pod_name}:{interface} still contains netem ('{qdisc}').")
        return True

