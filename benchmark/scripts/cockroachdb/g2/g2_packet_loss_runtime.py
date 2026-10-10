"""
g2_packet_loss_runtime.py - Packet-Loss Runtime Subsystem for Scenario G2.

Protocol Reference:
- G2-UD-01: Uniform random packet loss (`netem loss <P>%`).
- G2-UD-02: Unfiltered asymmetric egress loss on target pod interface (`eth0`).
- G2-UD-03: Dynamic JIT active leaseholder targeting Range 108.
- Valid levels: 10%, 30%, 50% (G2-L1, G2-L2, G2-L3).
"""

import enum
import os
import re
import shlex
import subprocess
from typing import Any, Callable, Dict, List, Optional, Tuple


class LinuxRuntimeError(RuntimeError):
    """Base error for runtime netem operations."""
    pass


class TargetVerificationError(LinuxRuntimeError):
    """Raised when target binding or netns verification fails."""
    pass


class QdiscConflictError(LinuxRuntimeError):
    """Raised when an unexpected qdisc already exists on the interface."""
    pass


G2_QDISC_HANDLE = "10:"
APPROVED_PACKET_LOSS_PERCENTAGES = frozenset({10, 30, 50})
APPROVED_LOSS_DISTRIBUTION = "uniform"  # Uniform random per G2-UD-01


class NetnsIdentity:
    def __init__(self, ns_inode: str, path: Optional[str] = None):
        self.ns_inode = str(ns_inode).strip()
        self.path = path

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, NetnsIdentity):
            return self.ns_inode == other.ns_inode
        return False

    def __repr__(self) -> str:
        return f"NetnsIdentity(ns_inode='{self.ns_inode}', path={self.path!r})"


class ProcessIdentity:
    def __init__(self, pid: int, start_time_ticks: Optional[int] = None, comm: Optional[str] = None):
        self.pid = int(pid)
        self.start_time_ticks = start_time_ticks
        self.comm = comm

    def __repr__(self) -> str:
        return f"ProcessIdentity(pid={self.pid}, comm={self.comm!r})"


class OwnedQdiscRecord:
    def __init__(
        self,
        experiment_qdisc_id: str,
        pod_name: str,
        handle: str,
        interface: str,
        loss_percentage: int,
        distribution: str,
    ):
        self.experiment_qdisc_id = experiment_qdisc_id
        self.pod_name = pod_name
        self.handle = handle
        self.interface = interface
        self.loss_percentage = loss_percentage
        self.distribution = distribution

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_qdisc_id": self.experiment_qdisc_id,
            "pod_name": self.pod_name,
            "handle": self.handle,
            "interface": self.interface,
            "loss_percentage": self.loss_percentage,
            "distribution": self.distribution,
        }


class G2LinuxRuntimePlanner:
    """Pure command planning and argument validation with zero OS side-effects."""

    @staticmethod
    def validate_interface(interface: str) -> None:
        if not isinstance(interface, str) or not re.match(r"^[a-zA-Z0-9_\-\.]{2,16}$", interface):
            raise LinuxRuntimeError(f"Invalid interface name: {interface!r}")

    @staticmethod
    def validate_handle(handle: str) -> None:
        if not isinstance(handle, str) or not re.match(r"^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{0,4}$", handle):
            raise LinuxRuntimeError(f"Invalid qdisc handle: {handle!r}")

    @classmethod
    def plan_show_qdisc(cls, interface: str) -> List[str]:
        cls.validate_interface(interface)
        return ["tc", "qdisc", "show", "dev", interface]

    @classmethod
    def plan_add_egress_packet_loss(
        cls,
        interface: str,
        loss_percentage: int,
        handle: str = G2_QDISC_HANDLE,
    ) -> List[str]:
        cls.validate_interface(interface)
        cls.validate_handle(handle)
        if loss_percentage not in APPROVED_PACKET_LOSS_PERCENTAGES:
            raise LinuxRuntimeError(
                f"Unsupported packet loss percentage {loss_percentage}%. "
                f"Must be one of {sorted(APPROVED_PACKET_LOSS_PERCENTAGES)} (G2-L1=10, G2-L2=30, G2-L3=50)."
            )
        # Uniform random packet loss per G2-UD-01 and G2-UD-02:
        # tc qdisc add dev <interface> root handle <handle> netem loss <loss_percentage>%
        return [
            "tc", "qdisc", "add", "dev", interface, "root", "handle", handle,
            "netem", "loss", f"{loss_percentage}%"
        ]

    @classmethod
    def plan_del_root_qdisc(cls, interface: str) -> List[str]:
        cls.validate_interface(interface)
        return ["tc", "qdisc", "del", "dev", interface, "root"]


class G2LinuxRuntime:
    """
    Executes and tracks packet-loss queue discipline operations.
    Supports dependency-injected runner for offline testing.
    """

    def __init__(self, runner: Optional[Callable[[List[str], Optional[str]], Tuple[int, str, str]]] = None):
        self.runner = runner or self._default_runner
        self.owned_qdiscs: Dict[str, OwnedQdiscRecord] = {}
        self.unresolved_fault: bool = False

    @staticmethod
    def _default_runner(cmd: List[str], netns_path: Optional[str] = None) -> Tuple[int, str, str]:
        if not netns_path:
            raise LinuxRuntimeError("Missing netns path: refusing execution in local container namespace.")
        full_cmd = ["nsenter", f"--net={netns_path}"] + cmd
        proc = subprocess.run(full_cmd, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    def inspect_interface_and_qdisc(self, netns: NetnsIdentity, interface: str = "eth0") -> str:
        if not netns or not netns.path:
            raise LinuxRuntimeError("Missing netns path: refusing read-only qdisc inspection without target network namespace.")
        cmd = G2LinuxRuntimePlanner.plan_show_qdisc(interface)
        rc, out, err = self.runner(cmd, netns.path)
        if rc != 0:
            raise LinuxRuntimeError(f"Failed to inspect qdisc on {interface}: {err.strip()}")
        return out.strip()

    def apply_egress_packet_loss(
        self,
        run_id: str,
        pod_name: str,
        netns: NetnsIdentity,
        proc: ProcessIdentity,
        loss_percentage: int,
        interface: str = "eth0",
    ) -> OwnedQdiscRecord:
        if not netns or not netns.path:
            raise LinuxRuntimeError("Missing netns path: refusing fault injection without target network namespace.")
        if self.unresolved_fault:
            raise LinuxRuntimeError("Refusing fault injection: prior unresolved fault requires cleanup.")
        if pod_name in self.owned_qdiscs:
            raise QdiscConflictError(f"Pod '{pod_name}' already has an active owned fault.")

        current = self.inspect_interface_and_qdisc(netns, interface)
        if "netem" in current:
            raise QdiscConflictError(
                f"Existing netem qdisc detected on {interface} of {pod_name} before injection: {current}"
            )

        cmd = G2LinuxRuntimePlanner.plan_add_egress_packet_loss(
            interface=interface,
            loss_percentage=loss_percentage,
            handle=G2_QDISC_HANDLE,
        )
        rc, out, err = self.runner(cmd, netns.path)
        if rc != 0:
            self.unresolved_fault = True
            raise LinuxRuntimeError(f"Failed to apply netem loss: {err.strip()}")

        # Verify application
        post_qdisc = self.inspect_interface_and_qdisc(netns, interface)
        if f"loss {loss_percentage}%" not in post_qdisc and "netem" not in post_qdisc:
            self.unresolved_fault = True
            raise LinuxRuntimeError(f"Verification failed: expected netem loss {loss_percentage}% in {post_qdisc}")

        record = OwnedQdiscRecord(
            experiment_qdisc_id=f"{run_id}:{pod_name}:{G2_QDISC_HANDLE}",
            pod_name=pod_name,
            handle=G2_QDISC_HANDLE,
            interface=interface,
            loss_percentage=loss_percentage,
            distribution=APPROVED_LOSS_DISTRIBUTION,
        )
        self.owned_qdiscs[pod_name] = record
        return record

    def remove_owned_qdisc(self, pod_name: str, netns: NetnsIdentity, interface: str = "eth0") -> Dict[str, Any]:
        """
        Idempotent removal of owned qdisc.
        Verifies that the interface returns to default qdisc (e.g. noqueue or fq_codel).
        """
        if not netns or not netns.path:
            raise LinuxRuntimeError("Missing netns path: refusing qdisc cleanup without target network namespace.")
        cmd = G2LinuxRuntimePlanner.plan_del_root_qdisc(interface)
        rc, out, err = self.runner(cmd, netns.path)
        # rc == 0 or 'Cannot find specified qdisc' is treated as cleared
        if rc != 0 and "No such file or directory" not in err and "Cannot find specified qdisc" not in err:
            self.unresolved_fault = True
            raise LinuxRuntimeError(f"Failed to remove qdisc: {err.strip()}")

        # Verify physical clearance
        post = self.inspect_interface_and_qdisc(netns, interface)
        if "netem" in post:
            self.unresolved_fault = True
            raise LinuxRuntimeError(f"Clearance verification failed: netem qdisc still present: {post}")

        record = self.owned_qdiscs.pop(pod_name, None)
        self.unresolved_fault = False
        return {
            "status": "CLEARED",
            "pod_name": pod_name,
            "interface": interface,
            "record": record.to_dict() if record else None,
            "post_qdisc": post,
        }

