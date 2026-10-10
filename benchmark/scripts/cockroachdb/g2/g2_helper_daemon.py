"""
g2_helper_daemon.py - Autonomous Two-Phase Controller for Scenario G2 Helper.

Coordinates:
- Safe startup and readiness probe without privileged calls.
- Phase 2 transition upon detection of G2_FAULT_AUTHORIZED.json.
- Verifying and claiming token via G2HelperFaultAuthorizer.
- Binding target netns and verifying against token netns_inode.
- Applying uniform random packet loss on eth0 via G2LinuxRuntime.
- Autonomous watchdog armed prior to netlink calls.
- Verified idempotent qdisc teardown at completion or shutdown.
"""

import enum
import json
import os
import signal
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional

try:
    from benchmark.scripts.cockroachdb.g2.g2_authorizer import (
        FaultAuthorizationError,
        G2HelperFaultAuthorizer,
    )
    from benchmark.scripts.cockroachdb.g2.g2_packet_loss_runtime import (
        G2LinuxRuntime,
        G2LinuxRuntimePlanner,
        NetnsIdentity,
        ProcessIdentity,
        APPROVED_PACKET_LOSS_PERCENTAGES,
        APPROVED_LOSS_DISTRIBUTION,
    )
except ImportError:
    from g2_authorizer import (
        FaultAuthorizationError,
        G2HelperFaultAuthorizer,
    )
    from g2_packet_loss_runtime import (
        G2LinuxRuntime,
        G2LinuxRuntimePlanner,
        NetnsIdentity,
        ProcessIdentity,
        APPROVED_PACKET_LOSS_PERCENTAGES,
        APPROVED_LOSS_DISTRIBUTION,
    )


class HelperState(str, enum.Enum):
    INIT = "INIT"
    IDLE = "IDLE"
    AUTHORIZING = "AUTHORIZING"
    BINDING = "BINDING"
    FAULT_ACTIVE = "FAULT_ACTIVE"
    CLEANUP = "CLEANUP"
    COMPLETED = "COMPLETED"
    IDLE_EXPIRED = "IDLE_EXPIRED"
    IDLE_SHUTDOWN = "IDLE_SHUTDOWN"
    FAILED_CLOSED = "FAILED_CLOSED"
    UNRESOLVED_FAULT = "UNRESOLVED_FAULT"


ALLOWED_TRANSITIONS: Dict[HelperState, frozenset] = {
    HelperState.INIT: frozenset({HelperState.IDLE, HelperState.FAILED_CLOSED}),
    HelperState.IDLE: frozenset({HelperState.AUTHORIZING, HelperState.IDLE_EXPIRED, HelperState.IDLE_SHUTDOWN}),
    HelperState.AUTHORIZING: frozenset({HelperState.BINDING, HelperState.FAILED_CLOSED}),
    HelperState.BINDING: frozenset({HelperState.FAULT_ACTIVE, HelperState.FAILED_CLOSED, HelperState.UNRESOLVED_FAULT}),
    HelperState.FAULT_ACTIVE: frozenset({HelperState.CLEANUP}),
    HelperState.CLEANUP: frozenset({HelperState.COMPLETED, HelperState.UNRESOLVED_FAULT}),
}

EXIT_CODES: Dict[HelperState, int] = {
    HelperState.COMPLETED: 0,
    HelperState.IDLE_SHUTDOWN: 0,
    HelperState.IDLE_EXPIRED: 3,
    HelperState.FAILED_CLOSED: 1,
    HelperState.UNRESOLVED_FAULT: 2,
}


class IllegalTransitionError(RuntimeError):
    pass


class AutonomousWatchdog:
    """Arms a hard timeout to trigger qdisc cleanup if orchestrator fails."""

    def __init__(self, timeout_sec: float, cleanup_fn: Callable[[], Any]):
        self.timeout_sec = float(timeout_sec)
        self.cleanup_fn = cleanup_fn
        self.armed_at: Optional[float] = None
        self._tripped: bool = False

    def arm(self, now: Optional[float] = None) -> None:
        self.armed_at = now or time.monotonic()
        self._tripped = False

    def disarm(self) -> None:
        self.armed_at = None

    def check_status(self, now: Optional[float] = None) -> str:
        if self.armed_at is None:
            return "DISARMED"
        current = now or time.monotonic()
        if (current - self.armed_at) >= self.timeout_sec:
            self._tripped = True
            try:
                self.cleanup_fn()
            except Exception:
                pass
            return "TRIPPED"
        return "ARMED"


class G2HelperConfig:
    def __init__(
        self,
        run_id: str,
        target_pod: str,
        loss_percentage: int,
        target_namespace: str = "cockroachdb",
        target_interface: str = "eth0",
        duration_sec: int = 180,
        expected_netns_inode: Optional[str] = None,
        expected_pid: Optional[int] = None,
    ):
        self.run_id = run_id
        self.target_pod = target_pod
        self.loss_percentage = int(loss_percentage)
        self.target_namespace = target_namespace
        self.target_interface = target_interface
        self.duration_sec = int(duration_sec)
        self.expected_netns_inode = expected_netns_inode
        self.expected_pid = expected_pid

    def validate(self) -> None:
        if not self.run_id or not (self.run_id.startswith("crdb-g2") or self.run_id.startswith("crdb-g2l")):
            raise ValueError(f"Invalid G2 run_id: {self.run_id!r}")
        if self.loss_percentage not in APPROVED_PACKET_LOSS_PERCENTAGES:
            raise ValueError(
                f"Invalid loss_percentage {self.loss_percentage}%. Must be in {sorted(APPROVED_PACKET_LOSS_PERCENTAGES)}."
            )
        if self.duration_sec != 180:
            raise ValueError(f"Invalid duration_sec {self.duration_sec}. G2 protocol mandates exactly 180s.")
        if self.expected_pid is None or self.expected_pid <= 0:
            raise ValueError(f"Invalid expected_pid {self.expected_pid!r}. FAULT mode requires a verified target PID > 0.")
        G2LinuxRuntimePlanner.validate_interface(self.target_interface)


class G2TwoPhaseHelperController:
    """
    Coordinates safe startup, idle observation, authorized fault application, and verified cleanup.
    """

    def __init__(
        self,
        config: G2HelperConfig,
        authorizer: G2HelperFaultAuthorizer,
        runtime_factory: Callable[[], G2LinuxRuntime],
        token_path: Optional[str] = None,
        idle_max_sec: float = 600.0,
        poll_interval_sec: float = 1.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
        stop_event: Optional[threading.Event] = None,
        emit: Optional[Callable[..., None]] = None,
    ):
        self.config = config
        self.authorizer = authorizer
        self.runtime_factory = runtime_factory
        self.token_path = token_path or os.path.join(authorizer.base_dir, authorizer.TOKEN_FILENAME)
        self.idle_max_sec = float(idle_max_sec)
        self.poll_interval_sec = float(poll_interval_sec)
        self.monotonic = monotonic
        self.sleep_fn = sleep_fn
        self.stop_event = stop_event or threading.Event()
        self._emit_fn = emit

        self.state = HelperState.INIT
        self.history: List[str] = [HelperState.INIT.value]
        self.runtime: Optional[G2LinuxRuntime] = None
        self._netns: Optional[NetnsIdentity] = None
        self._cleaned: bool = False
        self._phase2_entered: bool = False
        self.watchdog = AutonomousWatchdog(
            timeout_sec=self.config.duration_sec + 30.0,
            cleanup_fn=self.cleanup,
        )

    def _emit(self, level: str, event: str, **fields: Any) -> None:
        rec = {"level": level, "event": event, "state": self.state.value, **fields}
        if self._emit_fn:
            self._emit_fn(level, event, state=self.state.value, **fields)

    def _transition(self, new: HelperState, **fields: Any) -> None:
        if new not in ALLOWED_TRANSITIONS.get(self.state, frozenset()):
            raise IllegalTransitionError(f"{self.state.value} -> {new.value} not permitted")
        self.state = new
        self.history.append(new.value)
        self._emit("INFO", "state_transition", to=new.value, **fields)

    def cleanup(self) -> Dict[str, Any]:
        """Idempotent teardown callback."""
        if self._cleaned or self.runtime is None or self._netns is None:
            return {"status": "NOTHING_TO_CLEAN"}
        try:
            res = self.runtime.remove_owned_qdisc(
                pod_name=self.config.target_pod,
                netns=self._netns,
                interface=self.config.target_interface,
            )
            self.watchdog.disarm()
            self._cleaned = True
            self._emit("INFO", "cleanup_completed", result=res)
            return res
        except Exception as exc:
            self._emit("ERROR", "cleanup_failed", error=str(exc))
            raise

    def run(self) -> int:
        try:
            self.config.validate()
        except Exception as exc:
            self._transition(HelperState.FAILED_CLOSED, reason=f"invalid_config: {exc}")
            return EXIT_CODES[self.state]

        self._transition(HelperState.IDLE)
        idle_start = self.monotonic()
        while True:
            if self.stop_event.is_set():
                self._transition(HelperState.IDLE_SHUTDOWN)
                return EXIT_CODES[self.state]
            if (self.monotonic() - idle_start) >= self.idle_max_sec:
                self._transition(HelperState.IDLE_EXPIRED)
                return EXIT_CODES[self.state]

            if os.path.lexists(self.token_path):
                break
            self.sleep_fn(self.poll_interval_sec)

        return self._phase2()

    def _phase2(self) -> int:
        if self._phase2_entered:
            raise IllegalTransitionError("Phase 2 may be entered only once per container lifetime.")
        self._phase2_entered = True
        self._transition(HelperState.AUTHORIZING)

        try:
            payload = self.authorizer.verify_and_claim(
                expected_run_id=self.config.run_id,
                expected_target_pod=self.config.target_pod,
                expected_loss_percentage=self.config.loss_percentage,
                expected_target_namespace=self.config.target_namespace,
                expected_duration_sec=self.config.duration_sec,
                observed_netns_inode=self.config.expected_netns_inode,
            )
            self._emit("INFO", "fault_authorization_claimed", authorized_by=payload.get("authorized_by_operator"))
        except Exception as exc:
            self._transition(HelperState.FAILED_CLOSED, reason=f"authorization_failed: {exc}")
            return EXIT_CODES[self.state]

        self._transition(HelperState.BINDING)
        try:
            self.runtime = self.runtime_factory()
            if not self.config.expected_pid or self.config.expected_pid <= 0:
                raise ValueError(f"Missing or invalid expected_pid: {self.config.expected_pid!r}")

            netns_path = f"/proc/{self.config.expected_pid}/ns/net"
            if not os.path.exists(netns_path):
                raise FileNotFoundError(f"Target process netns path does not exist: {netns_path}")

            # Re-verify target netns inode immediately before binding
            try:
                observed_link = os.readlink(netns_path)
            except OSError:
                st = os.stat(netns_path)
                observed_link = f"net:[{st.st_ino}]"

            if observed_link != payload["target_netns_inode"]:
                raise FaultAuthorizationError(
                    f"Target netns inode drift detected at binding: expected '{payload['target_netns_inode']}', "
                    f"observed '{observed_link}'"
                )

            # Netns and Process identity constructed from verified parameters
            self._netns = NetnsIdentity(
                ns_inode=payload["target_netns_inode"],
                path=netns_path,
            )
            proc = ProcessIdentity(pid=self.config.expected_pid)
            self._emit("INFO", "target_bound", pod=self.config.target_pod, netns=self._netns.ns_inode, pid=proc.pid)
        except Exception as exc:
            self._transition(HelperState.FAILED_CLOSED, reason=f"binding_failed: {exc}")
            return EXIT_CODES[self.state]

        if self.stop_event.is_set():
            self._transition(HelperState.FAILED_CLOSED, reason="stop_before_apply")
            return EXIT_CODES[self.state]

        # Arm autonomous watchdog strictly before netlink apply
        self.watchdog.arm(now=self.monotonic())
        try:
            record = self.runtime.apply_egress_packet_loss(
                run_id=self.config.run_id,
                pod_name=self.config.target_pod,
                netns=self._netns,
                proc=proc,
                loss_percentage=self.config.loss_percentage,
                interface=self.config.target_interface,
            )
            self._emit("INFO", "fault_applied", record=record.to_dict())
        except Exception as exc:
            self.watchdog.disarm()
            unresolved = bool(getattr(self.runtime, "unresolved_fault", False))
            self._transition(
                HelperState.UNRESOLVED_FAULT if unresolved else HelperState.FAILED_CLOSED,
                reason=f"apply_failed: {exc}",
            )
            return EXIT_CODES[self.state]

        self._transition(HelperState.FAULT_ACTIVE)
        t0 = self.monotonic()
        while not self.stop_event.is_set():
            elapsed = self.monotonic() - t0
            if elapsed >= float(self.config.duration_sec):
                break
            if self.watchdog.check_status(now=self.monotonic()) == "TRIPPED":
                self._emit("WARN", "watchdog_tripped", elapsed_sec=elapsed)
                break
            self.sleep_fn(min(1.0, float(self.config.duration_sec) - elapsed))

        self._transition(HelperState.CLEANUP)
        try:
            self.cleanup()
        except Exception as exc:
            self._transition(HelperState.UNRESOLVED_FAULT, reason=f"cleanup_failed: {exc}")
            return EXIT_CODES[self.state]

        self._transition(HelperState.COMPLETED)
        return EXIT_CODES[self.state]

