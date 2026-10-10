"""
g1_helper_two_phase_integrated.py - Integrated Two-Phase Helper Controller & Safe Path Resolver.

Stage 5.2.5 Implementation:
- Implements two-phase finite state machine (INIT -> IDLE -> AUTHORIZING -> BINDING -> FAULT_ACTIVE -> CLEANUP -> COMPLETED).
- Integrates RemediatedG1HelperFaultAuthorizer and SafePathResolver.
- Supports native /healthz (liveness) and /readyz (readiness) HTTP probes.
- Guarantees zero privileged objects, zero /proc scans, zero namespace entries, and zero netlink calls during IDLE.
- Enforces single-use token claim and at most one fault attempt per container lifetime.
- Arms AutonomousWatchdog prior to netlink latency injection.
- Enforces fault duration against time.monotonic().
"""

import enum
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import signal
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from g1_helper_authorizer_REMEDIATED import (
    FaultAuthorizationError,
    RemediatedG1HelperFaultAuthorizer,
)
from g1_safe_path_resolver import PathSecurityError, SafePathResolver


def log_json(level: str, event: str, **fields: Any) -> None:
    payload: Dict[str, Any] = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "component": "g1-helper",
        "event": event,
    }
    payload.update(fields)
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


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


class HelperHealthState:
    def __init__(self) -> None:
        self.ready: bool = False
        self.healthy: bool = True
        self.shutting_down: bool = False
        self.current_state: HelperState = HelperState.INIT


def make_health_handler(state: HelperHealthState) -> type:
    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                code = 200 if state.healthy else 503
                body = {"status": "ok" if state.healthy else "unhealthy", "state": state.current_state.value}
            elif self.path == "/readyz":
                code = 200 if (state.ready and not state.shutting_down) else 503
                body = {"status": "ready" if state.ready else "not_ready", "state": state.current_state.value}
            elif self.path == "/state":
                code = 200
                body = {
                    "state": state.current_state.value,
                    "ready": state.ready,
                    "healthy": state.healthy,
                    "shutting_down": state.shutting_down,
                }
            else:
                code = 404
                body = {"status": "not_found"}

            raw = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    return HealthHandler


class TwoPhaseHelperController:
    """
    Coordinates safe startup, idle observation, and single-attempt authorized fault execution.
    """

    def __init__(
        self,
        config: Any,
        authorizer: Any,
        runtime_factory: Callable[[], Any],
        watchdog: Any,
        health_state: Optional[HelperHealthState] = None,
        token_path: Optional[str] = None,
        idle_max_sec: float = 600.0,
        poll_interval_sec: float = 2.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
        stop_event: Optional[threading.Event] = None,
        emit: Optional[Callable[..., None]] = None,
    ) -> None:
        self.config = config
        self.authorizer = authorizer
        self.runtime_factory = runtime_factory
        self.watchdog = watchdog
        self.health = health_state or HelperHealthState()
        self.token_path = token_path or os.path.join(
            getattr(authorizer, "base_dir", "/var/run/g1-auth"),
            getattr(authorizer, "TOKEN_FILENAME", "G1_FAULT_AUTHORIZED.json"),
        )
        self.idle_max_sec = float(idle_max_sec)
        self.poll_interval_sec = float(poll_interval_sec)
        self.monotonic = monotonic
        self.sleep_fn = sleep_fn
        self.stop_event = stop_event or threading.Event()
        self._emit_fn = emit
        self.state = HelperState.INIT
        self.history: List[str] = [HelperState.INIT.value]
        self.events: List[Dict[str, Any]] = []
        self.runtime: Any = None
        self._netns: Any = None
        self._cleanup_lock = threading.Lock()
        self._cleaned = False
        self._phase2_entered = False

    def _emit(self, level: str, event: str, **fields: Any) -> None:
        rec = {"level": level, "event": event, "state": self.state.value, **fields}
        self.events.append(rec)
        if self._emit_fn is not None:
            self._emit_fn(level, event, state=self.state.value, **fields)
        else:
            log_json(level, event, state=self.state.value, **fields)

    def _transition(self, new: HelperState, **fields: Any) -> None:
        if new not in ALLOWED_TRANSITIONS.get(self.state, frozenset()):
            raise IllegalTransitionError(f"{self.state.value} -> {new.value} not permitted")
        self.state = new
        self.history.append(new.value)
        self.health.current_state = new
        # Pod is Ready strictly when in IDLE (standby ready) or FAULT_ACTIVE (experiment running)
        self.health.ready = new in (HelperState.IDLE, HelperState.FAULT_ACTIVE)
        if new in (HelperState.FAILED_CLOSED, HelperState.UNRESOLVED_FAULT):
            self.health.healthy = False
        self._emit("INFO", "state_transition", to=new.value, **fields)

    def status(self) -> Dict[str, Any]:
        """Read-only status for observable endpoints. Never includes secret token contents."""
        return {
            "state": self.state.value,
            "phase2_entered": self._phase2_entered,
            "ready": self.health.ready,
            "healthy": self.health.healthy,
        }

    def cleanup(self) -> Dict[str, Any]:
        """Idempotent teardown callback. Touches netlink strictly if a fault was actually bound."""
        with self._cleanup_lock:
            if self._cleaned or self.runtime is None or self._netns is None:
                return {"status": "NOTHING_TO_CLEAN"}
            res = self.runtime.remove_owned_qdisc(
                pod_name=self.config.target_pod,
                netns=self._netns,
                interface=self.config.target_interface,
            )
            self.watchdog.disarm()
            self._cleaned = True
            self._emit("INFO", "cleanup_completed", result=res)
            return res

    def request_stop(self) -> None:
        self.stop_event.set()

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
            if self.monotonic() - idle_start >= self.idle_max_sec:
                self._transition(HelperState.IDLE_EXPIRED)
                return EXIT_CODES[self.state]

            # Non-blocking existence probe: never opens or parses file in IDLE
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
                expected_target_namespace=self.config.target_namespace,
                expected_fault_type="egress_latency",
                expected_delay_ms=self.config.delay_ms,
                expected_jitter_ms=self.config.jitter_ms,
                expected_duration_sec=self.config.duration_sec,
            )
            self._emit("INFO", "fault_authorization_claimed", authorized_by=payload.get("authorized_by_operator"))
        except Exception as exc:
            self._transition(HelperState.FAILED_CLOSED, reason=f"authorization_failed: {exc}")
            return EXIT_CODES[self.state]

        self._transition(HelperState.BINDING)
        try:
            # Privileged runtime constructed strictly after authorization succeeds
            self.runtime = self.runtime_factory()
            proc, netns = self.runtime.bind_target(
                pod_name=self.config.target_pod,
                expected_start_time_ticks=getattr(self.config, "expected_start_time_ticks", None),
                expected_netns_inode=getattr(self.config, "expected_netns_inode", None),
            )
            self.authorizer.verify_target_binding(payload, netns.ns_inode)
            self._netns = netns
            self._emit("INFO", "target_bound", pod=self.config.target_pod, pid=proc.pid, netns=netns.ns_inode)
        except Exception as exc:
            self._transition(HelperState.FAILED_CLOSED, reason=f"binding_failed: {exc}")
            return EXIT_CODES[self.state]

        if self.stop_event.is_set():
            self._transition(HelperState.FAILED_CLOSED, reason="stop_before_apply")
            return EXIT_CODES[self.state]

        # Watchdog pre-armed strictly before netlink apply (F-522-01 fix)
        self.watchdog.arm()
        try:
            record = self.runtime.apply_egress_latency(
                run_id=self.config.run_id,
                pod_name=self.config.target_pod,
                netns=netns,
                proc=proc,
                interface=self.config.target_interface,
                delay_ms=self.config.delay_ms,
                jitter_ms=self.config.jitter_ms,
            )
            self._emit("INFO", "fault_applied", experiment_qdisc_id=record.experiment_qdisc_id)
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
            if self.watchdog.check_status(elapsed_sec=elapsed) == "TRIPPED":
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

