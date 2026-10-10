"""
g1_helper_entrypoint.py - Container Entrypoint & Lifecycle Runner for the G1 Privileged Chaos Helper.

Remediations (Phase F.2.4 Workstream 1):
- Replaces standby skeleton with full HelperLifecycleRunner:
  1. Validates configuration and target identity.
  2. Initializes LinuxNetnsRuntime, PrivilegedHelperDaemon, and AutonomousWatchdog.
  3. Registers real idempotent cleanup callback on SIGTERM/SIGINT.
  4. Rejects invalid or stale targets and duplicate fault applications.
  5. Emits structured JSON lifecycle events.
  6. Fails closed if any required component is missing or fails.
- Explicitly notes: SIGTERM/SIGINT handlers do NOT guarantee cleanup after SIGKILL,
  node failure, or forced pod deletion.
"""

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
import datetime
import json
import os
import re
import signal
import sys
import threading
import time
from typing import Any, Callable, Dict, Optional


def log_json(level: str, event: str, **fields: Any) -> None:
    payload: Dict[str, Any] = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "level": level,
        "component": "g1-helper",
        "event": event,
    }
    payload.update(fields)
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


class HelperHealthState:
    def __init__(self) -> None:
        self.ready: bool = False
        self.healthy: bool = True
        self.shutting_down: bool = False


def make_health_handler(state: HelperHealthState) -> type:
    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                code = 200 if state.healthy else 503
                body = {"status": "ok" if state.healthy else "unhealthy"}
            elif self.path == "/readyz":
                code = 200 if (state.ready and not state.shutting_down) else 503
                body = {"status": "ready" if state.ready else "not_ready"}
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


def register_shutdown_handlers(
    state: HelperHealthState,
    cleanup_fn: Optional[Callable[[], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> Callable[[int, Any], None]:
    def _handle_signal(signum: int, _frame: Any) -> None:
        state.shutting_down = True
        state.ready = False
        log_json("WARN", "shutdown_signal_received", signal=signum)
        if stop_event is not None:
            stop_event.set()
        if cleanup_fn is not None:
            try:
                cleanup_fn()
                log_json("INFO", "graceful_cleanup_completed")
            except Exception as exc:
                state.healthy = False
                log_json("CRITICAL", "graceful_cleanup_failed", error=str(exc))

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    return _handle_signal


@dataclass(frozen=True)
class HelperRuntimeConfig:
    run_id: str
    target_pod: str
    target_namespace: str
    target_interface: str
    delay_ms: int
    jitter_ms: int
    duration_sec: int
    expected_netns_inode: Optional[str] = None
    expected_start_time_ticks: Optional[int] = None

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "HelperRuntimeConfig":
        src = env if env is not None else os.environ
        run_id = src.get("G1_RUN_ID", "").strip()
        target_pod = src.get("G1_TARGET_POD", "").strip()
        target_ns = src.get("G1_TARGET_NAMESPACE", "cockroachdb").strip()
        iface = src.get("G1_TARGET_INTERFACE", "eth0").strip()
        try:
            delay_ms = int(src.get("G1_FAULT_DELAY_MS", "1000"))
            jitter_ms = int(src.get("G1_FAULT_JITTER_MS", "20"))
            duration_sec = int(src.get("G1_FAULT_DURATION_SEC", "180"))
        except ValueError as exc:
            raise ValueError(f"Invalid numeric fault parameter in environment: {exc}") from exc
        ticks_raw = src.get("G1_EXPECTED_START_TIME_TICKS", "").strip()
        ticks = int(ticks_raw) if ticks_raw else None
        netns_inode = src.get("G1_EXPECTED_NETNS_INODE", "").strip() or None

        cfg = cls(
            run_id=run_id,
            target_pod=target_pod,
            target_namespace=target_ns,
            target_interface=iface,
            delay_ms=delay_ms,
            jitter_ms=jitter_ms,
            duration_sec=duration_sec,
            expected_netns_inode=netns_inode,
            expected_start_time_ticks=ticks,
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not self.run_id or "<" in self.run_id or ">" in self.run_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", self.run_id):
            raise ValueError(f"Invalid or missing G1_RUN_ID '{self.run_id}': must match [A-Za-z0-9][A-Za-z0-9._-]{{2,63}}.")
        if not self.target_pod or "<" in self.target_pod or ">" in self.target_pod:
            raise ValueError(f"Invalid or missing G1_TARGET_POD '{self.target_pod}'.")
        if self.target_namespace != "cockroachdb":
            raise ValueError(f"Invalid target namespace '{self.target_namespace}': expected 'cockroachdb'.")
        if self.target_interface != "eth0":
            raise ValueError(f"Invalid target interface '{self.target_interface}': expected 'eth0'.")
        if self.delay_ms != 1000 or self.jitter_ms != 20:
            raise ValueError(f"Unapproved latency/jitter ({self.delay_ms}ms/{self.jitter_ms}ms): expected 1000ms/20ms.")
        if self.duration_sec <= 0 or self.duration_sec > 180:
            raise ValueError(f"Invalid G1_FAULT_DURATION_SEC={self.duration_sec}: must be 1..180.")


class HelperLifecycleRunner:
    """
    Executes the full helper lifecycle with dependency-injected runtime, watchdog,
    and health state so it can be deterministically tested offline and run live in EKS.
    """

    def __init__(
        self,
        config: HelperRuntimeConfig,
        runtime: Any,
        watchdog: Any,
        authorizer: Any = None,
        health_state: Optional[HelperHealthState] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        stop_event: Optional[threading.Event] = None,
    ):
        self.config = config
        self.runtime = runtime
        self.watchdog = watchdog
        self.authorizer = authorizer
        self.health_state = health_state or HelperHealthState()
        self.sleep_fn = sleep_fn
        self.stop_event = stop_event or threading.Event()
        self.events: list = []
        self._bound_netns: Any = None
        self._cleanup_lock = threading.Lock()
        self._cleaned_up = False

    def _emit(self, level: str, event: str, **fields: Any) -> None:
        record = {"level": level, "event": event, "run_id": self.config.run_id, **fields}
        self.events.append(record)
        log_json(level, event, run_id=self.config.run_id, **fields)

    def cleanup_callback(self) -> Dict[str, Any]:
        """Idempotent cleanup callback invoked on normal exit, watchdog trip, or SIGTERM/SIGINT."""
        with self._cleanup_lock:
            if self._cleaned_up or self._bound_netns is None:
                return {"status": "ALREADY_CLEARED"}
            res = self.runtime.remove_owned_qdisc(
                pod_name=self.config.target_pod,
                netns=self._bound_netns,
                interface=self.config.target_interface,
            )
            self.watchdog.disarm()
            self._cleaned_up = True
            self._emit("INFO", "cleanup_callback_finished", result=res)
            return res

    def run(self, register_signals: bool = True) -> int:
        if self.runtime is None or self.watchdog is None or self.authorizer is None:
            self._emit("ERROR", "missing_required_components")
            return 1

        self.config.validate()
        if register_signals:
            register_shutdown_handlers(
                self.health_state,
                cleanup_fn=self.cleanup_callback,
                stop_event=self.stop_event,
            )

        try:
            auth_payload = self.authorizer.verify_and_claim(
                expected_run_id=self.config.run_id,
                expected_target_pod=self.config.target_pod,
                expected_target_namespace=self.config.target_namespace,
                expected_fault_type="egress_latency",
                expected_delay_ms=self.config.delay_ms,
                expected_jitter_ms=self.config.jitter_ms,
                expected_duration_sec=self.config.duration_sec,
            )
            self._emit("INFO", "fault_authorization_claimed", authorized_by=auth_payload.get("authorized_by_operator"))

            proc, netns = self.runtime.bind_target(
                pod_name=self.config.target_pod,
                expected_start_time_ticks=self.config.expected_start_time_ticks,
                expected_netns_inode=self.config.expected_netns_inode,
            )
            self.authorizer.verify_target_binding(auth_payload, netns.ns_inode)
            self._bound_netns = netns
            self._emit("INFO", "target_bound", pod=self.config.target_pod, pid=proc.pid, netns=netns.ns_inode)

            self.health_state.ready = True
            record = self.runtime.apply_egress_latency(
                run_id=self.config.run_id,
                pod_name=self.config.target_pod,
                netns=netns,
                proc=proc,
                interface=self.config.target_interface,
                delay_ms=self.config.delay_ms,
                jitter_ms=self.config.jitter_ms,
            )
            self.watchdog.arm()
            self._emit("INFO", "fault_applied", experiment_qdisc_id=record.experiment_qdisc_id)

            elapsed = 0.0
            step = 1.0
            while not self.stop_event.is_set() and elapsed < float(self.config.duration_sec):
                if self.watchdog.check_status(elapsed_sec=elapsed) == "TRIPPED":
                    self._emit("WARN", "watchdog_tripped", elapsed_sec=elapsed)
                    break
                self.sleep_fn(min(step, float(self.config.duration_sec) - elapsed))
                elapsed += step

            self.cleanup_callback()
            self.health_state.ready = False
            self._emit("INFO", "helper_lifecycle_completed")
            return 0
        except Exception as exc:
            self.health_state.healthy = False
            self.health_state.ready = False
            self._emit("ERROR", "helper_lifecycle_failed", error=str(exc))
            try:
                self.cleanup_callback()
            except Exception as rb_exc:
                self._emit("CRITICAL", "emergency_cleanup_after_failure_failed", error=str(rb_exc))
            return 1


def main() -> int:
    state = HelperHealthState()
    port = int(os.environ.get("G1_HELPER_HEALTH_PORT", "8081"))
    server = HTTPServer(("0.0.0.0", port), make_health_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        config = HelperRuntimeConfig.from_env()
    except Exception as exc:
        log_json("ERROR", "invalid_helper_configuration", error=str(exc))
        server.shutdown()
        return 1

    # Lazy import inside main so standalone unit tests can inject mocks directly.
    from g1.g1_helper_authorizer import G1HelperFaultAuthorizer, KubernetesLeaseClaimStore
    from g1.g1_helper_daemon import AutonomousWatchdog
    from g1.g1_linux_runtime import LinuxNetnsRuntime, LinuxSubprocessExecutor, LiveProcFilesystemInspector

    allow_ro = os.environ.get("G1_AUTH_ALLOW_READONLY_SECRET", "0") == "1"
    claim_store = (
        KubernetesLeaseClaimStore(namespace=os.environ.get("G1_CLAIM_NAMESPACE", "g1-chaos"))
        if allow_ro
        else None
    )
    pod_ident = f"{os.environ.get('G1_HELPER_POD_NAME', os.environ.get('HOSTNAME', 'g1-helper'))}:{os.environ.get('G1_HELPER_POD_UID', 'unknown')}"
    authorizer = G1HelperFaultAuthorizer(
        base_dir=os.environ.get("G1_AUTH_TOKEN_DIR", "/var/run/g1-auth"),
        lock_dir=os.environ.get("G1_AUTH_LOCK_DIR", "/var/run/g1-lock"),
        allow_readonly_secret=allow_ro,
        claim_store=claim_store,
        holder_identity=pod_ident,
    )
    runtime = LinuxNetnsRuntime(
        executor=LinuxSubprocessExecutor(),
        inspector=LiveProcFilesystemInspector(proc_root="/proc"),
    )
    watchdog = AutonomousWatchdog(max_duration_sec=config.duration_sec)
    runner = HelperLifecycleRunner(
        config=config,
        runtime=runtime,
        watchdog=watchdog,
        authorizer=authorizer,
        health_state=state,
    )
    rc = runner.run(register_signals=True)
    server.shutdown()
    return rc


if __name__ == "__main__":
    sys.exit(main())
