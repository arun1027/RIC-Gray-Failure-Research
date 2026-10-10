"""
g1_linux_runtime.py - Linux Network Namespace & tc netem Runtime Abstraction for Scenario G1.

Separates:
- Command planning (TcCommandPlanner)
- Command execution (ICommandExecutor, MockCommandExecutor, LinuxSubprocessExecutor)
- Process & network namespace inspection (ProcNetnsInspector)
- Runtime orchestration (LinuxNetnsRuntime)
- Runtime evidence capture (RuntimeEvidenceLog)

Safety & Fail-Closed Guarantees:
- Never executes real tc or setns operations unless LinuxSubprocessExecutor is explicitly instantiated
  on a Linux host with required capabilities; offline unit tests inject MockCommandExecutor.
- Rejects unrelated interfaces (only approved interface, default 'eth0', is permitted).
- Rejects PID reuse, ambiguous multi-PID matches, and stale network namespace inodes.
- Enforces handle-specific qdisc ownership (handle 100:) and multi-factor verification
  (handle + netem + delay/jitter parameters) before and after apply/rollback.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import datetime
import os
import re
import subprocess
from typing import Any, Callable, Dict, List, Optional, Tuple


APPROVED_INTERFACES = ("eth0",)
APPROVED_DISTRIBUTIONS = ("normal", "uniform", "pareto", "paretonormal")
G1_QDISC_HANDLE = "100:"


class LinuxRuntimeError(Exception):
    """Base error for Linux netns / tc runtime operations."""
    pass


class RuntimeTargetAmbiguityError(LinuxRuntimeError):
    """Raised when target process, PID, or network namespace identity is ambiguous or stale."""
    pass


class RuntimeInterfaceError(LinuxRuntimeError):
    """Raised when target network interface is invalid, unrelated, or missing."""
    pass


class RuntimeQdiscConflictError(LinuxRuntimeError):
    """Raised when an existing or foreign qdisc conflicts with G1 fault injection or ownership."""
    pass


class RuntimeVerificationError(LinuxRuntimeError):
    """Raised when post-apply or post-rollback qdisc verification fails."""
    pass


class RuntimeUnresolvedFaultError(RuntimeVerificationError):
    """Raised when partial installation or rollback leaves an unverified/unresolved kernel qdisc."""
    pass


@dataclass(frozen=True)
class ProcessIdentity:
    """Verified Linux process identity for a CockroachDB container process."""
    pid: int
    cmdline: str
    cgroup_path: str
    start_time_ticks: int
    pod_name: str
    container_name: str = "cockroachdb"


@dataclass(frozen=True)
class NetnsIdentity:
    """Resolved network namespace identity from /proc/<pid>/ns/net."""
    pid: int
    ns_path: str
    ns_inode: str  # e.g. "net:[4026532456]"


@dataclass(frozen=True)
class CommandResult:
    """Result of an executed command via ICommandExecutor."""
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str


class ICommandExecutor(ABC):
    """Injectable command execution interface for offline testability and live isolation."""

    @abstractmethod
    def run(self, argv: List[str], netns_path: Optional[str] = None, timeout_sec: int = 10) -> CommandResult:
        """Executes argv, optionally inside netns_path via nsenter/setns."""
        pass


class MockCommandExecutor(ICommandExecutor):
    """
    Offline mock executor that records planned commands and returns deterministic responses
    without ever invoking OS binaries or kernel syscalls.
    """

    def __init__(self, handler: Optional[Callable[[List[str], Optional[str]], CommandResult]] = None):
        self.recorded_calls: List[Tuple[List[str], Optional[str]]] = []
        self._handler = handler

    def run(self, argv: List[str], netns_path: Optional[str] = None, timeout_sec: int = 10) -> CommandResult:
        self.recorded_calls.append((list(argv), netns_path))
        if self._handler is not None:
            return self._handler(argv, netns_path)
        return CommandResult(argv=list(argv), returncode=0, stdout="", stderr="")


class LinuxSubprocessExecutor(ICommandExecutor):
    """
    Live Linux executor using nsenter --net=<netns_path> for tc commands.
    Note: Requires Linux host with CAP_SYS_ADMIN and CAP_NET_ADMIN. Never invoked in offline tests.
    """

    def run(self, argv: List[str], netns_path: Optional[str] = None, timeout_sec: int = 10) -> CommandResult:
        if os.name != "posix":
            raise LinuxRuntimeError("LinuxSubprocessExecutor can only run on POSIX/Linux hosts.")
        full_argv = list(argv)
        if netns_path:
            full_argv = ["/usr/bin/nsenter", f"--net={netns_path}", "--"] + full_argv
        proc = subprocess.run(
            full_argv,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return CommandResult(
            argv=full_argv,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )


class TcCommandPlanner:
    """
    Pure command planner for Linux iproute2 `tc` operations.
    Validates interface allowlist, handle format, and approved G1 fault parameters.
    """

    @staticmethod
    def validate_interface(interface: str) -> None:
        if not interface or interface not in APPROVED_INTERFACES:
            raise RuntimeInterfaceError(
                f"Rejected unrelated or unapproved interface '{interface}'. Allowed: {APPROVED_INTERFACES}."
            )

    @staticmethod
    def validate_handle(handle: str) -> None:
        if not re.fullmatch(r"[0-9a-fA-F]+:", handle):
            raise LinuxRuntimeError(f"Invalid tc qdisc handle '{handle}'. Expected '<hex>:' (e.g. '100:').")

    @classmethod
    def plan_show_qdisc(cls, interface: str) -> List[str]:
        cls.validate_interface(interface)
        return ["/sbin/tc", "qdisc", "show", "dev", interface]

    @classmethod
    def plan_link_show(cls, interface: str) -> List[str]:
        cls.validate_interface(interface)
        return ["/sbin/ip", "link", "show", "dev", interface]

    @classmethod
    def plan_add_egress_netem(
        cls,
        interface: str,
        handle: str = G1_QDISC_HANDLE,
        delay_ms: int = 1000,
        jitter_ms: int = 20,
        distribution: str = "normal",
    ) -> List[str]:
        cls.validate_interface(interface)
        cls.validate_handle(handle)
        if delay_ms <= 0 or jitter_ms < 0:
            raise LinuxRuntimeError(f"Invalid delay/jitter values: delay_ms={delay_ms}, jitter_ms={jitter_ms}.")
        if distribution not in APPROVED_DISTRIBUTIONS:
            raise LinuxRuntimeError(
                f"Unsupported netem distribution '{distribution}'. Allowed: {APPROVED_DISTRIBUTIONS}."
            )
        return [
            "/sbin/tc", "qdisc", "add", "dev", interface,
            "root", "handle", handle, "netem",
            "delay", f"{delay_ms}ms", f"{jitter_ms}ms",
            "distribution", distribution,
        ]

    @classmethod
    def plan_del_root_qdisc(cls, interface: str, handle: str = G1_QDISC_HANDLE) -> List[str]:
        cls.validate_interface(interface)
        cls.validate_handle(handle)
        return ["/sbin/tc", "qdisc", "del", "dev", interface, "root", "handle", handle]


@dataclass
class OwnedQdiscRecord:
    """Tracks exact experiment-owned qdisc metadata for safe verification and cleanup."""
    experiment_qdisc_id: str
    pod_name: str
    pid: int
    netns_inode: str
    interface: str
    handle: str
    delay_ms: int
    jitter_ms: int
    distribution: str
    applied_utc: str


class ProcNetnsInspector:
    """
    Resolves CockroachDB process and network namespace identity using an injectable
    process/namespace lookup provider (or /proc on live Linux).
    """

    def __init__(
        self,
        process_lister: Optional[Callable[[], List[ProcessIdentity]]] = None,
        netns_resolver: Optional[Callable[[int], NetnsIdentity]] = None,
    ):
        self._process_lister = process_lister
        self._netns_resolver = netns_resolver

    def identify_target_process(
        self,
        pod_name: str,
        container_name: Optional[str] = None,
        expected_start_time_ticks: Optional[int] = None,
    ) -> ProcessIdentity:
        if self._process_lister is None:
            raise LinuxRuntimeError(
                "No process lister configured; refusing unverified /proc scan in offline mode."
            )
        # Filter candidates by pod_name and cockroach in cmdline.
        # If container_name is provided, also match container_name ('db', 'cockroachdb', etc.).
        # If container_name is None, match any verified container for that pod.
        candidates = [
            p for p in self._process_lister()
            if p.pod_name == pod_name
            and (container_name is None or p.container_name == container_name or container_name in ("db", "cockroachdb"))
            and "cockroach" in p.cmdline
        ]
        if not candidates:
            raise RuntimeTargetAmbiguityError(
                f"No matching CockroachDB process found for pod '{pod_name}' container '{container_name}'."
            )
        if len(candidates) > 1:
            pids = [c.pid for c in candidates]
            raise RuntimeTargetAmbiguityError(
                f"Ambiguous CockroachDB process match for pod '{pod_name}': multiple PIDs {pids}."
            )
        proc = candidates[0]
        if expected_start_time_ticks is not None and proc.start_time_ticks != expected_start_time_ticks:
            raise RuntimeTargetAmbiguityError(
                f"PID reuse detected for PID {proc.pid}: expected start_time={expected_start_time_ticks}, "
                f"observed={proc.start_time_ticks}."
            )
        return proc

    def resolve_netns(self, proc: ProcessIdentity, expected_inode: Optional[str] = None) -> NetnsIdentity:
        if self._netns_resolver is None:
            raise LinuxRuntimeError(
                "No netns resolver configured; refusing unverified /proc/<pid>/ns/net read."
            )
        netns = self._netns_resolver(proc.pid)
        if expected_inode is not None and netns.ns_inode != expected_inode:
            raise RuntimeTargetAmbiguityError(
                f"Stale network namespace detected for PID {proc.pid}: expected '{expected_inode}', "
                f"observed '{netns.ns_inode}'."
            )
        return netns


class LinuxNetnsRuntime:
    """
    Coordinates target process/netns binding, tc command planning, execution via ICommandExecutor,
    and evidence recording without mixing planning, execution, and evidence concerns.
    """

    def __init__(
        self,
        executor: ICommandExecutor,
        inspector: ProcNetnsInspector,
        handle: str = G1_QDISC_HANDLE,
    ):
        self.executor = executor
        self.inspector = inspector
        self.handle = handle
        self.owned_qdiscs: Dict[str, OwnedQdiscRecord] = {}
        self.runtime_evidence: List[Dict[str, Any]] = []
        self.unresolved_fault: bool = False

    def bind_target(
        self,
        pod_name: str,
        container_name: Optional[str] = None,
        expected_start_time_ticks: Optional[int] = None,
        expected_netns_inode: Optional[str] = None,
    ) -> Tuple[ProcessIdentity, NetnsIdentity]:
        proc = self.inspector.identify_target_process(
            pod_name=pod_name,
            container_name=container_name,
            expected_start_time_ticks=expected_start_time_ticks,
        )
        netns = self.inspector.resolve_netns(proc, expected_inode=expected_netns_inode)
        self._record_evidence("target_bound", {
            "pod_name": pod_name,
            "pid": proc.pid,
            "start_time_ticks": proc.start_time_ticks,
            "netns_path": netns.ns_path,
            "netns_inode": netns.ns_inode,
        })
        return proc, netns

    def inspect_interface_and_qdisc(self, netns: NetnsIdentity, interface: str = "eth0") -> str:
        link_cmd = TcCommandPlanner.plan_link_show(interface)
        link_res = self.executor.run(link_cmd, netns_path=netns.ns_path)
        if link_res.returncode != 0:
            raise RuntimeInterfaceError(
                f"Target interface '{interface}' inspection failed in {netns.ns_inode}: {link_res.stderr}"
            )
        qdisc_cmd = TcCommandPlanner.plan_show_qdisc(interface)
        qdisc_res = self.executor.run(qdisc_cmd, netns_path=netns.ns_path)
        if qdisc_res.returncode != 0:
            raise LinuxRuntimeError(
                f"Failed to query qdisc on '{interface}' in {netns.ns_inode}: {qdisc_res.stderr}"
            )
        return qdisc_res.stdout.strip()

    def apply_egress_latency(
        self,
        run_id: str,
        pod_name: str,
        netns: NetnsIdentity,
        proc: ProcessIdentity,
        interface: str = "eth0",
        delay_ms: int = 1000,
        jitter_ms: int = 20,
        distribution: str = "normal",
    ) -> OwnedQdiscRecord:
        if self.unresolved_fault:
            raise RuntimeUnresolvedFaultError(
                "Refusing fault injection: unresolved fault state from prior failure requires verified cleanup."
            )
        if pod_name in self.owned_qdiscs:
            raise RuntimeQdiscConflictError(
                f"Duplicate fault application rejected: pod '{pod_name}' already has active owned qdisc "
                f"'{self.owned_qdiscs[pod_name].experiment_qdisc_id}'."
            )
        current_qdisc = self.inspect_interface_and_qdisc(netns, interface)
        if "netem" in current_qdisc or (current_qdisc and "noqueue" not in current_qdisc and "mq" not in current_qdisc and "fq_codel" not in current_qdisc):
            raise RuntimeQdiscConflictError(
                f"Refusing injection on {pod_name}:{interface}: existing qdisc '{current_qdisc}' detected."
            )

        add_cmd = TcCommandPlanner.plan_add_egress_netem(
            interface=interface,
            handle=self.handle,
            delay_ms=delay_ms,
            jitter_ms=jitter_ms,
            distribution=distribution,
        )
        add_res = self.executor.run(add_cmd, netns_path=netns.ns_path)
        if add_res.returncode != 0:
            raise LinuxRuntimeError(f"Failed to apply tc netem on {pod_name}:{interface}: {add_res.stderr}")

        # Verify installed qdisc matches requested parameters; on partial/mismatched install,
        # immediately attempt scoped rollback and verify resulting state.
        # Note: Linux iproute2 `tc qdisc show` formats 1000ms as `1s` (e.g. `delay 1s  20ms`).
        def _tc_time_tokens(ms: int) -> Tuple[str, ...]:
            tokens = [f"{ms}ms"]
            if ms >= 1000:
                if ms % 1000 == 0:
                    tokens.append(f"{ms // 1000}s")
                else:
                    tokens.append(f"{ms / 1000:g}s")
            return tuple(tokens)

        verify_err: Optional[str] = None
        verify_out = ""
        try:
            verify_out = self.inspect_interface_and_qdisc(netns, interface)
            delay_ok = any(tok in verify_out for tok in _tc_time_tokens(delay_ms))
            jitter_ok = any(tok in verify_out for tok in _tc_time_tokens(jitter_ms))
            if not (self.handle in verify_out and "netem" in verify_out and delay_ok and jitter_ok):
                verify_err = (
                    f"Post-apply qdisc verification failed on {pod_name}:{interface}: observed '{verify_out}'."
                )
        except Exception as exc:
            verify_err = f"Post-apply qdisc inspection failed on {pod_name}:{interface}: {exc}"

        if verify_err is not None:
            rollback_status = "NOT_ATTEMPTED"
            post_qdisc = ""
            try:
                if (self.handle in verify_out and "netem" in verify_out) or verify_out == "":
                    del_cmd = TcCommandPlanner.plan_del_root_qdisc(interface=interface, handle=self.handle)
                    del_res = self.executor.run(del_cmd, netns_path=netns.ns_path)
                    if del_res.returncode != 0:
                        rollback_status = f"ROLLBACK_CMD_FAILED:{del_res.stderr}"
                    else:
                        post_qdisc = self.inspect_interface_and_qdisc(netns, interface)
                        if "netem" in post_qdisc:
                            rollback_status = f"ROLLBACK_VERIFY_FAILED:{post_qdisc}"
                        else:
                            rollback_status = "ROLLED_BACK_AND_VERIFIED"
                else:
                    rollback_status = f"REFUSED_FOREIGN_QDISC:{verify_out}"
            except Exception as rb_exc:
                rollback_status = f"ROLLBACK_EXCEPTION:{rb_exc}"

            self._record_evidence("partial_install_rollback", {
                "pod_name": pod_name,
                "interface": interface,
                "handle": self.handle,
                "original_error": verify_err,
                "rollback_status": rollback_status,
                "post_qdisc": post_qdisc,
            })
            if rollback_status == "ROLLED_BACK_AND_VERIFIED":
                raise RuntimeVerificationError(f"{verify_err} Scoped rollback succeeded and verified clean.")
            self.unresolved_fault = True
            raise RuntimeUnresolvedFaultError(
                f"{verify_err} Scoped rollback did not verify clean ({rollback_status}); UNRESOLVED FAULT."
            )

        record = OwnedQdiscRecord(
            experiment_qdisc_id=f"{run_id}:{pod_name}:{self.handle}",
            pod_name=pod_name,
            pid=proc.pid,
            netns_inode=netns.ns_inode,
            interface=interface,
            handle=self.handle,
            delay_ms=delay_ms,
            jitter_ms=jitter_ms,
            distribution=distribution,
            applied_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        self.owned_qdiscs[pod_name] = record
        self._record_evidence("qdisc_applied", {
            "experiment_qdisc_id": record.experiment_qdisc_id,
            "pod_name": pod_name,
            "interface": interface,
            "handle": self.handle,
            "verified_output": verify_out,
        })
        return record

    def remove_owned_qdisc(self, pod_name: str, netns: NetnsIdentity, interface: str = "eth0") -> Dict[str, Any]:
        TcCommandPlanner.validate_interface(interface)
        owned = self.owned_qdiscs.get(pod_name)
        if owned is None:
            return {"pod_name": pod_name, "interface": interface, "status": "ALREADY_CLEARED"}
        if owned.netns_inode != netns.ns_inode:
            raise RuntimeTargetAmbiguityError(
                f"Refusing cleanup on '{pod_name}': netns inode mismatch "
                f"(owned={owned.netns_inode}, current={netns.ns_inode})."
            )

        try:
            current_qdisc = self.inspect_interface_and_qdisc(netns, interface)
        except RuntimeInterfaceError as exc:
            if "ENODEV" in str(exc) or "Cannot find device" in str(exc):
                self.owned_qdiscs.pop(pod_name, None)
                return {"pod_name": pod_name, "interface": interface, "status": "NATURALLY_CLEARED_ENODEV"}
            raise

        if "netem" not in current_qdisc:
            if "noqueue" in current_qdisc or current_qdisc == "":
                self.owned_qdiscs.pop(pod_name, None)
                return {"pod_name": pod_name, "interface": interface, "status": "ALREADY_CLEARED"}
            raise RuntimeQdiscConflictError(
                f"Refusing cleanup: active qdisc '{current_qdisc}' on {pod_name}:{interface} is not netem."
            )
        if self.handle not in current_qdisc:
            raise RuntimeQdiscConflictError(
                f"Refusing cleanup: active netem qdisc '{current_qdisc}' does not match owned handle '{self.handle}'."
            )

        del_cmd = TcCommandPlanner.plan_del_root_qdisc(interface=interface, handle=self.handle)
        del_res = self.executor.run(del_cmd, netns_path=netns.ns_path)
        if del_res.returncode != 0:
            self.unresolved_fault = True
            self._record_evidence("qdisc_removal_unresolved_fault", {
                "pod_name": pod_name,
                "interface": interface,
                "handle": self.handle,
                "experiment_qdisc_id": owned.experiment_qdisc_id,
                "error": del_res.stderr,
                "unresolved_fault": True,
            })
            raise RuntimeUnresolvedFaultError(
                f"Failed to delete owned qdisc on {pod_name}:{interface}: {del_res.stderr}"
            )

        post_qdisc = self.inspect_interface_and_qdisc(netns, interface)
        if "netem" in post_qdisc:
            self.unresolved_fault = True
            self._record_evidence("qdisc_removal_unresolved_fault", {
                "pod_name": pod_name,
                "interface": interface,
                "handle": self.handle,
                "experiment_qdisc_id": owned.experiment_qdisc_id,
                "observed_post_qdisc": post_qdisc,
                "unresolved_fault": True,
            })
            raise RuntimeUnresolvedFaultError(
                f"Post-rollback verification failed on {pod_name}:{interface}: '{post_qdisc}' still present."
            )

        self.unresolved_fault = False
        self.owned_qdiscs.pop(pod_name, None)
        result = {
            "pod_name": pod_name,
            "interface": interface,
            "handle": self.handle,
            "experiment_qdisc_id": owned.experiment_qdisc_id,
            "status": "CLEARED",
        }
        self._record_evidence("qdisc_removed", result)
        return result

    def _record_evidence(self, event: str, details: Dict[str, Any]) -> None:
        self.runtime_evidence.append({
            "event": event,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "details": details,
        })


class LiveProcFilesystemInspector(ProcNetnsInspector):
    """
    Concrete Linux /proc filesystem inspector (Workstream 4).
    Reads <proc_root>/<pid>/cmdline, cgroup, stat (start_time_ticks), and ns/net.
    Injectable proc_root allows offline testing against local temp directory fixtures
    without ever touching host /proc.
    """

    def __init__(self, proc_root: str = "/proc", pod_uid_resolver: Optional[Callable[[str], str]] = None):
        self.proc_root = proc_root
        self.pod_uid_resolver = pod_uid_resolver
        super().__init__(
            process_lister=self._scan_proc,
            netns_resolver=self._read_netns,
        )

    def _scan_proc(self) -> List[ProcessIdentity]:
        results: List[ProcessIdentity] = []
        if not os.path.isdir(self.proc_root):
            return results
        for entry in os.listdir(self.proc_root):
            if not entry.isdigit():
                continue
            pid = int(entry)
            pid_dir = os.path.join(self.proc_root, entry)
            try:
                with open(os.path.join(pid_dir, "cmdline"), "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                if "cockroach" not in cmdline:
                    continue
                with open(os.path.join(pid_dir, "cgroup"), "r", encoding="utf-8", errors="replace") as f:
                    cgroup_text = f.read().strip()
                with open(os.path.join(pid_dir, "stat"), "r", encoding="utf-8", errors="replace") as f:
                    stat_text = f.read().strip()
                # /proc/<pid>/stat field 22 (1-based) after comm '(...)' is starttime
                rparen = stat_text.rfind(")")
                if rparen == -1:
                    continue
                after_comm = stat_text[rparen + 2:].split()
                start_time_ticks = int(after_comm[19])
                pod_name = ""
                environ_path = os.path.join(pid_dir, "environ")
                if os.path.exists(environ_path):
                    with open(environ_path, "rb") as ef:
                        for kv in ef.read().split(b"\x00"):
                            if kv.startswith(b"HOSTNAME="):
                                pod_name = kv.split(b"=", 1)[1].decode("utf-8", errors="replace")
                                break
                results.append(ProcessIdentity(
                    pid=pid,
                    cmdline=cmdline,
                    cgroup_path=cgroup_text,
                    start_time_ticks=start_time_ticks,
                    pod_name=pod_name,
                    container_name="cockroachdb",
                ))
            except (OSError, ValueError, IndexError):
                continue
        return results

    def _read_netns(self, pid: int) -> NetnsIdentity:
        ns_path = os.path.join(self.proc_root, str(pid), "ns", "net")
        if os.path.islink(ns_path):
            ns_inode = os.readlink(ns_path)
        elif os.path.isfile(ns_path):
            # Support text fixture file on Windows/offline tests where symlinks are restricted
            with open(ns_path, "r", encoding="utf-8") as f:
                ns_inode = f.read().strip()
        else:
            raise RuntimeTargetAmbiguityError(f"Network namespace path missing for PID {pid}: {ns_path}")
        return NetnsIdentity(pid=pid, ns_path=ns_path, ns_inode=ns_inode)


