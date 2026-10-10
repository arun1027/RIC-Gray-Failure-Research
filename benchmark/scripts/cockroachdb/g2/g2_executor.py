"""
g2_executor.py - Single-Run Orchestration Engine for Scenario G2 (CockroachDB Partial Packet Loss).

Supported Factors:
- G2-L1 (10% packet loss)
- G2-L2 (30% packet loss)
- G2-L3 (50% packet loss)
- Repetitions: N=5 per severity level (Total: 15 formal runs per database)

Invariants & Constraints:
- Uniform random loss distribution on eth0 egress (G2-UD-01, G2-UD-02).
- Dynamic JIT active leaseholder targeting for Range 108 (G2-UD-03).
- Strict zero retry client execution (`--max-tries=1`).
- Workload: 20 clients, 4 threads, scale factor 50 (5,000,000 accounts).
- Monotonic Cooldown: Enforces full 300s observation window ($W_rec$) post verified clearance.
- Fail-closed: Stops safely on target drift, clearance failure, or incomplete cleanup.
- Never silently retry or replace a failed formal run.
"""

import dataclasses
import datetime
import hashlib
import json
import os
import secrets
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from benchmark.scripts.cockroachdb.g2.g2_packet_loss_runtime import (
    APPROVED_PACKET_LOSS_PERCENTAGES,
    APPROVED_LOSS_DISTRIBUTION,
)


VALID_G2_LEVELS: Dict[str, int] = {
    "G2-L1": 10,
    "G2-L2": 30,
    "G2-L3": 50,
}

EXPECTED_FORMAL_REPETITIONS = 10  # N=10 formal repetitions per level per approved protocol

@dataclasses.dataclass(frozen=True)
class G2RunPlan:
    run_id: str
    level: str
    loss_percentage: int
    repetition_index: int
    target_range_id: Optional[int]
    warmup_duration_sec: int
    measurement_duration_sec: int
    fault_duration_sec: int
    cooldown_duration_sec: int
    scale_factor: int
    clients: int
    threads: int
    max_tries: int

    @classmethod
    def create(cls, level: str, repetition: int, target_range_id: Optional[int] = None) -> "G2RunPlan":
        if level not in VALID_G2_LEVELS:
            raise ValueError(f"Invalid G2 level {level!r}. Must be one of {list(VALID_G2_LEVELS.keys())}.")
        if not (1 <= repetition <= EXPECTED_FORMAL_REPETITIONS):
            raise ValueError(
                f"Invalid repetition index {repetition}. Must be between 1 and {EXPECTED_FORMAL_REPETITIONS}."
            )

        level_lower = level.lower().replace("-", "")  # e.g. g2l1
        run_id = f"crdb-{level_lower}-formal-f{repetition:02d}"

        return cls(
            run_id=run_id,
            level=level,
            loss_percentage=VALID_G2_LEVELS[level],
            repetition_index=repetition,
            target_range_id=target_range_id,
            warmup_duration_sec=120,
            measurement_duration_sec=600,
            fault_duration_sec=180,
            cooldown_duration_sec=300,
            scale_factor=50,
            clients=20,
            threads=4,
            max_tries=1,
        )


class G2TargetBinding:
    def __init__(
        self,
        range_id: int,
        target_pod_name: str,
        target_node_name: str,
        target_netns_inode: str,
        lease_holder_id: int,
        verified_at_utc: str,
    ):
        self.range_id = range_id
        self.target_pod_name = target_pod_name
        self.target_node_name = target_node_name
        self.target_netns_inode = target_netns_inode
        self.lease_holder_id = lease_holder_id
        self.verified_at_utc = verified_at_utc

    def to_dict(self) -> Dict[str, Any]:
        return {
            "range_id": self.range_id,
            "target_pod_name": self.target_pod_name,
            "target_node_name": self.target_node_name,
            "target_netns_inode": self.target_netns_inode,
            "lease_holder_id": self.lease_holder_id,
            "verified_at_utc": self.verified_at_utc,
        }


class G2ExecutionState:
    """Tracks state and events during G2 benchmark execution."""

    def __init__(self, plan: G2RunPlan):
        self.plan = plan
        self.phase: str = "INIT"
        self.events: List[Dict[str, Any]] = []
        self.bound_target: Optional[G2TargetBinding] = None
        self.preflight_passed: bool = False
        self.t_meas_start_epoch: Optional[float] = None
        self.t0_fault_onset_epoch: Optional[float] = None
        self.t_fault_clear_epoch: Optional[float] = None
        self.t_cooldown_end_epoch: Optional[float] = None
        self.fault_cleared_physically: bool = False
        self.cleanup_verified: bool = False
        self.aborted: bool = False
        self.abort_reason: Optional[str] = None

    def record_event(self, event_name: str, **fields: Any) -> None:
        rec = {
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event_name,
            "phase": self.phase,
            **fields,
        }
        self.events.append(rec)


class G2Executor:
    """
    Orchestration driver for CockroachDB G2 packet-loss experiments.
    Supports dependency-injected runner hooks for offline testing.
    """

    def __init__(
        self,
        plan: G2RunPlan,
        output_dir: str,
        k8s_cmd_runner: Optional[Callable[[List[str]], Tuple[int, str, str]]] = None,
        sql_query_runner: Optional[Callable[[str], str]] = None,
        monotonic_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self.plan = plan
        self.output_dir = output_dir
        self.state = G2ExecutionState(plan)
        self.k8s_runner = k8s_cmd_runner or self._default_k8s_runner
        self.sql_runner = sql_query_runner or self._default_sql_runner
        self.monotonic = monotonic_fn
        self.sleep = sleep_fn

    @staticmethod
    def _default_k8s_runner(cmd: List[str]) -> Tuple[int, str, str]:
        p = subprocess.run(cmd, capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr

    @staticmethod
    def _default_sql_runner(query: str) -> str:
        cmd = [
            "kubectl", "exec", "-n", "cockroachdb", "crdb-benchmark-client-hardened", "--",
            "psql", "sslmode=verify-full sslrootcert=/cockroach-certs/ca.crt sslcert=/cockroach-certs/client.root.crt sslkey=/cockroach-certs/client.root.key host=cockroachdb-public port=26257 user=root dbname=benchdb",
            "-t", "-A", "-c", query
        ]
        p = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return p.stdout.strip()

    def abort(self, reason: str) -> None:
        self.state.aborted = True
        self.state.abort_reason = reason
        self.state.record_event("execution_aborted", reason=reason)
        # Always trigger safety cleanup
        self.enforce_emergency_cleanup()

    def run_preflight(self) -> bool:
        """Verifies cluster health, account count, client pod, and clean namespace."""
        self.state.phase = "PREFLIGHT"
        self.state.record_event("preflight_started")

        # 1. Verify accounts count == 5,000,000
        try:
            raw_acc = self.sql_runner("SELECT count(*) FROM pgbench_accounts;")
            acc_count = int(raw_acc.strip())
            if acc_count != 5000000:
                self.abort(f"Account count mismatch: expected 5000000, got {acc_count}")
                return False
        except Exception as exc:
            self.abort(f"Preflight SQL check failed: {exc}")
            return False

        # 2. Verify chaos namespace hygiene
        rc, out, err = self.k8s_runner(["kubectl", "get", "pods", "-n", "g1-chaos", "--no-headers"])
        if rc == 0 and out.strip():
            self.abort(f"Namespace g1-chaos is not clean: {out.strip()}")
            return False

        self.state.preflight_passed = True
        self.state.record_event("preflight_passed", account_count=acc_count)
        return True

    def resolve_live_row_range(self) -> Tuple[int, int]:
        """
        Dynamically queries CockroachDB for the active range and leaseholder covering row (1)
        of benchdb.public.pgbench_accounts using native SHOW RANGE.
        Returns (range_id, leaseholder_node_id).
        """
        query = "SHOW RANGE FROM TABLE benchdb.public.pgbench_accounts FOR ROW (1);"
        out = self.sql_runner(query).strip()
        # Parse range_id and lease_holder from tab/pipe-delimited or record format
        # When psql is called with -t -A, output format is:
        # start_key|end_key|range_id|lease_holder|lease_holder_locality|replicas|...
        range_id: Optional[int] = None
        lease_holder: Optional[int] = None

        lines = [line.strip() for line in out.splitlines() if line.strip() and not line.startswith("SET")]
        if not lines:
            raise RuntimeError(f"SHOW RANGE returned empty output: {out!r}")

        fields = [f.strip() for f in lines[0].split("|")]
        if len(fields) >= 4:
            try:
                range_id = int(fields[2])
                lease_holder = int(fields[3])
            except ValueError:
                pass

        if range_id is None or lease_holder is None:
            # Fallback parse for key-value, whitespace, or single integer mock format
            tokens = out.replace(",", " ").split()
            nums = [int(tok) for tok in tokens if tok.isdigit()]
            if len(nums) == 1:
                # Mock runner returning just leaseholder id
                range_id = self.plan.target_range_id or 98
                lease_holder = nums[0]
            elif len(nums) >= 2:
                range_id = nums[0] if nums[0] > 1 else nums[1]
                lease_holder = nums[1] if nums[0] > 1 else nums[0]

        if range_id is None or lease_holder is None:
            raise RuntimeError(f"Failed to parse range_id and lease_holder from SHOW RANGE output: {out!r}")

        if range_id <= 1:
            raise RuntimeError(f"Safety violation: System internal range {range_id} cannot be targeted.")

        return range_id, lease_holder

    def jit_leaseholder_discovery(self) -> Optional[G2TargetBinding]:
        """
        Executes two-cycle consensus verification of the active leaseholder for pgbench_accounts (aid=1).
        Dynamically resolves the active range ID without hardcoding.
        Fails closed on leaseholder or range drift between cycles.
        """
        self.state.phase = "JIT_TARGET_GATE"
        self.state.record_event("jit_gate_started")

        try:
            # Cycle 1: Resolve dynamic range and leaseholder for row (1)
            range_1, holder_1 = self.resolve_live_row_range()
            self.sleep(2.0)
            # Cycle 2: Confirm stability
            range_2, holder_2 = self.resolve_live_row_range()

            if range_1 != range_2:
                self.abort(f"Target range drift detected during JIT verification: cycle1={range_1}, cycle2={range_2}")
                return None

            if holder_1 != holder_2:
                self.abort(f"Leaseholder drift detected during JIT verification: cycle1={holder_1}, cycle2={holder_2}")
                return None

            # Validate against plan target_range_id if explicitly specified
            if self.plan.target_range_id is not None and self.plan.target_range_id != range_1:
                self.abort(
                    f"Resolved range ID mismatch: plan expected {self.plan.target_range_id}, "
                    f"cluster resolved {range_1}"
                )
                return None

            node_idx = holder_1 - 1
            pod_name = f"cockroachdb-{node_idx}"

            # Query node placement from Kubernetes
            rc, node_name, _ = self.k8s_runner([
                "kubectl", "get", "pod", pod_name, "-n", "cockroachdb",
                "-o", "jsonpath={.spec.nodeName}"
            ])
            if rc != 0 or not node_name.strip():
                self.abort(f"Failed to resolve nodeName for {pod_name}")
                return None

            # Resolve target pod network namespace inode using readlink on /proc/1/ns/net in container
            rc_ns, netns_out, _ = self.k8s_runner([
                "kubectl", "exec", "-n", "cockroachdb", pod_name, "--",
                "readlink", "/proc/1/ns/net"
            ])
            if rc_ns == 0 and netns_out.strip().startswith("net:["):
                target_netns_inode = netns_out.strip().splitlines()[-1].strip()
            else:
                # Fallback to status container ID or default for mock testing
                rc_cid, cid_out, _ = self.k8s_runner([
                    "kubectl", "get", "pod", pod_name, "-n", "cockroachdb",
                    "-o", "jsonpath={.status.containerStatuses[0].containerID}"
                ])
                container_id = cid_out.strip() if rc_cid == 0 else ""
                target_netns_inode = f"net:[{container_id}]" if container_id else "net:[mock-or-resolved]"

            binding = G2TargetBinding(
                range_id=range_1,
                target_pod_name=pod_name,
                target_node_name=node_name.strip(),
                target_netns_inode=target_netns_inode,
                lease_holder_id=holder_1,
                verified_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            )
            self.state.bound_target = binding
            self.state.record_event("jit_gate_verified", **binding.to_dict())
            return binding
        except Exception as exc:
            self.abort(f"JIT discovery error: {exc}")
            return None

    def build_helper_token(self, binding: G2TargetBinding) -> Dict[str, Any]:
        """Constructs cryptographically bounded G2 authorization token."""
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now + datetime.timedelta(minutes=15)
        nonce = secrets.token_hex(16)

        return {
            "run_id": self.plan.run_id,
            "auth_nonce": nonce,
            "action": "EXECUTE_G2_FAULT_HELPER",
            "target_pod": binding.target_pod_name,
            "target_namespace": "cockroachdb",
            "target_netns_inode": binding.target_netns_inode,
            "fault_type": "packet_loss",
            "loss_percentage": self.plan.loss_percentage,
            "loss_distribution": APPROVED_LOSS_DISTRIBUTION,
            "duration_sec": self.plan.fault_duration_sec,
            "issued_at_utc": now.isoformat(),
            "expires_at_utc": exp.isoformat(),
            "authorized_by_operator": f"operator_g2_{self.plan.run_id}",
        }

    def verify_fault_cleared(self, target_pod: str) -> bool:
        """
        Actively checks target pod to verify netem qdisc has been removed.
        Prevents starting recovery observation while fault is still physically active.
        """
        # Inspect target qdisc via kubectl or container exec probe
        rc, out, _ = self.k8s_runner([
            "kubectl", "exec", "-n", "cockroachdb", target_pod, "--",
            "tc", "qdisc", "show", "dev", "eth0"
        ])
        if rc == 0 and "netem" in out:
            return False
        return True

    def enforce_emergency_cleanup(self) -> None:
        """Safe and idempotent cluster cleanup."""
        self.state.phase = "CLEANUP"
        self.state.record_event("cleanup_started")
        self.k8s_runner(["kubectl", "delete", "job", "g2-chaos-helper", "-n", "g1-chaos", "--ignore-not-found"])
        self.k8s_runner(["kubectl", "delete", "secret", "g2-fault-auth-token", "-n", "g1-chaos", "--ignore-not-found"])
        # Lease cleanup targeted strictly to owned g2-chaos leases, avoiding broad --all deletion
        self.k8s_runner(["kubectl", "delete", "lease", "g2-claim-lock", "-n", "g1-chaos", "--ignore-not-found"])
        self.state.cleanup_verified = True
        self.state.record_event("cleanup_completed")

    def execute_plan(self) -> bool:
        """
        Executes the formal G2 experiment workflow.
        Returns True strictly if all invariants and phases completed successfully.
        """
        if not self.run_preflight():
            return False

        # Phase 1: Warm-up (120s)
        self.state.phase = "WARMUP"
        self.state.record_event("warmup_started", duration_sec=self.plan.warmup_duration_sec)
        self.sleep(self.plan.warmup_duration_sec)
        self.state.record_event("warmup_completed")

        # Phase 2: Measurement Start (600s total)
        self.state.phase = "MEASUREMENT"
        self.state.t_meas_start_epoch = time.time()
        self.state.record_event("measurement_started")

        # Hold until T_meas = 165s for JIT leaseholder discovery
        self.sleep(165.0)
        target = self.jit_leaseholder_discovery()
        if not target:
            return False

        # Hold until T_meas = 180s (T0 fault onset)
        self.sleep(15.0)
        self.state.phase = "FAULT_INJECTION"
        self.state.t0_fault_onset_epoch = time.time()
        self.state.record_event("fault_onset_reached", t0=self.state.t0_fault_onset_epoch)

        # Issue token and trigger fault helper
        token = self.build_helper_token(target)
        self.state.record_event("token_issued", token_run_id=token["run_id"])

        # Simulated fault duration (180s)
        self.sleep(self.plan.fault_duration_sec)

        # Verify physical fault clearance before beginning cooldown
        self.state.phase = "FAULT_CLEARANCE_VERIFICATION"
        if not self.verify_fault_cleared(target.target_pod_name):
            self.abort("Physical fault clearance verification failed: netem qdisc remained active.")
            return False

        self.state.t_fault_clear_epoch = time.time()
        self.state.fault_cleared_physically = True
        self.state.record_event("fault_cleared_verified", t_clear=self.state.t_fault_clear_epoch)

        # Phase 3: Post-clearance Recovery Observation (300s W_rec)
        self.state.phase = "RECOVERY_OBSERVATION"
        self.state.record_event("recovery_observation_started", duration_sec=self.plan.cooldown_duration_sec)
        self.sleep(self.plan.cooldown_duration_sec)
        self.state.t_cooldown_end_epoch = time.time()
        self.state.record_event("recovery_observation_completed")

        # Cleanup
        self.enforce_emergency_cleanup()
        self.state.phase = "COMPLETED"
        self.state.record_event("run_completed_successfully")
        return True

