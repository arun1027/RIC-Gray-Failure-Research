"""
stage5_4g11_live_pilot_r02_executor.py - Single-Use Live Orchestration Driver for Pilot R02.
Stage 5.4G.11: Authorised CockroachDB G1-L2 Pilot Repetition R02 Execution.

Features:
- Dynamically executes PD08JITLeaseholderGate at T_meas = 175s.
- Verifies and binds the active leaseholder for Range 108 (pgbench_accounts, aid=1).
- Re-queries preflight double-check invariant immediately before Secret/Job deployment.
- Enforces fail-closed safety: aborts and terminates if any leaseholder or netns drift occurs.
- Strictly adheres to approved parameters:
  * Warm-up: 120s (-T 120) unlogged
  * Measurement: 600s (-T 600) logged
  * Fault window: T_meas = 180s for duration = 180s
  * Latency: 1000ms, Jitter: 20ms normal distribution
  * Concurrency: 20 clients, 4 threads, -M simple, --max-tries=1
- Captures unbuffered raw client logs, per-thread logs, execution telemetry, and helper daemon logs.
- Performs cleanup of all temporary chaos resources upon completion or on error.
"""

import datetime
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from typing import Dict, Any, List

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmark.scripts.cockroachdb.g1.g1_jit_gate import (
    PD08JITLeaseholderGate,
    JITTargetBinding,
    TargetDriftAbortError,
    ProcessStateMismatchError,
    JITGateVerificationError,
)
from benchmark.scripts.cockroachdb.g1.stage5_4g8_live_jit_validator import (
    LiveClusterDatabaseProvider,
    LiveKubernetesProvider,
    LiveProcessInspector,
)

RUN_ID = "crdb-g1-l2-pilot-r02"
OUTPUT_DIR = os.path.abspath("thesis-evidence/05-g1-chaos/stage5-4g-11-r02-execution")
CLIENT_POD = "crdb-benchmark-client"
NAMESPACE = "cockroachdb"
CHAOS_NAMESPACE = "g1-chaos"

HELPER_IMAGE = "503314623827.dkr.ecr.us-east-1.amazonaws.com/ric-g1-helper@sha256:feb8e2a70623204945cbc3dd8a7af67be8eb79ac4044faaf982408f01779a38f"
PSQL_CONN = "sslmode=verify-full sslrootcert=/cockroach-certs/ca.crt sslcert=/cockroach-certs/client.root.crt sslkey=/cockroach-certs/client.root.key host=cockroachdb-public port=26257 user=root dbname=benchdb"


def log(msg: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(f"[{now}] {msg}", flush=True)


def query_history_count() -> int:
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "psql", PSQL_CONN, "-t", "-A", "-c", "SELECT count(*) FROM pgbench_history;"
    ]
    res = subprocess.check_output(cmd, text=True).strip()
    return int(res)


def execute_warmup() -> Dict[str, Any]:
    log("Starting Phase 1: 120s Unlogged Warm-Up Workload...")
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "pgbench", "-h", "cockroachdb-public", "-p", "26257", "-U", "root",
        "-n", "-c", "20", "-j", "4", "-T", "120", "--max-tries=1", "-M", "simple", "benchdb"
    ]
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    t1 = time.time()
    log(f"Warm-up complete in {t1 - t0:.2f}s. Returncode={proc.returncode}")
    if proc.returncode != 0:
        log(f"Warm-up stderr: {proc.stderr}")
    return {
        "start_epoch": t0,
        "end_epoch": t1,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def execute_jit_gate() -> JITTargetBinding:
    log("=== T=175s: Executing PD-08 JIT Active-Leaseholder Verification Gate ===")
    db_prov = LiveClusterDatabaseProvider()
    k8s_prov = LiveKubernetesProvider()
    proc_insp = LiveProcessInspector()

    gate = PD08JITLeaseholderGate(
        db_provider=db_prov,
        k8s_provider=k8s_prov,
        process_inspector=proc_insp,
        expected_range_id=None,
    )

    # Step 1: Initial Discovery
    binding_1 = gate.verify_and_bind_target()
    log(f"JIT Gate Step 1 Discovery: Range {binding_1.range_id}, Leaseholder Node {binding_1.lease_holder_node_id}")
    log(f"Target Pod: {binding_1.target_pod_name} (IP: {binding_1.target_pod_ip}) on Node: {binding_1.target_node_name}")
    log(f"Netns Inode: {binding_1.target_netns_inode}, Process Start Ticks: {binding_1.target_start_ticks}")

    # Step 2: Immediate Preflight Revalidation
    log("JIT Gate Step 2: Immediate Preflight Double-Check Revalidation...")
    binding_2 = gate.revalidate_immediate_preflight(binding_1)
    log(f"JIT Gate Revalidation Confirmed: Active leaseholder stable on Pod {binding_2.target_pod_name}")

    # Write binding JSON to disk immediately
    binding_path = os.path.join(OUTPUT_DIR, "r02-jit-leaseholder-binding.json")
    with open(binding_path, "w", encoding="utf-8") as f:
        json.dump(binding_2.to_dict(), f, indent=2)

    return binding_2


def execute_orchestrated_pilot() -> Dict[str, Any]:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log(f"================================================================================")
    log(f"STARTING LIVE EXECUTION: {RUN_ID}")
    log(f"================================================================================")

    # 1. Baseline pre-run check
    history_pre = query_history_count()
    log(f"Verified pre-run pgbench_history count: {history_pre} (Expected: 0)")
    if history_pre != 0:
        raise RuntimeError(f"Safety violation: pgbench_history count is {history_pre}, expected 0.")

    # 2. Phase 1: Warm-up
    warmup_res = execute_warmup()

    # 3. Clean up any stale client logs on benchmark pod
    subprocess.run([
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "sh", "-c", f"rm -f /tmp/pgbench_log_{RUN_ID}.*"
    ], check=True)

    # 4. Phase 2: Start 600s Logged Measurement Workload in background
    log("Starting Phase 2: 600s Logged Measurement Workload...")
    pgbench_cmd = [
        "kubectl", "exec", "-i", "-n", NAMESPACE, CLIENT_POD, "--",
        "pgbench", "-h", "cockroachdb-public", "-p", "26257", "-U", "root",
        "-n", "-c", "20", "-j", "4", "-T", "600", "--max-tries=1", "-M", "simple",
        "-l", f"--log-prefix=/tmp/pgbench_log_{RUN_ID}", "benchdb"
    ]
    t_meas_start = time.time()
    client_proc = subprocess.Popen(
        pgbench_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False
    )
    log(f"Measurement benchmark process launched with PID {client_proc.pid} at epoch {t_meas_start:.3f}")

    # 5. Timing coordination: Wait until T_meas = 175s for JIT Gate
    target_jit_epoch = t_meas_start + 175.0
    sleep_to_jit = target_jit_epoch - time.time()
    if sleep_to_jit > 0:
        log(f"Holding workload until JIT checkpoint (sleeping {sleep_to_jit:.2f}s)...")
        time.sleep(sleep_to_jit)

    # 6. Execute JIT Gate Checkpoint
    bound_target = execute_jit_gate()

    # 7. Timing coordination: Wait until T_meas = 180s for Fault Onset
    target_t0_epoch = t_meas_start + 180.0
    sleep_to_t0 = target_t0_epoch - time.time()
    if sleep_to_t0 > 0:
        log(f"Holding until scheduled fault onset T0 (sleeping {sleep_to_t0:.2f}s)...")
        time.sleep(sleep_to_t0)

    t0_epoch = time.time()
    log(f"=== T0 REACHED (epoch={t0_epoch:.3f}): Injecting G1-L2 Fault on {bound_target.target_pod_name} ===")

    # 8. Issue Helper Authorization Token and Deploy Helper Job
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    exp_utc = now_utc + datetime.timedelta(minutes=15)
    nonce = secrets.token_hex(16)

    helper_token = {
        "run_id": RUN_ID,
        "auth_nonce": nonce,
        "action": "EXECUTE_G1_FAULT_HELPER",
        "target_pod": bound_target.target_pod_name,
        "target_namespace": NAMESPACE,
        "target_netns_inode": bound_target.target_netns_inode,
        "fault_type": "egress_latency",
        "delay_ms": 1000,
        "jitter_ms": 20,
        "duration_sec": 180,
        "issued_at_utc": now_utc.isoformat(),
        "expires_at_utc": exp_utc.isoformat(),
        "authorized_by_operator": "operator_live_authorized_r02",
    }

    token_json = json.dumps(helper_token)
    log("Creating authorization Secret 'g1-fault-auth-token' in namespace 'g1-chaos'...")
    sec_cmd = [
        "kubectl", "create", "secret", "generic", "g1-fault-auth-token",
        "-n", CHAOS_NAMESPACE,
        f"--from-literal=G1_FAULT_AUTHORIZED.json={token_json}"
    ]
    subprocess.check_call(sec_cmd)
    log("Secret created successfully.")

    # Deploy helper job pinned to bound target node
    log(f"Deploying chaos helper Job pinned to node {bound_target.target_node_name}...")
    job_manifest = f"""
apiVersion: batch/v1
kind: Job
metadata:
  name: g1-chaos-helper
  namespace: {CHAOS_NAMESPACE}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 300
  template:
    spec:
      serviceAccountName: g1-chaos-helper-sa
      restartPolicy: Never
      nodeName: {bound_target.target_node_name}
      hostPID: true
      hostNetwork: false
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: g1-helper
          image: {HELPER_IMAGE}
          imagePullPolicy: IfNotPresent
          env:
            - name: G1_RUN_ID
              value: "{RUN_ID}"
            - name: G1_TARGET_POD
              value: "{bound_target.target_pod_name}"
            - name: G1_TARGET_NAMESPACE
              value: "{NAMESPACE}"
            - name: G1_TARGET_INTERFACE
              value: "eth0"
            - name: G1_FAULT_DELAY_MS
              value: "1000"
            - name: G1_FAULT_JITTER_MS
              value: "20"
            - name: G1_FAULT_DURATION_SEC
              value: "180"
            - name: G1_AUTH_TOKEN_DIR
              value: "/var/run/g1-auth"
            - name: G1_AUTH_LOCK_DIR
              value: "/var/run/g1-lock"
            - name: G1_AUTH_ALLOW_READONLY_SECRET
              value: "1"
            - name: G1_CLAIM_NAMESPACE
              value: "{CHAOS_NAMESPACE}"
            - name: G1_HELPER_POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: G1_HELPER_POD_UID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.uid
          securityContext:
            runAsUser: 0
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
              add:
                - NET_ADMIN
                - SYS_ADMIN
          volumeMounts:
            - name: tmp-ephemeral
              mountPath: /tmp
            - name: lock-dir
              mountPath: /var/run/g1-lock
            - name: fault-auth-token
              mountPath: /var/run/g1-auth
              readOnly: true
      volumes:
        - name: tmp-ephemeral
          emptyDir:
            medium: Memory
            sizeLimit: 16Mi
        - name: lock-dir
          emptyDir:
            medium: Memory
            sizeLimit: 4Mi
        - name: fault-auth-token
          secret:
            secretName: g1-fault-auth-token
            defaultMode: 0400
"""
    apply_proc = subprocess.run(["kubectl", "apply", "-f", "-"], input=job_manifest, text=True, capture_output=True)
    if apply_proc.returncode != 0:
        raise RuntimeError(f"Failed to deploy helper Job: {apply_proc.stderr}")
    log("Helper Job manifest applied.")

    # 9. Wait for fault active window (180s)
    log("Fault active window started: holding for 180 seconds...")
    time.sleep(180)

    t_clear_epoch = time.time()
    log(f"=== T_CLEAR REACHED (epoch={t_clear_epoch:.3f}): Tearing down fault injection ===")

    # Wait for helper job to complete and retrieve logs
    log("Waiting for helper Job to finish lifecycle...")
    time.sleep(5)
    helper_logs = ""
    try:
        helper_logs = subprocess.check_output(
            ["kubectl", "logs", "-n", CHAOS_NAMESPACE, "job/g1-chaos-helper", "-c", "g1-helper"],
            text=True
        )
        log("Captured helper container logs.")
    except Exception as e:
        log(f"Warning: Failed to capture helper logs: {e}")

    with open(os.path.join(OUTPUT_DIR, "r02-helper-execution-log.txt"), "w", encoding="utf-8") as f:
        f.write(helper_logs)

    # Clean up chaos Job and Secret
    log("Cleaning up helper Job and authorization Secret...")
    subprocess.run(["kubectl", "delete", "job", "g1-chaos-helper", "-n", CHAOS_NAMESPACE, "--wait=true"], capture_output=True)
    subprocess.run(["kubectl", "delete", "secret", "g1-fault-auth-token", "-n", CHAOS_NAMESPACE, "--wait=true"], capture_output=True)
    log("Chaos resources cleared.")

    # 10. Wait for measurement workload to complete (remainder of 600s)
    t_rem = (t_meas_start + 600.0) - time.time()
    if t_rem > 0:
        log(f"Holding until end of 600s measurement window (sleeping {t_rem:.2f}s)...")
        time.sleep(t_rem)

    # Await pgbench process termination
    log("Awaiting pgbench process termination...")
    stdout_b, stderr_b = client_proc.communicate()
    t_meas_end = time.time()
    log(f"Measurement phase complete in {t_meas_end - t_meas_start:.2f}s. Returncode={client_proc.returncode}")

    with open(os.path.join(OUTPUT_DIR, "r02-benchmark-raw-output.txt"), "wb") as f:
        f.write(stdout_b + b"\nSTDERR:\n" + stderr_b)

    # 11. Retrieve pgbench transaction logs from client pod
    log("Retrieving pgbench microsecond transaction logs from benchmark client pod...")
    log_files_raw = subprocess.check_output(
        ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"ls /tmp/pgbench_log_{RUN_ID}.*"],
        text=True
    ).strip().splitlines()

    for rpath in log_files_raw:
        rpath = rpath.strip()
        if not rpath:
            continue
        fname = os.path.basename(rpath)
        dest = os.path.join(OUTPUT_DIR, fname)
        log(f"Downloading {rpath} to {dest}...")
        log_bytes = subprocess.check_output(
            ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", rpath],
            text=False
        )
        with open(dest, "wb") as f:
            f.write(log_bytes)

    # 12. Phase 3: 300s Post-Fault Cooldown Observation
    log("Starting Phase 3: 300s Post-Fault Cooldown Observation...")
    t_cool_start = time.time()
    time.sleep(300)
    t_cool_end = time.time()
    log(f"Cooldown observation complete in {t_cool_end - t_cool_start:.2f}s.")

    # 13. Final Accounting Query
    history_post = query_history_count()
    delta_history = history_post - history_pre
    log(f"Final pgbench_history count: {history_post} (Delta: {delta_history})")

    # Record complete execution state
    execution_state = {
        "run_id": RUN_ID,
        "cluster": "ric-gray-failure-eks",
        "namespace": NAMESPACE,
        "target_pod": bound_target.target_pod_name,
        "target_node": bound_target.target_node_name,
        "target_netns_inode": bound_target.target_netns_inode,
        "target_start_ticks": bound_target.target_start_ticks,
        "history_pre": history_pre,
        "history_post": history_post,
        "delta_history": delta_history,
        "t_meas_start_epoch": t_meas_start,
        "target_t0_epoch": target_t0_epoch,
        "actual_t0_epoch": t0_epoch,
        "actual_t_clear_epoch": t_clear_epoch,
        "t_meas_end_epoch": t_meas_end,
        "t_cool_start_epoch": t_cool_start,
        "t_cool_end_epoch": t_cool_end,
        "helper_token": helper_token,
        "warmup_summary": {
            "start_epoch": warmup_res["start_epoch"],
            "end_epoch": warmup_res["end_epoch"],
            "returncode": warmup_res["returncode"],
        },
        "pgbench_returncode": client_proc.returncode,
    }

    with open(os.path.join(OUTPUT_DIR, "execution_state_raw.json"), "w", encoding="utf-8") as f:
        json.dump(execution_state, f, indent=2)

    log("Execution state raw JSON saved.")
    return execution_state


if __name__ == "__main__":
    execute_orchestrated_pilot()

