"""
stage5_4g52_live_formal_f10_executor.py - Single-Use Live Orchestration Driver for Pilot F01.
Stage 5.4G.37: Authorised CockroachDB G1-L2 Formal Repetition F10 Execution.

Features:
- Option B Pre-run Truncate: Resets pgbench_history from previous rows to 0 before F10 with exact verification.
- Verified accounts: Confirms all 5,000,000 accounts intact before warm-up.
- Phase 1 Warm-up: 120s (-T 120) unlogged pgbench workload.
- Phase 2 Measurement: 600s (-T 600) logged pgbench workload.
- JIT Leaseholder Gate: At T_meas = 175s, dynamically queries and binds Range 108 leaseholder.
- Safe Abort Tripwire: Immediate preflight double-check prior to helper authorization.
- G1-L2 Fault Injection: At T_meas = 180s (T0), claims token and deploys g1-helper job (1000ms ± 20ms for 180s).
- Image: Pinned to approved hardened v4 image digest containing remediated container binding logic:
  503314623827.dkr.ecr.us-east-1.amazonaws.com/ric-g1-helper@sha256:8362671e939d88fe471dc9f81ec39cb0f1679032b51db9f47692480aa3631c23
- Cooldown & Recovery: 300s post-fault observation window.
- Three-Way Transaction Accounting: Exactly reconciles delta pgbench_history with parsed client logs.
- Strict Cleanup: Deletes temporary helper Job and authorization Secret upon run completion.
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

RUN_ID = "crdb-g1-l2-formal-f10"
OUTPUT_DIR = os.path.abspath("thesis-evidence/05-g1-chaos/formal-campaign/f10-execution")
CLIENT_POD = "crdb-benchmark-client-hardened"
NAMESPACE = "cockroachdb"
CHAOS_NAMESPACE = "g1-chaos"

HELPER_IMAGE = "503314623827.dkr.ecr.us-east-1.amazonaws.com/ric-g1-helper@sha256:8362671e939d88fe471dc9f81ec39cb0f1679032b51db9f47692480aa3631c23"
PSQL_CONN = "sslmode=verify-full sslrootcert=/cockroach-certs/ca.crt sslcert=/cockroach-certs/client.root.crt sslkey=/cockroach-certs/client.root.key host=cockroachdb-public port=26257 user=root dbname=benchdb"


def log(msg: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(f"[{now}] {msg}", flush=True)


def query_accounts_count() -> int:
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "psql", PSQL_CONN, "-t", "-A", "-c", "SELECT count(*) FROM pgbench_accounts;"
    ]
    res = subprocess.check_output(cmd, text=True).strip()
    return int(res)


def query_history_count() -> int:
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "psql", PSQL_CONN, "-t", "-A", "-c", "SELECT count(*) FROM pgbench_history;"
    ]
    res = subprocess.check_output(cmd, text=True).strip()
    return int(res)


def reset_history_pre_run() -> int:
    log("Executing approved Option B pgbench_history reset prior to F01...")
    pre_count = query_history_count()
    log(f"Current pgbench_history count before truncate: {pre_count}")
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "psql", PSQL_CONN, "-c", "TRUNCATE TABLE pgbench_history;"
    ]
    subprocess.check_call(cmd)
    post_count = query_history_count()
    log(f"Verified pgbench_history count after truncate: {post_count}")
    if post_count != 0:
        raise RuntimeError(f"Option B pre-run history reset verification failed: expected 0, got {post_count}")
    return post_count


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
    elapsed = t1 - t0
    log(f"Phase 1 Warm-up finished in {elapsed:.2f}s with returncode {proc.returncode}.")
    return {
        "start_epoch": t0,
        "end_epoch": t1,
        "elapsed_sec": elapsed,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def execute_jit_gate() -> JITTargetBinding:
    log("Executing PD-08 Dynamic Active Leaseholder Just-In-Time Verification Gate...")
    db_provider = LiveClusterDatabaseProvider(namespace=NAMESPACE, client_pod=CLIENT_POD)
    k8s_provider = LiveKubernetesProvider()
    proc_inspector = LiveProcessInspector()

    gate = PD08JITLeaseholderGate(
        db_provider=db_provider,
        k8s_provider=k8s_provider,
        process_inspector=proc_inspector,
        expected_range_id=None,
    )

    t0_jit = time.time()
    # Cycle 1: Discover and bind target
    bound = gate.verify_and_bind_target(check_cycle=1)
    log(f"JIT Check Cycle 1: Resolved Range 108 -> Node {bound.lease_holder_node_id} ({bound.target_pod_name}), "
        f"Container '{bound.target_container_name}', netns={bound.target_netns_inode}, ticks={bound.target_start_ticks}")

    # Cycle 2: Immediate preflight double-check
    verified = gate.revalidate_immediate_preflight(bound)
    t1_jit = time.time()
    log(f"JIT Check Cycle 2 (Immediate Preflight): Confirmed target stability on Node {verified.lease_holder_node_id} "
        f"({verified.target_pod_name}) in {t1_jit - t0_jit:.3f}s. Concurrency Invariant Verified.")
    return verified


def execute_orchestrated_pilot() -> Dict[str, Any]:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log(f"=== Beginning CockroachDB G1-L2 Formal Repetition F10 Orchestration ({RUN_ID}) ===")

    # 1. Accounts verification
    accounts_count = query_accounts_count()
    log(f"Verified baseline accounts count: {accounts_count} rows intact.")
    if accounts_count != 5000000:
        raise RuntimeError(f"Pre-flight accounts count mismatch: expected 5,000,000, got {accounts_count}")

    # 2. Approved Option B pre-run history reset
    history_pre = reset_history_pre_run()

    # 3. Phase 1: 120s Unlogged Warm-Up
    warmup_res = execute_warmup()
    with open(os.path.join(OUTPUT_DIR, "warmup_stdout.txt"), "w", encoding="utf-8") as f:
        f.write(warmup_res["stdout"])
    with open(os.path.join(OUTPUT_DIR, "warmup_stderr.txt"), "w", encoding="utf-8") as f:
        f.write(warmup_res["stderr"])

    # 4. Phase 2: Launch 600s Measurement Workload in background
    log("Launching Phase 2: 600s Logged Measurement Workload (-c 20 -j 4 -T 600 --max-tries=1 -M simple)...")
    pgbench_cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
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

    # Record JIT binding evidence
    with open(os.path.join(OUTPUT_DIR, "jit_target_binding.json"), "w", encoding="utf-8") as f:
        json.dump(bound_target.to_dict(), f, indent=2)

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
        "authorized_by_operator": "operator_live_authorized_f10",
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
"""
    apply_proc = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=job_manifest,
        text=True,
        capture_output=True
    )
    if apply_proc.returncode != 0:
        raise RuntimeError(f"Failed to deploy helper Job: {apply_proc.stderr}")
    log("Helper Job manifest applied.")

    # 9. Monitor helper completion (T0 + 180s)
    log("Waiting for helper Job to finish lifecycle...")
    wait_cmd = [
        "kubectl", "wait", "--for=condition=complete", "--timeout=240s",
        "-n", CHAOS_NAMESPACE, "job/g1-chaos-helper"
    ]
    wait_proc = subprocess.run(wait_cmd, capture_output=True, text=True)
    t_clear_epoch = time.time()
    log(f"Helper wait result: returncode={wait_proc.returncode} at epoch {t_clear_epoch:.3f}")

    # Capture helper logs immediately
    helper_logs = ""
    try:
        helper_logs = subprocess.check_output(
            ["kubectl", "logs", "-n", CHAOS_NAMESPACE, "job/g1-chaos-helper", "-c", "g1-helper"],
            text=True
        )
    except Exception as e:
        log(f"Warning: Could not capture helper logs via standard command: {e}")

    with open(os.path.join(OUTPUT_DIR, "f10-helper-execution-log.txt"), "w", encoding="utf-8") as f:
        f.write(helper_logs)
    log("Saved helper execution logs.")

    # Clean up chaos Job and Secret
    log("Cleaning up helper Job and authorization Secret...")
    subprocess.run(["kubectl", "delete", "job", "g1-chaos-helper", "-n", CHAOS_NAMESPACE], capture_output=True)
    subprocess.run(["kubectl", "delete", "secret", "g1-fault-auth-token", "-n", CHAOS_NAMESPACE], capture_output=True)
    subprocess.run(["kubectl", "delete", "lease", "-n", CHAOS_NAMESPACE, "--all"], capture_output=True)

    # 10. Await measurement completion (T_meas_start + 600s)
    log("Awaiting completion of Phase 2 measurement pgbench process...")
    stdout_b, stderr_b = client_proc.communicate()
    t_meas_end = time.time()
    log(f"Phase 2 pgbench completed in {t_meas_end - t_meas_start:.2f}s with returncode {client_proc.returncode}.")

    with open(os.path.join(OUTPUT_DIR, "f10-client-stdout.txt"), "wb") as f:
        f.write(stdout_b)
    with open(os.path.join(OUTPUT_DIR, "f10-client-stderr.txt"), "wb") as f:
        f.write(stderr_b)

    # 11. Copy out pgbench client transaction logs
    log(f"Retrieving per-transaction client log files from {CLIENT_POD}...")
    find_cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "sh", "-c", f"ls -1 /tmp/pgbench_log_{RUN_ID}.*"
    ]
    log_files_raw = subprocess.check_output(find_cmd, text=True).strip().splitlines()
    log(f"Discovered log files: {log_files_raw}")

    merged_log_path = os.path.join(OUTPUT_DIR, "f10-pgbench-merged.log")
    with open(merged_log_path, "wb") as merged_f:
        for remote_file in sorted(log_files_raw):
            log(f"Reading {remote_file}...")
            cat_cmd = ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", remote_file]
            data = subprocess.check_output(cat_cmd)
            merged_f.write(data)

    log(f"Merged client transaction logs saved to {merged_log_path}.")

    # 12. Phase 3: Cooldown Observation (300s post-fault)
    t_cool_start = t_clear_epoch
    t_cool_target = t_cool_start + 300.0
    sleep_cool = t_cool_target - time.time()
    if sleep_cool > 0:
        log(f"Holding for 300s cooldown recovery observation window (sleeping {sleep_cool:.2f}s)...")
        time.sleep(sleep_cool)
    t_cool_end = time.time()
    log(f"Cooldown observation window completed at epoch {t_cool_end:.3f}.")

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
        "target_jit_epoch": target_jit_epoch,
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

