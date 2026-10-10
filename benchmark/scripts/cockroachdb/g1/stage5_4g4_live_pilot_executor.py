"""
stage5_4g4_live_pilot_executor.py - Single-Use Live Orchestration Driver for Pilot R01.
Stage 5.4G.4: CockroachDB G1-L2 Pilot Repetition R01 Execution.
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

RUN_ID = "crdb-g1-l2-pilot-r01"
OUTPUT_DIR = os.path.abspath("thesis-evidence/05-g1-chaos/stage5-4g-4-r01-execution")
TARGET_POD = "cockroachdb-0"
TARGET_NODE = "ip-10-0-1-75.ec2.internal"
TARGET_NETNS_INODE = "net:[4026532747]"
TARGET_START_TICKS = 6876
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
    duration = time.time() - t0
    log(f"Warm-up finished in {duration:.2f}s with exit code {proc.returncode}")
    if proc.returncode != 0:
        raise RuntimeError(f"Warm-up failed: {proc.stderr}")
    return {"exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "duration": duration}

def main():
    log("=== Stage 5.4G.4: Initiating Authorised Live Pilot R01 Execution ===")
    
    # 1. Snapshot S0
    s0 = query_history_count()
    log(f"Snapshot S0 recorded: {s0} rows in pgbench_history")
    
    # 2. Warm-up (120s)
    warmup_res = execute_warmup()
    
    # 3. Snapshot S1
    s1 = query_history_count()
    log(f"Snapshot S1 recorded: {s1} rows in pgbench_history (Warm-up produced {s1 - s0} rows)")
    
    # 4. Phase 2: Start 600s Measurement in Background
    log("Starting Phase 2: 600s Measurement Workload (20 clients, 4 threads, per-tx logging)...")
    log_prefix = f"/logs/pgbench_log_{RUN_ID}"
    measurement_cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "pgbench", "-h", "cockroachdb-public", "-p", "26257", "-U", "root",
        "-n", "-c", "20", "-j", "4", "-T", "600", "--max-tries=1", "-M", "simple",
        "-l", f"--log-prefix={log_prefix}", "benchdb"
    ]
    
    measurement_start_epoch = time.time()
    measurement_proc = subprocess.Popen(measurement_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    log(f"Measurement process started with PID {measurement_proc.pid} at epoch {measurement_start_epoch:.3f}")
    
    # Sleep until T = 180s into measurement
    log("Workload running in steady state. Waiting 180 seconds before fault injection...")
    time.sleep(180)
    
    t0_epoch = time.time()
    log(f"=== T0 REACHED (epoch={t0_epoch:.3f}): Injecting G1-L2 Fault (1000ms ± 20ms) ===")
    
    # Construct 13-field helper token
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    exp_utc = now_utc + datetime.timedelta(minutes=15)
    nonce = secrets.token_hex(16)
    
    helper_token = {
        "run_id": RUN_ID,
        "auth_nonce": nonce,
        "action": "EXECUTE_G1_FAULT_HELPER",
        "target_pod": TARGET_POD,
        "target_namespace": NAMESPACE,
        "target_netns_inode": TARGET_NETNS_INODE,
        "fault_type": "egress_latency",
        "delay_ms": 1000,
        "jitter_ms": 20,
        "duration_sec": 180,
        "issued_at_utc": now_utc.isoformat(),
        "expires_at_utc": exp_utc.isoformat(),
        "authorized_by_operator": "operator_live_authorized_r01",
    }
    
    token_json = json.dumps(helper_token)
    
    # Inject Secret
    log("Creating authorization Secret 'g1-fault-auth-token' in namespace 'g1-chaos'...")
    sec_cmd = [
        "kubectl", "create", "secret", "generic", "g1-fault-auth-token",
        "-n", CHAOS_NAMESPACE,
        f"--from-literal=G1_FAULT_AUTHORIZED.json={token_json}"
    ]
    subprocess.check_call(sec_cmd)
    log("Secret created successfully.")
    
    # Construct & Deploy Helper Job pinned to node
    log(f"Deploying chaos helper Job 'g1-chaos-helper' pinned to node {TARGET_NODE}...")
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
      nodeName: {TARGET_NODE}
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
              value: "{TARGET_POD}"
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
    
    # Wait for fault active duration (180s)
    log("Fault injected. Holding active fault window for 180 seconds...")
    time.sleep(180)
    
    t_clear_epoch = time.time()
    log(f"=== T_CLEAR REACHED (epoch={t_clear_epoch:.3f}): Tearing down fault injection ===")
    
    # Delete Secret and Job
    log("Deleting Secret and helper Job to ensure immediate cleanup...")
    subprocess.run(["kubectl", "delete", "secret", "g1-fault-auth-token", "-n", CHAOS_NAMESPACE, "--ignore-not-found"], check=False)
    subprocess.run(["kubectl", "delete", "job", "g1-chaos-helper", "-n", CHAOS_NAMESPACE, "--ignore-not-found"], check=False)
    
    # Wait for measurement workload to complete (total 600s, remaining: 600 - (180 + 180) = 240s)
    elapsed_so_far = time.time() - measurement_start_epoch
    remaining_measurement = max(0.0, 600.0 - elapsed_so_far)
    log(f"Post-fault observation: waiting remaining {remaining_measurement:.1f}s for measurement to finish...")
    stdout, stderr = measurement_proc.communicate(timeout=remaining_measurement + 60)
    log(f"Measurement process finished with exit code {measurement_proc.returncode}")
    
    # 5. Phase 3: Cooldown Observation (300s)
    log("Starting Phase 3: 300s Post-Measurement Cooldown Observation...")
    time.sleep(300)
    log("Cooldown observation complete.")
    
    # 6. Snapshot S3
    s3 = query_history_count()
    log(f"Snapshot S3 recorded: {s3} rows in pgbench_history")
    
    # Write execution summary state
    summary = {
        "run_id": RUN_ID,
        "s0": s0,
        "s1": s1,
        "s3": s3,
        "delta_history": s3 - s1,
        "measurement_stdout": stdout,
        "measurement_stderr": stderr,
        "measurement_exit_code": measurement_proc.returncode,
        "t0_epoch": t0_epoch,
        "t_clear_epoch": t_clear_epoch,
        "measurement_start_epoch": measurement_start_epoch,
        "helper_token": helper_token,
    }
    with open(os.path.join(OUTPUT_DIR, "execution_state_raw.json"), "w") as f:
        json.dump(summary, f, indent=2)
    log("Raw execution state saved. Ready for post-run analysis.")

if __name__ == "__main__":
    main()

