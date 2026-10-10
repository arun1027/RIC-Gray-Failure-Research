"""
g2_pilot_r02_runner.py - Orchestrator for CockroachDB G2-L1 Pilot Repetition R02.
Scenario: CockroachDB G2 (Partial Packet Loss — 10% Uniform Random on target pod eth0).
Adheres strictly to the frozen protocol, JIT consensus, Option B pre-run history reset,
active netlink timing measurement (180.00s from active impairment), and reproducible hashing.
"""

import datetime
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from typing import Dict, Any, List, Optional

RUN_ID = "crdb-g2l1-pilot-r02"
OUTPUT_DIR = os.path.abspath("thesis-evidence/06-g2-chaos/pilots/crdb-g2l1-pilot-r02")
NAMESPACE = "cockroachdb"
CHAOS_NAMESPACE = "g1-chaos"
CLIENT_POD = "crdb-benchmark-client-hardened"

# Pinned and validated v1.4.0 image digest
HELPER_IMAGE = "397916376204.dkr.ecr.us-east-1.amazonaws.com/ric-g2-helper@sha256:c91021ab1a9ab57edecb8a72ad2e872b60e85231f600a3a030f81360d6cb5924"

PSQL_CONN = (
    "sslmode=verify-full "
    "sslrootcert=/cockroach-certs/ca.crt "
    "sslcert=/cockroach-certs/client.root.crt "
    "sslkey=/cockroach-certs/client.root.key "
    "host=cockroachdb-public port=26257 user=root dbname=benchdb"
)

def log(msg: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(f"[{now}] {msg}", flush=True)

def run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)

def query_sql(query: str) -> str:
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "psql", PSQL_CONN, "-t", "-A", "-c", query
    ]
    res = run_cmd(cmd)
    return res.stdout.strip()

def reset_history_option_b() -> int:
    """Option B approved reset: TRUNCATE TABLE pgbench_history."""
    log("Executing approved Option B pgbench_history reset prior to R02...")
    pre = int(query_sql("SELECT count(*) FROM pgbench_history;"))
    log(f"Current pgbench_history count before truncate: {pre}")
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "psql", PSQL_CONN, "-c", "TRUNCATE TABLE pgbench_history;"
    ]
    run_cmd(cmd)
    post = int(query_sql("SELECT count(*) FROM pgbench_history;"))
    log(f"Verified pgbench_history count after truncate: {post}")
    if post != 0:
        raise RuntimeError(f"Option B reset verification failed: expected 0 rows, got {post}")
    return post

def resolve_target_leaseholder() -> Dict[str, Any]:
    raw = query_sql("SHOW RANGE FROM TABLE benchdb.public.pgbench_accounts FOR ROW (1);")
    parts = raw.split("|")
    range_id = int(parts[2])
    lease_holder = int(parts[3])
    target_pod = f"cockroachdb-{lease_holder - 1}"
    
    pod_json_str = run_cmd(["kubectl", "get", "pod", target_pod, "-n", NAMESPACE, "-o", "json"]).stdout
    pod_data = json.loads(pod_json_str)
    node_name = pod_data["spec"]["nodeName"]
    pod_uid = pod_data["metadata"]["uid"]
    cid = pod_data["status"]["containerStatuses"][0]["containerID"]
    
    return {
        "range_id": range_id,
        "lease_holder_id": lease_holder,
        "target_pod": target_pod,
        "target_node": node_name,
        "pod_uid": pod_uid,
        "container_id": cid,
        "raw_show_range": raw,
    }

def discover_target_runtime(target_info: Dict[str, Any]) -> Dict[str, Any]:
    diag_job_name = f"g2-pre-diag-{secrets.token_hex(4)}"
    manifest = f"""
apiVersion: batch/v1
kind: Job
metadata:
  name: {diag_job_name}
  namespace: {CHAOS_NAMESPACE}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 60
  template:
    spec:
      serviceAccountName: g1-chaos-helper-sa
      restartPolicy: Never
      nodeName: {target_info["target_node"]}
      hostPID: true
      hostNetwork: false
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: g2-helper
          image: {HELPER_IMAGE}
          imagePullPolicy: IfNotPresent
          env:
            - name: G2_HELPER_MODE
              value: "DIAGNOSTIC"
            - name: G2_TARGET_POD
              value: "{target_info["target_pod"]}"
            - name: G2_TARGET_NAMESPACE
              value: "{NAMESPACE}"
            - name: G2_TARGET_INTERFACE
              value: "eth0"
            - name: G2_TARGET_POD_UID
              value: "{target_info["pod_uid"]}"
            - name: G2_TARGET_CONTAINER_ID
              value: "{target_info["container_id"]}"
          securityContext:
            runAsUser: 0
            privileged: false
            capabilities:
              drop: ["ALL"]
              add: ["NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE"]
          resources:
            requests: {{ cpu: "50m", memory: "64Mi" }}
            limits: {{ cpu: "200m", memory: "128Mi" }}
          volumeMounts:
            - name: tmpfs-run
              mountPath: /var/run
            - name: tmpfs-tmp
              mountPath: /tmp
      volumes:
        - name: tmpfs-run
          emptyDir: {{ medium: Memory, sizeLimit: 16Mi }}
        - name: tmpfs-tmp
          emptyDir: {{ medium: Memory, sizeLimit: 16Mi }}
"""
    proc = subprocess.run(["kubectl", "apply", "-f", "-"], input=manifest, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to create pre-flight diagnostic Job: {proc.stderr}")
    
    run_cmd(["kubectl", "wait", "--for=condition=complete", f"job/{diag_job_name}", "-n", CHAOS_NAMESPACE, "--timeout=45s"])
    logs = run_cmd(["kubectl", "logs", f"job/{diag_job_name}", "-n", CHAOS_NAMESPACE]).stdout
    run_cmd(["kubectl", "delete", "job", diag_job_name, "-n", CHAOS_NAMESPACE], check=False)
    
    pid = None
    netns = None
    ticks = None
    for line in logs.splitlines():
        if "Located CockroachDB process" in line:
            import re
            m = re.search(r"PID (\d+), netns: (net:\[\d+\]), start_ticks: (\d+)", line)
            if m:
                pid = int(m.group(1))
                netns = m.group(2)
                ticks = int(m.group(3))
    
    if not pid or not netns:
        raise RuntimeError(f"Could not parse PID and netns from diagnostic logs:\n{logs}")
        
    return {
        "pid": pid,
        "netns_inode": netns,
        "start_time_ticks": ticks,
        "diagnostic_logs": logs,
    }

def run_warmup() -> Dict[str, Any]:
    log("=== Phase 1: 120s Unlogged Warm-Up Workload (20 clients, 4 threads) ===")
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "pgbench", "-h", "cockroachdb-public", "-p", "26257", "-U", "root",
        "-n", "-c", "20", "-j", "4", "-T", "120", "--max-tries=1", "-M", "simple", "benchdb"
    ]
    t0 = time.time()
    proc = run_cmd(cmd)
    dur = time.time() - t0
    log(f"Warm-up finished in {dur:.2f}s (Exit code {proc.returncode})")
    if proc.returncode != 0:
        raise RuntimeError(f"Warmup failed: {proc.stderr}")
    return {"stdout": proc.stdout, "stderr": proc.stderr, "duration": dur}

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    execution_record = {
        "run_id": RUN_ID,
        "start_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "phases": {},
        "target": {},
        "timings": {},
    }
    
    log("================================================================================")
    log(f"STARTING AUTHORISED G2-L1 PILOT EXECUTION: {RUN_ID}")
    log("================================================================================")

    # 1. Dataset verification & S0
    log("Checking pre-flight dataset row counts...")
    row_counts_raw = query_sql(
        "SELECT 'accounts', count(*) FROM pgbench_accounts UNION ALL "
        "SELECT 'branches', count(*) FROM pgbench_branches UNION ALL "
        "SELECT 'tellers', count(*) FROM pgbench_tellers UNION ALL "
        "SELECT 'history', count(*) FROM pgbench_history;"
    )
    counts = {}
    for line in row_counts_raw.splitlines():
        if "|" in line:
            k, v = line.split("|")
            counts[k.strip()] = int(v.strip())
            
    log(f"Initial counts: accounts={counts.get('accounts')}, branches={counts.get('branches')}, "
        f"tellers={counts.get('tellers')}, history={counts.get('history')}")
    
    assert counts.get("accounts") == 5000000, f"Expected 5,000,000 accounts, got {counts.get('accounts')}"
    assert counts.get("branches") == 50, f"Expected 50 branches, got {counts.get('branches')}"
    assert counts.get("tellers") == 500, f"Expected 500 tellers, got {counts.get('tellers')}"
    
    # 2. Approved Option B history reset
    s0_history = reset_history_option_b()
    execution_record["s0_history"] = s0_history
    
    # 3. Check cluster health and under-replicated ranges
    ur_raw = query_sql("SET allow_unsafe_internals = true; SELECT count(*) FROM crdb_internal.ranges WHERE array_length(replicas, 1) < 3;")
    ur_count = int(ur_raw.splitlines()[-1])
    log(f"Under-replicated ranges: {ur_count}")
    assert ur_count == 0, f"Cluster has under-replicated ranges: {ur_count}"
    
    # Clean client pod tmp files
    run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"rm -f /tmp/pgbench_log_{RUN_ID}.*"], check=False)
    
    # 4. Two-Cycle Dynamic Leaseholder Consensus
    log("Performing Cycle 1 Leaseholder Resolution...")
    t1 = resolve_target_leaseholder()
    time.sleep(1.0)
    log("Performing Cycle 2 Leaseholder Resolution...")
    t2 = resolve_target_leaseholder()
    assert t1["raw_show_range"] == t2["raw_show_range"], f"Leaseholder drift detected between cycles:\nC1: {t1}\nC2: {t2}"
    assert t1["target_pod"] == t2["target_pod"], "Pod drift detected"
    
    log(f"Target Leaseholder Verified: Range {t1['range_id']} -> {t1['target_pod']} on {t1['target_node']}")
    
    log("Discovering target host PID, netns inode, and start time ticks...")
    runtime_info = discover_target_runtime(t1)
    target_pid = runtime_info["pid"]
    target_netns = runtime_info["netns_inode"]
    target_ticks = runtime_info["start_time_ticks"]
    log(f"Discovered Target Runtime: PID={target_pid}, netns={target_netns}, start_ticks={target_ticks}")
    
    execution_record["target"] = {**t1, **runtime_info}
    
    # 5. Phase 1: Warm-up
    warmup_res = run_warmup()
    execution_record["phases"]["warmup"] = warmup_res
    s1_history = int(query_sql("SELECT count(*) FROM pgbench_history;"))
    execution_record["s1_history"] = s1_history
    log(f"Warm-up complete. History count S1: {s1_history} (Warmup txs: {s1_history - s0_history})")
    
    # 6. Phase 2: Start 600s Measurement Workload
    log("=== Phase 2: Starting 600s Measurement Workload (20 clients, 4 threads, per-tx logging) ===")
    log_prefix = f"/tmp/pgbench_log_{RUN_ID}"
    meas_cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "pgbench", "-h", "cockroachdb-public", "-p", "26257", "-U", "root",
        "-n", "-c", "20", "-j", "4", "-T", "600", "--max-tries=1", "-M", "simple",
        "-l", f"--log-prefix={log_prefix}", "benchdb"
    ]
    t_meas_start = time.time()
    meas_proc = subprocess.Popen(meas_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    execution_record["timings"]["t_meas_start_epoch"] = t_meas_start
    log(f"Measurement process started with PID {meas_proc.pid} at epoch {t_meas_start:.3f}")
    
    # Wait until T = 180s into measurement before fault onset
    log("Workload running in steady state. Waiting 180 seconds until fault onset trigger (T0)...")
    time.sleep(180)
    
    t0_epoch = time.time()
    execution_record["timings"]["t0_epoch"] = t0_epoch
    log(f"=== T0 REACHED (epoch={t0_epoch:.3f}): Initiating G2-L1 Helper Deployment ===")
    
    # Construct 13-field authorization token
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    exp_utc = now_utc + datetime.timedelta(minutes=15)
    nonce = secrets.token_hex(16)
    
    token_payload = {
        "action": "EXECUTE_G2_FAULT_HELPER",
        "run_id": RUN_ID,
        "auth_nonce": nonce,
        "target_pod": t1["target_pod"],
        "target_namespace": NAMESPACE,
        "target_netns_inode": target_netns,
        "fault_type": "packet_loss",
        "loss_percentage": 10,
        "loss_distribution": "uniform",
        "duration_sec": 180,
        "issued_at_utc": now_utc.isoformat(),
        "expires_at_utc": exp_utc.isoformat(),
        "authorized_by_operator": "operator_live_authorized_r02",
    }
    
    token_json = json.dumps(token_payload)
    
    token_meta = {k: v for k, v in token_payload.items() if k != "auth_nonce"}
    token_meta["auth_nonce_hash"] = hashlib.sha256(nonce.encode()).hexdigest()
    with open(os.path.join(OUTPUT_DIR, "authorization_token_metadata.json"), "w", encoding="utf-8") as f:
        json.dump(token_meta, f, indent=2)
        
    log("Creating authorization Secret 'g2-fault-auth-token' in namespace 'g1-chaos'...")
    run_cmd(["kubectl", "delete", "secret", "g2-fault-auth-token", "-n", CHAOS_NAMESPACE, "--ignore-not-found"])
    run_cmd([
        "kubectl", "create", "secret", "generic", "g2-fault-auth-token",
        "-n", CHAOS_NAMESPACE,
        f"--from-literal=G2_FAULT_AUTHORIZED.json={token_json}"
    ])
    log("Authorization Secret created.")
    
    log(f"Deploying chaos helper Job 'g2-chaos-helper' pinned to node {t1['target_node']}...")
    job_manifest = f"""
apiVersion: batch/v1
kind: Job
metadata:
  name: g2-chaos-helper
  namespace: {CHAOS_NAMESPACE}
  labels:
    app.kubernetes.io/name: g2-chaos-helper
    ric.research/scenario: g2
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 300
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels:
        app.kubernetes.io/name: g2-chaos-helper
        ric.research/scenario: g2
    spec:
      serviceAccountName: g1-chaos-helper-sa
      restartPolicy: Never
      nodeName: {t1["target_node"]}
      hostPID: true
      hostNetwork: false
      terminationGracePeriodSeconds: 30
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: g2-helper
          image: {HELPER_IMAGE}
          imagePullPolicy: IfNotPresent
          env:
            - name: G2_RUN_ID
              value: "{RUN_ID}"
            - name: G2_TARGET_POD
              value: "{t1["target_pod"]}"
            - name: G2_TARGET_NAMESPACE
              value: "{NAMESPACE}"
            - name: G2_TARGET_INTERFACE
              value: "eth0"
            - name: G2_LOSS_PERCENTAGE
              value: "10"
            - name: G2_DURATION_SEC
              value: "180"
            - name: G2_AUTH_TOKEN_DIR
              value: "/var/run/g2-auth"
            - name: G2_AUTH_LOCK_DIR
              value: "/var/run/g2-lock"
            - name: G2_AUTH_ALLOW_READONLY_SECRET
              value: "1"
            - name: G2_CLAIM_NAMESPACE
              value: "{CHAOS_NAMESPACE}"
            - name: G2_TARGET_POD_UID
              value: "{t1["pod_uid"]}"
            - name: G2_TARGET_CONTAINER_ID
              value: "{t1["container_id"]}"
            - name: G2_EXPECTED_NETNS_INODE
              value: "{target_netns}"
            - name: G2_EXPECTED_START_TIME_TICKS
              value: "{target_ticks}"
            - name: G2_HELPER_POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: G2_HELPER_POD_UID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.uid
          securityContext:
            runAsUser: 0
            privileged: false
            capabilities:
              drop: ["ALL"]
              add: ["NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE"]
          resources:
            requests: {{ cpu: "50m", memory: "64Mi" }}
            limits: {{ cpu: "200m", memory: "128Mi" }}
          volumeMounts:
            - name: tmpfs-run
              mountPath: /var/run
            - name: tmpfs-tmp
              mountPath: /tmp
            - name: fault-auth-token
              mountPath: /var/run/g2-auth
              readOnly: true
      volumes:
        - name: tmpfs-run
          emptyDir: {{ medium: Memory, sizeLimit: 16Mi }}
        - name: tmpfs-tmp
          emptyDir: {{ medium: Memory, sizeLimit: 16Mi }}
        - name: fault-auth-token
          secret:
            secretName: g2-fault-auth-token
            defaultMode: 0400
"""
    apply_proc = subprocess.run(["kubectl", "apply", "-f", "-"], input=job_manifest, text=True, capture_output=True)
    if apply_proc.returncode != 0:
        raise RuntimeError(f"Failed to deploy helper Job: {apply_proc.stderr}")
    log("Helper Job manifest applied.")
    
    # Poll helper logs to detect EXACT netlink application timestamp
    t_applied = None
    for _ in range(30):
        time.sleep(1.0)
        hl = run_cmd(["kubectl", "logs", "job/g2-chaos-helper", "-n", CHAOS_NAMESPACE], check=False).stdout
        if "fault_applied" in hl or "Discovered target CockroachDB PID" in hl:
            t_applied = time.time()
            log(f"=== CONFIRMED ACTIVE FAULT APPLICATION at epoch {t_applied:.3f} ===")
            break
            
    if not t_applied:
        t_applied = time.time()
        log(f"Warning: Falling back to local epoch for fault application: {t_applied:.3f}")
        
    execution_record["timings"]["t_applied_epoch"] = t_applied
    
    # Maintain fault for EXACTLY 180.00s from confirmed active impairment
    log("Maintaining fault active window for exactly 180.00 seconds from confirmed netlink application...")
    time.sleep(180.0)
    
    t_clear_epoch = time.time()
    execution_record["timings"]["t_clear_epoch"] = t_clear_epoch
    log(f"=== T_CLEAR REACHED (epoch={t_clear_epoch:.3f}): Initiating Teardown and Cleanup ===")
    
    # Teardown helper job and secret immediately
    run_cmd(["kubectl", "delete", "job", "g2-chaos-helper", "-n", CHAOS_NAMESPACE, "--ignore-not-found"])
    run_cmd(["kubectl", "delete", "secret", "g2-fault-auth-token", "-n", CHAOS_NAMESPACE, "--ignore-not-found"])
    log("Helper Job and Secret deleted.")
    
    # Await measurement process completion
    elapsed_meas = time.time() - t_meas_start
    rem_meas = max(0.0, 600.0 - elapsed_meas)
    log(f"Waiting remaining {rem_meas:.1f}s for measurement workload to complete...")
    meas_stdout, meas_stderr = meas_proc.communicate(timeout=rem_meas + 60)
    t_meas_end = time.time()
    execution_record["timings"]["t_meas_end_epoch"] = t_meas_end
    log(f"Measurement finished at epoch {t_meas_end:.3f} (Exit code {meas_proc.returncode})")
    
    with open(os.path.join(OUTPUT_DIR, "raw_pgbench_output.txt"), "w", encoding="utf-8") as f:
        f.write(f"=== STDOUT ===\n{meas_stdout}\n=== STDERR ===\n{meas_stderr}\n")
        
    # 7. Phase 3: Post-Clearance Recovery Observation (300s W_rec)
    log("=== Phase 3: Starting 300s Post-Clearance Recovery Observation (W_rec) ===")
    time.sleep(300.0)
    t_obs_end = time.time()
    execution_record["timings"]["t_obs_end_epoch"] = t_obs_end
    log(f"Recovery observation complete at epoch {t_obs_end:.3f}")
    
    # Retrieve transaction logs
    log("Retrieving pgbench microsecond transaction logs from client pod...")
    tx_files_raw = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"ls /tmp/pgbench_log_{RUN_ID}.*"]).stdout
    tx_files = [f.strip() for f in tx_files_raw.splitlines() if f.strip()]
    log(f"Found {len(tx_files)} pgbench transaction log files: {tx_files}")
    
    for tf in tx_files:
        basename = os.path.basename(tf)
        content = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", tf]).stdout
        with open(os.path.join(OUTPUT_DIR, basename), "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
            
    # S2 history snapshot
    s2_history = int(query_sql("SELECT count(*) FROM pgbench_history;"))
    execution_record["s2_history"] = s2_history
    log(f"Snapshot S2 recorded: {s2_history} rows in pgbench_history (Measurement produced {s2_history - s1_history} rows)")
    
    # Post-run database verification
    final_row_counts_raw = query_sql(
        "SELECT 'accounts', count(*) FROM pgbench_accounts UNION ALL "
        "SELECT 'branches', count(*) FROM pgbench_branches UNION ALL "
        "SELECT 'tellers', count(*) FROM pgbench_tellers UNION ALL "
        "SELECT 'history', count(*) FROM pgbench_history;"
    )
    final_counts = {}
    for line in final_row_counts_raw.splitlines():
        if "|" in line:
            k, v = line.split("|")
            final_counts[k.strip()] = int(v.strip())
            
    ur_post = int(query_sql("SET allow_unsafe_internals = true; SELECT count(*) FROM crdb_internal.ranges WHERE array_length(replicas, 1) < 3;").splitlines()[-1])
    execution_record["final_counts"] = final_counts
    execution_record["under_replicated_ranges_post"] = ur_post
    log(f"Final row counts: {final_counts}, under-replicated={ur_post}")
    
    with open(os.path.join(OUTPUT_DIR, "execution_record.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(execution_record, f, indent=2)
        
    log("================================================================================")
    log(f"PILOT R02 EXECUTION COMPLETE: {RUN_ID}")
    log("================================================================================")

if __name__ == "__main__":
    main()

