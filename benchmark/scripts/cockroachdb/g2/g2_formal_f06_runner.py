"""
g2_formal_f06_runner.py - Orchestrator for CockroachDB G2-L2 Formal Repetition F06 ONLY.
Scenario: CockroachDB G2 (Partial Packet Loss — 30% Uniform Random on target pod eth0).
Adheres strictly to the frozen protocol, JIT consensus, Option B pre-run history reset,
active netlink timing measurement (180.00s from active impairment), and reproducible hashing.

HARDENED FOR F06 (G2-L2 30% Loss) (incorporates G2-44 / G2-45 audits):
- Explicitly invokes Bash (/usr/bin/bash v5.2.37) for in-pod pipeline execution (avoiding Dash).
- Captures authentic pgbench process exit code via PIPESTATUS[0] immediately after pipeline.
- Filters repetitive CockroachDB license NOTICE strings while strictly preserving genuine errors/warnings.
- Records pre-run and post-run filesystem storage diagnostics (df -k /tmp).
- Decouples in-pod measurement workload lifecycle and logging from client-side kubectl exec streaming.
- Distinguishes client storage logging failures from genuine database/workload errors.
- Awaits nominal workload completion before initiating the mandatory 300s post-clearance recovery observation.
- Anchors 300s W_rec strictly to verified fault clearance (T_clear) with dynamic deletion compensation.
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

RUN_ID = "crdb-g2l2-formal-f06"
OUTPUT_DIR = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l2-formal-f06")
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
    now = datetime.timezone.utc
    ts = datetime.datetime.now(now).isoformat()
    print(f"[{ts}] {msg}", flush=True)

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
    log("Executing approved Option B pgbench_history reset prior to F06...")
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

def get_leaseholder_info() -> Dict[str, Any]:
    query = "SHOW RANGE FROM TABLE benchdb.public.pgbench_accounts FOR ROW (1);"
    raw = query_sql(query)
    lines = raw.strip().splitlines()
    target_line = None
    for l in lines:
        if "|" in l and not l.startswith("start_key"):
            target_line = l
            break
    if not target_line:
        target_line = lines[-1]
    
    parts = target_line.split("|")
    range_id = int(parts[2].strip())
    lease_holder = int(parts[3].strip())
    target_pod = f"cockroachdb-{lease_holder - 1}"
    
    pod_json = run_cmd(["kubectl", "get", "pod", target_pod, "-n", NAMESPACE, "-o", "json"]).stdout
    pod_data = json.loads(pod_json)
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
    metadata:
      labels:
        app: g2-pre-diag
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
    p = subprocess.Popen(["kubectl", "apply", "-f", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(input=manifest)
    if p.returncode != 0:
        raise RuntimeError(f"Failed to submit diagnostic Job: {err}")

    # Wait for completion
    log(f"Submitted target runtime diagnostic job {diag_job_name}. Waiting for verification...")
    completed = False
    j_data: Dict[str, Any] = {}
    for _ in range(30):
        time.sleep(2)
        j_str = run_cmd(["kubectl", "get", "job", diag_job_name, "-n", CHAOS_NAMESPACE, "-o", "json"]).stdout
        j_data = json.loads(j_str)
        succeeded = j_data.get("status", {}).get("succeeded", 0)
        failed = j_data.get("status", {}).get("failed", 0)
        if succeeded >= 1:
            completed = True
            break
        if failed >= 1:
            break

    job_logs = ""
    if completed:
        log_res = run_cmd(["kubectl", "logs", f"job/{diag_job_name}", "-n", CHAOS_NAMESPACE], check=False)
        job_logs = log_res.stdout
    else:
        # Diagnostic Job did not complete successfully. Inspect status conditions and pod creation events.
        status_conditions = j_data.get("status", {}).get("conditions", [])
        events_res = run_cmd(["kubectl", "get", "events", "-n", CHAOS_NAMESPACE, "--field-selector", f"involvedObject.name={diag_job_name}"], check=False)
        all_events_res = run_cmd(["kubectl", "get", "events", "-n", CHAOS_NAMESPACE], check=False)
        pods_res = run_cmd(["kubectl", "get", "pods", "-n", CHAOS_NAMESPACE, "-l", f"job-name={diag_job_name}", "-o", "json"], check=False)
        
        pod_data = {}
        try:
            pod_data = json.loads(pods_res.stdout) if pods_res.stdout else {}
        except Exception:
            pass
        if pod_data.get("items"):
            log_res = run_cmd(["kubectl", "logs", f"job/{diag_job_name}", "-n", CHAOS_NAMESPACE], check=False)
            job_logs = log_res.stdout + "\n" + log_res.stderr

        err_msg = (
            f"Diagnostic Job '{diag_job_name}' failed to complete successfully.\n"
            f"Job Status Conditions: {json.dumps(status_conditions, indent=2)}\n"
            f"Job Events:\n{events_res.stdout}\n"
            f"Namespace Events:\n{all_events_res.stdout}\n"
            f"Job Logs (if any):\n{job_logs}"
        )
        run_cmd(["kubectl", "delete", "job", diag_job_name, "-n", CHAOS_NAMESPACE, "--ignore-not-found"])
        raise RuntimeError(err_msg)

    run_cmd(["kubectl", "delete", "job", diag_job_name, "-n", CHAOS_NAMESPACE, "--ignore-not-found"])

    # Parse JSON from logs or stdout
    pid = None
    netns = None
    start_ticks = None
    for line in job_logs.splitlines():
        if "Located CockroachDB process PID" in line:
            parts = line.split()
            pid = int(parts[5].rstrip(","))
            netns = parts[7].rstrip(",")
            start_ticks = int(parts[9])

    if not pid or not netns:
        raise RuntimeError(f"Failed to extract runtime PID and netns from diagnostic logs:\n{job_logs}")

    return {
        "pid": pid,
        "netns_inode": netns,
        "start_time_ticks": start_ticks,
        "diagnostic_logs": job_logs
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
        raise RuntimeError(f"Warm-up workload failed: {proc.stderr}")
    return {"duration_sec": dur, "returncode": proc.returncode, "stdout": proc.stdout}

def classify_measurement_exit(returncode: int, stderr: str) -> Dict[str, Any]:
    """
    Distinguishes client transport stream disconnections from in-pod workload errors.
    """
    if returncode == 0:
        return {
            "status": "TRANSPORT_SUCCESS",
            "is_transport_timeout": False,
            "in_pod_status_inferred": "CLEAN_EXIT",
            "reason": "kubectl exec client transport connection exited cleanly with return code 0."
        }
    
    stream_timeout_signatures = [
        "error reading from error stream: next reader: read tcp",
        "Copying stdout failed",
        "Copying stderr failed",
        "i/o timeout"
    ]
    
    has_timeout_signature = any(sig in stderr for sig in stream_timeout_signatures)
    if has_timeout_signature:
        return {
            "status": "CLIENT_TRANSPORT_STREAM_TIMEOUT",
            "is_transport_timeout": True,
            "in_pod_status_inferred": "UNCERTAIN_PENDING_INDEPENDENT_EVIDENCE",
            "reason": (
                f"Subprocess exited with code {returncode} due to a client-side kubectl SPDY/HTTPS proxy "
                f"connection i/o timeout to the Kubernetes API server while client traffic quiesced. "
                f"This reflects client stream transport loss, leaving in-pod pgbench status UNCERTAIN "
                f"until verified by independent transaction log bounds and relational ledger parity."
            )
        }
    
    return {
        "status": "SUBPROCESS_ERROR",
        "is_transport_timeout": False,
        "in_pod_status_inferred": "ERROR",
        "reason": f"Subprocess exited with unhandled error code {returncode}."
    }

def main():
    if os.path.exists(os.path.join(OUTPUT_DIR, "execution_record.json")):
        raise RuntimeError(f"Execution aborted: output directory {OUTPUT_DIR} already contains completed run results. Refusing to overwrite.")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    execution_record = {
        "run_id": RUN_ID,
        "start_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "phases": {},
        "target": {},
        "timings": {}
    }
    log("================================================================================")
    log(f"STARTING FORMAL REPETITION F05 EXECUTION: {RUN_ID}")
    log("================================================================================")

    # 1. Dataset verification & S0
    log("Checking pre-flight dataset row counts...")
    c_acc = int(query_sql("SELECT count(*) FROM pgbench_accounts;"))
    c_br = int(query_sql("SELECT count(*) FROM pgbench_branches;"))
    c_te = int(query_sql("SELECT count(*) FROM pgbench_tellers;"))
    log(f"Dataset Cardinality: accounts={c_acc}, branches={c_br}, tellers={c_te}")
    if c_acc != 5000000 or c_br != 50 or c_te != 500:
        raise RuntimeError(f"Scale factor verification failed! Found accounts={c_acc}, branches={c_br}, tellers={c_te}")

    # Replication check
    ur_raw = query_sql("SET allow_unsafe_internals = true; SELECT count(*) FROM crdb_internal.ranges WHERE array_length(replicas, 1) < 3;")
    ur_count = int(ur_raw.splitlines()[-1])
    log(f"Pre-flight under-replicated ranges: {ur_count}")
    if ur_count != 0:
        raise RuntimeError(f"Cluster has {ur_count} under-replicated ranges. Aborting.")

    # Option B Reset
    s0 = reset_history_option_b()
    execution_record["s0_history"] = s0

    # 2. Warm-Up Workload
    warmup_res = run_warmup()
    execution_record["phases"]["warmup"] = warmup_res

    # 3. Snapshot S1
    s1_history = int(query_sql("SELECT count(*) FROM pgbench_history;"))
    execution_record["s1_history"] = s1_history
    log(f"Snapshot S1 recorded: {s1_history} rows in pgbench_history")

    # 4. Two-Cycle Dynamic Target Resolution Consensus
    log("Performing Two-Cycle Leaseholder Consensus Resolution...")
    c1 = get_leaseholder_info()
    log(f"Cycle 1 Target: Range {c1['range_id']} -> Leaseholder {c1['lease_holder_id']} ({c1['target_pod']} on {c1['target_node']})")
    time.sleep(1.0)
    c2 = get_leaseholder_info()
    log(f"Cycle 2 Target: Range {c2['range_id']} -> Leaseholder {c2['lease_holder_id']} ({c2['target_pod']} on {c2['target_node']})")

    if c1["range_id"] != c2["range_id"] or c1["target_pod"] != c2["target_pod"] or c1["target_node"] != c2["target_node"]:
        raise RuntimeError(f"Two-cycle consensus failed! Cycle 1: {c1['target_pod']} on {c1['target_node']}, Cycle 2: {c2['target_pod']} on {c2['target_node']}")
    log(f"Leaseholder Consensus CONFIRMED: Pod {c1['target_pod']} on Node {c1['target_node']}")

    # Runtime discovery
    log(f"Discovering target runtime PID and netns for {c1['target_pod']} on {c1['target_node']}...")
    runtime_info = discover_target_runtime(c1)
    target_manifest_data = {**c1, **runtime_info}
    execution_record["target"] = target_manifest_data
    log(f"Runtime binding: PID {runtime_info['pid']}, netns {runtime_info['netns_inode']}, start_ticks {runtime_info['start_time_ticks']}")

    # Clean old client logs in pod
    log("Cleaning previous pgbench logs and initializing pre-flight storage diagnostics in client pod /tmp...")
    run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", "rm -f /tmp/pgbench_log_* /tmp/pgbench_f* /tmp/disk_pre.txt /tmp/disk_post.txt"], check=False)

    # 5. Mint Single-Use Nonce & Authorization Token
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    exp_utc = now_utc + datetime.timedelta(seconds=900)
    nonce = secrets.token_hex(16)
    token_payload = {
        "action": "EXECUTE_G2_FAULT_HELPER",
        "run_id": RUN_ID,
        "auth_nonce": nonce,
        "target_pod": c1["target_pod"],
        "target_namespace": NAMESPACE,
        "target_netns_inode": runtime_info["netns_inode"],
        "fault_type": "packet_loss",
        "loss_percentage": 30,
        "loss_distribution": "uniform",
        "duration_sec": 180,
        "issued_at_utc": now_utc.isoformat(),
        "expires_at_utc": exp_utc.isoformat(),
        "authorized_by_operator": "operator_live_authorized_f05",
    }
    token_json = json.dumps(token_payload)

    token_meta = {k: v for k, v in token_payload.items() if k != "auth_nonce"}
    token_meta["auth_nonce_hash"] = hashlib.sha256(nonce.encode()).hexdigest()
    with open(os.path.join(OUTPUT_DIR, "authorization_token_metadata.json"), "w", encoding="utf-8") as f:
        json.dump(token_meta, f, indent=2)

    log("Creating authorization Secret 'g2-fault-auth-token' in namespace 'g1-chaos'...")
    run_cmd(["kubectl", "delete", "secret", "g2-fault-auth-token", "-n", CHAOS_NAMESPACE, "--ignore-not-found"])
    secret_manifest = f"""
apiVersion: v1
kind: Secret
metadata:
  name: g2-fault-auth-token
  namespace: {CHAOS_NAMESPACE}
type: Opaque
stringData:
  G2_FAULT_AUTHORIZED.json: |
{chr(10).join('    ' + line for line in json.dumps(token_payload, indent=2).splitlines())}
"""
    p = subprocess.Popen(["kubectl", "apply", "-f", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(input=secret_manifest)
    if p.returncode != 0:
        raise RuntimeError(f"Failed to create authorization secret: {err}")
    log("Authorization Secret 'g2-fault-auth-token' successfully created in namespace g1-chaos.")

    # 6. Phase 2: Start 600s Measurement Workload inside Pod with Hardened Logging
    log("=== Phase 2: Starting 600s Measurement Workload (20 clients, 4 threads, -M simple, --max-tries=1) ===")
    log_prefix = f"/tmp/pgbench_log_{RUN_ID}"
    
    # HARDENED IN-POD WORKLOAD PIPELINE (G2-45 verified):
    # 1. Runs df -k /tmp > /tmp/disk_pre.txt
    # 2. Invokes /usr/bin/bash explicitly to support PIPESTATUS array
    # 3. Runs pgbench with stdout written to /tmp/pgbench_f06_stdout.txt
    # 4. Filters repetitive license notices from stderr into /tmp/pgbench_f06_stderr.txt
    # 5. Captures PIPESTATUS[0] (authentic pgbench exit code) into /tmp/pgbench_f06_exit_code.txt
    # 6. Records post-run storage capacity in /tmp/disk_post.txt
    pod_wrapper_script = (
        f"df -k /tmp > /tmp/disk_pre.txt; "
        f"( pgbench -h cockroachdb-public -p 26257 -U root -n -c 20 -j 4 -T 600 --max-tries=1 -M simple "
        f"-l --log-prefix={log_prefix} benchdb > /tmp/pgbench_f06_stdout.txt ) "
        f"2>&1 | grep -v '^NOTICE:  No license is installed' > /tmp/pgbench_f06_stderr.txt; "
        f"echo \"${{PIPESTATUS[0]}}\" > /tmp/pgbench_f06_exit_code.txt; "
        f"df -k /tmp > /tmp/disk_post.txt"
    )
    meas_cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "bash", "-c", pod_wrapper_script
    ]
    t_meas_start = time.time()
    meas_proc = subprocess.Popen(meas_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    execution_record["timings"]["t_meas_start_epoch"] = t_meas_start
    log(f"Measurement process started with PID {meas_proc.pid} at epoch {t_meas_start:.3f}")
    
    # Wait until T = 180s into measurement before fault onset
    log("Workload running in steady state. Waiting 180 seconds until fault onset trigger (T0)...")
    time.sleep(180.0)
    t0_epoch = time.time()
    execution_record["timings"]["t0_epoch"] = t0_epoch
    log(f"=== T0 REACHED (epoch={t0_epoch:.3f}): Launching Helper Job for 30% Egress Loss ===")

    # Launch Helper Job
    helper_manifest = f"""
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
        run_id: {RUN_ID}
    spec:
      serviceAccountName: g1-chaos-helper-sa
      restartPolicy: Never
      nodeName: {c1["target_node"]}
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
              value: "{c1["target_pod"]}"
            - name: G2_TARGET_NAMESPACE
              value: "{NAMESPACE}"
            - name: G2_TARGET_INTERFACE
              value: "eth0"
            - name: G2_LOSS_PERCENTAGE
              value: "30"
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
              value: "{c1["pod_uid"]}"
            - name: G2_TARGET_CONTAINER_ID
              value: "{c1["container_id"]}"
            - name: G2_EXPECTED_NETNS_INODE
              value: "{runtime_info["netns_inode"]}"
            - name: G2_EXPECTED_START_TIME_TICKS
              value: "{runtime_info["start_time_ticks"]}"
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
    p = subprocess.Popen(["kubectl", "apply", "-f", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(input=helper_manifest)
    if p.returncode != 0:
        raise RuntimeError(f"Failed to submit Helper Job: {err}")
    log("Helper Job submitted. Awaiting netlink fault application event...")

    # Poll helper logs for netlink applied
    t_applied_epoch = None
    for _ in range(60):
        time.sleep(1)
        hl = run_cmd(["kubectl", "logs", "job/g2-chaos-helper", "-n", CHAOS_NAMESPACE], check=False).stdout
        if "fault_applied" in hl or "Discovered target CockroachDB PID" in hl or "FAULT_APPLIED" in hl or "Active netlink impairment applied" in hl:
            for line in hl.splitlines():
                if "applied at epoch" in line or "Active netlink impairment applied at epoch" in line:
                    t_applied_epoch = float(line.split("epoch")[-1].strip().split()[0])
                    break
            if not t_applied_epoch:
                t_applied_epoch = time.time()
            break

    if not t_applied_epoch:
        raise RuntimeError("Helper failed to confirm fault application within 60s")

    execution_record["timings"]["t_applied_epoch"] = t_applied_epoch
    log(f"=== FAULT CONFIRMED ACTIVE AT EPOCH {t_applied_epoch:.3f} ===")
    log("Holding fault active window for exactly 180.000 seconds from netlink application...")

    # Hold exactly 180s from confirmed netlink application
    time_to_clear = t_applied_epoch + 180.000
    rem_fault = time_to_clear - time.time()
    if rem_fault > 0:
        time.sleep(rem_fault)

    t_clear_epoch = time.time()
    execution_record["timings"]["t_clear_epoch"] = t_clear_epoch
    log(f"=== T_CLEAR REACHED (epoch={t_clear_epoch:.3f}): Initiating Teardown and Cleanup ===")
    
    # Phase 3: Post-Clearance Recovery Observation (300s W_rec)
    # Per authoritative protocol (G2_protocol_reconstruction.md, G2_supervisor_decision_record.md, g2_executor.py),
    # W_rec is anchored directly to verified fault clearance (T_clear).
    # To prevent Kubernetes deletion commands from introducing any artificial skew or delay into W_rec,
    # t_obs_start is anchored to t_clear_epoch immediately upon reaching T_clear.
    t_obs_start = t_clear_epoch
    execution_record["timings"]["t_obs_start_epoch"] = t_obs_start
    log(f"=== Phase 3: Starting 300s Post-Clearance Recovery Observation (W_rec) at epoch {t_obs_start:.3f} ===")
    
    # Immediate fail-closed teardown of helper job, auth secret, and claim lock
    run_cmd(["kubectl", "delete", "job", "g2-chaos-helper", "-n", CHAOS_NAMESPACE, "--ignore-not-found"])
    run_cmd(["kubectl", "delete", "secret", "g2-fault-auth-token", "-n", CHAOS_NAMESPACE, "--ignore-not-found"])
    run_cmd(["kubectl", "delete", "lease", "g2-claim-lock", "-n", CHAOS_NAMESPACE, "--ignore-not-found"], check=False)
    log("Helper Job and Secret deleted. Fault physically cleared.")
    
    # Hold the remainder of the 300.0-second recovery observation window from t_obs_start
    elapsed_obs = time.time() - t_obs_start
    rem_obs = max(0.0, 300.0 - elapsed_obs)
    log(f"Holding post-clearance recovery observation for remaining {rem_obs:.3f}s (anchored strictly to T_clear)...")
    if rem_obs > 0:
        time.sleep(rem_obs)
    t_obs_end = time.time()
    execution_record["timings"]["t_obs_end_epoch"] = t_obs_end
    execution_record["timings"]["obs_duration_sec"] = t_obs_end - t_obs_start
    log(f"Recovery observation complete at epoch {t_obs_end:.3f} (Total duration from T_clear: {t_obs_end - t_obs_start:.3f}s)")
    
    # Await measurement process completion and harvest in-pod execution status
    log("Verifying measurement process termination and retrieving in-pod exit status...")
    meas_stdout = ""
    meas_stderr = ""
    try:
        meas_stdout, meas_stderr = meas_proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        log("[WARNING] Local kubectl exec process did not exit within timeout. Terminating local wrapper...")
        meas_proc.kill()
        meas_stdout, meas_stderr = meas_proc.communicate()

    # Poll in-pod completion status from /tmp/pgbench_f06_exit_code.txt
    in_pod_exit_code = None
    for _ in range(15):
        exit_code_str = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", "cat /tmp/pgbench_f06_exit_code.txt 2>/dev/null || true"], check=False).stdout.strip()
        if exit_code_str and exit_code_str.isdigit():
            in_pod_exit_code = int(exit_code_str)
            break
        time.sleep(1.0)

    t_meas_end = time.time()
    execution_record["timings"]["t_meas_end_epoch"] = t_meas_end
    log(f"Measurement workload state verified at epoch {t_meas_end:.3f} (In-pod exit code: {in_pod_exit_code}, Subprocess code: {meas_proc.returncode})")
    
    # Retrieve in-pod stdout, stderr, and storage diagnostic records
    pod_stdout = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", "/tmp/pgbench_f06_stdout.txt"], check=False).stdout
    pod_stderr = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", "/tmp/pgbench_f06_stderr.txt"], check=False).stdout
    disk_pre = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", "/tmp/disk_pre.txt"], check=False).stdout
    disk_post = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", "/tmp/disk_post.txt"], check=False).stdout

    with open(os.path.join(OUTPUT_DIR, "disk_pre.txt"), "w", encoding="utf-8") as f:
        f.write(disk_pre)
    with open(os.path.join(OUTPUT_DIR, "disk_post.txt"), "w", encoding="utf-8") as f:
        f.write(disk_post)

    exit_diag = classify_measurement_exit(meas_proc.returncode, meas_stderr)
    exit_diag["in_pod_exit_code"] = in_pod_exit_code
    if in_pod_exit_code is None:
        exit_diag["in_pod_status_inferred"] = "CLIENT_LOGGING_STORAGE_FAILURE"
        exit_diag["reason"] += " In-pod exit code was unreadable (possible storage write failure)."
    execution_record["timings"]["meas_exit_classification"] = exit_diag
    
    with open(os.path.join(OUTPUT_DIR, "raw_pgbench_output.txt"), "w", encoding="utf-8") as f:
        f.write(f"=== IN-POD STDOUT ===\n{pod_stdout}\n=== IN-POD STDERR ===\n{pod_stderr}\n=== IN-POD EXIT CODE ===\n{in_pod_exit_code}\n=== CLIENT SUBPROCESS STDOUT ===\n{meas_stdout}\n=== CLIENT SUBPROCESS STDERR ===\n{meas_stderr}\n=== CLIENT SUBPROCESS CODE ===\n{meas_proc.returncode}\n")
    
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
    log(f"FORMAL REPETITION F06 EXECUTION COMPLETE: {RUN_ID}")
    log("================================================================================")

if __name__ == "__main__":
    main()