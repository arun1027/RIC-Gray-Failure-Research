"""
g3_baseline_b01_executor.py - Dedicated Non-Fault Baseline Runner for crdb-g3-baseline-b01.
Scenario: Pure Non-Fault Baseline Characterization under Workload.
Strictly adheres to the approved four-clock timing model, Option B dataset safety,
live Prometheus and cgroup telemetry capture, and RFC-compliant SHA-256 evidence generation.
ZERO FAULT IS APPLIED. ZERO CGROUP LIMITS ARE MODIFIED.
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from typing import Dict, Any, List

RUN_ID = "crdb-g3-baseline-b01"
OUTPUT_DIR = os.path.abspath("thesis-evidence/07-g3-chaos/baselines/crdb-g3-baseline-b01")
NAMESPACE = "cockroachdb"
CHAOS_NAMESPACE = "g1-chaos"
CLIENT_POD = "crdb-benchmark-client-hardened"

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

def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def build_manifest(output_dir: str) -> str:
    manifest_path = os.path.join(output_dir, "SHA256SUMS.txt")
    lines = []
    for root, _, files in os.walk(output_dir):
        for file in sorted(files):
            if file == "SHA256SUMS.txt":
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, output_dir).replace("\\", "/")
            digest = compute_sha256(full_path)
            lines.append(f"{digest}  {rel_path}\n")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    log(f"Generated SHA-256 manifest at {manifest_path}")
    return manifest_path

def sample_cgroup_iostat(target_pod: str) -> Dict[str, Any]:
    cmd = ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", "/sys/fs/cgroup/io.stat"]
    res = run_cmd(cmd, check=False)
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "timestamp": timestamp,
        "raw": res.stdout.strip() if res.returncode == 0 else "ERROR",
        "pod": target_pod
    }

def sample_crdb_metrics(target_pod: str) -> Dict[str, Any]:
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, target_pod, "--",
        "curl", "-k", "-s", "https://localhost:8080/_status/vars"
    ]
    res = run_cmd(cmd, check=False)
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    metrics = {}
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if any(k in line for k in [
                "storage_disk_write_bytes", "storage_disk_write_count",
                "storage_disk_write_max_bytespersecond", "storage_disk_write_max_iops",
                "storage_disk_read_bytes", "storage_disk_read_count",
                "storage_disk_iopsinprogress", "storage_disk_stalled",
                "ranges_underreplicated", "rebalancing_writespersecond"
            ]):
                parts = line.split(" ")
                if len(parts) == 2:
                    metrics[parts[0]] = parts[1]
    return {
        "timestamp": timestamp,
        "metrics": metrics,
        "pod": target_pod
    }

def telemetry_poller(target_pod: str, stop_event: threading.Event, telemetry_records: List[Dict[str, Any]], interval: float = 5.0):
    while not stop_event.is_set():
        iostat = sample_cgroup_iostat(target_pod)
        crdb = sample_crdb_metrics(target_pod)
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "iostat": iostat,
            "crdb_metrics": crdb
        }
        telemetry_records.append(record)
        time.sleep(interval)

def execute_b01():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    execution_record: Dict[str, Any] = {
        "run_id": RUN_ID,
        "timestamp_start": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "workload": {
            "clients": 20,
            "threads": 4,
            "protocol": "simple",
            "max_tries": 1,
            "warmup_sec": 120,
            "measurement_sec": 600,
            "nominal_window_sec": 180,
            "wrec_min_sec": 300,
        },
        "preflight": {},
        "target": {},
        "snapshots": {},
        "phases": {},
    }

    log(f"=== Starting CockroachDB G3 Baseline Execution: {RUN_ID} ===")
    
    # 1. Preflight Invariants
    log("Running preflight checks...")
    row_count = query_sql("SELECT count(*) FROM benchdb.public.pgbench_accounts;")
    if row_count != "5000000":
        raise RuntimeError(f"Preflight FAILED: Accounts count is {row_count}, expected 5000000")
    
    s0_history = int(query_sql("SELECT count(*) FROM benchdb.public.pgbench_history;"))
    log(f"Initial pgbench_history count (S0): {s0_history}")
    execution_record["snapshots"]["s0_history"] = s0_history

    # Dynamic target leaseholder discovery
    show_range = query_sql("SHOW RANGE FROM TABLE benchdb.public.pgbench_accounts FOR ROW (1);")
    parts = show_range.split("|")
    range_id = int(parts[2])
    leaseholder_id = int(parts[3])
    target_pod = f"cockroachdb-{leaseholder_id - 1}"
    
    pod_json = json.loads(run_cmd(["kubectl", "get", "pod", target_pod, "-n", NAMESPACE, "-o", "json"]).stdout)
    target_node = pod_json["spec"]["nodeName"]
    cid = pod_json["status"]["containerStatuses"][0]["containerID"].replace("containerd://", "")
    stat_dec = int(run_cmd(["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "stat", "-c", "%d", "/cockroach/cockroach-data"]).stdout.strip())
    dev_major = stat_dec >> 8
    dev_minor = stat_dec & 0xFF
    
    target_info = {
        "range_id": range_id,
        "leaseholder_id": leaseholder_id,
        "target_pod": target_pod,
        "target_node": target_node,
        "container_id": cid,
        "dev_major": dev_major,
        "dev_minor": dev_minor,
        "dev_stat_dec": stat_dec,
        "raw_show_range": show_range
    }
    execution_record["target"] = target_info
    log(f"Dynamic target: Range {range_id}, Leaseholder {leaseholder_id} ({target_pod} on {target_node}), Dev {dev_major}:{dev_minor}")

    # Clean old logs on client pod
    run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"rm -f /tmp/pgbench_log_{RUN_ID}.*"], check=False)

    # 2. Warmup Phase (120s)
    log("=== Phase 1: Executing 120s Warmup (Unlogged) ===")
    warmup_start = time.time()
    warmup_cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "pgbench", "-h", "cockroachdb-public", "-p", "26257", "-U", "root",
        "-n", "-c", "20", "-j", "4", "-T", "120", "--max-tries=1", "-M", "simple", "benchdb"
    ]
    warmup_res = run_cmd(warmup_cmd)
    warmup_dur = time.time() - warmup_start
    log(f"Warmup finished in {warmup_dur:.2f}s. Exit code: {warmup_res.returncode}")
    execution_record["phases"]["warmup"] = {
        "duration_sec": warmup_dur,
        "exit_code": warmup_res.returncode,
        "stdout": warmup_res.stdout
    }

    # Snapshot S1
    s1_history = int(query_sql("SELECT count(*) FROM benchdb.public.pgbench_history;"))
    log(f"Post-warmup pgbench_history count (S1): {s1_history} (Warmup txs: {s1_history - s0_history})")
    execution_record["snapshots"]["s1_history"] = s1_history

    # 3. Telemetry Thread Start
    telemetry_records: List[Dict[str, Any]] = []
    stop_telemetry = threading.Event()
    poller_thread = threading.Thread(
        target=telemetry_poller,
        args=(target_pod, stop_telemetry, telemetry_records, 5.0)
    )
    poller_thread.daemon = True
    poller_thread.start()
    log("Background telemetry poller started (5s sampling interval).")

    # 4. Measurement Phase (600s)
    log("=== Phase 2: Starting 600s Measurement Workload (-M simple, -T 600, microsecond logging) ===")
    log_prefix = f"/tmp/pgbench_log_{RUN_ID}"
    meas_cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "pgbench", "-h", "cockroachdb-public", "-p", "26257", "-U", "root",
        "-n", "-c", "20", "-j", "4", "-T", "600", "--max-tries=1", "-M", "simple",
        "-l", f"--log-prefix={log_prefix}", "benchdb"
    ]
    meas_start = time.time()
    meas_proc = subprocess.Popen(meas_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Progress monitoring
    elapsed = 0
    while meas_proc.poll() is None:
        time.sleep(10)
        elapsed = time.time() - meas_start
        if int(elapsed) % 60 == 0 or int(elapsed) in [120, 300]:
            log(f"Measurement progress: {elapsed:.1f}s / 600s (Zero fault applied)")

    meas_stdout, meas_stderr = meas_proc.communicate()
    meas_dur = time.time() - meas_start
    log(f"Measurement stream completed in {meas_dur:.2f}s with exit code {meas_proc.returncode}")
    
    execution_record["phases"]["measurement"] = {
        "duration_sec": meas_dur,
        "exit_code": meas_proc.returncode,
        "stdout": meas_stdout,
        "stderr": meas_stderr
    }

    # Snapshot S2
    s2_history = int(query_sql("SELECT count(*) FROM benchdb.public.pgbench_history;"))
    log(f"Post-measurement pgbench_history count (S2): {s2_history} (Measurement txs: {s2_history - s1_history})")
    execution_record["snapshots"]["s2_history"] = s2_history

    # 5. Post-Measurement Monitoring Window (Wrec >= 300s)
    log("=== Phase 3: Observing Post-Measurement Stabilization Window (300s) ===")
    wrec_start = time.time()
    for i in range(6):
        time.sleep(50)
        log(f"Post-measurement observation: {(i+1)*50}s / 300s")
    wrec_dur = time.time() - wrec_start
    log(f"Post-measurement observation complete in {wrec_dur:.2f}s.")
    execution_record["phases"]["post_measurement_observation"] = {
        "duration_sec": wrec_dur
    }

    # Stop telemetry
    stop_telemetry.set()
    poller_thread.join(timeout=10)
    log(f"Captured {len(telemetry_records)} telemetry samples.")

    # 6. Retrieve Evidence & Generate Artifacts
    log("Retrieving pgbench microsecond transaction logs from client pod...")
    tx_files_raw = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"ls {log_prefix}.*"]).stdout
    tx_files = [f.strip() for f in tx_files_raw.splitlines() if f.strip()]
    
    for tf in tx_files:
        local_name = os.path.basename(tf)
        local_path = os.path.join(OUTPUT_DIR, local_name)
        cat_cmd = ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "cat", tf]
        with open(local_path, "w", encoding="utf-8") as lf:
            subprocess.run(cat_cmd, stdout=lf, check=True)
        log(f"Retrieved {local_name} ({os.path.getsize(local_path)} bytes)")

    with open(os.path.join(OUTPUT_DIR, "raw_pgbench_output.txt"), "w", encoding="utf-8") as f:
        f.write(f"=== STDOUT ===\n{meas_stdout}\n=== STDERR ===\n{meas_stderr}\n")

    with open(os.path.join(OUTPUT_DIR, "telemetry_timeseries.json"), "w", encoding="utf-8") as f:
        json.dump(telemetry_records, f, indent=2)

    execution_record["timestamp_end"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open(os.path.join(OUTPUT_DIR, "execution_record.json"), "w", encoding="utf-8") as f:
        json.dump(execution_record, f, indent=2)

    # 7. Generate RFC-compliant SHA-256 Manifest
    manifest_file = build_manifest(OUTPUT_DIR)
    log(f"=== CockroachDB G3 Baseline {RUN_ID} Completed Successfully ===")

if __name__ == "__main__":
    execute_b01()

