"""
g3_baseline_b03_executor.py - Hardened Dedicated Non-Fault Baseline Runner for crdb-g3-baseline-b03.
Scenario: Pure Non-Fault Baseline Characterization under Workload.
Engineering Enhancements over B01:
1. In-pod shell wrapper decoupling stdout/stderr into /tmp/ files with isolated process-group session (setsid).
2. Hard timeout enforcement (630s) on measurement process with two-stage graceful escalation:
   - Stage 1: Graceful SIGTERM to process group (-${PGID}) with bounded 5s wait.
   - Stage 2: Forceful SIGKILL to process group (-${PGID}) with independent verification.
3. Hard failure reporting if remote processes fail to terminate.
4. Incremental JSONL telemetry output with instant fsync flushing.
5. Clean process termination handling and in-pod exit code capture.
6. Post-measurement system quiescence observation (300s) cleanly distinguished from workload.
7. RFC-compliant SHA-256 evidence manifest generation.
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
from typing import Dict, Any, List, Optional, Tuple

RUN_ID = "crdb-g3-baseline-b03"
OUTPUT_DIR = os.path.abspath("thesis-evidence/07-g3-chaos/baselines/crdb-g3-baseline-b03")
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

def run_cmd(cmd: List[str], check: bool = True, timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)

def query_sql(query: str) -> str:
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "psql", PSQL_CONN, "-t", "-A", "-c", query
    ]
    res = run_cmd(cmd, timeout=30.0)
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

def check_storage_capacity(min_avail_mb: float = 30.0) -> Dict[str, Any]:
    """
    Checks available capacity on /tmp in the benchmark client pod.
    Fail-closed: if free space is below min_avail_mb, raises RuntimeError.
    """
    cmd = ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "df", "-k", "/tmp"]
    res = run_cmd(cmd, check=False, timeout=10.0)
    if res.returncode != 0:
        raise RuntimeError(f"Storage check failed with code {res.returncode}: {res.stderr}")
    
    lines = res.stdout.strip().split("\n")
    if len(lines) < 2:
        raise RuntimeError(f"Unexpected df output: {res.stdout}")
    parts = lines[1].split()
    total_kb = int(parts[1])
    used_kb = int(parts[2])
    avail_kb = int(parts[3])
    avail_mb = avail_kb / 1024.0
    
    log(f"[STORAGE MONITOR] /tmp capacity: Total={total_kb/1024.0:.1f}MB, Used={used_kb/1024.0:.1f}MB, Avail={avail_mb:.1f}MB")
    if avail_mb < min_avail_mb:
        raise RuntimeError(f"FAIL-CLOSED: Available /tmp storage ({avail_mb:.1f}MB) is below safety threshold ({min_avail_mb:.1f}MB)")
    
    return {
        "total_kb": total_kb,
        "used_kb": used_kb,
        "avail_kb": avail_kb,
        "avail_mb": avail_mb
    }

def construct_in_pod_wrapper(run_id: str, duration_sec: int) -> str:
    """
    Constructs the B03 in-pod shell execution wrapper.
    Enhancements over B02:
    1. Line-buffered streaming stderr filter via mawk:
       - Suppresses repetitive 'NOTICE:  No license is installed' messages.
       - Counts suppressed notices and preserves up to 10 sample lines in notice_samples.txt.
       - Streams all genuine WARNING, ERROR, FATAL, and non-license diagnostics to stderr_filtered.txt.
    2. Decoupled diagnostic and log artifacts with pre- and post-disk capacity audits.
    3. Isolated process session via setsid.
    """
    log_prefix = f"/tmp/pgbench_log_{run_id}"
    awk_filter = (
        "mawk -W interactive '"
        "BEGIN { count = 0; } "
        "/^NOTICE:  No license is installed/ { "
        "  count++; "
        f"  if (count <= 10) {{ print $0 > \"/tmp/pgbench_{run_id}_notice_samples.txt\"; }} "
        "  next; "
        "} "
        "{ "
        f"  print $0 > \"/tmp/pgbench_{run_id}_stderr.txt\"; "
        "} "
        "END { "
        f"  print count > \"/tmp/pgbench_{run_id}_notice_count.txt\"; "
        "}'"
    )
    script = (
        f"df -k /tmp > /tmp/disk_pre_{run_id}.txt; "
        f"setsid pgbench -h cockroachdb-public -p 26257 -U root -n -c 20 -j 4 -T {duration_sec} --max-tries=1 -M simple "
        f"-l --log-prefix={log_prefix} benchdb > /tmp/pgbench_{run_id}_stdout.txt 2> >({awk_filter}) & "
        f"BENCH_PGID=$!; "
        f'echo "${{BENCH_PGID}}" > /tmp/pgbench_{run_id}_pgid.txt; '
        f"wait ${{BENCH_PGID}}; "
        f"EXIT_CODE=$?; "
        f'echo "${{EXIT_CODE}}" > /tmp/pgbench_{run_id}_exit_code.txt; '
        f"sleep 1; "
        f"df -k /tmp > /tmp/disk_post_{run_id}.txt"
    )
    return script

def query_live_processes_in_pgid(pgid: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Enumerates all processes running in the benchmark client pod and filters for processes
    matching the specified PGID.
    
    Returns:
        (live_procs, zombie_procs)
    where each entry is a dict with keys: 'pid', 'pgid', 'stat', 'comm'.
    
    Live processes are those whose STAT does NOT start with 'Z'.
    Zombie processes (STAT starting with 'Z') are excluded from live_procs because they
    have already exited and are merely awaiting parent waitpid harvest.
    
    Fail-closed guarantees:
    - If ps exits non-zero, raises RuntimeError.
    - If ps times out or fails to execute, raises RuntimeError.
    - If output is empty or missing a valid header, raises RuntimeError.
    - If any data row has fewer than 4 columns or non-integer PID/PGID, raises RuntimeError.
    """
    if not isinstance(pgid, int) or pgid <= 0:
        raise ValueError(f"Invalid PGID: {pgid}. Must be a positive integer.")

    cmd = ["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "ps", "-eo", "pid,pgid,stat,comm"]
    res = run_cmd(cmd, check=False, timeout=10.0)
    if res.returncode != 0:
        raise RuntimeError(f"ps command failed with code {res.returncode}: {res.stderr}")

    raw_output = res.stdout.strip()
    if not raw_output:
        raise RuntimeError("ps command returned empty output; unable to verify process table.")

    lines = raw_output.split("\n")
    header_parts = lines[0].split()
    if len(header_parts) < 4 or header_parts[0] != "PID" or header_parts[1] != "PGID":
        raise RuntimeError(f"ps command returned unexpected header format: '{lines[0]}'")

    live_procs = []
    zombie_procs = []
    for line_idx, line in enumerate(lines[1:], start=2):
        line_clean = line.strip()
        if not line_clean:
            continue
        parts = line_clean.split(maxsplit=3)
        if len(parts) < 4:
            raise RuntimeError(f"Malformed process row at line {line_idx}: expected at least 4 fields, got {len(parts)} ('{line_clean}')")

        p_pid_s, p_pgid_s, p_stat, p_comm = parts[0], parts[1], parts[2], parts[3]
        try:
            p_pid_i = int(p_pid_s)
            p_pgid_i = int(p_pgid_s)
        except ValueError as ve:
            raise RuntimeError(f"Unparseable numeric PID/PGID at line {line_idx} ('{line_clean}'): {ve}")

        if p_pgid_i == pgid:
            proc_info = {
                "pid": p_pid_i,
                "pgid": p_pgid_i,
                "stat": p_stat,
                "comm": p_comm
            }
            if p_stat.startswith("Z"):
                zombie_procs.append(proc_info)
            else:
                live_procs.append(proc_info)

    return live_procs, zombie_procs

def terminate_remote_process_group(pgid: int, timeout_grace_sec: float = 5.0) -> Dict[str, Any]:
    """
    Executes a bounded two-stage process-group termination inside the client pod:
    Stage 1: SIGTERM to process group (-pgid)
    Stage 2: Bounded wait up to timeout_grace_sec verifying zero live processes in PGID
    Stage 3: If any live process remains or if grace verification failed, SIGKILL to process group (-pgid)
    Stage 4: Verification via full ps enumeration confirming zero live processes in PGID.
    
    Fail-closed guarantees:
    - Any error or unparseable output during query_live_processes_in_pgid prevents verified_dead=True.
    - If stage 4 verification fails, returns verified_dead=False with explicit error description.
    """
    if not isinstance(pgid, int) or pgid <= 0:
        raise ValueError(f"Invalid PGID: {pgid}. Must be a positive integer.")

    log(f"[PROCESS LIFECYCLE] Initiating termination of remote process group -{pgid}...")
    term_record: Dict[str, Any] = {
        "pgid": pgid,
        "sigterm_sent_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "graceful_success": False,
        "sigkill_sent": False,
        "sigkill_sent_timestamp": None,
        "verified_dead": False,
        "surviving_procs": [],
        "zombie_procs": [],
        "error": None
    }

    # Stage 1: Send SIGTERM to process group
    run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "/usr/bin/kill", "-TERM", f"-{pgid}"], check=False, timeout=10.0)

    # Stage 2: Bounded wait verifying process group enumeration
    t_start = time.time()
    grace_live_count: Optional[int] = None
    while time.time() - t_start < timeout_grace_sec:
        time.sleep(1.0)
        try:
            live, zombies = query_live_processes_in_pgid(pgid)
            grace_live_count = len(live)
            if grace_live_count == 0:
                term_record["graceful_success"] = True
                term_record["verified_dead"] = True
                term_record["zombie_procs"] = zombies
                log(f"[PROCESS LIFECYCLE] Process group -{pgid} terminated gracefully via SIGTERM (Live: 0, Zombies: {len(zombies)}).")
                return term_record
        except Exception as e:
            log(f"[PROCESS LIFECYCLE] Warning: failed to query live processes during grace wait: {e}")
            grace_live_count = None
            continue

    # Stage 3: Forceful SIGKILL
    reason_str = f"{grace_live_count} live processes remaining" if grace_live_count is not None else "verification query failures during grace window"
    log(f"[PROCESS LIFECYCLE] Process group -{pgid} has {reason_str} after {timeout_grace_sec}s grace. Escalating to SIGKILL...")
    term_record["sigkill_sent"] = True
    term_record["sigkill_sent_timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "/usr/bin/kill", "-KILL", f"-{pgid}"], check=False, timeout=10.0)

    time.sleep(1.0)
    try:
        final_live, final_zombies = query_live_processes_in_pgid(pgid)
    except Exception as e:
        term_record["verified_dead"] = False
        term_record["error"] = f"POST_KILL_VERIFICATION_FAILED: Could not query process table: {e}"
        log(f"[CRITICAL ERROR] {term_record['error']}")
        return term_record

    term_record["surviving_procs"] = final_live
    term_record["zombie_procs"] = final_zombies

    if len(final_live) == 0:
        term_record["verified_dead"] = True
        log(f"[PROCESS LIFECYCLE] Process group -{pgid} confirmed DEAD following SIGKILL (Live: 0, Zombies: {len(final_zombies)}).")
    else:
        term_record["verified_dead"] = False
        term_record["error"] = f"HARD_FAILURE: Process group -{pgid} has {len(final_live)} live processes surviving SIGKILL: {final_live}"
        log(f"[CRITICAL ERROR] {term_record['error']}")

    return term_record

def sample_cgroup_iostat(target_pod: str) -> Dict[str, Any]:
    cmd = ["kubectl", "exec", "-n", NAMESPACE, target_pod, "--", "cat", "/sys/fs/cgroup/io.stat"]
    try:
        res = run_cmd(cmd, check=False, timeout=10.0)
        raw = res.stdout.strip() if res.returncode == 0 else "ERROR"
    except Exception as e:
        raw = f"TIMEOUT_OR_ERROR: {e}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "timestamp": timestamp,
        "raw": raw,
        "pod": target_pod
    }

def sample_crdb_metrics(target_pod: str) -> Dict[str, Any]:
    cmd = [
        "kubectl", "exec", "-n", NAMESPACE, target_pod, "--",
        "curl", "-k", "-s", "https://localhost:8080/_status/vars"
    ]
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    metrics = {}
    try:
        res = run_cmd(cmd, check=False, timeout=10.0)
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
    except Exception as e:
        metrics["ERROR"] = str(e)
    return {
        "timestamp": timestamp,
        "metrics": metrics,
        "pod": target_pod
    }

def incremental_telemetry_poller(target_pod: str, stop_event: threading.Event, telemetry_file_path: str, interval: float = 5.0):
    while not stop_event.is_set():
        iostat = sample_cgroup_iostat(target_pod)
        crdb = sample_crdb_metrics(target_pod)
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "iostat": iostat,
            "crdb_metrics": crdb
        }
        try:
            with open(telemetry_file_path, "a", encoding="utf-8") as tf:
                tf.write(json.dumps(record) + "\n")
                tf.flush()
                os.fsync(tf.fileno())
        except Exception as e:
            log(f"[WARNING] Telemetry flush error: {e}")
        time.sleep(interval)

def execute_b03():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    telemetry_jsonl = os.path.join(OUTPUT_DIR, "telemetry_timeseries.jsonl")

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
            "hard_timeout_sec": 630,
            "nominal_window_sec": 180,
            "wrec_min_sec": 300,
        },
        "preflight": {},
        "target": {},
        "snapshots": {},
        "phases": {},
    }

    log(f"=== Starting Hardened CockroachDB G3 Baseline Execution: {RUN_ID} ===")

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

    # Clean previous run tmp files on client pod
    clean_cmd = f"rm -f /tmp/pgbench_log_{RUN_ID}.* /tmp/pgbench_{RUN_ID}_* /tmp/disk_*_{RUN_ID}.txt"
    run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", clean_cmd], check=False)

    # 2. Warmup Phase (120s Standalone)
    log("=== Phase 1: Executing 120s Warmup (Unlogged Standalone) ===")
    warmup_start = time.time()
    warmup_cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "pgbench", "-h", "cockroachdb-public", "-p", "26257", "-U", "root",
        "-n", "-c", "20", "-j", "4", "-T", "120", "--max-tries=1", "-M", "simple", "benchdb"
    ]
    warmup_res = run_cmd(warmup_cmd, timeout=180.0)
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

    # 3. Telemetry Thread Start (Incremental JSONL with instant fsync)
    stop_telemetry = threading.Event()
    poller_thread = threading.Thread(
        target=incremental_telemetry_poller,
        args=(target_pod, stop_telemetry, telemetry_jsonl, 5.0)
    )
    poller_thread.daemon = True
    poller_thread.start()
    log(f"Incremental telemetry poller started -> {telemetry_jsonl}")

    # 4. Measurement Phase (600s with in-pod wrapper, setsid, and 630s hard timeout)
    log("=== Phase 2: Starting 600s Measurement Workload via In-Pod Wrapper ===")
    wrapper_script = construct_in_pod_wrapper(RUN_ID, 600)
    meas_cmd = [
        "kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--",
        "bash", "-c", wrapper_script
    ]
    meas_start = time.time()
    meas_proc = subprocess.Popen(meas_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Hard timeout monitoring loop (max 630 seconds)
    timed_out = False
    remote_pgid: Optional[int] = None
    term_audit: Optional[Dict[str, Any]] = None

    while meas_proc.poll() is None:
        time.sleep(10)
        elapsed = time.time() - meas_start

        # Poll in-pod PGID if not yet retrieved
        if remote_pgid is None:
            pgid_str = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"cat /tmp/pgbench_{RUN_ID}_pgid.txt 2>/dev/null || true"], check=False).stdout.strip()
            if pgid_str and pgid_str.isdigit():
                remote_pgid = int(pgid_str)
                log(f"In-pod pgbench session running under PGID {remote_pgid}")

        if int(elapsed) % 60 == 0:
            log(f"Measurement progress: {elapsed:.1f}s / 600s")

        if elapsed > 630.0:
            log("[ALERT] Hard timeout (630s) exceeded! Triggering process-group termination...")
            timed_out = True
            meas_proc.kill()
            if remote_pgid:
                term_audit = terminate_remote_process_group(remote_pgid, timeout_grace_sec=5.0)
                if not term_audit["verified_dead"]:
                    raise RuntimeError(f"HARD FAILURE: Remote process group -{remote_pgid} could not be terminated: {term_audit['error']}")
            else:
                log("[WARNING] Remote PGID not captured before timeout. Executing fallback pkill...")
                run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "pkill", "-9", "-f", "pgbench"], check=False)
            break

    meas_stdout, meas_stderr = meas_proc.communicate()
    meas_dur = time.time() - meas_start
    log(f"Measurement process terminated at {meas_dur:.2f}s (TimedOut={timed_out})")

    # Read in-pod exit status
    exit_code_str = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"cat /tmp/pgbench_{RUN_ID}_exit_code.txt 2>/dev/null || true"], check=False).stdout.strip()
    in_pod_exit = int(exit_code_str) if exit_code_str and exit_code_str.isdigit() else None
    log(f"In-pod pgbench exit code: {in_pod_exit}")

    execution_record["phases"]["measurement"] = {
        "duration_sec": meas_dur,
        "timed_out": timed_out,
        "remote_pgid": remote_pgid,
        "termination_audit": term_audit,
        "in_pod_exit_code": in_pod_exit,
        "subprocess_returncode": meas_proc.returncode,
    }

    # Snapshot S2
    s2_history = int(query_sql("SELECT count(*) FROM benchdb.public.pgbench_history;"))
    log(f"Post-measurement pgbench_history count (S2): {s2_history} (Measurement txs: {s2_history - s1_history})")
    execution_record["snapshots"]["s2_history"] = s2_history

    # 5. Post-Measurement Observation Window (Wrec >= 300s)
    # NOTE: In a non-fault baseline, Wrec is purely a system-observation window monitoring post-stream quiescence,
    # background compaction, and WAL recycling. It does NOT require or feature a continuing transaction stream.
    log("=== Phase 3: Observing Post-Measurement System Quiescence Window (300s) ===")
    wrec_start = time.time()
    for i in range(6):
        time.sleep(50)
        log(f"Post-measurement observation: {(i+1)*50}s / 300s (System quiescence)")
    wrec_dur = time.time() - wrec_start
    log(f"Post-measurement observation complete in {wrec_dur:.2f}s.")
    execution_record["phases"]["post_measurement_observation"] = {
        "duration_sec": wrec_dur,
        "meaning": "System quiescence, background compaction, and cluster stability monitoring. No active workload."
    }

    # Stop telemetry thread
    stop_telemetry.set()
    poller_thread.join(timeout=10)

    # 6. Retrieve Evidence from Pod
    log("Retrieving logs and diagnostics from client pod via kubectl cp...")
    pod_files = [
        f"/tmp/pgbench_{RUN_ID}_stdout.txt",
        f"/tmp/pgbench_{RUN_ID}_stderr.txt",
        f"/tmp/pgbench_{RUN_ID}_pgid.txt",
        f"/tmp/pgbench_{RUN_ID}_exit_code.txt",
        f"/tmp/disk_pre_{RUN_ID}.txt",
        f"/tmp/disk_post_{RUN_ID}.txt",
    ]
    for pf in pod_files:
        local_name = os.path.basename(pf)
        local_path = os.path.join(OUTPUT_DIR, local_name)
        run_cmd(["kubectl", "cp", f"{NAMESPACE}/{CLIENT_POD}:{pf}", local_path], check=False, timeout=15.0)

    tx_files_raw = run_cmd(["kubectl", "exec", "-n", NAMESPACE, CLIENT_POD, "--", "sh", "-c", f"ls /tmp/pgbench_log_{RUN_ID}.*"]).stdout
    tx_files = [f.strip() for f in tx_files_raw.splitlines() if f.strip()]
    for tf in tx_files:
        local_name = os.path.basename(tf)
        local_path = os.path.join(OUTPUT_DIR, local_name)
        run_cmd(["kubectl", "cp", f"{NAMESPACE}/{CLIENT_POD}:{tf}", local_path], check=False, timeout=30.0)
        log(f"Retrieved {local_name}")

    execution_record["timestamp_end"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open(os.path.join(OUTPUT_DIR, "execution_record.json"), "w", encoding="utf-8") as f:
        json.dump(execution_record, f, indent=2)

    # 7. Generate Checksum Manifest
    build_manifest(OUTPUT_DIR)
    log(f"=== CockroachDB G3 Baseline {RUN_ID} Completed Successfully ===")

if __name__ == "__main__":
    execute_b03()
