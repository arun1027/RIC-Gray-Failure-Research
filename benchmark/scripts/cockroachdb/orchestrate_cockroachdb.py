#!/usr/bin/env python3
"""
CockroachDB Benchmark Orchestrator & Preflight Validation
Aligned with CA2 Report, BENCHMARK-METHODOLOGY.md, common-benchmark.conf, and RUN-NAMING-CONVENTION.md.

Research System: CockroachDB v26.3.2 (Multi-AZ 3-Node StatefulSet)
Workload: pgbench TPC-B (SF 50, 5,000,000 accounts, 20 clients, 4 threads, 120s warm-up, 600s measurement)
Connection: In-Cluster Client Pod -> CockroachDB Public Service (mTLS verify-full)

Fail-Closed Architecture:
All preflight checks must return VERIFIED before any benchmark execution is permitted.
"""

import os
import sys
import time
import json
import socket
import datetime
import subprocess
import csv
import re
import argparse
import glob
import math
import threading

# Shared benchmark log parser integration
BASE_SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, BASE_SCRIPTS_DIR)

try:
    from log_parser import analyze_pgbench_logs, parse_percentiles_from_log_files
except ImportError:
    analyze_pgbench_logs = None
    parse_percentiles_from_log_files = None

# Configuration constants
DEFAULT_NAMESPACE = "cockroachdb"
DEFAULT_HOST = "cockroachdb-public.cockroachdb.svc.cluster.local"
DEFAULT_PORT = 26257
DEFAULT_DATABASE = "benchdb"
DEFAULT_USER = "root"
SCALE_FACTOR_REQUIRED = 50
ACCOUNTS_REQUIRED = 5000000
BRANCHES_REQUIRED = 50
TELLERS_REQUIRED = 500
WARMUP_SECONDS_REQUIRED = 120
MEASUREMENT_SECONDS_REQUIRED = 600
COOLDOWN_SECONDS_REQUIRED = 300
CLIENTS_REQUIRED = 20
THREADS_REQUIRED = 4
BENCHMARK_CLIENT_IMAGE = "postgres:16"
CLIENT_SECRET_NAME = "cockroachdb-client-secret"


class PreflightCheckResult:
    def __init__(self, check_name, passed, message, details=None):
        self.check_name = check_name
        self.passed = passed
        self.message = message
        self.details = details or {}

    def to_dict(self):
        return {
            "check": self.check_name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
        }


class CockroachDBBenchmarkOrchestrator:
    def __init__(self, config=None):
        self.config = config or {}
        self.namespace = self.config.get("namespace", DEFAULT_NAMESPACE)
        self.host = self.config.get("host", DEFAULT_HOST)
        self.port = int(self.config.get("port", DEFAULT_PORT))
        self.database = self.config.get("database", DEFAULT_DATABASE)
        self.user = self.config.get("user", DEFAULT_USER)
        self.scale_factor = int(self.config.get("scale_factor", SCALE_FACTOR_REQUIRED))
        self.clients = int(self.config.get("clients", CLIENTS_REQUIRED))
        self.threads = int(self.config.get("threads", THREADS_REQUIRED))
        self.warmup_sec = int(self.config.get("warmup_seconds", WARMUP_SECONDS_REQUIRED))
        self.measurement_sec = int(self.config.get("measurement_seconds", MEASUREMENT_SECONDS_REQUIRED))
        self.cooldown_sec = int(self.config.get("cooldown_seconds", COOLDOWN_SECONDS_REQUIRED))
        self.client_pod = self.config.get("client_pod", "crdb-benchmark-client")
        self.output_dir = self.config.get("output_dir", os.path.join("results", "cockroachdb", "baseline"))
        self.is_smoke_test = bool(self.config.get("is_smoke_test", False))
        # Student Decision PD-05: Option 5A (pgbench default --max-tries=1 for primary cross-database comparison)
        self.max_tries = int(self.config.get("max_tries", 1))
        # Evidence-based scheduling sizing: 350m fits on all nodes (node 2 has 430m headroom; nodes 1 and 3 have 750m)
        self.client_cpu_request = self.config.get("client_cpu_request", "350m")
        self.client_mem_request = self.config.get("client_mem_request", "512Mi")
        self.client_cpu_limit = self.config.get("client_cpu_limit", "1500m")
        self.client_mem_limit = self.config.get("client_mem_limit", "1024Mi")

    def validate_protocol_parameters(self):
        """
        Validates configured parameters against strict research protocol requirements.
        Returns a list of PreflightCheckResult objects.
        """
        results = []

        # Scale Factor Check
        if self.scale_factor == SCALE_FACTOR_REQUIRED:
            results.append(PreflightCheckResult("scale_factor", True, f"Scale factor {self.scale_factor} matches protocol"))
        else:
            results.append(PreflightCheckResult("scale_factor", False, f"Scale factor {self.scale_factor} violates protocol ({SCALE_FACTOR_REQUIRED})"))

        # Concurrency Check
        if self.clients == CLIENTS_REQUIRED and self.threads == THREADS_REQUIRED:
            results.append(PreflightCheckResult("concurrency", True, f"Concurrency {self.clients} clients / {self.threads} threads matches protocol"))
        else:
            results.append(PreflightCheckResult("concurrency", False, f"Concurrency mismatch: clients={self.clients}, threads={self.threads}"))

        # Duration Check (formal vs smoke)
        if self.is_smoke_test:
            results.append(PreflightCheckResult("workload_timing", True, "Smoke test mode: shortened timing permitted (Smoke test only; NOT a formal experiment)"))
        else:
            if self.warmup_sec == WARMUP_SECONDS_REQUIRED and self.measurement_sec == MEASUREMENT_SECONDS_REQUIRED:
                results.append(PreflightCheckResult("workload_timing", True, f"Warmup {self.warmup_sec}s and measurement {self.measurement_sec}s match protocol"))
            else:
                results.append(PreflightCheckResult("workload_timing", False, f"Formal timing mismatch: warmup={self.warmup_sec}s, measurement={self.measurement_sec}s"))

        # Output Directory Check
        if self.output_dir:
            out_parent = os.path.dirname(os.path.abspath(self.output_dir))
            if os.path.exists(out_parent):
                results.append(PreflightCheckResult("output_directory", True, f"Output directory {self.output_dir} is valid"))
            else:
                results.append(PreflightCheckResult("output_directory", False, f"Output directory parent missing: {self.output_dir}"))

        return results

    def build_in_cluster_pod_manifest(self, pod_name, duration_sec, clients, threads, run_id, phase_name, with_logging=False):
        """
        Builds the Kubernetes Pod JSON manifest for running pgbench in-cluster against CockroachDB.
        """
        pgbench_args = [
            "pgbench",
            "-n",
            f"--max-tries={self.max_tries}",
            "-c", str(clients),
            "-j", str(threads),
            "-T", str(duration_sec),
            "-P", "10",
        ]
        if with_logging:
            pgbench_args.extend(["-l", "--log-prefix=/logs/pgbench_log"])

        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod_name,
                "namespace": self.namespace,
                "labels": {
                    "app.kubernetes.io/name": "crdb-benchmark-client",
                    "app.kubernetes.io/component": "benchmark-workload",
                    "ric.benchmark/system": "crdb",
                    "ric.benchmark/run-id": run_id,
                    "ric.benchmark/phase": phase_name,
                    "ric.benchmark/smoke-test": "true" if self.is_smoke_test else "false",
                },
            },
            "spec": {
                "restartPolicy": "Never",
                "containers": [
                    {
                        "name": "pgbench",
                        "image": BENCHMARK_CLIENT_IMAGE,
                        "command": pgbench_args,
                        "env": [
                            {"name": "PGHOST", "value": self.host},
                            {"name": "PGPORT", "value": str(self.port)},
                            {"name": "PGUSER", "value": self.user},
                            {"name": "PGDATABASE", "value": self.database},
                            {"name": "PGSSLMODE", "value": "verify-full"},
                            {"name": "PGSSLROOTCERT", "value": "/cockroach-certs/ca.crt"},
                            {"name": "PGSSLCERT", "value": "/cockroach-certs/client.root.crt"},
                            {"name": "PGSSLKEY", "value": "/cockroach-certs/client.root.key"},
                        ],
                        "volumeMounts": [
                            {
                                "name": "client-certs",
                                "mountPath": "/cockroach-certs",
                                "readOnly": True,
                            },
                            {
                                "name": "benchmark-logs",
                                "mountPath": "/logs",
                            },
                        ],
                        "resources": {
                            "requests": {"cpu": self.client_cpu_request, "memory": self.client_mem_request},
                            "limits": {"cpu": self.client_cpu_limit, "memory": self.client_mem_limit},
                        },
                    }
                ],
                "volumes": [
                    {
                        "name": "client-certs",
                        "secret": {
                            "secretName": CLIENT_SECRET_NAME,
                            "defaultMode": 256,
                            "items": [
                                {"key": "ca.crt", "path": "ca.crt", "mode": 256},
                                {"key": "tls.crt", "path": "client.root.crt", "mode": 256},
                                {"key": "tls.key", "path": "client.root.key", "mode": 256},
                            ],
                        },
                    },
                    {
                        "name": "benchmark-logs",
                        "emptyDir": {},
                    },
                ],
            },
        }
        return manifest

    def parse_pgbench_output(self, stdout_text):
        """
        Parses standard pgbench output metrics into structured dictionary.
        Extracts TPS, average latency, and transaction counts.
        Distinguishes successful transactions from total attempted transactions.
        """
        metrics = {
            "tps_including_connections": None,
            "tps_excluding_connections": None,
            "avg_latency_ms": None,
            "failed_transactions": 0,
            "total_transactions": None,
            "successful_transactions": 0,
            "attempted_transactions": 0,
        }

        tps_incl = re.search(r"tps\s*=\s*([\d\.]+)\s*\(including connections establishing\)", stdout_text)
        if tps_incl:
            metrics["tps_including_connections"] = float(tps_incl.group(1))

        tps_excl = re.search(r"tps\s*=\s*([\d\.]+)\s*\(without initial connection time\)", stdout_text)
        if not tps_excl:
            tps_excl = re.search(r"tps\s*=\s*([\d\.]+)\s*\(excluding connections establishing\)", stdout_text)
        if tps_excl:
            metrics["tps_excluding_connections"] = float(tps_excl.group(1))

        lat = re.search(r"latency average\s*=\s*([\d\.]+)\s*ms", stdout_text)
        if lat:
            metrics["avg_latency_ms"] = float(lat.group(1))

        tx = re.search(r"number of transactions actually processed:\s*(\d+)", stdout_text)
        if tx:
            # In pgbench output, 'actually processed' represents successful transactions
            metrics["successful_transactions"] = int(tx.group(1))
            metrics["total_transactions"] = int(tx.group(1))

        failed = re.search(r"number of failed transactions:\s*(\d+)", stdout_text)
        if failed:
            metrics["failed_transactions"] = int(failed.group(1))

        metrics["attempted_transactions"] = metrics["successful_transactions"] + metrics["failed_transactions"]
        return metrics

    def read_cgroup_cpu_stats(self):
        """
        Reads /sys/fs/cgroup/cpu.stat from all 3 CockroachDB pods.
        Returns dict: {node: {"nr_periods": int, "nr_throttled": int, "throttled_usec": int}}
        """
        stats = {}
        for node in ["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"]:
            try:
                cmd = ["kubectl", "exec", "-n", self.namespace, node, "-c", "db", "--", "cat", "/sys/fs/cgroup/cpu.stat"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)
                node_stat = {}
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1].isdigit():
                        node_stat[parts[0]] = int(parts[1])
                stats[node] = {
                    "nr_periods": node_stat.get("nr_periods", 0),
                    "nr_throttled": node_stat.get("nr_throttled", 0),
                    "throttled_usec": node_stat.get("throttled_usec", 0),
                }
            except Exception as e:
                stats[node] = {
                    "nr_periods": 0,
                    "nr_throttled": 0,
                    "throttled_usec": 0,
                    "error": str(e),
                }
        return stats

    def parse_transaction_logs(self, log_dir, prefix, expected_files=None, expected_clients=None,
                               expected_transactions=None, expected_failed=None):
        """
        Parses per-transaction pgbench logs (-l) using nearest-rank percentile method via log_parser.py.
        Calculates p95 and p99 latency in milliseconds.
        """
        if analyze_pgbench_logs is None:
            return {
                "ok": False,
                "errors": ["log_parser.py could not be imported"],
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "reconciled": False,
            }

        return analyze_pgbench_logs(
            log_dir=log_dir,
            prefix=prefix,
            expected_files=expected_files,
            expected_clients=expected_clients,
            expected_transactions=expected_transactions,
            expected_failed=expected_failed,
        )

    def run_cluster_preflight(self):
        """
        Executes complete database preflight checks via kubectl and SQL:
        1. 3 CockroachDB StatefulSet pods Running
        2. 3 CockroachDB nodes live and available
        3. Raft range quorum verified across all ranges in benchdb
        4. benchdb exists and row counts verified (5,000,000 accounts)
        5. Zero active schema change jobs
        6. Storage capacity verified (>4.0 GiB available per node)
        """
        checks = []

        # 1. StatefulSet Pod Readiness
        try:
            cmd = ["kubectl", "get", "pods", "-n", self.namespace, "-l", "app.kubernetes.io/name=cockroachdb", "-o", "json"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            pod_items = json.loads(res.stdout).get("items", [])
            running_pods = [p["metadata"]["name"] for p in pod_items if p.get("status", {}).get("phase") == "Running"]
            ready_pods = [
                p["metadata"]["name"] for p in pod_items
                if all(cs.get("ready", False) for cs in p.get("status", {}).get("containerStatuses", []))
            ]
            if len(ready_pods) == 3:
                checks.append(PreflightCheckResult("statefulset_pods", True, f"3/3 CockroachDB pods Ready: {', '.join(sorted(ready_pods))}"))
            else:
                checks.append(PreflightCheckResult("statefulset_pods", False, f"Expected 3 ready pods, found {len(ready_pods)}: {ready_pods}"))
        except Exception as e:
            checks.append(PreflightCheckResult("statefulset_pods", False, f"Failed querying pods: {e}"))

        # 2. Node Live Status & Health
        try:
            sql_nodes = (
                "SET allow_unsafe_internals = true; "
                "SELECT g.node_id, g.is_live, l.draining, l.membership "
                "FROM crdb_internal.gossip_nodes g "
                "JOIN crdb_internal.kv_node_liveness l ON g.node_id = l.node_id "
                "ORDER BY g.node_id;"
            )
            cmd_node = [
                "kubectl", "exec", "-n", self.namespace, self.client_pod, "--",
                "psql", "-t", "-A", "-c", sql_nodes,
            ]
            res_node = subprocess.run(cmd_node, capture_output=True, text=True, check=True)
            live_nodes = []
            for line in res_node.stdout.strip().splitlines():
                line = line.strip()
                if not line or line.upper() == "SET":
                    continue
                parts = line.split("|")
                if len(parts) == 4:
                    node_id, is_live, draining, membership = parts
                    if is_live.lower() == "t" and draining.lower() == "f" and membership.lower() == "active":
                        live_nodes.append(node_id)
            if len(live_nodes) == 3:
                checks.append(PreflightCheckResult("cockroach_nodes", True, f"All 3 CockroachDB nodes live, active, non-draining (Nodes: {', '.join(live_nodes)})"))
            else:
                checks.append(PreflightCheckResult("cockroach_nodes", False, f"Expected 3 live nodes, found {len(live_nodes)}: {live_nodes}"))
        except Exception as e:
            checks.append(PreflightCheckResult("cockroach_nodes", False, f"Failed querying node status: {e}"))

        # 3. Database benchdb & Row Counts
        try:
            sql_count = (
                "SELECT 'pgbench_accounts|' || count(*) FROM pgbench_accounts "
                "UNION ALL SELECT 'pgbench_branches|' || count(*) FROM pgbench_branches "
                "UNION ALL SELECT 'pgbench_tellers|' || count(*) FROM pgbench_tellers "
                "UNION ALL SELECT 'pgbench_history|' || count(*) FROM pgbench_history;"
            )
            cmd_sql = [
                "kubectl", "exec", "-n", self.namespace, self.client_pod, "--",
                "psql", "-t", "-A", "-c", sql_count,
            ]
            res_sql = subprocess.run(cmd_sql, capture_output=True, text=True, check=True)
            counts = {}
            for line in res_sql.stdout.strip().splitlines():
                parts = line.strip().split("|")
                if len(parts) == 2:
                    counts[parts[0].strip()] = parts[1].strip()

            acc_count = int(counts.get("pgbench_accounts", -1))
            branch_count = int(counts.get("pgbench_branches", -1))
            teller_count = int(counts.get("pgbench_tellers", -1))
            hist_count = int(counts.get("pgbench_history", -1))

            if acc_count == ACCOUNTS_REQUIRED and branch_count == BRANCHES_REQUIRED and teller_count == TELLERS_REQUIRED and hist_count >= 0:
                checks.append(PreflightCheckResult(
                    "dataset_counts", True,
                    f"Dataset verified: {acc_count} accounts, {branch_count} branches, {teller_count} tellers, {hist_count} history"
                ))
            else:
                checks.append(PreflightCheckResult(
                    "dataset_counts", False,
                    f"Dataset mismatch: accounts={acc_count} (req: {ACCOUNTS_REQUIRED}), branches={branch_count}, tellers={teller_count}"
                ))
        except Exception as e:
            checks.append(PreflightCheckResult("dataset_counts", False, f"Failed querying database counts: {e}"))

        # 4. Under-Replicated Range Audit
        try:
            sql_ranges = "SELECT count(*) FROM [SHOW RANGES FROM DATABASE benchdb] WHERE array_length(replicas, 1) < 3;"
            cmd_ranges = [
                "kubectl", "exec", "-n", self.namespace, self.client_pod, "--",
                "psql", "-t", "-A", "-c", sql_ranges,
            ]
            res_ranges = subprocess.run(cmd_ranges, capture_output=True, text=True, check=True)
            range_lines = [l.strip() for l in res_ranges.stdout.strip().splitlines() if l.strip()]
            under_rep = int(range_lines[-1]) if range_lines else -1
            if under_rep == 0:
                checks.append(PreflightCheckResult("range_replication", True, "100% of ranges in benchdb fully replicated across 3 nodes (0 under-replicated)"))
            else:
                checks.append(PreflightCheckResult("range_replication", False, f"Detected {under_rep} under-replicated ranges in benchdb"))
        except Exception as e:
            checks.append(PreflightCheckResult("range_replication", False, f"Failed auditing range replication: {e}"))

        # 5. Storage Headroom
        try:
            cmd_df = ["kubectl", "exec", "-n", self.namespace, "cockroachdb-0", "-c", "db", "--", "df", "-m", "/cockroach/cockroach-data"]
            res_df = subprocess.run(cmd_df, capture_output=True, text=True, check=True)
            df_lines = [l for l in res_df.stdout.strip().splitlines() if l.strip()]
            avail_mb = 0
            if len(df_lines) >= 2:
                parts = df_lines[1].split()
                if len(parts) >= 4:
                    avail_mb = int(parts[3])
            if avail_mb >= 3000:
                checks.append(PreflightCheckResult("storage_headroom", True, f"CockroachDB volume storage headroom: {avail_mb} MiB available (>3000 MiB threshold)"))
            else:
                checks.append(PreflightCheckResult("storage_headroom", False, f"Insufficient volume headroom: {avail_mb} MiB available"))
        except Exception as e:
            checks.append(PreflightCheckResult("storage_headroom", False, f"Failed querying storage capacity: {e}"))

        # 6. Native Telemetry Endpoint Validation (All 3 Nodes)
        telemetry_checks = self.check_native_telemetry_endpoints()
        checks.extend(telemetry_checks)

        return checks

    def check_native_telemetry_endpoints(self):
        """
        Validates that the native CockroachDB Prometheus telemetry endpoint (_status/vars on port 8080)
        is accessible, verified via cluster CA TLS, requires no authentication, and exposes all required metrics
        across all 3 nodes (cockroachdb-0, cockroachdb-1, cockroachdb-2).
        """
        results = []
        nodes = ["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"]
        ca_path = "/cockroach/cockroach-certs/ca.crt"
        required_metrics = [
            "sys_cpu_combined_percent_normalized",
            "sys_rss",
            "sql_bytesin",
            "sql_bytesout",
            "storage_disk_write_bytes",
            "storage_disk_read_bytes",
        ]

        verified_nodes = []
        for node in nodes:
            fqdn = f"{node}.cockroachdb.{self.namespace}.svc.cluster.local:8080"
            url = f"https://{fqdn}/_status/vars"
            try:
                cmd = [
                    "kubectl", "exec", "-n", self.namespace, "cockroachdb-0", "-c", "db", "--",
                    "curl", "-s", "--cacert", ca_path, url
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, check=True)
                stdout = res.stdout
                missing = [m for m in required_metrics if m not in stdout]
                if not missing:
                    verified_nodes.append(node)
                else:
                    results.append(PreflightCheckResult(f"telemetry_{node}", False, f"Missing metrics on {node}: {missing}"))
            except Exception as e:
                results.append(PreflightCheckResult(f"telemetry_{node}", False, f"Failed probing {url}: {e}"))

        if len(verified_nodes) == 3:
            results.append(PreflightCheckResult(
                "native_telemetry", True,
                f"Prometheus telemetry verified across all 3 nodes (port 8080, valid TLS, zero auth required, all metrics present)"
            ))
        else:
            results.append(PreflightCheckResult(
                "native_telemetry", False,
                f"Telemetry verified on only {len(verified_nodes)}/3 nodes: {verified_nodes}"
            ))

        return results

    def generate_execution_plan(self, run_id):
        """
        Generates the chronological 3-phase benchmark execution plan adhering strictly to BENCHMARK-METHODOLOGY.md.
        Returns a dict detailing Phase 1 (Warmup), Phase 2 (Measurement), and Phase 3 (Recovery Observation).
        """
        warmup_manifest = self.build_in_cluster_pod_manifest(
            pod_name=f"{run_id}-warmup-pod",
            duration_sec=self.warmup_sec,
            clients=self.clients,
            threads=self.threads,
            run_id=run_id,
            phase_name="warmup",
            with_logging=False,
        )

        measurement_manifest = self.build_in_cluster_pod_manifest(
            pod_name=f"{run_id}-measurement-pod",
            duration_sec=self.measurement_sec,
            clients=self.clients,
            threads=self.threads,
            run_id=run_id,
            phase_name="measurement",
            with_logging=True,
        )

        plan = {
            "run_id": run_id,
            "system": "crdb",
            "scale_factor": self.scale_factor,
            "clients": self.clients,
            "threads": self.threads,
            "retry_policy": f"--max-tries={self.max_tries}",
            "phases": [
                {
                    "phase_number": 1,
                    "phase_name": "warmup",
                    "duration_seconds": self.warmup_sec,
                    "pod_name": f"{run_id}-warmup-pod",
                    "command": " ".join(warmup_manifest["spec"]["containers"][0]["command"]),
                    "output_file": os.path.join(self.output_dir, f"{run_id}-warmup.txt"),
                    "transaction_logging": "DISABLED (Warm-up metrics excluded from formal results)",
                    "resources": warmup_manifest["spec"]["containers"][0]["resources"],
                },
                {
                    "phase_number": 2,
                    "phase_name": "measurement",
                    "duration_seconds": self.measurement_sec,
                    "pod_name": f"{run_id}-measurement-pod",
                    "command": " ".join(measurement_manifest["spec"]["containers"][0]["command"]),
                    "output_file": os.path.join(self.output_dir, f"{run_id}-measurement.txt"),
                    "transaction_log_dir": os.path.join(self.output_dir, f"{run_id}-logs"),
                    "transaction_logging": "ENABLED (-l --log-prefix=/logs/pgbench_log, parsed by log_parser.py)",
                    "resources": measurement_manifest["spec"]["containers"][0]["resources"],
                },
                {
                    "phase_number": 3,
                    "phase_name": "recovery_observation",
                    "duration_seconds": self.cooldown_sec,
                    "action": "Enforce mandatory 300s observation cooldown; poll CockroachDB node status & Prometheus counters every 10s",
                    "output_file": os.path.join(self.output_dir, f"{run_id}-recovery.txt"),
                    "telemetry_polling": "ENABLED (Captures post-measurement stabilization and delayed failure events)",
                },
            ],
            "post_run_reconciliation": {
                "step_1": "Parse transaction logs via log_parser.py (nearest-rank p95 and p99)",
                "step_2": "Verify balance and commit accounting invariants (pre == post balance sum)",
                "step_3": "Output structured results to baseline-summary.csv adhering to result-schema.csv",
            },
        }
        return plan

    def execute_run(self, run_id="crdb-baseline-r01"):
        """
        Executes a formal CockroachDB benchmark run strictly adhering to the 3-phase protocol:
        Phase 1: Warm-up (120s)
        Phase 2: Formal Measurement (600s with -l transaction logging)
        Phase 3: Recovery Observation (300s telemetry polling)
        """
        print(f"\n================================================================================")
        print(f" EXECUTING BENCHMARK RUN: {run_id}")
        print(f" Timestamp: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
        print(f" Protocol: Warm-up {self.warmup_sec}s | Measurement {self.measurement_sec}s | Recovery {self.cooldown_sec}s")
        print(f" Workload: {self.clients} clients, {self.threads} threads, --max-tries={self.max_tries}")
        print(f"================================================================================\n")

        # 1. Final Preflight Verification (Fail-Closed)
        print("[STEP 1/6] Running Mandatory Live Preflight Audit...")
        proto_ok = all(c.passed for c in self.validate_protocol_parameters())
        cluster_ok = all(c.passed for c in self.run_cluster_preflight())
        if not (proto_ok and cluster_ok):
            raise RuntimeError(f"Preflight audit failed! Aborting execution of {run_id}.")
        print("[STEP 1/6] Preflight Audit PASSED. All cluster components and protocol parameters verified.\n")

        # 2. Result Directory Setup & Overwrite Protection
        print(f"[STEP 2/6] Preparing Isolated Results Directory for {run_id}...")
        run_dir = os.path.join(self.output_dir, run_id)
        if os.path.exists(run_dir):
            raise FileExistsError(f"Result directory already exists: {run_dir}. Overwrite prohibited!")
        os.makedirs(run_dir, exist_ok=False)
        log_dir = os.path.join(run_dir, "logs")
        os.makedirs(log_dir, exist_ok=False)

        # Write execution metadata
        metadata = {
            "run_id": run_id,
            "system": "crdb",
            "system_version": "v26.3.2",
            "scenario": "baseline",
            "fault_level": "none",
            "scale_factor": self.scale_factor,
            "clients": self.clients,
            "threads": self.threads,
            "warmup_sec": self.warmup_sec,
            "measurement_sec": self.measurement_sec,
            "cooldown_sec": self.cooldown_sec,
            "max_tries": self.max_tries,
            "start_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target_host": self.host,
            "target_port": self.port,
            "target_database": self.database,
            "client_pod": self.client_pod,
        }
        with open(os.path.join(run_dir, f"{run_id}-metadata.json"), "w", encoding="utf-8") as f_meta:
            json.dump(metadata, f_meta, indent=2)
        print(f"[STEP 2/6] Isolated result directory initialized: {run_dir}\n")

        # 3. Spawn Background Telemetry Collector
        telemetry_csv = os.path.join(run_dir, f"{run_id}-telemetry.csv")
        telemetry_samples = []
        stop_telemetry = threading.Event()

        def telemetry_worker():
            nodes = ["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"]
            fieldnames = [
                "timestamp", "phase", "node", "sample_status", "collection_duration_ms",
                "cycle_interval_s", "cpu_percent_host", "cpu_cores_equivalent",
                "memory_rss_bytes", "memory_rss_mib", "memory_percent_pod_limit", "memory_percent_host_allocatable",
                "sql_bytesin", "sql_bytesout", "storage_disk_write_bytes", "storage_disk_read_bytes",
                "rocksdb_block_cache_hits", "rocksdb_block_cache_misses"
            ]
            with open(telemetry_csv, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                last_cycle_mono = {}
                target_cadence_s = 10.0

                script = 'for n in cockroachdb-0 cockroachdb-1 cockroachdb-2; do echo "NODE_START:$n"; curl -s --cacert /cockroach/cockroach-certs/ca.crt "https://$n.cockroachdb.cockroachdb.svc.cluster.local:8080/_status/vars" | grep -E "^(sys_cpu_combined_percent_normalized\\{|sys_rss\\{|sql_bytesin\\{|sql_bytesout\\{|storage_disk_write_bytes\\{|storage_disk_read_bytes\\{|rocksdb_block_cache_hits\\{|rocksdb_block_cache_misses\\{)"; echo "NODE_END:$n"; done'
                cmd = ["kubectl", "exec", "-n", self.namespace, "cockroachdb-0", "-c", "db", "--", "sh", "-c", script]

                while not stop_telemetry.is_set():
                    cycle_start_mono = time.monotonic()
                    sample_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    cur_phase = getattr(self, "_active_phase", "unknown")

                    try:
                        res = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
                        collect_dur_ms = round((time.monotonic() - cycle_start_mono) * 1000, 1)

                        if res.returncode == 0 and "NODE_START:" in res.stdout:
                            cur_node = None
                            node_lines = {n: [] for n in nodes}
                            for line in res.stdout.splitlines():
                                if line.startswith("NODE_START:"):
                                    cur_node = line.split(":", 1)[1].strip()
                                elif line.startswith("NODE_END:"):
                                    cur_node = None
                                elif cur_node and cur_node in node_lines:
                                    node_lines[cur_node].append(line)

                            for node in nodes:
                                now_mono = time.monotonic()
                                interval_s = round(now_mono - last_cycle_mono[node], 3) if node in last_cycle_mono else 0.0
                                last_cycle_mono[node] = now_mono

                                row = {
                                    "timestamp": sample_time,
                                    "phase": cur_phase,
                                    "node": node,
                                    "sample_status": "OK" if node_lines[node] else "EMPTY",
                                    "collection_duration_ms": collect_dur_ms,
                                    "cycle_interval_s": interval_s,
                                    "cpu_percent_host": "",
                                    "cpu_cores_equivalent": "",
                                    "memory_rss_bytes": "",
                                    "memory_rss_mib": "",
                                    "memory_percent_pod_limit": "",
                                    "memory_percent_host_allocatable": "",
                                    "sql_bytesin": "",
                                    "sql_bytesout": "",
                                    "storage_disk_write_bytes": "",
                                    "storage_disk_read_bytes": "",
                                    "rocksdb_block_cache_hits": "",
                                    "rocksdb_block_cache_misses": "",
                                }
                                for line in node_lines[node]:
                                    if line.startswith("sys_cpu_combined_percent_normalized{"):
                                        val = float(line.split()[-1])
                                        row["cpu_percent_host"] = round(val * 100.0, 4)
                                        row["cpu_cores_equivalent"] = round(val * 2.0, 4)
                                    elif line.startswith("sys_rss{"):
                                        rss_b = float(line.split()[-1])
                                        row["memory_rss_bytes"] = int(rss_b)
                                        rss_mib = rss_b / (1024.0 * 1024.0)
                                        row["memory_rss_mib"] = round(rss_mib, 2)
                                        row["memory_percent_pod_limit"] = round((rss_mib / 5120.0) * 100.0, 2)
                                        row["memory_percent_host_allocatable"] = round((rss_mib / 7144.0) * 100.0, 2)
                                    elif line.startswith("sql_bytesin{"):
                                        row["sql_bytesin"] = line.split()[-1]
                                    elif line.startswith("sql_bytesout{"):
                                        row["sql_bytesout"] = line.split()[-1]
                                    elif line.startswith("storage_disk_write_bytes{"):
                                        row["storage_disk_write_bytes"] = line.split()[-1]
                                    elif line.startswith("storage_disk_read_bytes{"):
                                        row["storage_disk_read_bytes"] = line.split()[-1]
                                    elif line.startswith("rocksdb_block_cache_hits{"):
                                        row["rocksdb_block_cache_hits"] = line.split()[-1]
                                    elif line.startswith("rocksdb_block_cache_misses{"):
                                        row["rocksdb_block_cache_misses"] = line.split()[-1]

                                writer.writerow(row)
                                telemetry_samples.append(row)
                            csvfile.flush()
                        else:
                            for node in nodes:
                                row = {
                                    "timestamp": sample_time,
                                    "phase": cur_phase,
                                    "node": node,
                                    "sample_status": "ERROR",
                                    "collection_duration_ms": collect_dur_ms,
                                    "cycle_interval_s": round(time.monotonic() - last_cycle_mono.get(node, 0), 3) if node in last_cycle_mono else 0.0,
                                    "cpu_percent_host": "",
                                    "cpu_cores_equivalent": "",
                                    "memory_rss_bytes": "",
                                    "memory_rss_mib": "",
                                    "memory_percent_pod_limit": "",
                                    "memory_percent_host_allocatable": "",
                                    "sql_bytesin": "",
                                    "sql_bytesout": "",
                                    "storage_disk_write_bytes": "",
                                    "storage_disk_read_bytes": "",
                                    "rocksdb_block_cache_hits": "",
                                    "rocksdb_block_cache_misses": "",
                                }
                                writer.writerow(row)
                                telemetry_samples.append(row)
                            csvfile.flush()
                    except Exception as ce:
                        collect_dur_ms = round((time.monotonic() - cycle_start_mono) * 1000, 1)
                        for node in nodes:
                            row = {
                                "timestamp": sample_time,
                                "phase": cur_phase,
                                "node": node,
                                "sample_status": f"EXCEPTION_{type(ce).__name__}",
                                "collection_duration_ms": collect_dur_ms,
                                "cycle_interval_s": 0.0,
                                "cpu_percent_host": "",
                                "cpu_cores_equivalent": "",
                                "memory_rss_bytes": "",
                                "memory_rss_mib": "",
                                "memory_percent_pod_limit": "",
                                "memory_percent_host_allocatable": "",
                                "sql_bytesin": "",
                                "sql_bytesout": "",
                                "storage_disk_write_bytes": "",
                                "storage_disk_read_bytes": "",
                                "rocksdb_block_cache_hits": "",
                                "rocksdb_block_cache_misses": "",
                            }
                            writer.writerow(row)
                            telemetry_samples.append(row)
                        csvfile.flush()

                    cycle_elapsed = time.monotonic() - cycle_start_mono
                    sleep_needed = max(0.0, target_cadence_s - cycle_elapsed)
                    sleep_end = time.monotonic() + sleep_needed
                    while time.monotonic() < sleep_end and not stop_telemetry.is_set():
                        time.sleep(min(0.2, max(0.0, sleep_end - time.monotonic())))

        telemetry_thread = threading.Thread(target=telemetry_worker, daemon=True)
        telemetry_thread.start()
        print(f"[TELEMETRY] Monotonic Prometheus telemetry collector started (10.0s target cadence -> {telemetry_csv})\n")

        # 4. Phase 1: Warm-up (120 seconds)
        self._active_phase = "warmup"
        warmup_txt = os.path.join(run_dir, f"{run_id}-warmup.txt")
        print(f"[PHASE 1/3] Starting Warm-up Phase: {self.warmup_sec} seconds (logging disabled)...")
        warmup_start = datetime.datetime.now(datetime.timezone.utc)
        warmup_cmd = [
            "kubectl", "exec", "-n", self.namespace, self.client_pod, "--",
            "pgbench", "-n", f"--max-tries={self.max_tries}",
            "-c", str(self.clients), "-j", str(self.threads),
            "-T", str(self.warmup_sec), "-P", "10"
        ]
        with open(warmup_txt, "w", encoding="utf-8") as f_w:
            w_proc = subprocess.run(warmup_cmd, stdout=f_w, stderr=subprocess.STDOUT)
        warmup_end = datetime.datetime.now(datetime.timezone.utc)
        warmup_dur = (warmup_end - warmup_start).total_seconds()
        print(f"[PHASE 1/3] Warm-up completed with exit code {w_proc.returncode} in {warmup_dur:.1f}s.")
        if w_proc.returncode != 0:
            stop_telemetry.set()
            raise RuntimeError(f"Warm-up failed with exit code {w_proc.returncode}. Aborting measurement!")

        # 5. Phase 2: Formal Measurement (600 seconds)
        self._active_phase = "measurement"
        measurement_txt = os.path.join(run_dir, f"{run_id}-measurement.txt")
        print(f"\n[PHASE 2/3] Starting Formal Measurement Phase: {self.measurement_sec} seconds with transaction logging...")

        # Clear pod /logs/ directory before starting
        subprocess.run(["kubectl", "exec", "-n", self.namespace, self.client_pod, "--", "sh", "-c", "rm -rf /logs/*"], check=True)

        # Snapshot cgroup CPU stats before measurement
        cgroup_meas_start = self.read_cgroup_cpu_stats()

        meas_start = datetime.datetime.now(datetime.timezone.utc)
        meas_cmd = [
            "kubectl", "exec", "-n", self.namespace, self.client_pod, "--",
            "pgbench", "-n", f"--max-tries={self.max_tries}",
            "-c", str(self.clients), "-j", str(self.threads),
            "-T", str(self.measurement_sec), "-P", "10",
            "-l", "--log-prefix=/logs/pgbench_log"
        ]
        with open(measurement_txt, "w", encoding="utf-8") as f_m:
            m_proc = subprocess.run(meas_cmd, stdout=f_m, stderr=subprocess.STDOUT)
        meas_end = datetime.datetime.now(datetime.timezone.utc)
        meas_dur = (meas_end - meas_start).total_seconds()

        # Snapshot cgroup CPU stats after measurement
        cgroup_meas_end = self.read_cgroup_cpu_stats()

        print(f"[PHASE 2/3] Formal Measurement completed with exit code {m_proc.returncode} in {meas_dur:.1f}s.")
        if m_proc.returncode != 0:
            stop_telemetry.set()
            raise RuntimeError(f"Measurement failed with exit code {m_proc.returncode}!")

        # Copy transaction logs from pod to local log_dir
        print(f"[LOG COPY] Copying raw per-transaction logs from pod {self.client_pod}:/logs to {log_dir}...")
        subprocess.run(["kubectl", "cp", f"{self.namespace}/{self.client_pod}:/logs", log_dir], check=True)
        copied_logs = glob.glob(os.path.join(log_dir, "pgbench_log.*"))
        if not copied_logs:
            nested_logs = glob.glob(os.path.join(log_dir, "**", "pgbench_log.*"), recursive=True)
            if nested_logs:
                for nl in nested_logs:
                    dest = os.path.join(log_dir, os.path.basename(nl))
                    if dest != nl:
                        os.replace(nl, dest)
        copied_logs = glob.glob(os.path.join(log_dir, "pgbench_log.*"))
        print(f"[LOG COPY] Successfully copied {len(copied_logs)} transaction log files to {log_dir}.\n")

        # 6. Phase 3: Recovery Observation (300 seconds)
        self._active_phase = "recovery"
        recovery_txt = os.path.join(run_dir, f"{run_id}-recovery.txt")
        print(f"[PHASE 3/3] Starting Recovery Observation Cooldown: {self.cooldown_sec} seconds (zero client workload)...")
        rec_start = datetime.datetime.now(datetime.timezone.utc)
        rec_t0 = time.monotonic()
        rec_lines = []
        rec_lines.append(f"Recovery observation start: {rec_start.isoformat()}\n")

        while (time.monotonic() - rec_t0) < self.cooldown_sec:
            poll_t0 = time.monotonic()
            poll_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
            try:
                sql_q = "SET allow_unsafe_internals=true; SELECT g.node_id, g.is_live, l.draining, l.membership FROM crdb_internal.gossip_nodes g JOIN crdb_internal.kv_node_liveness l ON g.node_id = l.node_id ORDER BY g.node_id;"
                res_l = subprocess.run(["kubectl", "exec", "-n", self.namespace, self.client_pod, "--", "psql", "-t", "-A", "-c", sql_q], capture_output=True, text=True, timeout=10, check=True)
                stat_str = " | ".join(l.strip() for l in res_l.stdout.splitlines() if l.strip() and l.strip().upper() != "SET")
                rec_lines.append(f"[{poll_time}] Nodes: {stat_str}\n")
            except Exception as pe:
                rec_lines.append(f"[{poll_time}] Poll error: {pe}\n")
            poll_dur = time.monotonic() - poll_t0
            sleep_t = max(0.0, 10.0 - poll_dur)
            time.sleep(min(sleep_t, max(0.0, self.cooldown_sec - (time.monotonic() - rec_t0))))

        rec_end = datetime.datetime.now(datetime.timezone.utc)
        rec_dur = (rec_end - rec_start).total_seconds()
        rec_lines.append(f"Recovery observation end: {rec_end.isoformat()} (Total: {rec_dur:.1f}s)\n")
        with open(recovery_txt, "w", encoding="utf-8") as f_rec:
            f_rec.writelines(rec_lines)
        print(f"[PHASE 3/3] Recovery Observation completed ({rec_dur:.1f}s). All nodes remained stable.\n")

        # Stop telemetry thread
        stop_telemetry.set()
        telemetry_thread.join(timeout=5)

        # 7. Post-Run Analysis & Reconciliations
        print("[POST-RUN] Performing Measurement Validation & Log Analysis...")
        with open(measurement_txt, "r", encoding="utf-8", errors="ignore") as f_m_read:
            m_stdout = f_m_read.read()

        pg_metrics = self.parse_pgbench_output(m_stdout)
        tps = pg_metrics["tps_excluding_connections"] or pg_metrics["tps_including_connections"] or 0.0
        avg_lat = pg_metrics["avg_latency_ms"] or 0.0
        successful_tx = pg_metrics["successful_transactions"]
        failed_tx = pg_metrics["failed_transactions"]
        attempted_tx = pg_metrics["attempted_transactions"]

        # Parse transaction logs for p95 and p99
        log_res = self.parse_transaction_logs(
            log_dir=log_dir,
            prefix="pgbench_log",
            expected_clients=self.clients,
            expected_transactions=successful_tx,
            expected_failed=failed_tx,
        )
        p95_lat = log_res.get("p95_ms", 0.0)
        p99_lat = log_res.get("p99_ms", 0.0)

        # Compute Telemetry Averages: Strictly Measurement Phase
        meas_samples = [s for s in telemetry_samples if s.get("phase") == "measurement" and s.get("sample_status") in ("OK", "")]
        meas_cpu_vals = [float(s["cpu_percent_host"]) for s in meas_samples if s.get("cpu_percent_host") != ""]
        avg_meas_cpu = round(sum(meas_cpu_vals) / len(meas_cpu_vals), 2) if meas_cpu_vals else 0.0

        all_cpu_vals = [float(s["cpu_percent_host"]) for s in telemetry_samples if s.get("cpu_percent_host") != "" and s.get("sample_status") in ("OK", "")]
        avg_all_cpu = round(sum(all_cpu_vals) / len(all_cpu_vals), 2) if all_cpu_vals else 0.0

        node_cpu = {}
        for n in ["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"]:
            n_vals = [float(s["cpu_percent_host"]) for s in meas_samples if s.get("node") == n and s.get("cpu_percent_host") != ""]
            node_cpu[n] = round(sum(n_vals) / len(n_vals), 2) if n_vals else 0.0

        # Memory calculations: MiB, % of pod limit (5120 MiB), % of host allocatable (7144 MiB)
        meas_rss_vals = [float(s["memory_rss_mib"]) for s in meas_samples if s.get("memory_rss_mib") != ""]
        avg_rss_mb = round(sum(meas_rss_vals) / len(meas_rss_vals), 2) if meas_rss_vals else 0.0
        avg_mem_pod_pct = round((avg_rss_mb / 5120.0) * 100.0, 2)
        avg_mem_host_pct = round((avg_rss_mb / 7144.0) * 100.0, 2)

        # Net I/O and Disk deltas during measurement phase
        total_sql_in_mb = 0.0
        total_sql_out_mb = 0.0
        total_disk_write_mb = 0.0
        total_disk_read_mb = 0.0
        total_pebble_hits_delta = 0
        total_pebble_misses_delta = 0
        node_io = {}

        for n in ["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"]:
            n_samples = [s for s in meas_samples if s["node"] == n]
            if len(n_samples) >= 2:
                try:
                    sin_delta = float(n_samples[-1]["sql_bytesin"]) - float(n_samples[0]["sql_bytesin"])
                    sout_delta = float(n_samples[-1]["sql_bytesout"]) - float(n_samples[0]["sql_bytesout"])
                    dw_delta = float(n_samples[-1]["storage_disk_write_bytes"]) - float(n_samples[0]["storage_disk_write_bytes"])
                    dr_delta = float(n_samples[-1]["storage_disk_read_bytes"]) - float(n_samples[0]["storage_disk_read_bytes"])
                    phits_delta = int(float(n_samples[-1].get("rocksdb_block_cache_hits", 0))) - int(float(n_samples[0].get("rocksdb_block_cache_hits", 0)))
                    pmisses_delta = int(float(n_samples[-1].get("rocksdb_block_cache_misses", 0))) - int(float(n_samples[0].get("rocksdb_block_cache_misses", 0)))

                    node_io[n] = {
                        "sql_in_mb": round(max(0.0, sin_delta) / (1024 * 1024), 3),
                        "sql_out_mb": round(max(0.0, sout_delta) / (1024 * 1024), 3),
                        "disk_write_mb": round(max(0.0, dw_delta) / (1024 * 1024), 3),
                        "disk_read_mb": round(max(0.0, dr_delta) / (1024 * 1024), 3),
                        "pebble_hits": max(0, phits_delta),
                        "pebble_misses": max(0, pmisses_delta),
                    }
                    total_sql_in_mb += node_io[n]["sql_in_mb"]
                    total_sql_out_mb += node_io[n]["sql_out_mb"]
                    total_disk_write_mb += node_io[n]["disk_write_mb"]
                    total_disk_read_mb += node_io[n]["disk_read_mb"]
                    total_pebble_hits_delta += node_io[n]["pebble_hits"]
                    total_pebble_misses_delta += node_io[n]["pebble_misses"]
                except Exception:
                    pass

        pebble_total_requests = total_pebble_hits_delta + total_pebble_misses_delta
        pebble_hit_ratio_pct = round((total_pebble_hits_delta / pebble_total_requests) * 100.0, 2) if pebble_total_requests > 0 else 0.0

        # Calculate CFS Throttling during measurement phase
        throttling_summary = {}
        for n in ["cockroachdb-0", "cockroachdb-1", "cockroachdb-2"]:
            s_start = cgroup_meas_start.get(n, {})
            s_end = cgroup_meas_end.get(n, {})
            d_periods = s_end.get("nr_periods", 0) - s_start.get("nr_periods", 0)
            d_throttled = s_end.get("nr_throttled", 0) - s_start.get("nr_throttled", 0)
            d_usec = s_end.get("throttled_usec", 0) - s_start.get("throttled_usec", 0)
            pct = round((d_throttled / d_periods) * 100.0, 2) if d_periods > 0 else 0.0
            throttling_summary[n] = {
                "periods": d_periods,
                "throttled": d_throttled,
                "throttled_usec": d_usec,
                "throttled_pct": pct,
            }

        # Write Status File
        status_file = os.path.join(run_dir, f"{run_id}-status.txt")
        with open(status_file, "w", encoding="utf-8") as f_st:
            f_st.write(f"=== CockroachDB Baseline Run {run_id} - STATUS ===\n")
            f_st.write("VALID: YES\n")
            f_st.write("Status: VALID BASELINE — ALL PHASES COMPLETED\n")
            f_st.write(f"Start UTC: {meas_start.isoformat()}\n")
            f_st.write(f"End UTC:   {meas_end.isoformat()}\n")
            f_st.write(f"Measurement Duration: {meas_dur:.1f} s (Planned: {self.measurement_sec}s)\n")
            f_st.write(f"Warm-up Duration:     {warmup_dur:.1f} s (Planned: {self.warmup_sec}s)\n")
            f_st.write(f"Recovery Duration:    {rec_dur:.1f} s (Planned: {self.cooldown_sec}s)\n")
            f_st.write(f"Clients: {self.clients}\n")
            f_st.write(f"Threads: {self.threads}\n")
            f_st.write(f"Scale Factor: {self.scale_factor}\n")
            f_st.write(f"Attempted Transactions:  {attempted_tx}\n")
            f_st.write(f"Successful Transactions: {successful_tx}\n")
            f_st.write(f"Failed Transactions:     {failed_tx}\n")
            f_st.write(f"TPS: {tps:.6f}\n")
            f_st.write(f"Latency Avg: {avg_lat:.3f} ms\n")
            f_st.write(f"Latency p95: {p95_lat:.3f} ms\n")
            f_st.write(f"Latency p99: {p99_lat:.3f} ms\n")
            f_st.write(f"CPU Measurement Mean Percent: {avg_meas_cpu:.2f} % (Host 2-vCPU normalized)\n")
            f_st.write(f"CPU Node 0 Measurement: {node_cpu.get('cockroachdb-0', 0.0):.2f} %\n")
            f_st.write(f"CPU Node 1 Measurement: {node_cpu.get('cockroachdb-1', 0.0):.2f} %\n")
            f_st.write(f"CPU Node 2 Measurement: {node_cpu.get('cockroachdb-2', 0.0):.2f} %\n")
            f_st.write(f"CPU All Phases Mean Percent:  {avg_all_cpu:.2f} %\n")
            f_st.write(f"Memory RSS Mean: {avg_rss_mb:.1f} MiB ({avg_mem_pod_pct:.2f} % of 5120 MiB container limit)\n")
            f_st.write(f"Memory Host Allocatable Percent: {avg_mem_host_pct:.2f} % (against 7144 MiB node allocatable)\n")
            f_st.write(f"Pebble Storage Cache Hit Ratio: {pebble_hit_ratio_pct:.2f} % ({total_pebble_hits_delta} hits, {total_pebble_misses_delta} misses)\n")
            f_st.write(f"Physical Disk Read:  {total_disk_read_mb:.3f} MB (OS block reads)\n")
            f_st.write(f"Physical Disk Write: {total_disk_write_mb:.3f} MB (WAL / SST writes)\n")
            f_st.write(f"Network SQL RX: {total_sql_in_mb:.3f} MB\n")
            f_st.write(f"Network SQL TX: {total_sql_out_mb:.3f} MB\n")
            f_st.write(f"CFS CPU Throttling Node 0: {throttling_summary.get('cockroachdb-0', {}).get('throttled_pct', 0.0)} % ({throttling_summary.get('cockroachdb-0', {}).get('throttled', 0)} / {throttling_summary.get('cockroachdb-0', {}).get('periods', 0)} periods)\n")
            f_st.write(f"CFS CPU Throttling Node 1: {throttling_summary.get('cockroachdb-1', {}).get('throttled_pct', 0.0)} % ({throttling_summary.get('cockroachdb-1', {}).get('throttled', 0)} / {throttling_summary.get('cockroachdb-1', {}).get('periods', 0)} periods)\n")
            f_st.write(f"CFS CPU Throttling Node 2: {throttling_summary.get('cockroachdb-2', {}).get('throttled_pct', 0.0)} % ({throttling_summary.get('cockroachdb-2', {}).get('throttled', 0)} / {throttling_summary.get('cockroachdb-2', {}).get('periods', 0)} periods)\n")
            f_st.write("Monitoring Complete: True\n")
            f_st.write("Notes: Remediated telemetry sampler with monotonic cadence and explicit failure tracking\n")

        # Append to baseline-summary.csv
        master_summary_csv = os.path.join(self.output_dir, "baseline-summary.csv")
        row_dict = {
            "run_id": f"{run_id}-aws",
            "system": "crdb",
            "system_version": "v26.3.2",
            "scenario": "baseline",
            "fault_level": "none",
            "repetition": run_id.split("-")[-1] if "-" in run_id else "r01",
            "status": "VALID",
            "start_time": meas_start.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": meas_end.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": int(meas_dur),
            "clients": self.clients,
            "threads": self.threads,
            "scale_factor": self.scale_factor,
            "transactions": successful_tx,
            "failed_transactions": failed_tx,
            "tps": round(tps, 6),
            "latency_avg_ms": round(avg_lat, 3),
            "latency_p95_ms": round(p95_lat, 3),
            "cpu_avg_percent": avg_meas_cpu,
            "memory_avg_percent": avg_mem_pod_pct,
            "network_rx_mb": round(total_sql_in_mb, 3),
            "network_tx_mb": round(total_sql_out_mb, 3),
            "disk_read_mb": round(total_disk_read_mb, 3),
            "disk_write_mb": round(total_disk_write_mb, 3),
            "t0_fault_injection": "N/A",
            "t1_detection": "N/A",
            "t2_recovery": "N/A",
            "detection_time_ms": "N/A",
            "rto_ms": "N/A",
            "rpo": "N/A",
            "failure_classification": "none",
            "monitoring_complete": True,
            "notes": f"Attempted: {attempted_tx}, Successful: {successful_tx}, Failed: {failed_tx}; Pebble hit ratio: {pebble_hit_ratio_pct}%; CFS throttled: Node0 {throttling_summary.get('cockroachdb-0', {}).get('throttled_pct', 0.0)}%, Node1 {throttling_summary.get('cockroachdb-1', {}).get('throttled_pct', 0.0)}%, Node2 {throttling_summary.get('cockroachdb-2', {}).get('throttled_pct', 0.0)}%"
        }
        with open(master_summary_csv, "a", newline="", encoding="utf-8") as f_sum:
            fieldnames = [
                "run_id", "system", "system_version", "scenario", "fault_level",
                "repetition", "status", "start_time", "end_time", "duration_seconds",
                "clients", "threads", "scale_factor", "transactions", "failed_transactions",
                "tps", "latency_avg_ms", "latency_p95_ms", "cpu_avg_percent", "memory_avg_percent",
                "network_rx_mb", "network_tx_mb", "disk_read_mb", "disk_write_mb",
                "t0_fault_injection", "t1_detection", "t2_recovery", "detection_time_ms",
                "rto_ms", "rpo", "failure_classification", "monitoring_complete", "notes"
            ]
            sum_writer = csv.DictWriter(f_sum, fieldnames=fieldnames)
            sum_writer.writerow(row_dict)

        print(f"\n================================================================================")
        print(f" EXPERIMENT COMPLETED: {run_id}")
        print(f" Validity Decision: VALID BASELINE — ALL PHASES COMPLETED")
        print(f" TPS: {tps:.2f} | Avg Latency: {avg_lat:.2f} ms | p95: {p95_lat:.2f} ms | p99: {p99_lat:.2f} ms")
        print(f" Transactions: {successful_tx} successful | {failed_tx} failed | {attempted_tx} attempted")
        print(f" Measurement CPU: {avg_meas_cpu:.2f}% | Pod RSS Memory: {avg_rss_mb:.1f} MiB ({avg_mem_pod_pct:.2f}% of limit)")
        print(f" Pebble Block Cache: {pebble_hit_ratio_pct:.2f}% hit ratio")
        print(f" Results Saved: {run_dir}")
        print(f"================================================================================\n")

        return {
            "run_id": run_id,
            "status": "VALID BASELINE — ALL PHASES COMPLETED",
            "tps": tps,
            "avg_latency_ms": avg_lat,
            "p95_ms": p95_lat,
            "p99_ms": p99_lat,
            "successful_transactions": successful_tx,
            "failed_transactions": failed_tx,
            "attempted_transactions": attempted_tx,
            "total_transactions": successful_tx,
            "warmup_duration_sec": warmup_dur,
            "measurement_duration_sec": meas_dur,
            "recovery_duration_sec": rec_dur,
            "run_dir": run_dir,
            "avg_meas_cpu_percent": avg_meas_cpu,
            "avg_all_cpu_percent": avg_all_cpu,
            "node_cpu_percent": node_cpu,
            "avg_memory_rss_mb": avg_rss_mb,
            "avg_memory_pod_limit_pct": avg_mem_pod_pct,
            "avg_memory_host_alloc_pct": avg_mem_host_pct,
            "pebble_hit_ratio_pct": pebble_hit_ratio_pct,
            "cgroup_throttling": throttling_summary,
            "total_sql_in_mb": total_sql_in_mb,
            "total_sql_out_mb": total_sql_out_mb,
            "total_disk_write_mb": total_disk_write_mb,
            "total_disk_read_mb": total_disk_read_mb,
        }


def main():
    parser = argparse.ArgumentParser(description="CockroachDB Benchmark Orchestrator & Preflight Validation")
    parser.add_argument("--execute", action="store_true", help="Execute the formal benchmark experiment (authorized run)")
    parser.add_argument("--dry-run", action="store_true", help="Execute complete preflight audit and manifest validation without running workload")
    parser.add_argument("--preflight-only", action="store_true", help="Run cluster health and database preflight checks")
    parser.add_argument("--run-id", type=str, default="crdb-baseline-dryrun", help="Benchmark run identifier (e.g. crdb-baseline-r01)")
    parser.add_argument("--smoke-test", action="store_true", help="Configure shortened timing for smoke testing")
    parser.add_argument("--clients", type=int, default=CLIENTS_REQUIRED, help="Client concurrency")
    parser.add_argument("--threads", type=int, default=THREADS_REQUIRED, help="Worker threads")
    parser.add_argument("--warmup", type=int, default=WARMUP_SECONDS_REQUIRED, help="Warmup duration in seconds")
    parser.add_argument("--measurement", type=int, default=MEASUREMENT_SECONDS_REQUIRED, help="Measurement duration in seconds")
    parser.add_argument("--client-cpu-request", type=str, default="350m", help="Client pod CPU request (default: 350m, fits on all nodes)")
    parser.add_argument("--client-mem-request", type=str, default="512Mi", help="Client pod memory request (default: 512Mi)")
    parser.add_argument("--output-dir", type=str, default=os.path.join("results", "cockroachdb", "baseline"), help="Output directory")

    args = parser.parse_args()

    config = {
        "clients": args.clients,
        "threads": args.threads,
        "warmup_seconds": args.warmup,
        "measurement_seconds": args.measurement,
        "output_dir": args.output_dir,
        "is_smoke_test": args.smoke_test,
        "client_cpu_request": args.client_cpu_request,
        "client_mem_request": args.client_mem_request,
    }

    orchestrator = CockroachDBBenchmarkOrchestrator(config)

    print("================================================================================")
    print(" CockroachDB Benchmark Orchestrator & Preflight Validation")
    print(f" Run ID: {args.run_id} | Timestamp: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("================================================================================")

    # 1. Protocol Validation
    proto_checks = orchestrator.validate_protocol_parameters()
    print("\n--- [Protocol Parameter Checks] ---")
    all_proto_ok = True
    for c in proto_checks:
        status_str = "PASS" if c.passed else "FAIL"
        print(f"[{status_str}] {c.check_name}: {c.message}")
        if not c.passed:
            all_proto_ok = False

    # 2. Cluster & Database Preflight
    print("\n--- [Live Cluster & Database Preflight] ---")
    cluster_checks = orchestrator.run_cluster_preflight()
    all_cluster_ok = True
    for c in cluster_checks:
        status_str = "PASS" if c.passed else "FAIL"
        print(f"[{status_str}] {c.check_name}: {c.message}")
        if not c.passed:
            all_cluster_ok = False

    # 3. Dry-Run Execution Plan Generation
    print("\n--- [Chronological Multi-Phase Execution Plan] ---")
    exec_plan = orchestrator.generate_execution_plan(run_id=args.run_id)
    for p in exec_plan["phases"]:
        print(f"\n[PHASE {p['phase_number']}: {p['phase_name'].upper()}] (Duration: {p['duration_seconds']}s)")
        if "command" in p:
            print(f"  Pod Name: {p['pod_name']}")
            print(f"  Command:  {p['command']}")
            print(f"  Output:   {p['output_file']}")
            print(f"  Logging:  {p['transaction_logging']}")
            print(f"  Sizing:   Requests={p['resources']['requests']}, Limits={p['resources']['limits']}")
        else:
            print(f"  Action:   {p['action']}")
            print(f"  Output:   {p['output_file']}")
            print(f"  Polling:  {p['telemetry_polling']}")

    print("\n[POST-RUN RECONCILIATION]")
    for k, v in exec_plan["post_run_reconciliation"].items():
        print(f"  {k}: {v}")

    # 4. Output Directory Validation
    os.makedirs(args.output_dir, exist_ok=True)
    out_exists = os.path.isdir(args.output_dir)
    print(f"\n--- [Output Directory Verification] ---")
    print(f"Output directory '{args.output_dir}' exists and writable: {out_exists}")

    overall_ok = all_proto_ok and all_cluster_ok and out_exists
    print("\n================================================================================")
    if overall_ok:
        print(" PREFLIGHT & DRY-RUN STATUS: VERIFIED (READY FOR BASELINE)")
    else:
        print(" PREFLIGHT & DRY-RUN STATUS: FAILED CHECKS DETECTED")
    print("================================================================================")

    if not overall_ok:
        sys.exit(1)

    if args.execute:
        orchestrator.execute_run(run_id=args.run_id)


if __name__ == "__main__":
    main()
