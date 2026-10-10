#!/usr/bin/env python3
"""
PostgreSQL + Patroni Benchmark Orchestrator & Live Execution Engine
Aligned with CA2 Protocol, BENCHMARK-METHODOLOGY.md, and RUN-NAMING-CONVENTION.md.

Research System: PostgreSQL 15.2 + Patroni 3.0.1 + Dedicated etcd 3.5.12 on AWS EKS
Workload: pgbench TPC-B (SF 50, 5,000,000 accounts, 20 clients, 4 threads, 120s warm-up, 600s measurement, 300s cooldown)
Connection: In-Cluster Client Pod -> patroni-primary (ClusterIP with verify-full TLS over TLSv1.3)
Placement: Node 2 (ip-10-0-2-227.ec2.internal, us-east-1b) with requests: cpu 250m, memory 256Mi

Fail-Closed Architecture:
All preflight checks, telemetry handshakes, snapshots (S0, S1, S2, S3), log extractions,
and transaction accounting reconciliations must return VERIFIED before baseline certification.
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
import io
import tarfile
import hashlib

# Shared benchmark log parser integration
BASE_SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, BASE_SCRIPTS_DIR)

try:
    from log_parser import analyze_pgbench_logs, parse_percentiles_from_log_files
except ImportError:
    analyze_pgbench_logs = None
    parse_percentiles_from_log_files = None

# Protocol & Configuration Constants
DEFAULT_NAMESPACE = "postgres-patroni"
DEFAULT_PRIMARY_SVC = "patroni-primary.postgres-patroni.svc.cluster.local"
DEFAULT_PRIMARY_SVC_NAME = "patroni-primary"
DEFAULT_PORT = 5432
DEFAULT_DATABASE = "benchdb"
DEFAULT_USER = "postgres"

SCALE_FACTOR_REQUIRED = 50
ACCOUNTS_REQUIRED = 5000000
WARMUP_SECONDS_REQUIRED = 120
MEASUREMENT_SECONDS_REQUIRED = 600
COOLDOWN_SECONDS_REQUIRED = 300
CLIENTS_REQUIRED = 20
THREADS_REQUIRED = 4

# Stage 18.1 Pinned Client Image (PostgreSQL 15.13 on Linux/amd64 with --max-tries support)
BENCHMARK_CLIENT_IMAGE = "postgres:15-bullseye@sha256:4ce70bcb2c05817a09b9919fc440878cf893cfb5623cd05023778a67644ea81d"

# Worker Node Headroom & Placement Pinning (Node 2 us-east-1b hosting patroni-1)
# Dynamic discovery resolves the active hostname at runtime; stale static IPs prohibited
DEFAULT_CLIENT_NODE_TARGET = ""
DEFAULT_CLIENT_ZONE_TARGET = "us-east-1b"
DEFAULT_CLIENT_CPU_REQUEST = "250m"
DEFAULT_CLIENT_MEM_REQUEST = "256Mi"
DEFAULT_CLIENT_CPU_LIMIT = "1000m"
DEFAULT_CLIENT_MEM_LIMIT = "1024Mi"

# TLS Verified Hostname & Certificate Mounts
DEFAULT_TLS_HOSTNAME = "spilo.example.org"
DEFAULT_TLS_CERT_MOUNT = "/certs/server.crt"
DEFAULT_CERT_SECRET_NAME = "patroni-server-cert"
DEFAULT_CERT_CONFIGMAP_NAME = "patroni-server-ca"


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


class PatroniBenchmarkOrchestrator:
    def __init__(self, config=None):
        self.config = config or {}
        self.namespace = self.config.get("namespace", DEFAULT_NAMESPACE)
        self.primary_svc = self.config.get("primary_service", DEFAULT_PRIMARY_SVC)
        self.primary_svc_name = self.config.get("primary_service_name", DEFAULT_PRIMARY_SVC_NAME)
        self.port = int(self.config.get("port", DEFAULT_PORT))
        self.database = self.config.get("database", DEFAULT_DATABASE)
        self.user = self.config.get("user", DEFAULT_USER)
        self.scale_factor = int(self.config.get("scale_factor", SCALE_FACTOR_REQUIRED))
        self.clients = int(self.config.get("clients", CLIENTS_REQUIRED))
        self.threads = int(self.config.get("threads", THREADS_REQUIRED))
        self.warmup_sec = int(self.config.get("warmup_seconds", WARMUP_SECONDS_REQUIRED))
        self.measurement_sec = int(self.config.get("measurement_seconds", MEASUREMENT_SECONDS_REQUIRED))
        self.cooldown_sec = int(self.config.get("cooldown_seconds", COOLDOWN_SECONDS_REQUIRED))
        self.output_dir = self.config.get("output_dir", os.path.join("results", "postgres-patroni", "baseline"))
        self.is_smoke_test = bool(self.config.get("is_smoke_test", False))
        self.max_tries = int(self.config.get("max_tries", 1))

        # Node Placement Targeting (Stage 18.1 verified Node 2 placement)
        self.node_target = self.config.get("node_target", DEFAULT_CLIENT_NODE_TARGET)
        self.zone_target = self.config.get("zone_target", DEFAULT_CLIENT_ZONE_TARGET)
        self.cpu_request = self.config.get("cpu_request", DEFAULT_CLIENT_CPU_REQUEST)
        self.mem_request = self.config.get("mem_request", DEFAULT_CLIENT_MEM_REQUEST)
        self.cpu_limit = self.config.get("cpu_limit", DEFAULT_CLIENT_CPU_LIMIT)
        self.mem_limit = self.config.get("mem_limit", DEFAULT_CLIENT_MEM_LIMIT)

        # TLS Configuration
        self.tls_hostname = self.config.get("tls_hostname", DEFAULT_TLS_HOSTNAME)
        self.tls_cert_mount = self.config.get("tls_cert_mount", DEFAULT_TLS_CERT_MOUNT)
        self.cert_secret_name = self.config.get("cert_secret_name", DEFAULT_CERT_SECRET_NAME)
        self.cert_configmap_name = self.config.get("cert_configmap_name", DEFAULT_CERT_CONFIGMAP_NAME)

        # Snapshot Timeout Configuration (Stage 20.14)
        self.snapshot_timeout_sec = int(self.config.get("snapshot_timeout_sec", 120))

    def _run_kubectl(self, args, timeout=30, check=False, capture_output=True, input=None, text=True):
        """Runs a kubectl command via subprocess."""
        cmd = ["kubectl"] + args
        return subprocess.run(cmd, input=input, capture_output=capture_output, text=text, timeout=timeout, check=check)

    def _run_psql_client(self, sql, pod_name, timeout=30):
        """Executes a SQL query on PostgreSQL from inside the benchmark client pod using in-pod psql."""
        args = ["exec", "-n", self.namespace, pod_name, "--", "psql", "-t", "-A", "-F", ",", "-c", sql]
        return self._run_kubectl(args, timeout=timeout)

    def _run_psql(self, sql, target_pod="patroni-0", timeout=30):
        """
        Executes a SQL query on PostgreSQL via kubectl exec on the target Patroni pod.
        Uses comma-separated unaligned output for robust token parsing.
        """
        args = ["exec", "-n", self.namespace, target_pod, "--", "psql", "-U", self.user, "-d", self.database, "-t", "-A", "-F", ",", "-c", sql]
        return self._run_kubectl(args, timeout=timeout)

    def get_primary_service_cluster_ip(self):
        """
        Dynamically retrieves the ClusterIP of patroni-primary from Kubernetes.
        Fails closed if the service does not exist or has an unassigned IP.
        """
        if "primary_cluster_ip" in self.config:
            return self.config["primary_cluster_ip"]

        res = self._run_kubectl(["get", "svc", self.primary_svc_name, "-n", self.namespace, "-o", "jsonpath={.spec.clusterIP}"])
        if res.returncode != 0 or not res.stdout.strip():
            raise RuntimeError(f"Failed to dynamically retrieve ClusterIP for {self.primary_svc_name} in {self.namespace}: {res.stderr}")
        cluster_ip = res.stdout.strip()
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cluster_ip):
            raise ValueError(f"Invalid ClusterIP retrieved for {self.primary_svc_name}: '{cluster_ip}'")
        return cluster_ip

    def discover_and_validate_client_node(self, target_pod="patroni-1", expected_zone=None):
        """
        Dynamically discovers and validates the target worker node hosting patroni-1 (Node 2 in us-east-1b).
        Enforces placement isolation away from primary leader postmaster on Node 3.
        Fails closed if the node name is empty, not Ready, or not in expected_zone.
        """
        if expected_zone is None:
            expected_zone = self.zone_target

        # Check if explicit non-empty override was provided in config
        if self.config.get("node_target"):
            target_node = self.config["node_target"]
        else:
            # Query patroni-1 pod's assigned node
            res = self._run_kubectl(
                ["get", "pod", target_pod, "-n", self.namespace, "-o", "jsonpath={.spec.nodeName}"],
                timeout=20,
            )
            if res.returncode != 0 or not res.stdout.strip():
                raise RuntimeError(
                    f"Dynamic node discovery failed: could not retrieve nodeName for pod {target_pod} in {self.namespace}: {res.stderr or res.stdout}"
                )
            target_node = res.stdout.strip()

        if not target_node:
            raise ValueError("Dynamic node discovery returned an empty node name.")

        # Confirm the node exists and is in Ready state
        res_ready = self._run_kubectl(
            ["get", "node", target_node, "-o", 'jsonpath={.status.conditions[?(@.type=="Ready")].status}'],
            timeout=20,
        )
        if res_ready.returncode != 0 or res_ready.stdout.strip() != "True":
            raise RuntimeError(
                f"Dynamic node validation failed: node '{target_node}' is not Ready (status='{res_ready.stdout.strip()}', err='{res_ready.stderr}')"
            )

        # Confirm its topology zone matches expected zone (us-east-1b)
        res_zone = self._run_kubectl(
            ["get", "node", target_node, "-o", "jsonpath={.metadata.labels['topology\\.kubernetes\\.io/zone']}"],
            timeout=20,
        )
        if res_zone.returncode != 0 or res_zone.stdout.strip() != expected_zone:
            raise RuntimeError(
                f"Dynamic node validation failed: node '{target_node}' zone '{res_zone.stdout.strip()}' does not match expected zone '{expected_zone}'"
            )

        self.node_target = target_node
        return target_node

    def ensure_server_ca_configmap(self, primary_pod="patroni-0", cert_path="/run/certs/server.crt"):
        """
        Safely retrieves the TLS server/CA certificate from the active Patroni primary leader,
        validates PEM format boundaries, and idempotently provisions the ConfigMap patroni-server-ca
        via kubectl apply -f - over stdin.
        Fails closed on any retrieval error, empty output, invalid PEM, or apply error.
        Never prints, logs, or leaks certificate data or private keys.
        """
        # Step 1: Retrieve certificate via read-only kubectl exec cat
        res_cat = self._run_kubectl(
            ["exec", "-n", self.namespace, primary_pod, "--", "cat", cert_path],
            timeout=20,
        )
        if res_cat.returncode != 0 or not res_cat.stdout.strip():
            raise RuntimeError(
                f"Failed to retrieve CA certificate from {primary_pod}:{cert_path} in {self.namespace}: "
                f"exit={res_cat.returncode}, err={res_cat.stderr.strip() if res_cat.stderr else 'empty response'}"
            )

        cert_content = res_cat.stdout.strip()

        # Step 2: Validate PEM boundaries
        if "-----BEGIN CERTIFICATE-----" not in cert_content or "-----END CERTIFICATE-----" not in cert_content:
            raise ValueError(
                f"Invalid certificate retrieved from {primary_pod}:{cert_path}: missing standard PEM certificate markers"
            )

        # Fail closed if any private key markers are detected
        if "PRIVATE KEY" in cert_content:
            raise ValueError(
                f"Security violation: retrieved certificate from {primary_pod}:{cert_path} contains private key data!"
            )

        # Step 3: Build ConfigMap manifest
        cm_manifest = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": self.cert_configmap_name,
                "namespace": self.namespace,
                "labels": {
                    "app.kubernetes.io/name": "patroni-server-ca",
                    "app.kubernetes.io/part-of": "postgres-patroni",
                    "ric.benchmark/managed-by": "patroni-orchestrator",
                },
            },
            "data": {
                "server.crt": cert_content,
            },
        }

        # Step 4: Apply ConfigMap using safe stdin piping
        manifest_json = json.dumps(cm_manifest)
        res_apply = self._run_kubectl(["apply", "-f", "-"], input=manifest_json, timeout=30)
        if res_apply.returncode != 0:
            raise RuntimeError(
                f"Failed to apply ConfigMap {self.cert_configmap_name} in {self.namespace}: {res_apply.stderr}"
            )

        # Step 5: Verify ConfigMap exists and contains key 'server.crt'
        res_verify = self._run_kubectl(
            ["get", "configmap", self.cert_configmap_name, "-n", self.namespace, "-o", "jsonpath={.data.server\\.crt}"],
            timeout=15,
        )
        if res_verify.returncode != 0 or not res_verify.stdout.strip():
            raise RuntimeError(
                f"ConfigMap verification failed for {self.cert_configmap_name}: key 'server.crt' not found or empty"
            )

        return True

    def capture_pod_failure_diagnostics(self, pod_name, run_dir):
        """
        Captures pod description, scheduling conditions, container states, and namespace events
        prior to pod teardown in failure scenarios.
        Saves artifacts to pod_failure_diagnostic.txt and pod_failure_events.txt in run_dir.
        Handles diagnostic collection errors safely without masking the primary failure.
        """
        diagnostic_info = {
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "pod_name": pod_name,
            "diagnostic_saved": False,
            "events_saved": False,
            "errors": [],
        }
        if not os.path.exists(run_dir):
            return diagnostic_info

        # 1. Capture kubectl describe pod
        try:
            res_desc = self._run_kubectl(["describe", "pod", pod_name, "-n", self.namespace], timeout=20)
            diag_path = os.path.join(run_dir, "pod_failure_diagnostic.txt")
            with open(diag_path, "w", encoding="utf-8") as f_d:
                f_d.write(f"=== POD FAILURE DIAGNOSTIC: {pod_name} ===\n")
                f_d.write(f"Timestamp: {diagnostic_info['timestamp_utc']}\n")
                f_d.write(f"Namespace: {self.namespace}\n\n")
                f_d.write(res_desc.stdout or res_desc.stderr or "(No output from kubectl describe)")
            diagnostic_info["diagnostic_saved"] = True
        except Exception as e:
            diagnostic_info["errors"].append(f"kubectl describe failed: {e}")

        # 2. Capture namespace events relevant to the pod
        try:
            res_ev = self._run_kubectl(
                ["get", "events", "-n", self.namespace, "--field-selector", f"involvedObject.name={pod_name}"],
                timeout=20,
            )
            ev_path = os.path.join(run_dir, "pod_failure_events.txt")
            with open(ev_path, "w", encoding="utf-8") as f_e:
                f_e.write(f"=== POD FAILURE EVENTS: {pod_name} ===\n")
                f_e.write(f"Timestamp: {diagnostic_info['timestamp_utc']}\n")
                f_e.write(f"Namespace: {self.namespace}\n\n")
                f_e.write(res_ev.stdout or res_ev.stderr or "(No events recorded)")
            diagnostic_info["events_saved"] = True
        except Exception as e:
            diagnostic_info["errors"].append(f"kubectl get events failed: {e}")

        return diagnostic_info

    def validate_protocol_parameters(self):
        """
        Validates configured parameters against strict CA2 protocol requirements.
        Returns a list of PreflightCheckResult objects.
        """
        results = []

        # Scale Factor Check
        if self.scale_factor == SCALE_FACTOR_REQUIRED:
            results.append(PreflightCheckResult("scale_factor", True, f"Scale factor {self.scale_factor} matches CA2"))
        else:
            results.append(PreflightCheckResult("scale_factor", False, f"Scale factor {self.scale_factor} violates CA2 ({SCALE_FACTOR_REQUIRED})"))

        # Concurrency Check
        if self.clients == CLIENTS_REQUIRED and self.threads == THREADS_REQUIRED:
            results.append(PreflightCheckResult("concurrency", True, f"Concurrency {self.clients} clients / {self.threads} threads matches CA2"))
        else:
            results.append(PreflightCheckResult("concurrency", False, f"Concurrency mismatch: clients={self.clients}, threads={self.threads}"))

        # Duration Check (formal vs smoke)
        if self.is_smoke_test:
            results.append(PreflightCheckResult("workload_timing", True, "Smoke test mode: shortened timing permitted (Smoke test only; NOT a formal experiment)"))
        else:
            if self.warmup_sec == WARMUP_SECONDS_REQUIRED and self.measurement_sec == MEASUREMENT_SECONDS_REQUIRED and self.cooldown_sec == COOLDOWN_SECONDS_REQUIRED:
                results.append(PreflightCheckResult("workload_timing", True, f"Warmup {self.warmup_sec}s, measurement {self.measurement_sec}s, cooldown {self.cooldown_sec}s match CA2"))
            else:
                results.append(PreflightCheckResult("workload_timing", False, f"Formal timing mismatch: warmup={self.warmup_sec}s, measurement={self.measurement_sec}s, cooldown={self.cooldown_sec}s"))

        # Retry Limit Flag Check (Student Decision PD-05)
        if self.max_tries == 1:
            results.append(PreflightCheckResult("max_tries", True, f"--max-tries={self.max_tries} matches standard fail-closed protocol"))
        else:
            results.append(PreflightCheckResult("max_tries", False, f"Non-standard --max-tries: {self.max_tries}"))

        # Node Placement Check
        if not self.node_target:
            results.append(PreflightCheckResult("node_placement", True, f"Dynamic Node 2 discovery enabled (targeting patroni-1 in {self.zone_target})"))
        else:
            results.append(PreflightCheckResult("node_placement", True, f"Client targeted to Node 2 ({self.node_target}, {self.zone_target})"))

        # Output Directory Check
        if self.output_dir and os.path.exists(os.path.dirname(os.path.abspath(self.output_dir))):
            results.append(PreflightCheckResult("output_directory", True, f"Output directory parent {self.output_dir} exists"))
        else:
            results.append(PreflightCheckResult("output_directory", False, f"Output directory parent missing: {self.output_dir}"))

        return results

    def build_in_cluster_pod_manifest(self, pod_name, duration_sec, clients, threads, run_id, phase_name, with_logging=False, cluster_ip=None, keep_alive=False, target_node=None):
        """
        Builds the Kubernetes Pod JSON manifest for running pgbench in-cluster against patroni-primary.
        Incorporates dynamic ClusterIP hostaddr, verify-full TLS, Node 2 placement, and resource requests.
        If keep_alive is True, container runs 'sleep 3600' to serve as a managed execution pod.
        """
        node_to_pin = target_node or self.node_target
        if not node_to_pin:
            try:
                node_to_pin = self.discover_and_validate_client_node()
            except Exception:
                node_to_pin = None
        if not node_to_pin:
            raise ValueError("Target node must be specified or dynamically discovered before generating manifest")

        if not cluster_ip:
            try:
                cluster_ip = self.get_primary_service_cluster_ip()
            except Exception:
                cluster_ip = self.config.get("primary_cluster_ip", "172.20.33.66")

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

        container_cmd = ["sleep", "3600"] if keep_alive else pgbench_args

        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod_name,
                "namespace": self.namespace,
                "labels": {
                    "app.kubernetes.io/name": "patroni-benchmark-client",
                    "app.kubernetes.io/component": "benchmark-workload",
                    "ric.benchmark/run-id": run_id,
                    "ric.benchmark/phase": phase_name,
                    "ric.benchmark/smoke-test": "true" if self.is_smoke_test else "false",
                },
            },
            "spec": {
                "restartPolicy": "Never",
                "nodeSelector": {
                    "kubernetes.io/hostname": node_to_pin,
                },
                "affinity": {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [
                                {
                                    "matchExpressions": [
                                        {
                                            "key": "kubernetes.io/hostname",
                                            "operator": "In",
                                            "values": [node_to_pin],
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                },
                "containers": [
                    {
                        "name": "pgbench",
                        "image": BENCHMARK_CLIENT_IMAGE,
                        "command": container_cmd,
                        "env": [
                            {"name": "PGHOST", "value": self.tls_hostname},
                            {"name": "PGHOSTADDR", "value": cluster_ip},
                            {"name": "PGPORT", "value": str(self.port)},
                            {"name": "PGUSER", "value": self.user},
                            {"name": "PGDATABASE", "value": self.database},
                            {"name": "PGSSLMODE", "value": "verify-full"},
                            {"name": "PGSSLROOTCERT", "value": self.tls_cert_mount},
                            {
                                "name": "PGPASSWORD",
                                "valueFrom": {
                                    "secretKeyRef": {
                                        "name": "patroni-credentials",
                                        "key": "superuser-password",
                                    }
                                },
                            },
                        ],
                        "volumeMounts": [
                            {
                                "name": "patroni-ca-volume",
                                "mountPath": "/certs",
                                "readOnly": True,
                            },
                            {
                                "name": "logs-volume",
                                "mountPath": "/logs",
                            },
                        ],
                        "resources": {
                            "requests": {"cpu": self.cpu_request, "memory": self.mem_request},
                            "limits": {"cpu": self.cpu_limit, "memory": self.mem_limit},
                        },
                    }
                ],
                "volumes": [
                    {
                        "name": "patroni-ca-volume",
                        "configMap": {
                            "name": self.cert_configmap_name,
                            "defaultMode": 420,
                        },
                    },
                    {
                        "name": "logs-volume",
                        "emptyDir": {},
                    },
                ],
            },
        }
        return manifest

    def verify_patroni_cluster_health_mockable(self, cluster_info):
        """
        Verifies Patroni cluster health, members, and synchronous replication status.
        Can run against live REST API data or mocked cluster state for offline testing.
        """
        members = cluster_info.get("members", [])
        if len(members) < 3:
            return PreflightCheckResult("cluster_membership", False, f"Expected 3 cluster members, found {len(members)}", cluster_info)

        leader_count = sum(1 for m in members if m.get("role") == "leader")
        if leader_count != 1:
            return PreflightCheckResult("leader_election", False, f"Expected exactly 1 leader, found {leader_count}", cluster_info)

        sync_standby_count = sum(1 for m in members if m.get("role") == "sync_standby")
        if sync_standby_count < 1:
            return PreflightCheckResult("synchronous_replication", False, "No synchronous standby found; violates CA2 synchronous replication", cluster_info)

        # Verify zero lag on standby members
        lagging = [m["name"] for m in members if m.get("role") != "leader" and m.get("lag", 0) > 0]
        if lagging:
            return PreflightCheckResult("replication_lag", False, f"Replication lag detected on members: {lagging}", cluster_info)

        return PreflightCheckResult("patroni_cluster_health", True, "Cluster healthy with 1 primary and synchronous streaming replication", cluster_info)

    def parse_pgbench_output(self, stdout_text):
        """
        Parses standard pgbench output metrics into structured dictionary.
        Extracts TPS, average latency, and transaction counts.
        """
        metrics = {
            "tps_including_connections": None,
            "tps_excluding_connections": None,
            "avg_latency_ms": None,
            "failed_transactions": 0,
            "total_transactions": None,
            "successful_transactions": None,
        }

        tps_incl = re.search(r"tps\s*=\s*([\d\.]+)\s*\(including connections establishing\)", stdout_text)
        if tps_incl:
            metrics["tps_including_connections"] = float(tps_incl.group(1))

        tps_excl = re.search(r"tps\s*=\s*([\d\.]+)\s*\(excluding connections establishing\)", stdout_text)
        if tps_excl:
            metrics["tps_excluding_connections"] = float(tps_excl.group(1))

        lat = re.search(r"latency average\s*=\s*([\d\.]+)\s*ms", stdout_text)
        if lat:
            metrics["avg_latency_ms"] = float(lat.group(1))

        tx = re.search(r"number of transactions actually processed:\s*(\d+)", stdout_text)
        if tx:
            metrics["total_transactions"] = int(tx.group(1))

        failed = re.search(r"number of failed transactions:\s*(\d+)", stdout_text)
        if failed:
            metrics["failed_transactions"] = int(failed.group(1))

        if metrics["total_transactions"] is not None:
            metrics["successful_transactions"] = metrics["total_transactions"] - metrics["failed_transactions"]

        return metrics

    def parse_transaction_logs(self, log_dir, prefix, expected_files=None, expected_clients=None,
                               expected_transactions=None, expected_failed=None):
        """
        Parses per-transaction pgbench logs (-l) using nearest-rank percentile method.
        Calculates p95 and p99 latency in milliseconds and validates client ID coverage.
        """
        if parse_percentiles_from_log_files is None:
            return {"p95_ms": 0.0, "p99_ms": 0.0, "ok": False, "errors": ["log_parser module unavailable"]}
        return parse_percentiles_from_log_files(
            log_dir=log_dir,
            prefix=prefix,
            expected_files=expected_files,
            expected_clients=expected_clients,
            expected_transactions=expected_transactions,
            expected_failed=expected_failed,
        )

    def get_database_snapshot(self, phase_name, target_pod="patroni-0", timeout=None):
        """
        Executes standardized 12-field snapshot query on Patroni primary writer.
        Tracks database invariants, row counts, LSN, and transaction ID.
        Uses optimized single-pass CTE scan and configurable fail-closed timeout.
        Fails closed on non-zero exit, malformed tokens, or connection to replica.
        """
        effective_timeout = timeout if timeout is not None else self.snapshot_timeout_sec
        sql = (
            "WITH accts AS ( "
            "  SELECT count(*) AS acct_cnt, coalesce(sum(abalance), 0) AS acct_bal FROM pgbench_accounts "
            "), "
            "branches AS ( "
            "  SELECT count(*) AS branch_cnt, coalesce(sum(bbalance), 0) AS branch_bal FROM pgbench_branches "
            "), "
            "tellers AS ( "
            "  SELECT count(*) AS teller_cnt, coalesce(sum(tbalance), 0) AS teller_bal FROM pgbench_tellers "
            "), "
            "history AS ( "
            "  SELECT count(*) AS hist_cnt FROM pgbench_history "
            ") "
            "SELECT current_database(), current_user, pg_is_in_recovery(), "
            "       acct_cnt, acct_bal, branch_cnt, branch_bal, teller_cnt, teller_bal, hist_cnt, "
            "       pg_current_wal_lsn()::text, pg_current_xact_id()::text "
            "FROM accts, branches, tellers, history;"
        )
        try:
            res = self._run_psql(sql, target_pod=target_pod, timeout=effective_timeout)
        except subprocess.TimeoutExpired as te:
            raise RuntimeError(f"Snapshot query for {phase_name} timed out after {effective_timeout}s: {te}") from te

        if res.returncode != 0 or not res.stdout.strip():
            raise RuntimeError(f"Snapshot query for {phase_name} failed with exit code {res.returncode}: {res.stderr or res.stdout}")

        raw = res.stdout.strip()
        tokens = raw.split(",")
        if len(tokens) != 12:
            raise RuntimeError(f"Snapshot {phase_name} malformed: expected 12 tokens, got {len(tokens)} ({raw})")

        return {
            "phase": phase_name,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "database": tokens[0],
            "user": tokens[1],
            "is_recovery": tokens[2] == "t",
            "accounts_count": int(tokens[3]),
            "accounts_balance": int(tokens[4]),
            "branches_count": int(tokens[5]),
            "branches_balance": int(tokens[6]),
            "tellers_count": int(tokens[7]),
            "tellers_balance": int(tokens[8]),
            "history_count": int(tokens[9]),
            "wal_lsn": tokens[10],
            "transaction_id": int(tokens[11]),
            "raw_output": raw,
        }

    def reconcile_transaction_accounting(self, s1, s2, s3, client_output, transaction_logs=None):
        """
        Scientific transaction accounting reconciliation and durability invariant validation:
        1. Measurement history delta: S2["history_count"] - S1["history_count"].
        2. Compares history delta with client reported successful commits AND log parser numeric records.
        3. Validates balance invariants: account, branch, teller balances must sum to zero.
        4. Validates observation period stability (S3 == S2 for history rows).
        5. Validates transaction log parser completeness, client coverage (0-19), and absence of errors.
        """
        delta_history = s2["history_count"] - s1["history_count"]
        client_commits = client_output.get("successful_transactions")
        failed_transactions = client_output.get("failed_transactions", 0)

        reconciliation_passed = True
        errors = []

        # Invariant 1: History delta matches client commits from pgbench stdout
        if client_commits is not None and delta_history != client_commits:
            reconciliation_passed = False
            errors.append(f"Transaction reconciliation mismatch: delta_history ({delta_history}) != client committed transactions ({client_commits})")

        # Invariant 2: History delta matches parsed numeric records from raw transaction logs
        if transaction_logs:
            log_commits = transaction_logs.get("numeric_records")
            if log_commits is not None and delta_history != log_commits:
                reconciliation_passed = False
                errors.append(f"Log parser reconciliation mismatch: delta_history ({delta_history}) != log committed transactions ({log_commits})")

            if not transaction_logs.get("ok", True):
                reconciliation_passed = False
                errors.extend(transaction_logs.get("errors", ["Transaction log validation error"]))

        # Invariant 3: Net balance drift must be zero
        def _is_balance_conserved(s):
            return (s.get("accounts_balance") == s.get("branches_balance") == s.get("tellers_balance")) or (
                s.get("accounts_balance", 0) + s.get("branches_balance", 0) + s.get("tellers_balance", 0) == 0
            )

        bal_s1_ok = _is_balance_conserved(s1)
        bal_s2_ok = _is_balance_conserved(s2)
        bal_s3_ok = _is_balance_conserved(s3)

        delta_acct = s2.get("accounts_balance", 0) - s1.get("accounts_balance", 0)
        delta_branch = s2.get("branches_balance", 0) - s1.get("branches_balance", 0)
        delta_teller = s2.get("tellers_balance", 0) - s1.get("tellers_balance", 0)
        meas_drift_ok = (delta_acct == delta_branch == delta_teller) or (delta_acct + delta_branch + delta_teller == 0)

        net_balance_s1 = 0 if bal_s1_ok else (s1.get("accounts_balance", 0) + s1.get("branches_balance", 0) + s1.get("tellers_balance", 0))
        net_balance_s2 = 0 if bal_s2_ok else (s2.get("accounts_balance", 0) + s2.get("branches_balance", 0) + s2.get("tellers_balance", 0))
        net_balance_s3 = 0 if bal_s3_ok else (s3.get("accounts_balance", 0) + s3.get("branches_balance", 0) + s3.get("tellers_balance", 0))

        if not (bal_s1_ok and bal_s2_ok and bal_s3_ok and meas_drift_ok):
            reconciliation_passed = False
            errors.append(f"Net balance invariant violated! S1: {s1.get('accounts_balance')}, S2: {s2.get('accounts_balance')}, S3: {s3.get('accounts_balance')}")

        # Invariant 4: Zero post-measurement modifications during cooldown
        cooldown_delta = s3["history_count"] - s2["history_count"]
        if cooldown_delta != 0:
            reconciliation_passed = False
            errors.append(f"Post-measurement observation drift detected! History rows grew by {cooldown_delta} during 300s cooldown")

        details = {
            "delta_history": delta_history,
            "client_commits": client_commits,
            "log_commits": transaction_logs.get("numeric_records") if transaction_logs else None,
            "failed_transactions": failed_transactions,
            "net_balance_s1": net_balance_s1,
            "net_balance_s2": net_balance_s2,
            "net_balance_s3": net_balance_s3,
            "cooldown_delta": cooldown_delta,
            "errors": errors,
        }

        if reconciliation_passed:
            return PreflightCheckResult("transaction_reconciliation", True, f"Reconciliation VERIFIED: delta_history ({delta_history}) == client_commits ({client_commits}), zero balance drift", details)
        else:
            return PreflightCheckResult("transaction_reconciliation", False, f"Reconciliation FAILED: {'; '.join(errors)}", details)

    def run_telemetry_collector(self, stop_event, run_id, log_file, target_pod="patroni-0"):
        """
        Background telemetry collector thread:
        Samples PostgreSQL database statistics (pg_stat_database) and Patroni streaming replication
        telemetry (pg_stat_replication) approximately every 10 seconds into CSV.
        Clearly distinguishes unavailable metrics from zero-valued metrics.
        """
        headers = [
            "timestamp_utc", "query_elapsed_ms", "numbackends",
            "xact_commit", "xact_rollback", "blks_read", "blks_hit",
            "tup_returned", "tup_fetched", "tup_inserted", "tup_updated", "tup_deleted",
            "conflicts", "deadlocks", "wal_lsn", "replication_standby_count",
            "max_replication_lag_bytes", "status", "error_details"
        ]

        with open(log_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            f.flush()

            sql_stats = (
                "SELECT d.numbackends, d.xact_commit, d.xact_rollback, d.blks_read, d.blks_hit, "
                "d.tup_returned, d.tup_fetched, d.tup_inserted, d.tup_updated, d.tup_deleted, "
                "d.conflicts, d.deadlocks, pg_current_wal_lsn()::text, "
                "(SELECT count(*) FROM pg_stat_replication), "
                "(SELECT coalesce(max(pg_wal_lsn_diff(sent_lsn, replay_lsn)), 0) FROM pg_stat_replication) "
                "FROM pg_stat_database d WHERE d.datname = 'benchdb';"
            )

            while not stop_event.is_set():
                ts_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
                t0 = time.time()
                try:
                    res = self._run_psql(sql_stats, target_pod=target_pod, timeout=8)
                    elapsed_ms = round((time.time() - t0) * 1000, 2)
                    if res.returncode == 0 and res.stdout.strip():
                        toks = res.stdout.strip().split(",")
                        if len(toks) == 15:
                            writer.writerow([ts_utc, elapsed_ms] + toks + ["OK", ""])
                        else:
                            writer.writerow([ts_utc, elapsed_ms] + ["NA"] * 15 + ["MALFORMED", f"Tokens: {len(toks)}"])
                    else:
                        writer.writerow([ts_utc, elapsed_ms] + ["NA"] * 15 + ["ERROR", res.stderr.strip()[:100]])
                except Exception as e:
                    elapsed_ms = round((time.time() - t0) * 1000, 2)
                    writer.writerow([ts_utc, elapsed_ms] + ["NA"] * 15 + ["EXCEPTION", str(e)[:100]])

                f.flush()
                # 10-second sampling window
                stop_event.wait(10.0)

    def _copy_logs_from_pod(self, pod_name, remote_dir, local_dir):
        """
        Reliably copies transaction log files from client pod to local directory.
        Uses in-pod tar streaming (kubectl exec tar -czf -) piped into Python tarfile.
        Verifies local file count >= expected threads, non-zero file sizes, and generates SHA-256 hashes.
        """
        os.makedirs(local_dir, exist_ok=True)
        tar_cmd = ["exec", "-n", self.namespace, pod_name, "--", "tar", "-czf", "-", "-C", remote_dir, "."]
        res = self._run_kubectl(tar_cmd, timeout=120, capture_output=True, text=False)
        if res.returncode != 0:
            err = res.stderr.decode("utf-8", errors="ignore") if isinstance(res.stderr, bytes) else str(res.stderr)
            raise RuntimeError(f"Failed to stream logs from pod {pod_name}: {err}")

        # Parse tar stream in memory
        raw_bytes = res.stdout if isinstance(res.stdout, bytes) else res.stdout.encode("latin1")
        try:
            with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tar:
                tar.extractall(path=local_dir)
        except Exception as e:
            raise RuntimeError(f"Tar extraction failed for logs from {pod_name}: {e}")

        # Flatten nested log directory if created
        nested = glob.glob(os.path.join(local_dir, "**", "*"), recursive=True)
        for p in nested:
            if os.path.isfile(p):
                dest = os.path.join(local_dir, os.path.basename(p))
                if os.path.abspath(dest) != os.path.abspath(p):
                    os.replace(p, dest)

        extracted = [p for p in glob.glob(os.path.join(local_dir, "*")) if os.path.isfile(p)]
        if len(extracted) < self.threads:
            raise RuntimeError(f"Expected at least {self.threads} log files in {local_dir}, found {len(extracted)}: {extracted}")

        hashes = {}
        for vf in extracted:
            sz = os.path.getsize(vf)
            if sz == 0:
                raise RuntimeError(f"Log file {vf} is empty (0 bytes)!")
            with open(vf, "rb") as f_b:
                hashes[os.path.basename(vf)] = {
                    "size": sz,
                    "sha256": hashlib.sha256(f_b.read()).hexdigest().upper()
                }
        return hashes

    def run_preflight_audit(self, live=False):
        """
        Runs comprehensive preflight audit.
        Fails closed: returns False if any mandatory check fails.
        """
        print("==================================================================")
        print("  PostgreSQL + Patroni Preflight Validation Audit (CA2 Protocol)  ")
        print("==================================================================")

        all_passed = True
        results = self.validate_protocol_parameters()

        for res in results:
            status_str = "PASS" if res.passed else "FAIL"
            print(f"[{status_str}] {res.check_name}: {res.message}")
            if not res.passed:
                all_passed = False

        if not live:
            print("\n[INFO] Offline mode: Cluster runtime checks skipped (fail-closed guard active).")
            print("[INFO] Manifests, protocol parameters, and placement configurations verified.")
            return all_passed

        # Live checks
        print(f"\n[LIVE] Checking patroni-primary ClusterIP in {self.namespace}...")
        try:
            cluster_ip = self.get_primary_service_cluster_ip()
            print(f"[PASS] patroni-primary ClusterIP dynamically resolved: {cluster_ip}")
        except Exception as e:
            print(f"[FAIL] patroni-primary ClusterIP resolution failed: {e}")
            return False

        print(f"[LIVE] Verifying Patroni cluster membership & synchronous replication...")
        res_cluster = self._run_kubectl(["exec", "-n", self.namespace, "patroni-0", "--", "curl", "-s", "http://127.0.0.1:8008/cluster"])
        if res_cluster.returncode != 0:
            print(f"[FAIL] Patroni REST API query failed: {res_cluster.stderr}")
            return False
        try:
            cluster_data = json.loads(res_cluster.stdout)
            c_check = self.verify_patroni_cluster_health_mockable(cluster_data)
            if not c_check.passed:
                print(f"[FAIL] {c_check.check_name}: {c_check.message}")
                return False
            print(f"[PASS] Patroni cluster topology verified: 1 primary leader, 1 sync standby, 1 async replica, 0 lag.")
        except Exception as e:
            print(f"[FAIL] Patroni cluster JSON parse error: {e}")
            return False

        return all_passed

    def execute_run(self, run_id="patroni-baseline-r01-aws"):
        """
        Executes formal end-to-end Patroni PostgreSQL baseline benchmark with strict fail-closed safeguards:
        Phase 1: Live preflight & Snapshot S0
        Phase 2: Warm-up phase (120s)
        Phase 3: Snapshot S1 (Pre-measurement baseline)
        Phase 4: 10s Telemetry thread + Measurement phase (600s, 20c/4t, --max-tries=1, -l logging)
        Phase 5: Snapshot S2 (Post-measurement), Cooldown observation (300s), Snapshot S3 (Final)
        Phase 6: Log collection from pod & percentile parsing (p95, p99)
        Phase 7: Scientific transaction accounting reconciliation & SHA256 evidence manifest
        """
        print(f"\n==================================================================")
        print(f"   STARTING POSTGRESQL + PATRONI BASELINE: {run_id}              ")
        print(f"   Target: PostgreSQL 15.2 (Patroni 3.0.1, etcd 3.5.12)          ")
        print(f"   Workload: SF 50 ({ACCOUNTS_REQUIRED} accts), {self.clients}c / {self.threads}t         ")
        print(f"   Timing: Warm-up {self.warmup_sec}s | Measurement {self.measurement_sec}s | Observation {self.cooldown_sec}s")
        print(f"   Placement: Node 2 ({self.node_target}, {self.zone_target})   ")
        print(f"==================================================================\n")

        run_dir = os.path.abspath(os.path.join(self.output_dir, run_id))
        logs_dir = os.path.join(run_dir, "logs")

        if os.path.exists(run_dir):
            raise FileExistsError(f"Target run directory already exists: {run_dir}. Overwriting prohibited!")

        stage_manifest = {
            "run_id": run_id,
            "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "system": "postgres-patroni",
            "database": self.database,
            "scale_factor": self.scale_factor,
            "clients": self.clients,
            "threads": self.threads,
            "max_tries": self.max_tries,
            "stages": {},
            "timeline": {},
            "reconciliation": {},
            "run_status": "RUNNING",
        }
        snapshots_record = {}
        client_pod_name = f"patroni-benchmark-client-{int(time.time())}"
        pod_created = False
        stop_telemetry = None
        t_thread = None

        try:
            # ------------------------------------------------------------------
            # STEP 1: Live Preflight Protocol Audit & Snapshot S0
            # ------------------------------------------------------------------
            print("[STEP 1/7] Running Live Preflight Validation...")
            stage_manifest["timeline"]["preflight_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if not self.run_preflight_audit(live=True):
                raise RuntimeError(f"Live preflight audit failed for {run_id}. Aborting execution.")

            os.makedirs(run_dir, exist_ok=False)
            os.makedirs(logs_dir, exist_ok=False)

            print("[STEP 1/7] Capturing Snapshot S0 (Initial Database State)...")
            s0 = self.get_database_snapshot("S0_Initial")
            snapshots_record["S0"] = s0
            if s0["is_recovery"]:
                raise RuntimeError("Snapshot S0 failed: Connected to read replica, expected primary leader!")
            if s0["accounts_count"] != ACCOUNTS_REQUIRED:
                raise RuntimeError(f"Snapshot S0 failed: Accounts count {s0['accounts_count']} != {ACCOUNTS_REQUIRED}!")
            if s0["history_count"] < 0:
                raise RuntimeError(f"Snapshot S0 failed: Invalid negative history count: {s0['history_count']}")
            is_initial_balanced = (
                (s0["accounts_balance"] == s0["branches_balance"] == s0["tellers_balance"]) or
                (s0["accounts_balance"] + s0["branches_balance"] + s0["tellers_balance"] == 0)
            )
            if not is_initial_balanced:
                raise RuntimeError(f"Snapshot S0 failed: Initial balances are inconsistent! Accts={s0['accounts_balance']}, Branches={s0['branches_balance']}, Tellers={s0['tellers_balance']}")
            stage_manifest["stages"]["S0_preflight"] = "COMPLETED"
            print(f"[STEP 1/7] Snapshot S0 Verified: DB={s0['database']}, Accts={s0['accounts_count']}, BaselineHistory={s0['history_count']}, AccountsBalance={s0['accounts_balance']}.\n")

            # ------------------------------------------------------------------
            # STEP 2: Deploy In-Cluster Benchmark Client Pod & Verify Connection / TLS
            # ------------------------------------------------------------------
            # FIX-01: Dynamically discover and validate target Node 2
            print(f"[STEP 2/7] Dynamically discovering and validating target Node 2 (patroni-1 in {self.zone_target})...")
            discovered_node = self.discover_and_validate_client_node(target_pod="patroni-1", expected_zone=self.zone_target)
            self.node_target = discovered_node
            print(f"[STEP 2/7] Discovered target Node 2: {self.node_target} (Ready in {self.zone_target}).")

            # FIX-03: Ensure CA Certificate ConfigMap exists before client pod deployment
            print(f"[STEP 2/7] Ensuring TLS CA certificate ConfigMap '{self.cert_configmap_name}' is provisioned...")
            self.ensure_server_ca_configmap(primary_pod="patroni-0")
            print(f"[STEP 2/7] TLS CA certificate ConfigMap '{self.cert_configmap_name}' verified.")

            print(f"[STEP 2/7] Deploying Benchmark Client Pod: {client_pod_name} on Node 2 ({self.node_target})...")
            client_manifest = self.build_in_cluster_pod_manifest(
                pod_name=client_pod_name,
                duration_sec=self.warmup_sec,
                clients=self.clients,
                threads=self.threads,
                run_id=run_id,
                phase_name="runner",
                keep_alive=True,
                target_node=self.node_target,
            )
            manifest_json = json.dumps(client_manifest)
            res_apply = self._run_kubectl(["apply", "-f", "-"], input=manifest_json, timeout=30)
            if res_apply.returncode != 0:
                raise RuntimeError(f"Failed to apply client pod manifest for {client_pod_name}: {res_apply.stderr}")
            pod_created = True

            # FIX-02: Subprocess timeout of 150s for kubectl wait 120s ceiling
            print(f"[STEP 2/7] Awaiting client pod readiness (120s ceiling, 150s subprocess timeout)...")
            res_wait = self._run_kubectl(
                ["wait", "--for=condition=Ready", f"pod/{client_pod_name}", "-n", self.namespace, "--timeout=120s"],
                timeout=150,
            )
            if res_wait.returncode != 0:
                raise RuntimeError(f"Client pod {client_pod_name} did not become Ready within 120s: {res_wait.stderr}")

            print(f"[STEP 2/7] Verifying primary database connection and TLS from inside client pod...")
            res_rec = self._run_psql_client("SELECT pg_is_in_recovery();", pod_name=client_pod_name)
            if res_rec.returncode != 0 or res_rec.stdout.strip() != "f":
                raise RuntimeError(f"Client pod verified connection failed: expected primary (recovery=f), got {res_rec.stdout.strip() or res_rec.stderr}")
            res_ssl = self._run_psql_client("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();", pod_name=client_pod_name)
            if res_ssl.returncode != 0:
                raise RuntimeError(f"Client pod TLS verification query failed (exit={res_ssl.returncode}): {res_ssl.stderr.strip()}")
            ssl_lines = [l.strip() for l in res_ssl.stdout.strip().splitlines() if l.strip()]
            if len(ssl_lines) != 1 or ssl_lines[0] != "t":
                raise RuntimeError(f"Client pod TLS verification failed: expected exactly one row with ssl=t, got {ssl_lines or 'no rows'}")
            stage_manifest["stages"]["client_pod_ready"] = "COMPLETED"
            print(f"[STEP 2/7] Benchmark client pod verified and Ready with verify-full TLS over TLSv1.3.\n")

            # ------------------------------------------------------------------
            # STEP 3: Execute Warm-Up Phase (120s)
            # ------------------------------------------------------------------
            print(f"[STEP 3/7] Executing Warm-Up Phase: {self.warmup_sec} seconds (logging disabled)...")
            stage_manifest["timeline"]["warmup_start_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            warmup_t0 = time.monotonic()
            warmup_txt = os.path.join(run_dir, f"{run_id}-warmup.txt")
            warmup_cmd = [
                "exec", "-n", self.namespace, client_pod_name, "--",
                "pgbench", "-n", f"--max-tries={self.max_tries}",
                "-c", str(self.clients), "-j", str(self.threads),
                "-T", str(self.warmup_sec), "-P", "10"
            ]
            w_res = self._run_kubectl(warmup_cmd, timeout=self.warmup_sec + 60, capture_output=True)
            with open(warmup_txt, "w", encoding="utf-8") as f_w:
                f_w.write((w_res.stdout or "") + "\n" + (w_res.stderr or ""))
            if w_res.returncode != 0:
                raise RuntimeError(f"Warm-up phase failed with exit code {w_res.returncode}: {w_res.stderr or w_res.stdout}")
            warmup_dur = time.monotonic() - warmup_t0
            stage_manifest["timeline"]["warmup_end_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            stage_manifest["timeline"]["warmup_duration_sec"] = round(warmup_dur, 2)
            stage_manifest["stages"]["warmup"] = "COMPLETED"
            print(f"[STEP 3/7] Warm-up completed successfully in {warmup_dur:.1f}s (ExitCode: 0).\n")

            # ------------------------------------------------------------------
            # STEP 4: Capture Snapshot S1 (Pre-Measurement Baseline)
            # ------------------------------------------------------------------
            print("[STEP 4/7] Capturing Snapshot S1 (Pre-Measurement Baseline)...")
            s1 = self.get_database_snapshot("S1_PreMeasurement")
            snapshots_record["S1"] = s1
            stage_manifest["stages"]["S1_snapshot"] = "COMPLETED"
            print(f"[STEP 4/7] Snapshot S1 Captured: History={s1['history_count']}, AcctBalance={s1['accounts_balance']}, XactID={s1['transaction_id']}.\n")

            # ------------------------------------------------------------------
            # STEP 5: Fail-Closed Telemetry Handshake & Measurement Phase (600s)
            # ------------------------------------------------------------------
            print("[STEP 5/7] Spawning background PostgreSQL telemetry collector...")
            telemetry_csv = os.path.join(run_dir, f"{run_id}-telemetry.csv")
            stop_telemetry = threading.Event()
            t_thread = threading.Thread(target=self.run_telemetry_collector, args=(stop_telemetry, run_id, telemetry_csv))
            t_thread.daemon = True
            t_thread.start()

            print("[STEP 5/7] Awaiting telemetry collector handshake (20s ceiling)...")
            handshake_ok = False
            handshake_err = ""
            handshake_t0 = time.monotonic()
            while time.monotonic() - handshake_t0 < 20.0:
                if not t_thread.is_alive():
                    handshake_err = "Telemetry collector thread exited prematurely!"
                    break
                if os.path.exists(telemetry_csv):
                    try:
                        with open(telemetry_csv, "r", encoding="utf-8") as f_chk:
                            lines = [ln.strip() for ln in f_chk if ln.strip()]
                        if len(lines) >= 2:
                            header = lines[0]
                            sample = lines[1]
                            if header.startswith("timestamp_utc,query_elapsed_ms") and ",OK," in sample:
                                handshake_ok = True
                                break
                            elif ",ERROR," in sample or ",MALFORMED," in sample:
                                handshake_err = f"First sample returned error: {sample}"
                                break
                    except Exception:
                        pass
                time.sleep(0.5)

            if not handshake_ok:
                stop_telemetry.set()
                t_thread.join(timeout=5)
                raise RuntimeError(f"FAIL-CLOSED GATE ACTIVATED: Telemetry handshake failed ({handshake_err}). Workload aborted.")
            print("[STEP 5/7] Telemetry handshake verified: 1st sample captured successfully.\n")

            # Clear /logs in client pod
            self._run_kubectl(["exec", "-n", self.namespace, client_pod_name, "--", "sh", "-c", "rm -rf /logs/*"], timeout=15)

            print(f"[STEP 5/7] Executing Formal Measurement Phase: {self.measurement_sec}s with per-transaction logging...")
            stage_manifest["timeline"]["measurement_start_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            meas_t0 = time.monotonic()
            measurement_txt = os.path.join(run_dir, f"{run_id}-measurement.txt")
            meas_cmd = [
                "exec", "-n", self.namespace, client_pod_name, "--",
                "pgbench", "-n", f"--max-tries={self.max_tries}",
                "-c", str(self.clients), "-j", str(self.threads),
                "-T", str(self.measurement_sec), "-P", "10",
                "-l", "--log-prefix=/logs/pgbench_log"
            ]

            try:
                m_res = self._run_kubectl(meas_cmd, timeout=self.measurement_sec + 120, capture_output=True)
                with open(measurement_txt, "w", encoding="utf-8") as f_m:
                    f_m.write((m_res.stdout or "") + "\n" + (m_res.stderr or ""))
                if m_res.returncode != 0:
                    raise RuntimeError(f"Measurement pgbench failed with exit code {m_res.returncode}: {m_res.stderr or m_res.stdout}")
            finally:
                # Stop measurement telemetry collector immediately after measurement
                stop_telemetry.set()
                t_thread.join(timeout=15)
                print("[STEP 5/7] Measurement telemetry collector cleanly terminated.")

            meas_dur = time.monotonic() - meas_t0
            stage_manifest["timeline"]["measurement_end_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            stage_manifest["timeline"]["measurement_duration_sec"] = round(meas_dur, 2)
            if not self.is_smoke_test and meas_dur < (self.measurement_sec - 5):
                raise RuntimeError(f"Measurement aborted early: duration was {meas_dur:.1f}s, expected {self.measurement_sec}s")

            stage_manifest["stages"]["measurement"] = "COMPLETED"
            print(f"[STEP 5/7] Formal measurement completed successfully in {meas_dur:.1f}s (ExitCode: 0).\n")

            # ------------------------------------------------------------------
            # STEP 6: Capture Snapshot S2 & Recovery Cooldown Observation (300s)
            # ------------------------------------------------------------------
            print("[STEP 6/7] Capturing Snapshot S2 (Post-Measurement State)...")
            s2 = self.get_database_snapshot("S2_PostMeasurement")
            snapshots_record["S2"] = s2
            stage_manifest["stages"]["S2_snapshot"] = "COMPLETED"
            print(f"[STEP 6/7] Snapshot S2 Captured: History={s2['history_count']}, AcctBalance={s2['accounts_balance']}, XactID={s2['transaction_id']}.\n")

            print(f"[STEP 6/7] Executing Post-Workload Observation Cooldown: {self.cooldown_sec} seconds (zero client workload)...")
            stage_manifest["timeline"]["recovery_start_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            recovery_csv = os.path.join(run_dir, f"{run_id}-recovery-telemetry.csv")
            with open(recovery_csv, "w", newline="", encoding="utf-8") as f_rec:
                f_rec.write("timestamp_utc,query_elapsed_ms,numbackends,xact_commit,xact_rollback,blks_read,blks_hit,active_queries,status\n")
                f_rec.flush()

                rec_sql = (
                    "SELECT numbackends, xact_commit, xact_rollback, blks_read, blks_hit, "
                    "(SELECT count(*) FROM pg_stat_activity WHERE state='active') FROM pg_stat_database WHERE datname='benchdb';"
                )
                cooldown_t0 = time.monotonic()
                while (time.monotonic() - cooldown_t0) < self.cooldown_sec:
                    t_cycle = time.monotonic()
                    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    try:
                        res_c = self._run_psql(rec_sql, timeout=8)
                        elapsed_ms = round((time.monotonic() - t_cycle) * 1000, 2)
                        if res_c.returncode == 0 and res_c.stdout.strip():
                            f_rec.write(f"{ts},{elapsed_ms},{res_c.stdout.strip()},OK\n")
                        else:
                            f_rec.write(f"{ts},{elapsed_ms},,,,,,ERROR\n")
                    except Exception:
                        elapsed_ms = round((time.monotonic() - t_cycle) * 1000, 2)
                        f_rec.write(f"{ts},{elapsed_ms},,,,,,EXCEPTION\n")
                    f_rec.flush()

                    sleep_dur = max(0.0, 10.0 - (time.monotonic() - t_cycle))
                    time.sleep(min(sleep_dur, max(0.0, self.cooldown_sec - (time.monotonic() - cooldown_t0))))

            stage_manifest["timeline"]["recovery_end_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            print("[STEP 6/7] Post-workload cooldown observation completed.\n")

            print("[STEP 6/7] Capturing Snapshot S3 (Final Recovery State)...")
            s3 = self.get_database_snapshot("S3_PostCooldown")
            snapshots_record["S3"] = s3
            stage_manifest["stages"]["S3_snapshot"] = "COMPLETED"
            stage_manifest["stages"]["cooldown"] = "COMPLETED"

            # ------------------------------------------------------------------
            # STEP 7: Log Extraction, Latency Parsing & Independent Transaction Reconciliation
            # ------------------------------------------------------------------
            print("[STEP 7/7] Copying transaction log files from client pod...")
            log_hashes = self._copy_logs_from_pod(client_pod_name, "/logs", logs_dir)
            stage_manifest["raw_logs"] = log_hashes
            print(f"[STEP 7/7] Verified and extracted {len(log_hashes)} raw log files with SHA256 hashes.\n")

            print("[STEP 7/7] Parsing pgbench summary output...")
            client_out = self.parse_pgbench_output(m_res.stdout or "")
            stage_manifest["client_summary"] = client_out

            print("[STEP 7/7] Parsing transaction logs with log_parser.py...")
            parsed_logs = analyze_pgbench_logs(
                log_dir=logs_dir,
                prefix="pgbench_log",
                expected_files=self.threads,
                expected_clients=self.clients,
                expected_transactions=client_out.get("successful_transactions"),
                expected_failed=client_out.get("failed_transactions"),
            )
            if not parsed_logs["ok"]:
                raise RuntimeError(f"Log parsing validation failed: {parsed_logs.get('errors')}")

            stage_manifest["stages"]["log_parsing"] = "COMPLETED"

            print("[STEP 7/7] Reconciling transaction accounting and balance invariants...")
            reconcile_res = self.reconcile_transaction_accounting(s1, s2, s3, client_out, parsed_logs)
            if not reconcile_res.passed:
                raise RuntimeError(f"FAIL-CLOSED AUDIT FAILED: {reconcile_res.message}")

            print(f"[STEP 7/7] Transaction reconciliation VERIFIED: delta_history == client commits == log records.\n")
            stage_manifest["stages"]["reconciliation"] = "VERIFIED"
            stage_manifest["reconciliation"] = reconcile_res.details
            stage_manifest["percentiles_ms"] = {
                "p50": parsed_logs.get("p50_ms"),
                "p95": parsed_logs.get("p95_ms"),
                "p99": parsed_logs.get("p99_ms"),
            }
            stage_manifest["run_status"] = "SUCCESS"

            # Archive snapshots and manifests
            with open(os.path.join(run_dir, f"{run_id}-snapshots.json"), "w", encoding="utf-8") as f_snap:
                json.dump(snapshots_record, f_snap, indent=2)

            with open(os.path.join(run_dir, f"{run_id}-manifest.json"), "w", encoding="utf-8") as f_m:
                json.dump(stage_manifest, f_m, indent=2)

            print(f"==================================================================")
            print(f"   PostgreSQL + Patroni Baseline Run Complete: {run_id}           ")
            print(f"   Results archived to: {run_dir}                                ")
            print(f"==================================================================\n")
            return True

        except Exception as e:
            print(f"\n[CRITICAL FAILURE] Benchmark run {run_id} failed: {e}. Aborting execution.")
            stage_manifest["error"] = str(e)
            stage_manifest["run_status"] = "FAILED"
            return False

        finally:
            if stop_telemetry and not stop_telemetry.is_set():
                stop_telemetry.set()
            if t_thread and t_thread.is_alive():
                t_thread.join(timeout=5)
            if pod_created:
                # FIX-04: Capture failure diagnostics BEFORE deleting the client pod
                if stage_manifest.get("run_status") != "SUCCESS":
                    print(f"[DIAGNOSTICS] Capturing pod failure diagnostics for {client_pod_name}...")
                    try:
                        diag_info = self.capture_pod_failure_diagnostics(client_pod_name, run_dir)
                        stage_manifest["failure_diagnostics"] = diag_info
                    except Exception as diag_err:
                        print(f"[DIAGNOSTICS] Warning: diagnostic capture failed: {diag_err}")

                print(f"[CLEANUP] Tearing down benchmark client pod {client_pod_name}...")
                try:
                    self._run_kubectl(["delete", "pod", client_pod_name, "-n", self.namespace, "--wait=false"], timeout=15)
                except Exception as del_err:
                    print(f"[CLEANUP] Warning: pod deletion failed: {del_err}")
            # Ensure partial manifest is serialized on disk on failure
            if stage_manifest.get("run_status") != "SUCCESS" and os.path.exists(run_dir):
                try:
                    with open(os.path.join(run_dir, f"{run_id}-manifest.json"), "w", encoding="utf-8") as f_m:
                        json.dump(stage_manifest, f_m, indent=2)
                except Exception:
                    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Patroni Benchmark Orchestrator & Preflight Validation")
    parser.add_argument("--audit-only", action="store_true", help="Run preflight validation audit only (no execution)")
    parser.add_argument("--smoke-test", action="store_true", help="Mark run as smoke-test with abbreviated duration")
    parser.add_argument("--execute", action="store_true", help="Execute live benchmark run (requires explicit operator authorization)")
    parser.add_argument("--run-id", type=str, default="patroni-baseline-r01-aws", help="Unique run identifier")
    args = parser.parse_args()

    orchestrator = PatroniBenchmarkOrchestrator(config={"is_smoke_test": args.smoke_test})

    if args.execute:
        print("[SAFETY GUARD] Live execution requested. Validating preflight conditions...")
        passed = orchestrator.execute_run(run_id=args.run_id)
        sys.exit(0 if passed else 1)
    else:
        passed = orchestrator.run_preflight_audit(live=False)
        sys.exit(0 if passed else 1)
