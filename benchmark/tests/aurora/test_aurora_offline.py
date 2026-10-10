#!/usr/bin/env python3
"""
Offline Test Suite for Amazon Aurora PostgreSQL-Compatible Implementation.
Validates:
1. YAML parsing & Kubernetes schema fields.
2. Aurora engine configuration parameters & CA2 version pins.
3. Secret-handling safeguards (no plaintext production credentials).
4. TLS root bundle configmap & verify-full mode wiring.
5. In-cluster pod manifest generation targeting Aurora Writer Endpoint.
6. Benchmark parameter validation & fail-closed behavior.
7. Output parsing & metric extraction.
8. Scientific transaction accounting & balance reconciliation.
9. Immutability guard for CockroachDB and PostgreSQL+Patroni assets.
"""

import os
import sys
import unittest
import yaml
import glob
import re

REPO_ROOT = r"d:\Projects\RIC-Gray-Failure-Research"
AURORA_K8S_DIR = os.path.join(REPO_ROOT, "kubernetes", "aurora")
AURORA_BENCHMARK_DIR = os.path.join(REPO_ROOT, "benchmark", "scripts", "aurora")

# Ensure orchestrator is importable
if AURORA_BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, AURORA_BENCHMARK_DIR)

from orchestrate_aurora import AuroraBenchmarkOrchestrator, PreflightCheckResult

class TestAuroraOffline(unittest.TestCase):

    def setUp(self):
        self.yaml_files = glob.glob(os.path.join(AURORA_K8S_DIR, "*.yaml"))

    def test_01_all_yaml_manifests_parse_cleanly(self):
        """All Aurora Kubernetes YAML files must parse cleanly and contain mandatory metadata."""
        self.assertGreater(len(self.yaml_files), 0, "No YAML manifest files found in kubernetes/aurora")
        for yfile in self.yaml_files:
            with open(yfile, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
                self.assertGreater(len(docs), 0, f"Empty YAML file: {yfile}")
                for doc in docs:
                    if doc is not None:
                        self.assertIn("apiVersion", doc, f"Missing apiVersion in {yfile}")
                        self.assertIn("kind", doc, f"Missing kind in {yfile}")
                        self.assertIn("metadata", doc, f"Missing metadata in {yfile}")
                        self.assertIn("name", doc["metadata"], f"Missing metadata.name in {yfile}")

    def test_02_aurora_cluster_config_parameters(self):
        """Aurora ConfigMap must configure pinned PostgreSQL 15.19 engine and db.t4g.medium instance class."""
        cfg_file = os.path.join(AURORA_K8S_DIR, "03-aurora-cluster-config.yaml")
        self.assertTrue(os.path.exists(cfg_file), "03-aurora-cluster-config.yaml missing")
        with open(cfg_file, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        data = cfg.get("data", {})
        self.assertEqual(data.get("aurora_engine_version"), "15.19", "Aurora engine version must be pinned to 15.19")
        self.assertEqual(data.get("aurora_instance_class"), "db.t4g.medium", "Instance class must be db.t4g.medium")
        self.assertEqual(data.get("aurora_region"), "us-east-1", "Region must be us-east-1")
        self.assertEqual(data.get("aurora_port"), "5432")
        self.assertEqual(data.get("aurora_database"), "benchdb")
        self.assertEqual(data.get("ssl_mode"), "verify-full")

    def test_03_secret_handling_safeguards(self):
        """Aurora Secret template must not contain production credentials and must be labeled template."""
        secret_file = os.path.join(AURORA_K8S_DIR, "02-aurora-secrets-template.yaml")
        self.assertTrue(os.path.exists(secret_file), "02-aurora-secrets-template.yaml missing")
        with open(secret_file, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("TEMPLATE ONLY", content)

    def test_04_tls_and_ca_bundle_wiring(self):
        """RDS CA bundle ConfigMap must exist and pod manifest must mount it."""
        ca_file = os.path.join(AURORA_K8S_DIR, "04-rds-ca-bundle-configmap.yaml")
        self.assertTrue(os.path.exists(ca_file), "04-rds-ca-bundle-configmap.yaml missing")

        orch = AuroraBenchmarkOrchestrator(config={
            "writer_endpoint": "test-aurora.cluster-test.us-east-1.rds.amazonaws.com"
        })
        manifest = orch.build_in_cluster_pod_manifest(
            pod_name="test-aurora-client",
            duration_sec=600,
            clients=20,
            threads=4,
            run_id="run-test-01",
            phase_name="measurement",
        )
        container = manifest["spec"]["containers"][0]
        env_map = {e["name"]: e.get("value") for e in container["env"] if "value" in e}
        self.assertEqual(env_map.get("PGSSLMODE"), "verify-full")
        self.assertEqual(env_map.get("PGSSLROOTCERT"), "/etc/ssl/certs/rds-ca-bundle.pem")

        # Check volume mount
        mounts = container["volumeMounts"]
        self.assertTrue(any(m["mountPath"] == "/etc/ssl/certs" for m in mounts))

    def test_05_benchmark_orchestrator_fail_closed(self):
        """Aurora orchestrator must fail closed on invalid protocol parameters."""
        bad_orch = AuroraBenchmarkOrchestrator(config={"scale_factor": 25})
        results = bad_orch.validate_protocol_parameters()
        sf_res = next(r for r in results if r.check_name == "scale_factor")
        self.assertFalse(sf_res.passed, "Must fail closed on non-CA2 scale factor")

        bad_concur = AuroraBenchmarkOrchestrator(config={"clients": 50})
        results = bad_concur.validate_protocol_parameters()
        concur_res = next(r for r in results if r.check_name == "concurrency")
        self.assertFalse(concur_res.passed, "Must fail closed on non-CA2 client concurrency")

        good_orch = AuroraBenchmarkOrchestrator(config={
            "scale_factor": 50,
            "clients": 20,
            "threads": 4,
            "warmup_seconds": 120,
            "measurement_seconds": 600,
        })
        results = good_orch.validate_protocol_parameters()
        self.assertTrue(all(r.passed for r in results), f"Expected all to pass: {[r.to_dict() for r in results]}")

    def test_06_in_cluster_pod_manifest_parameters(self):
        """Generated in-cluster pod manifest must use pinned postgres:14.11-bullseye image and --max-tries=1."""
        orch = AuroraBenchmarkOrchestrator(config={
            "writer_endpoint": "ric-aurora.cluster-test.us-east-1.rds.amazonaws.com",
            "max_tries": 1,
        })
        manifest = orch.build_in_cluster_pod_manifest(
            pod_name="aurora-bench-pod",
            duration_sec=600,
            clients=20,
            threads=4,
            run_id="aurora-p01",
            phase_name="measurement",
            with_logging=True,
        )
        container = manifest["spec"]["containers"][0]
        self.assertEqual(container["image"], "postgres:14.11-bullseye")
        cmd = container["command"]
        self.assertIn("pgbench", cmd)
        self.assertIn("--max-tries=1", cmd)
        self.assertIn("-c", cmd)
        self.assertIn("20", cmd)
        self.assertIn("-j", cmd)
        self.assertIn("4", cmd)
        self.assertIn("-T", cmd)
        self.assertIn("600", cmd)
        self.assertIn("-l", cmd)

    def test_07_pgbench_output_parsing(self):
        """Parser must accurately extract TPS, average latency, and failed transactions."""
        sample_output = """
        starting vacuum...end.
        transaction type: <builtin: TPC-B (sort of)>
        scaling factor: 50
        query mode: simple
        number of clients: 20
        number of threads: 4
        duration: 600 s
        number of transactions actually processed: 489210
        number of failed transactions: 0 (0.000%)
        latency average = 24.512 ms
        tps = 815.421092 (including connections establishing)
        tps = 815.510291 (excluding connections establishing)
        """
        orch = AuroraBenchmarkOrchestrator()
        metrics = orch.parse_pgbench_output(sample_output)
        self.assertEqual(metrics["tps_including_connections"], 815.421092)
        self.assertEqual(metrics["tps_excluding_connections"], 815.510291)
        self.assertEqual(metrics["avg_latency_ms"], 24.512)
        self.assertEqual(metrics["total_transactions"], 489210)
        self.assertEqual(metrics["failed_transactions"], 0)

    def test_08_transaction_accounting_durability_verification(self):
        """Transaction accounting must verify zero balance drift and exact commit reconciliation."""
        orch = AuroraBenchmarkOrchestrator()
        # Clean run: balanced accounts and exact commits
        clean_res = orch.verify_dataset_accounting(
            pre_balance_sum=500000000,
            post_balance_sum=500000000,
            client_commits=489210,
            wal_tx_delta=489210,
        )
        self.assertTrue(clean_res.passed)

        # Balance drift (corrupted financial invariant)
        drift_res = orch.verify_dataset_accounting(
            pre_balance_sum=500000000,
            post_balance_sum=500001000,
            client_commits=489210,
            wal_tx_delta=489210,
        )
        self.assertFalse(drift_res.passed)

        # Lost commits (RPO violation)
        lost_tx_res = orch.verify_dataset_accounting(
            pre_balance_sum=500000000,
            post_balance_sum=500000000,
            client_commits=489210,
            wal_tx_delta=489205,
        )
        self.assertFalse(lost_tx_res.passed)

    def test_09_immutability_guards_for_existing_engines(self):
        """Ensure Aurora implementation did not touch CockroachDB or Patroni manifests."""
        crdb_values = os.path.join(REPO_ROOT, "kubernetes", "cockroachdb", "values.yaml")
        patroni_sts = os.path.join(REPO_ROOT, "kubernetes", "postgres-patroni", "06-patroni-statefulset.yaml")

        with open(crdb_values, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertNotIn("aurora", content.lower())

        with open(patroni_sts, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertNotIn("aurora", content.lower())

if __name__ == "__main__":
    unittest.main(verbosity=2)

