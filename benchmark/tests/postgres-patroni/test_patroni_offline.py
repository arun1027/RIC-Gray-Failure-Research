#!/usr/bin/env python3
"""
Offline Test Suite for PostgreSQL + Patroni Architecture Implementation.
Validates:
1. YAML parsing & Kubernetes schema fields.
2. Exact image-version pins (never 'latest').
3. etcd member discovery & service ports.
4. Patroni synchronous streaming replication configuration.
5. Secret-handling safeguards (no plaintext production credentials).
6. Persistent storage & health probes.
7. Benchmark parameter validation & fail-closed behavior.
8. Output parsing & metric extraction.
9. CockroachDB immutability (no modifications to CockroachDB assets).
"""

import os
import sys
import unittest
import yaml
import glob
import re
import csv
import json
import tempfile
import shutil
import io
import tarfile
import hashlib
import subprocess
from unittest.mock import patch, MagicMock

REPO_ROOT = r"d:\Projects\RIC-Gray-Failure-Research"
PATRONI_DIR = os.path.join(REPO_ROOT, "kubernetes", "postgres-patroni")
BENCHMARK_DIR = os.path.join(REPO_ROOT, "benchmark", "scripts", "postgres-patroni")

# Ensure orchestrator is importable
if BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, BENCHMARK_DIR)

from orchestrate_patroni import PatroniBenchmarkOrchestrator, PreflightCheckResult

class TestPatroniManifestsOffline(unittest.TestCase):

    def setUp(self):
        self.yaml_files = glob.glob(os.path.join(PATRONI_DIR, "*.yaml"))

    def test_01_all_yaml_files_parse_cleanly(self):
        """All YAML manifests must be syntactically valid and parseable."""
        self.assertGreater(len(self.yaml_files), 0, "No YAML manifest files found in kubernetes/postgres-patroni")
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

    def test_02_exact_image_version_pins(self):
        """All container images must be pinned to immutable tags; never latest."""
        pinned_images_found = []
        for yfile in self.yaml_files:
            with open(yfile, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
                for doc in docs:
                    if not doc:
                        continue
                    kind = doc.get("kind")
                    if kind == "StatefulSet":
                        containers = doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
                        for c in containers:
                            img = c.get("image", "")
                            self.assertTrue(img, f"Container {c.get('name')} in {yfile} has no image defined")
                            self.assertNotIn(":latest", img, f"Prohibited :latest tag in {yfile}: {img}")
                            self.assertIn(":", img, f"Image without tag in {yfile}: {img}")
                            pinned_images_found.append(img)

        # Specifically check Spilo (PostgreSQL 15 + Patroni 3.0.x with immutable digest) and etcd 3.5.x
        expected_spilo_digest = "sha256:8f59f3856e228bc7bf602fc71a5f44d755c8a9a0215c4e99fd3bc5ae2e620e73"
        spilo_found = any("spilo-15:3.0-p1@" in img and expected_spilo_digest in img for img in pinned_images_found)
        etcd_found = any("etcd:3.5." in img for img in pinned_images_found)
        self.assertTrue(spilo_found, f"Zalando Spilo-15:3.0-p1 pinned digest not found in manifests: {pinned_images_found}")
        self.assertTrue(etcd_found, f"Bitnami etcd 3.5 not found in manifests: {pinned_images_found}")

    def test_03_etcd_member_discovery_and_ports(self):
        """etcd StatefulSet must configure 3 members, peer port 2380, and client port 2379."""
        etcd_file = os.path.join(PATRONI_DIR, "02-etcd-statefulset.yaml")
        self.assertTrue(os.path.exists(etcd_file), "02-etcd-statefulset.yaml missing")
        with open(etcd_file, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))

        sts_docs = [d for d in docs if d.get("kind") == "StatefulSet"]
        self.assertEqual(len(sts_docs), 1)
        etcd_sts = sts_docs[0]
        self.assertEqual(etcd_sts["spec"]["replicas"], 3)
        self.assertEqual(etcd_sts["metadata"]["namespace"], "postgres-patroni")

        # Check ports
        container = etcd_sts["spec"]["template"]["spec"]["containers"][0]
        port_names = {p["name"]: p["containerPort"] for p in container.get("ports", [])}
        self.assertEqual(port_names.get("client"), 2379)
        self.assertEqual(port_names.get("peer"), 2380)

        # Check cluster string env
        env_dict = {e["name"]: e.get("value") for e in container.get("env", []) if "value" in e}
        self.assertIn("ETCD_INITIAL_CLUSTER", env_dict)
        self.assertIn("etcd-0", env_dict["ETCD_INITIAL_CLUSTER"])
        self.assertIn("etcd-1", env_dict["ETCD_INITIAL_CLUSTER"])
        self.assertIn("etcd-2", env_dict["ETCD_INITIAL_CLUSTER"])

    def test_04_patroni_synchronous_replication_config(self):
        """Patroni ConfigMap must enforce synchronous_mode: true per CA2 protocol."""
        cm_file = os.path.join(PATRONI_DIR, "04-patroni-configmap.yaml")
        self.assertTrue(os.path.exists(cm_file), "04-patroni-configmap.yaml missing")
        with open(cm_file, "r", encoding="utf-8") as f:
            cm = yaml.safe_load(f)

        patroni_raw = cm["data"]["patroni.yml"]
        patroni_cfg = yaml.safe_load(patroni_raw)

        dcs = patroni_cfg.get("bootstrap", {}).get("dcs", {})
        self.assertIs(dcs.get("synchronous_mode"), True, "synchronous_mode must be True in Patroni DCS")
        self.assertEqual(dcs.get("synchronous_node_count"), 1)
        
        # PostgreSQL parameters
        pg_params = dcs.get("postgresql", {}).get("parameters", {})
        self.assertEqual(pg_params.get("wal_level"), "replica")
        self.assertEqual(pg_params.get("synchronous_commit"), "on")
        self.assertEqual(pg_params.get("hot_standby"), "on")

    def test_05_secret_handling_safeguards(self):
        """Secret template must not be applied directly as production credentials and must be labeled template."""
        secret_file = os.path.join(PATRONI_DIR, "03-patroni-secrets-template.yaml")
        self.assertTrue(os.path.exists(secret_file), "03-patroni-secrets-template.yaml missing")
        with open(secret_file, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("TEMPLATE ONLY", content)

    def test_06_persistent_volumes_and_health_probes(self):
        """Patroni StatefulSet must mount PVC and define health probes on port 8008."""
        sts_file = os.path.join(PATRONI_DIR, "06-patroni-statefulset.yaml")
        self.assertTrue(os.path.exists(sts_file), "06-patroni-statefulset.yaml missing")
        with open(sts_file, "r", encoding="utf-8") as f:
            sts = yaml.safe_load(f)

        self.assertEqual(sts["spec"]["replicas"], 3)
        container = sts["spec"]["template"]["spec"]["containers"][0]

        # Health probes
        self.assertIn("readinessProbe", container)
        self.assertIn("livenessProbe", container)
        self.assertEqual(container["readinessProbe"]["httpGet"]["port"], 8008)
        self.assertEqual(container["livenessProbe"]["httpGet"]["port"], 8008)
        self.assertIn(container["readinessProbe"]["httpGet"]["path"], ["/ready", "/readiness"])
        self.assertEqual(container["livenessProbe"]["httpGet"]["path"], "/liveness")

        # PVC template
        vc_templates = sts["spec"].get("volumeClaimTemplates", [])
        self.assertEqual(len(vc_templates), 1)
        self.assertEqual(vc_templates[0]["metadata"]["name"], "pgdata")
        storage_req = vc_templates[0]["spec"]["resources"]["requests"]["storage"]
        self.assertEqual(storage_req, "10Gi")

    def test_07_services_routing(self):
        """Services must configure separate primary (role=master) and replica (role=replica) endpoints."""
        svc_file = os.path.join(PATRONI_DIR, "05-patroni-services.yaml")
        self.assertTrue(os.path.exists(svc_file), "05-patroni-services.yaml missing")
        with open(svc_file, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))

        svc_map = {d["metadata"]["name"]: d for d in docs if d.get("kind") == "Service"}
        self.assertIn("patroni-headless", svc_map)
        self.assertIn("patroni-primary", svc_map)
        self.assertIn("patroni-replica", svc_map)

        # Primary selector
        primary_role = svc_map["patroni-primary"]["spec"]["selector"].get("spilo-role") or svc_map["patroni-primary"]["spec"]["selector"].get("role")
        self.assertEqual(primary_role, "master")
        # Replica selector
        replica_role = svc_map["patroni-replica"]["spec"]["selector"].get("spilo-role") or svc_map["patroni-replica"]["spec"]["selector"].get("role")
        self.assertEqual(replica_role, "replica")

    def test_08_benchmark_orchestrator_fail_closed(self):
        """Orchestrator must fail closed when invalid protocol parameters are supplied."""
        # Non-CA2 scale factor
        bad_orch = PatroniBenchmarkOrchestrator(config={"scale_factor": 10})
        results = bad_orch.validate_protocol_parameters()
        sf_res = next(r for r in results if r.check_name == "scale_factor")
        self.assertFalse(sf_res.passed, "Orchestrator should fail closed on non-CA2 scale factor")

        # Non-CA2 clients
        bad_concur = PatroniBenchmarkOrchestrator(config={"clients": 50})
        results = bad_concur.validate_protocol_parameters()
        concur_res = next(r for r in results if r.check_name == "concurrency")
        self.assertFalse(concur_res.passed, "Orchestrator should fail closed on non-CA2 client concurrency")

        # CA2 valid parameters
        good_orch = PatroniBenchmarkOrchestrator(config={
            "scale_factor": 50,
            "clients": 20,
            "threads": 4,
            "warmup_seconds": 120,
            "measurement_seconds": 600,
        })
        results = good_orch.validate_protocol_parameters()
        self.assertTrue(all(r.passed for r in results), f"Expected all checks to pass: {[r.to_dict() for r in results]}")

    def test_09_benchmark_pod_manifest_generation(self):
        """Orchestrator must generate a valid in-cluster Pod manifest targeting patroni-primary."""
        orch = PatroniBenchmarkOrchestrator(config={"node_target": "ip-10-0-2-111.ec2.internal"})
        manifest = orch.build_in_cluster_pod_manifest(
            pod_name="test-patroni-client",
            duration_sec=600,
            clients=20,
            threads=4,
            run_id="run-test-01",
            phase_name="measurement",
        )
        self.assertEqual(manifest["apiVersion"], "v1")
        self.assertEqual(manifest["kind"], "Pod")
        self.assertEqual(manifest["metadata"]["name"], "test-patroni-client")
        self.assertEqual(manifest["metadata"]["namespace"], "postgres-patroni")
        container = manifest["spec"]["containers"][0]
        self.assertEqual(container["image"], "postgres:15-bullseye@sha256:4ce70bcb2c05817a09b9919fc440878cf893cfb5623cd05023778a67644ea81d")
        cmd = container["command"]
        self.assertIn("pgbench", cmd)
        self.assertIn("-c", cmd)
        self.assertIn("20", cmd)
        self.assertIn("-j", cmd)
        self.assertIn("4", cmd)
        self.assertIn("-T", cmd)
        self.assertIn("600", cmd)

    def test_10_patroni_cluster_health_mock_validation(self):
        """Cluster health check must verify 1 leader and synchronous standbys."""
        orch = PatroniBenchmarkOrchestrator()
        
        # Valid cluster state
        valid_state = {
            "members": [
                {"name": "patroni-0", "role": "leader", "state": "running"},
                {"name": "patroni-1", "role": "sync_standby", "state": "running"},
                {"name": "patroni-2", "role": "replica", "state": "running"},
            ]
        }
        res = orch.verify_patroni_cluster_health_mockable(valid_state)
        self.assertTrue(res.passed)

        # Missing sync standby (replication gray failure / split-brain risk)
        nosync_state = {
            "members": [
                {"name": "patroni-0", "role": "leader", "state": "running"},
                {"name": "patroni-1", "role": "replica", "state": "running"},
                {"name": "patroni-2", "role": "replica", "state": "running"},
            ]
        }
        res_nosync = orch.verify_patroni_cluster_health_mockable(nosync_state)
        self.assertFalse(res_nosync.passed, "Must fail closed if synchronous standby is missing")

        # Two leaders (split-brain)
        split_brain_state = {
            "members": [
                {"name": "patroni-0", "role": "leader", "state": "running"},
                {"name": "patroni-1", "role": "leader", "state": "running"},
                {"name": "patroni-2", "role": "sync_standby", "state": "running"},
            ]
        }
        res_split = orch.verify_patroni_cluster_health_mockable(split_brain_state)
        self.assertFalse(res_split.passed, "Must fail closed if split-brain leader detected")

    def test_11_pgbench_output_parsing(self):
        """Parser must accurately extract TPS, average latency, and failed transactions."""
        sample_output = """
        starting vacuum...end.
        transaction type: <builtin: TPC-B (sort of)>
        scaling factor: 50
        query mode: simple
        number of clients: 20
        number of threads: 4
        duration: 600 s
        number of transactions actually processed: 345678
        number of failed transactions: 0 (0.000%)
        latency average = 34.712 ms
        tps = 576.128711 (including connections establishing)
        tps = 576.192410 (excluding connections establishing)
        """
        orch = PatroniBenchmarkOrchestrator()
        metrics = orch.parse_pgbench_output(sample_output)
        self.assertEqual(metrics["tps_including_connections"], 576.128711)
        self.assertEqual(metrics["tps_excluding_connections"], 576.192410)
        self.assertEqual(metrics["avg_latency_ms"], 34.712)
        self.assertEqual(metrics["total_transactions"], 345678)
        self.assertEqual(metrics["failed_transactions"], 0)

    def test_12_cockroachdb_immutability_guard(self):
        """Ensure no CockroachDB manifests or helm values were touched by this implementation."""
        crdb_dir = os.path.join(REPO_ROOT, "kubernetes", "cockroachdb")
        self.assertTrue(os.path.exists(crdb_dir))
        
        # Check values.yaml exists and contains CockroachDB configurations without any Patroni leakage
        crdb_values = os.path.join(crdb_dir, "values.yaml")
        with open(crdb_values, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("max-sql-memory", content.lower())
            self.assertNotIn("patroni", content.lower(), "Patroni settings must not leak into CockroachDB values")

    def test_13_pod_anti_affinity_and_storage_class_pinning(self):
        """StatefulSets must configure zone anti-affinity and gp3-csi storage class."""
        etcd_file = os.path.join(PATRONI_DIR, "02-etcd-statefulset.yaml")
        patroni_file = os.path.join(PATRONI_DIR, "06-patroni-statefulset.yaml")

        for fpath in (etcd_file, patroni_file):
            with open(fpath, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
            sts_docs = [d for d in docs if d.get("kind") == "StatefulSet"]
            self.assertEqual(len(sts_docs), 1, f"Missing StatefulSet in {fpath}")
            sts = sts_docs[0]

            # Verify pod anti-affinity
            affinity = sts["spec"]["template"]["spec"].get("affinity", {})
            self.assertIn("podAntiAffinity", affinity, f"Missing podAntiAffinity in {fpath}")
            anti = affinity["podAntiAffinity"].get("requiredDuringSchedulingIgnoredDuringExecution", [])
            topo_keys = [rule.get("topologyKey") for rule in anti]
            self.assertIn("topology.kubernetes.io/zone", topo_keys, f"Missing zone anti-affinity in {fpath}")

            # Verify storage class
            vc = sts["spec"].get("volumeClaimTemplates", [])
            self.assertGreater(len(vc), 0, f"Missing volumeClaimTemplates in {fpath}")
            self.assertEqual(vc[0]["spec"].get("storageClassName"), "gp3-csi", f"StorageClass must be gp3-csi in {fpath}")

    def test_14_secure_patroni_secrets_generator(self):
        """Dynamic secret generator must produce valid Secret with high-entropy tokens without printing."""
        import tempfile
        import shutil
        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "aws"))
        import importlib
        gen_mod = importlib.import_module("configure-patroni-secrets")

        tmp = tempfile.mkdtemp()
        try:
            sec_path = gen_mod.generate_patroni_credentials(output_dir=tmp)
            self.assertTrue(os.path.exists(sec_path))
            with open(sec_path, "r", encoding="utf-8") as f:
                sec_doc = yaml.safe_load(f)
            self.assertEqual(sec_doc["kind"], "Secret")
            self.assertGreaterEqual(len(sec_doc["stringData"]["superuser-password"]), 32)
            self.assertGreaterEqual(len(sec_doc["stringData"]["replication-password"]), 32)
            self.assertGreaterEqual(len(sec_doc["stringData"]["api-password"]), 32)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_15_dynamic_cluster_ip_resolution(self):
        """Dynamic ClusterIP resolution must handle configured, discovered, and invalid inputs."""
        import subprocess
        # 1. Config override
        orch_cfg = PatroniBenchmarkOrchestrator(config={"primary_cluster_ip": "172.20.99.99"})
        self.assertEqual(orch_cfg.get_primary_service_cluster_ip(), "172.20.99.99")

        # 2. Mocked successful discovery
        orch_mock = PatroniBenchmarkOrchestrator()
        orch_mock._run_kubectl = lambda args, **kwargs: subprocess.CompletedProcess(
            args=args, returncode=0, stdout="172.20.33.66\n", stderr=""
        )
        self.assertEqual(orch_mock.get_primary_service_cluster_ip(), "172.20.33.66")

        # 3. Invalid IP format fails closed
        orch_invalid = PatroniBenchmarkOrchestrator()
        orch_invalid._run_kubectl = lambda args, **kwargs: subprocess.CompletedProcess(
            args=args, returncode=0, stdout="invalid.ip.string\n", stderr=""
        )
        with self.assertRaises(ValueError):
            orch_invalid.get_primary_service_cluster_ip()

        # 4. Command failure fails closed
        orch_err = PatroniBenchmarkOrchestrator()
        orch_err._run_kubectl = lambda args, **kwargs: subprocess.CompletedProcess(
            args=args, returncode=1, stdout="", stderr="service not found"
        )
        with self.assertRaises(RuntimeError):
            orch_err.get_primary_service_cluster_ip()

    def test_16_pod_manifest_logging_node_affinity_resources_tls(self):
        """In-cluster pod manifest must enforce Node 2 placement, TLS verify-full, and resource limits."""
        orch = PatroniBenchmarkOrchestrator(config={"primary_cluster_ip": "172.20.33.66", "node_target": "ip-10-0-2-111.ec2.internal"})
        manifest = orch.build_in_cluster_pod_manifest(
            pod_name="patroni-benchmark-client-test",
            duration_sec=600,
            clients=20,
            threads=4,
            run_id="patroni-baseline-r01-aws",
            phase_name="measurement",
            with_logging=True,
        )

        spec = manifest["spec"]
        container = spec["containers"][0]

        # Pinned client image
        self.assertEqual(container["image"], "postgres:15-bullseye@sha256:4ce70bcb2c05817a09b9919fc440878cf893cfb5623cd05023778a67644ea81d")

        # Command arguments: --max-tries=1, -c 20, -j 4, -T 600, -P 10, -l, --log-prefix
        cmd = container["command"]
        self.assertEqual(cmd[0], "pgbench")
        self.assertIn("--max-tries=1", cmd)
        self.assertIn("-c", cmd)
        self.assertEqual(cmd[cmd.index("-c") + 1], "20")
        self.assertIn("-j", cmd)
        self.assertEqual(cmd[cmd.index("-j") + 1], "4")
        self.assertIn("-T", cmd)
        self.assertEqual(cmd[cmd.index("-T") + 1], "600")
        self.assertIn("-P", cmd)
        self.assertEqual(cmd[cmd.index("-P") + 1], "10")
        self.assertIn("-l", cmd)
        self.assertIn("--log-prefix=/logs/pgbench_log", cmd)

        # Node 2 placement pinning
        self.assertEqual(spec["nodeSelector"]["kubernetes.io/hostname"], "ip-10-0-2-111.ec2.internal")
        affinity_terms = spec["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
        match_expr = affinity_terms[0]["matchExpressions"][0]
        self.assertEqual(match_expr["key"], "kubernetes.io/hostname")
        self.assertEqual(match_expr["values"], ["ip-10-0-2-111.ec2.internal"])

        # Resource isolation
        resources = container["resources"]
        self.assertEqual(resources["requests"]["cpu"], "250m")
        self.assertEqual(resources["requests"]["memory"], "256Mi")
        self.assertEqual(resources["limits"]["cpu"], "1000m")
        self.assertEqual(resources["limits"]["memory"], "1024Mi")

        # Verified TLS configuration
        env_map = {e["name"]: e.get("value") for e in container["env"] if "value" in e}
        self.assertEqual(env_map.get("PGHOST"), "spilo.example.org")
        self.assertEqual(env_map.get("PGHOSTADDR"), "172.20.33.66")
        self.assertEqual(env_map.get("PGPORT"), "5432")
        self.assertEqual(env_map.get("PGUSER"), "postgres")
        self.assertEqual(env_map.get("PGDATABASE"), "benchdb")
        self.assertEqual(env_map.get("PGSSLMODE"), "verify-full")
        self.assertEqual(env_map.get("PGSSLROOTCERT"), "/certs/server.crt")

        # Volumes & mounts
        mount_map = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}
        self.assertEqual(mount_map.get("patroni-ca-volume"), "/certs")
        self.assertEqual(mount_map.get("logs-volume"), "/logs")

        vol_map = {v["name"]: v for v in spec["volumes"]}
        self.assertIn("patroni-ca-volume", vol_map)
        self.assertEqual(vol_map["patroni-ca-volume"]["configMap"]["name"], "patroni-server-ca")
        self.assertIn("logs-volume", vol_map)
        self.assertIn("emptyDir", vol_map["logs-volume"])

    def test_17_database_snapshot_query_and_token_parsing(self):
        """Snapshot query must extract 12 tokens and parse all fields fail-closed."""
        import subprocess
        orch = PatroniBenchmarkOrchestrator()

        # 1. Valid snapshot
        valid_raw = "benchdb,postgres,f,5000000,0,50,0,500,0,0,0/2C000000,123456\n"
        orch._run_psql = lambda sql, **kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=valid_raw, stderr=""
        )
        snap = orch.get_database_snapshot("S0_Initial")
        self.assertEqual(snap["phase"], "S0_Initial")
        self.assertEqual(snap["database"], "benchdb")
        self.assertEqual(snap["user"], "postgres")
        self.assertFalse(snap["is_recovery"])
        self.assertEqual(snap["accounts_count"], 5000000)
        self.assertEqual(snap["accounts_balance"], 0)
        self.assertEqual(snap["branches_count"], 50)
        self.assertEqual(snap["branches_balance"], 0)
        self.assertEqual(snap["tellers_count"], 500)
        self.assertEqual(snap["tellers_balance"], 0)
        self.assertEqual(snap["history_count"], 0)
        self.assertEqual(snap["wal_lsn"], "0/2C000000")
        self.assertEqual(snap["transaction_id"], 123456)

        # 2. Malformed token count raises RuntimeError
        orch._run_psql = lambda sql, **kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout="benchdb,postgres,f,5000000,0\n", stderr=""
        )
        with self.assertRaises(RuntimeError):
            orch.get_database_snapshot("S1_Malformed")

        # 3. psql failure raises RuntimeError
        orch._run_psql = lambda sql, **kwargs: subprocess.CompletedProcess(
            args=[], returncode=2, stdout="", stderr="connection refused"
        )
        with self.assertRaises(RuntimeError):
            orch.get_database_snapshot("S2_Error")

    def test_18_transaction_reconciliation_invariants(self):
        """Reconciliation must verify commits match history, zero net drift, and cooldown stability."""
        orch = PatroniBenchmarkOrchestrator()

        s1 = {
            "accounts_count": 5000000, "accounts_balance": 1000,
            "branches_count": 50, "branches_balance": -600,
            "tellers_count": 500, "tellers_balance": -400,
            "history_count": 5000,
        }
        s2 = {
            "accounts_count": 5000000, "accounts_balance": 2500,
            "branches_count": 50, "branches_balance": -1500,
            "tellers_count": 500, "tellers_balance": -1000,
            "history_count": 45000,
        }
        s3 = {
            "accounts_count": 5000000, "accounts_balance": 2500,
            "branches_count": 50, "branches_balance": -1500,
            "tellers_count": 500, "tellers_balance": -1000,
            "history_count": 45000,
        }

        # 1. Exact match (40000 delta history == 40000 commits, net balances == 0)
        client_out = {"successful_transactions": 40000, "failed_transactions": 0}
        res = orch.reconcile_transaction_accounting(s1, s2, s3, client_out)
        self.assertTrue(res.passed, f"Expected reconciliation to pass: {res.message}")

        # 2. Transaction mismatch fails
        bad_client_out = {"successful_transactions": 39990, "failed_transactions": 10}
        res_mismatch = orch.reconcile_transaction_accounting(s1, s2, s3, bad_client_out)
        self.assertFalse(res_mismatch.passed)
        self.assertIn("mismatch", res_mismatch.message)

        # 3. Net balance drift fails
        s2_drift = dict(s2, accounts_balance=3000)  # sum = 3000 - 1500 - 1000 = 500 != 0
        res_drift = orch.reconcile_transaction_accounting(s1, s2_drift, s3, client_out)
        self.assertFalse(res_drift.passed)
        self.assertIn("balance invariant", res_drift.message.lower())

        # 4. Observation period drift fails
        s3_drift = dict(s3, history_count=45050)
        res_obs = orch.reconcile_transaction_accounting(s1, s2, s3_drift, client_out)
        self.assertFalse(res_obs.passed)
        self.assertIn("observation drift", res_obs.message.lower())

        # 5. Log parsing failure passes through
        bad_logs = {"ok": False, "errors": ["Log file truncated"]}
        res_log_fail = orch.reconcile_transaction_accounting(s1, s2, s3, client_out, transaction_logs=bad_logs)
        self.assertFalse(res_log_fail.passed)

    def test_19_workload_timing_and_protocol_validation(self):
        """Timing validation must enforce 120s/600s/300s in formal mode while allowing smoke test override."""
        # 1. Formal timing matches CA2
        formal_orch = PatroniBenchmarkOrchestrator(config={
            "warmup_seconds": 120, "measurement_seconds": 600, "cooldown_seconds": 300
        })
        results = formal_orch.validate_protocol_parameters()
        timing_check = next(r for r in results if r.check_name == "workload_timing")
        self.assertTrue(timing_check.passed)

        # 2. Formal timing mismatch fails closed
        bad_timing_orch = PatroniBenchmarkOrchestrator(config={
            "warmup_seconds": 60, "measurement_seconds": 300, "cooldown_seconds": 60
        })
        results_bad = bad_timing_orch.validate_protocol_parameters()
        timing_check_bad = next(r for r in results_bad if r.check_name == "workload_timing")
        self.assertFalse(timing_check_bad.passed)

        # 3. Smoke test mode allows custom timing
        smoke_orch = PatroniBenchmarkOrchestrator(config={
            "is_smoke_test": True, "warmup_seconds": 10, "measurement_seconds": 30, "cooldown_seconds": 10
        })
        results_smoke = smoke_orch.validate_protocol_parameters()
        timing_check_smoke = next(r for r in results_smoke if r.check_name == "workload_timing")
        self.assertTrue(timing_check_smoke.passed)
        self.assertIn("Smoke test", timing_check_smoke.message)

    def test_20_telemetry_collector_csv_output(self):
        """Telemetry collector must write valid CSV with 19 columns and status flags."""
        import tempfile
        import threading
        import subprocess
        import shutil

        tmpdir = tempfile.mkdtemp()
        try:
            log_file = os.path.join(tmpdir, "telemetry_test.csv")
            orch = PatroniBenchmarkOrchestrator()

            # Mock successful query
            orch._run_psql = lambda sql, **kwargs: subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="21,50000,0,100,5000,50000,50000,1000,2000,500,0,0,0/2C000000,2,0\n",
                stderr=""
            )

            stop_evt = threading.Event()
            # Start collector in thread, let it sample once, then stop
            t = threading.Thread(target=orch.run_telemetry_collector, args=(stop_evt, "test-run", log_file))
            t.start()
            import time
            time.sleep(0.5)
            stop_evt.set()
            t.join(timeout=3)

            self.assertTrue(os.path.exists(log_file))
            with open(log_file, "r", encoding="utf-8") as f:
                reader = list(csv.reader(f))
            self.assertGreaterEqual(len(reader), 2)  # Header + at least 1 data row
            header = reader[0]
            self.assertEqual(len(header), 19)
            self.assertEqual(header[0], "timestamp_utc")
            self.assertEqual(header[-2], "status")
            self.assertEqual(header[-1], "error_details")

            first_data = reader[1]
            self.assertEqual(len(first_data), 19)
            self.assertEqual(first_data[-2], "OK")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_21_execute_run_safeguards(self):
        """execute_run must fail closed if output directory exists or preflight fails."""
        import tempfile
        import shutil

        tmpdir = tempfile.mkdtemp()
        try:
            orch = PatroniBenchmarkOrchestrator(config={"output_dir": tmpdir})
            existing_run_id = "test-existing-run"
            os.makedirs(os.path.join(tmpdir, existing_run_id), exist_ok=True)

            with self.assertRaises(FileExistsError):
                orch.execute_run(run_id=existing_run_id)

            # Preflight failure aborts run cleanly returning False
            orch_fail = PatroniBenchmarkOrchestrator(config={"output_dir": tmpdir, "scale_factor": 10})
            run_result = orch_fail.execute_run(run_id="test-new-run")
            self.assertFalse(run_result, "execute_run must return False fail-closed when preflight fails")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestPatroniExecutionRunnerOffline(unittest.TestCase):
    """
    Offline Test Suite for Patroni Benchmark Execution Runner.
    Mocks external cluster and subprocess boundaries to validate all 20 lifecycle requirements.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.test_dir, "results")
        os.makedirs(self.output_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _get_mock_snapshots(self, delta_history=1000, balance_drift=0, cooldown_drift=0):
        s0 = {
            "phase": "S0_Initial", "database": "benchdb", "user": "postgres", "is_recovery": False,
            "accounts_count": 5000000, "accounts_balance": 0, "branches_count": 50, "branches_balance": 0,
            "tellers_count": 500, "tellers_balance": 0, "history_count": 0,
            "wal_lsn": "0/2C000000", "transaction_id": 100000, "raw_output": "",
        }
        s1 = dict(s0, phase="S1_PreMeasurement", history_count=200, transaction_id=100200)
        s2 = dict(s0, phase="S2_PostMeasurement",
                  history_count=200 + delta_history,
                  accounts_balance=balance_drift,
                  transaction_id=100200 + delta_history)
        s3 = dict(s0, phase="S3_PostCooldown",
                  history_count=200 + delta_history + cooldown_drift,
                  accounts_balance=balance_drift,
                  transaction_id=100200 + delta_history + cooldown_drift)
        return [s0, s1, s2, s3]

    def _write_mock_logs(self, target_dir, threads=4, clients=20, tx_per_thread=250):
        os.makedirs(target_dir, exist_ok=True)
        res = {}
        for t in range(threads):
            fn = f"pgbench_log.1234.{t}"
            fp = os.path.join(target_dir, fn)
            with open(fp, "w", encoding="utf-8") as f:
                for i in range(tx_per_thread):
                    c = t * (clients // threads) + (i % (clients // threads))
                    f.write(f"{c} {i} 15000 0 1700000000 123456\n")
            res[fn] = {"size": os.path.getsize(fp), "sha256": "MOCK_SHA256"}
        return res

    def _base_mock_orchestrator(self, config_updates=None):
        cfg = {
            "output_dir": self.output_dir,
            "is_smoke_test": True,
            "warmup_seconds": 1,
            "measurement_seconds": 1,
            "cooldown_seconds": 1,
            "primary_cluster_ip": "172.20.33.66",
        }
        if config_updates:
            cfg.update(config_updates)
        return PatroniBenchmarkOrchestrator(config=cfg)

    def _default_k_side(self, args, **kwargs):
        cmd_str = " ".join(str(a) for a in args)
        if "get pod patroni-1" in cmd_str:
            return MagicMock(returncode=0, stdout="ip-10-0-2-111.ec2.internal\n", stderr="")
        if "get node" in cmd_str and "Ready" in cmd_str:
            return MagicMock(returncode=0, stdout="True\n", stderr="")
        if "get node" in cmd_str and "zone" in cmd_str:
            return MagicMock(returncode=0, stdout="us-east-1b\n", stderr="")
        if "cat /run/certs/server.crt" in cmd_str:
            return MagicMock(returncode=0, stdout="-----BEGIN CERTIFICATE-----\nMOCK_PEM_CERT\n-----END CERTIFICATE-----\n", stderr="")
        if "get configmap patroni-server-ca" in cmd_str:
            return MagicMock(returncode=0, stdout="-----BEGIN CERTIFICATE-----\nMOCK_PEM_CERT\n-----END CERTIFICATE-----\n", stderr="")
        if "describe pod" in cmd_str:
            return MagicMock(returncode=0, stdout="Mock pod describe: Status=Failed\n", stderr="")
        if "get events" in cmd_str:
            return MagicMock(returncode=0, stdout="Mock events: Warning FailedScheduling\n", stderr="")
        if "-T 1" in cmd_str:
            return MagicMock(returncode=0, stdout="number of transactions actually processed: 1000\nnumber of failed transactions: 0\nlatency average = 15.0 ms\n", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    def test_runner_01_successful_execution_lifecycle(self):
        """End-to-end benchmark execution must succeed and verify all invariants and artifacts."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-01-success"

        snapshots = self._get_mock_snapshots(delta_history=1000)

        def mock_copy(pod, rem, loc):
            return self._write_mock_logs(loc, threads=4, clients=20, tx_per_thread=250)

        def k_side(args, **kwargs):
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=snapshots), \
             patch.object(orch, "_run_psql_client", return_value=MagicMock(returncode=0, stdout="t\n" if "ssl" in "" else "f\n")), \
             patch.object(orch, "_run_psql", return_value=MagicMock(returncode=0, stdout="10,500,0,10,10,100,100,50,50,0,0,0,0/1,2,0\n")), \
             patch.object(orch, "_copy_logs_from_pod", side_effect=mock_copy), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):

            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")
            success = orch.execute_run(run_id=run_id)
            self.assertTrue(success, "execute_run should return True on fully valid execution")

            run_dir = os.path.join(self.output_dir, run_id)
            manifest_file = os.path.join(run_dir, f"{run_id}-manifest.json")
            self.assertTrue(os.path.exists(manifest_file))
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            self.assertEqual(manifest["run_status"], "SUCCESS")
            self.assertEqual(manifest["stages"]["reconciliation"], "VERIFIED")
            self.assertIn("p95", manifest["percentiles_ms"])
            self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-warmup.txt")))
            self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-measurement.txt")))
            self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-telemetry.csv")))
            self.assertTrue(os.path.exists(os.path.join(run_dir, f"{run_id}-recovery-telemetry.csv")))

    def test_runner_02_warmup_failure(self):
        """Warm-up failure must abort execution before S1 or measurement."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-02-warmup-fail"
        snapshots = self._get_mock_snapshots()

        def k_side(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "pgbench" in cmd_str and "--log-prefix" not in cmd_str:
                return MagicMock(returncode=1, stdout="", stderr="pgbench: error connecting to server")
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=snapshots), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            success = orch.execute_run(run_id=run_id)
            self.assertFalse(success, "Must return False when warm-up fails")
            run_dir = os.path.join(self.output_dir, run_id)
            self.assertFalse(os.path.exists(os.path.join(run_dir, f"{run_id}-measurement.txt")))

    def test_runner_03_measurement_execution_and_parsing(self):
        """Measurement stdout metrics must be parsed accurately into client_summary."""
        orch = self._base_mock_orchestrator()
        stdout_sample = (
            "transaction type: <builtin: TPC-B (sort of)>\n"
            "scaling factor: 50\n"
            "query mode: simple\n"
            "number of clients: 20\n"
            "number of threads: 4\n"
            "duration: 600 s\n"
            "number of transactions actually processed: 12345\n"
            "number of failed transactions: 0 (0.000%)\n"
            "latency average = 16.234 ms\n"
            "tps = 615.123 (including connections establishing)\n"
        )
        parsed = orch.parse_pgbench_output(stdout_sample)
        self.assertEqual(parsed["total_transactions"], 12345)
        self.assertEqual(parsed["successful_transactions"], 12345)
        self.assertEqual(parsed["failed_transactions"], 0)
        self.assertEqual(parsed["avg_latency_ms"], 16.234)

    def test_runner_04_measurement_duration_too_short(self):
        """Formal measurement (not smoke-test) aborted early must fail closed."""
        orch = PatroniBenchmarkOrchestrator(config={
            "output_dir": self.output_dir,
            "is_smoke_test": False,
            "warmup_seconds": 120,
            "measurement_seconds": 600,
            "cooldown_seconds": 300,
            "primary_cluster_ip": "172.20.33.66",
        })
        run_id = "test-run-04-early-abort"
        snapshots = self._get_mock_snapshots()

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=snapshots), \
             patch.object(orch, "_run_psql", return_value=MagicMock(returncode=0, stdout="10,500,0,10,10,100,100,50,50,0,0,0,0/1,2,0\n")), \
             patch.object(orch, "_run_kubectl", side_effect=self._default_k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            # Elapsed time is near 0s (mocked), far below 595s
            success = orch.execute_run(run_id=run_id)
            self.assertFalse(success, "Must fail closed if formal measurement duration < 595s")

    def test_runner_05_measurement_nonzero_exit(self):
        """Non-zero exit code in measurement must trigger fail-closed termination."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-05-meas-nonzero"
        snapshots = self._get_mock_snapshots()

        def k_side(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "--log-prefix" in cmd_str:
                return MagicMock(returncode=2, stdout="", stderr="pgbench: fatal error in worker thread")
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=snapshots), \
             patch.object(orch, "_run_psql", return_value=MagicMock(returncode=0, stdout="10,500,0,10,10,100,100,50,50,0,0,0,0/1,2,0\n")), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            success = orch.execute_run(run_id=run_id)
            self.assertFalse(success)

    def test_runner_06_missing_client_pod(self):
        """Failure to become Ready within ceiling must abort execution."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-06-not-ready"

        def k_side(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "wait" in cmd_str and "Ready" in cmd_str:
                return MagicMock(returncode=1, stdout="", stderr="timed out waiting for condition")
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):
            success = orch.execute_run(run_id=run_id)
            self.assertFalse(success)

    def test_runner_07_connection_or_tls_failure(self):
        """TLS failure inside client pod must abort before any workload."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-07-tls-fail"

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch, "_run_kubectl", side_effect=self._default_k_side):
            # pg_stat_ssl returns f
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="f\n")

            success = orch.execute_run(run_id=run_id)
            self.assertFalse(success)

    def test_32_ssl_verification_query_variants(self):
        """Comprehensive verification of pg_stat_ssl query handling."""
        # Case 1: SSL query returns true -> succeeds past TLS check
        orch1 = self._base_mock_orchestrator()
        with patch.object(orch1, "run_preflight_audit", return_value=True), \
             patch.object(orch1, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch1, "_run_kubectl", side_effect=self._default_k_side):
            called_queries = []
            def track_psql(sql, **kw):
                called_queries.append(sql)
                if "pg_stat_ssl" in sql:
                    return MagicMock(returncode=0, stdout="t\n")
                if "pg_is_in_recovery" in sql:
                    return MagicMock(returncode=0, stdout="f\n")
                return MagicMock(returncode=1, stdout="", stderr="stop early")
            orch1._run_psql_client = track_psql
            success = orch1.execute_run(run_id="test-ssl-var-1")
            self.assertFalse(success)
            self.assertTrue(any("pg_stat_ssl" in q for q in called_queries))

        # Case 2: SSL query returns false -> fail closed
        orch2 = self._base_mock_orchestrator()
        with patch.object(orch2, "run_preflight_audit", return_value=True), \
             patch.object(orch2, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch2, "_run_kubectl", side_effect=self._default_k_side):
            with patch.object(orch2, "_run_psql_client") as mock_psql:
                mock_psql.side_effect = [
                    MagicMock(returncode=0, stdout="f\n"),  # recovery = f
                    MagicMock(returncode=0, stdout="f\n"),  # ssl = f
                ]
                success = orch2.execute_run(run_id="test-ssl-var-2")
                self.assertFalse(success)

        # Case 3: SSL query returns empty / no rows -> fail closed
        orch3 = self._base_mock_orchestrator()
        with patch.object(orch3, "run_preflight_audit", return_value=True), \
             patch.object(orch3, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch3, "_run_kubectl", side_effect=self._default_k_side):
            with patch.object(orch3, "_run_psql_client") as mock_psql:
                mock_psql.side_effect = [
                    MagicMock(returncode=0, stdout="f\n"),  # recovery = f
                    MagicMock(returncode=0, stdout="\n"),   # empty output
                ]
                success = orch3.execute_run(run_id="test-ssl-var-3")
                self.assertFalse(success)

        # Case 4: SSL query returns NULL -> fail closed
        orch4 = self._base_mock_orchestrator()
        with patch.object(orch4, "run_preflight_audit", return_value=True), \
             patch.object(orch4, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch4, "_run_kubectl", side_effect=self._default_k_side):
            with patch.object(orch4, "_run_psql_client") as mock_psql:
                mock_psql.side_effect = [
                    MagicMock(returncode=0, stdout="f\n"),  # recovery = f
                    MagicMock(returncode=0, stdout="NULL\n"), # NULL
                ]
                success = orch4.execute_run(run_id="test-ssl-var-4")
                self.assertFalse(success)

        # Case 5: SSL query execution error -> fail closed
        orch5 = self._base_mock_orchestrator()
        with patch.object(orch5, "run_preflight_audit", return_value=True), \
             patch.object(orch5, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch5, "_run_kubectl", side_effect=self._default_k_side):
            with patch.object(orch5, "_run_psql_client") as mock_psql:
                mock_psql.side_effect = [
                    MagicMock(returncode=0, stdout="f\n"),  # recovery = f
                    MagicMock(returncode=1, stdout="", stderr="relation pg_stat_ssl does not exist\n"),
                ]
                success = orch5.execute_run(run_id="test-ssl-var-5")
                self.assertFalse(success)

        # Case 6: Multiple rows returned -> fail closed
        orch6 = self._base_mock_orchestrator()
        with patch.object(orch6, "run_preflight_audit", return_value=True), \
             patch.object(orch6, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch6, "_run_kubectl", side_effect=self._default_k_side):
            with patch.object(orch6, "_run_psql_client") as mock_psql:
                mock_psql.side_effect = [
                    MagicMock(returncode=0, stdout="f\n"),  # recovery = f
                    MagicMock(returncode=0, stdout="t\nt\n"), # two rows
                ]
                success = orch6.execute_run(run_id="test-ssl-var-6")
                self.assertFalse(success)

    def test_runner_08_missing_log_files(self):
        """Fewer log files than expected threads must trigger fail-closed error."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-08-missing-logs"

        # Mock copy returning only 2 files instead of 4
        def mock_copy_2(pod, rem, loc):
            os.makedirs(loc, exist_ok=True)
            res = {}
            for t in range(2):
                fn = f"pgbench_log.123.{t}"
                fp = os.path.join(loc, fn)
                with open(fp, "w") as f:
                    f.write("0 1 15000 0 1700000000 123456\n")
                res[fn] = {"size": 10, "sha256": "H"}
            return res

        def k_side(args, **kwargs):
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=self._get_mock_snapshots(1000)), \
             patch.object(orch, "_run_psql", return_value=MagicMock(returncode=0, stdout="10,500,0,10,10,100,100,50,50,0,0,0,0/1,2,0\n")), \
             patch.object(orch, "_copy_logs_from_pod", side_effect=mock_copy_2), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            success = orch.execute_run(run_id=run_id)
            self.assertFalse(success)

    def test_runner_09_corrupt_tar_extraction(self):
        """_copy_logs_from_pod must fail closed if corrupt tar bytes are received."""
        orch = self._base_mock_orchestrator()
        target_dir = os.path.join(self.test_dir, "corrupt_extract")

        # Mock kubectl returning invalid gzip stream
        orch._run_kubectl = lambda args, **kw: MagicMock(returncode=0, stdout=b"not-a-valid-gzip-stream", stderr=b"")

        with self.assertRaises(RuntimeError) as ctx:
            orch._copy_logs_from_pod("test-pod", "/logs", target_dir)
        self.assertIn("Tar extraction failed", str(ctx.exception))

    def test_runner_10_missing_client_id_coverage(self):
        """Logs missing client IDs from 0..19 must cause log validation to fail."""
        orch = self._base_mock_orchestrator()
        log_dir = os.path.join(self.test_dir, "missing_client_ids")
        os.makedirs(log_dir, exist_ok=True)

        # Write 4 files but only covering clients 0..15 (missing 16..19)
        for t in range(4):
            with open(os.path.join(log_dir, f"pgbench_log.111.{t}"), "w") as f:
                for i in range(25):
                    f.write(f"{t * 4 + (i % 4)} {i} 15000 0 1700000000 123456\n")

        res = orch.parse_transaction_logs(log_dir, "pgbench_log", expected_files=4, expected_clients=20)
        self.assertFalse(res["ok"])
        self.assertTrue(any("differ from expected" in e for e in res["errors"]))

    def test_runner_11_duplicate_or_malformed_log_entries(self):
        """Malformed rows in logs must be flagged by log_parser and cause rejection."""
        orch = self._base_mock_orchestrator()
        log_dir = os.path.join(self.test_dir, "malformed_logs")
        os.makedirs(log_dir, exist_ok=True)

        for t in range(4):
            with open(os.path.join(log_dir, f"pgbench_log.222.{t}"), "w") as f:
                if t == 0:
                    f.write("0 1 MALFORMED_TOKEN 0 1700000000 123456\n")
                else:
                    for i in range(10):
                        f.write(f"{t * 5} {i} 15000 0 1700000000 123456\n")

        res = orch.parse_transaction_logs(log_dir, "pgbench_log", expected_files=4, expected_clients=20)
        self.assertFalse(res["ok"])

    def test_runner_12_history_delta_mismatch(self):
        """Reconciliation must fail closed if delta_history != client_commits or log_commits."""
        orch = self._base_mock_orchestrator()
        s1 = {"accounts_balance": 0, "branches_balance": 0, "tellers_balance": 0, "history_count": 100}
        s2 = {"accounts_balance": 0, "branches_balance": 0, "tellers_balance": 0, "history_count": 1100}  # delta = 1000
        s3 = {"accounts_balance": 0, "branches_balance": 0, "tellers_balance": 0, "history_count": 1100}

        # Client reported 990 commits (lost 10 commits)
        client_out = {"successful_transactions": 990, "failed_transactions": 0}
        tx_logs = {"ok": True, "numeric_records": 1000}
        res = orch.reconcile_transaction_accounting(s1, s2, s3, client_out, tx_logs)
        self.assertFalse(res.passed)
        self.assertIn("mismatch", res.message)

    def test_runner_13_net_balance_drift_failure(self):
        """Reconciliation must fail if account, branch, teller balances don't sum to zero."""
        orch = self._base_mock_orchestrator()
        s1 = {"accounts_balance": 0, "branches_balance": 0, "tellers_balance": 0, "history_count": 100}
        s2 = {"accounts_balance": 500, "branches_balance": -200, "tellers_balance": -200, "history_count": 1100}  # sum = 100 != 0
        s3 = dict(s2)

        client_out = {"successful_transactions": 1000, "failed_transactions": 0}
        tx_logs = {"ok": True, "numeric_records": 1000}
        res = orch.reconcile_transaction_accounting(s1, s2, s3, client_out, tx_logs)
        self.assertFalse(res.passed)
        self.assertIn("Net balance invariant violated", res.message)

    def test_runner_14_observation_cooldown_drift_failure(self):
        """Reconciliation must fail if history records change during cooldown observation."""
        orch = self._base_mock_orchestrator()
        s1 = {"accounts_balance": 0, "branches_balance": 0, "tellers_balance": 0, "history_count": 100}
        s2 = {"accounts_balance": 0, "branches_balance": 0, "tellers_balance": 0, "history_count": 1100}
        s3 = {"accounts_balance": 0, "branches_balance": 0, "tellers_balance": 0, "history_count": 1105}  # grew by 5!

        client_out = {"successful_transactions": 1000, "failed_transactions": 0}
        tx_logs = {"ok": True, "numeric_records": 1000}
        res = orch.reconcile_transaction_accounting(s1, s2, s3, client_out, tx_logs)
        self.assertFalse(res.passed)
        self.assertIn("observation drift detected", res.message)

    def test_runner_15_telemetry_handshake_failure(self):
        """Telemetry returning ERROR on initial sample must activate fail-closed gate."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-15-handshake-fail"

        # Mock psql returning ERROR for telemetry query
        def psql_side(sql, **kw):
            if "pg_stat_database" in sql:
                return MagicMock(returncode=1, stdout="", stderr="server closed connection")
            return MagicMock(returncode=0, stdout="benchdb,postgres,f,5000000,0,50,0,500,0,0,0/1,1\n")

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch, "_run_psql", side_effect=psql_side), \
             patch.object(orch, "_run_kubectl", side_effect=self._default_k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            success = orch.execute_run(run_id=run_id)
            self.assertFalse(success, "Must fail closed if telemetry handshake fails")

    def test_runner_16_telemetry_thread_cleanup_on_exception(self):
        """Telemetry background thread must be stopped and joined in finally block."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-16-thread-cleanup"

        # Force exception during measurement
        def k_side(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "--log-prefix" in cmd_str:
                raise RuntimeError("Simulated unhandled exception during measurement")
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch, "_run_psql", return_value=MagicMock(returncode=0, stdout="10,500,0,10,10,100,100,50,50,0,0,0,0/1,2,0\n")), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            success = orch.execute_run(run_id=run_id)
            self.assertFalse(success)

    def test_runner_17_evidence_preservation_on_failure(self):
        """Partial manifest with error details must be preserved on disk when run fails."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-17-evidence-preserve"

        # Measurement fails
        def k_side(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "--log-prefix" in cmd_str:
                return MagicMock(returncode=1, stdout="", stderr="pgbench failed fatally")
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch, "_run_psql", return_value=MagicMock(returncode=0, stdout="10,500,0,10,10,100,100,50,50,0,0,0,0/1,2,0\n")), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            orch.execute_run(run_id=run_id)
            run_dir = os.path.join(self.output_dir, run_id)
            manifest_path = os.path.join(run_dir, f"{run_id}-manifest.json")
            self.assertTrue(os.path.exists(manifest_path), "Partial manifest must be preserved on disk")
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["run_status"], "FAILED")
            self.assertIn("error", data)

    def test_runner_18_pod_cleanup_on_failure(self):
        """kubectl delete pod must be called in finally block even when a step fails."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-18-pod-cleanup"
        deleted_pods = []

        def k_side(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "delete" in cmd_str and "pod" in cmd_str:
                deleted_pods.append(args[args.index("pod") + 1])
                return MagicMock(returncode=0, stdout="", stderr="")
            if "--log-prefix" in cmd_str:
                return MagicMock(returncode=1, stdout="", stderr="fatal error")
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch, "_run_psql", return_value=MagicMock(returncode=0, stdout="10,500,0,10,10,100,100,50,50,0,0,0,0/1,2,0\n")), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            orch.execute_run(run_id=run_id)
            self.assertEqual(len(deleted_pods), 1, "Client pod must be deleted in finally block")

    def test_runner_19_no_automatic_retry(self):
        """Runner must terminate and return False immediately without looping or retrying."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-19-no-retry"
        exec_count = [0]

        def k_side(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "--log-prefix" in cmd_str:
                exec_count[0] += 1
                return MagicMock(returncode=1, stdout="", stderr="crash")
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch, "_run_psql", return_value=MagicMock(returncode=0, stdout="10,500,0,10,10,100,100,50,50,0,0,0,0/1,2,0\n")), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            res = orch.execute_run(run_id=run_id)
            self.assertFalse(res)
            self.assertEqual(exec_count[0], 1, "Must not retry measurement on failure")

    def test_runner_20_correct_s0_s3_sequencing_and_telemetry_separation(self):
        """Snapshot phases must be called in exact order S0->S1->S2->S3 and telemetry CSVs separated."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-20-sequencing"
        recorded_phases = []

        def snap_side(phase_name, **kw):
            recorded_phases.append(phase_name)
            s0 = {
                "phase": phase_name, "database": "benchdb", "user": "postgres", "is_recovery": False,
                "accounts_count": 5000000, "accounts_balance": 0, "branches_count": 50, "branches_balance": 0,
                "tellers_count": 500, "tellers_balance": 0, "history_count": 0,
                "wal_lsn": "0/1", "transaction_id": 1, "raw_output": "",
            }
            if phase_name == "S1_PreMeasurement":
                s0["history_count"] = 50
            elif phase_name in ("S2_PostMeasurement", "S3_PostCooldown"):
                s0["history_count"] = 1050
            return s0

        def mock_copy(pod, rem, loc):
            return self._write_mock_logs(loc, threads=4, clients=20, tx_per_thread=250)

        def k_side(args, **kwargs):
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=snap_side), \
             patch.object(orch, "_run_psql", return_value=MagicMock(returncode=0, stdout="10,500,0,10,10,100,100,50,50,0,0,0,0/1,2,0\n")), \
             patch.object(orch, "_copy_logs_from_pod", side_effect=mock_copy), \
             patch.object(orch, "_run_kubectl", side_effect=k_side):
            orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

            success = orch.execute_run(run_id=run_id)
            self.assertTrue(success)
            self.assertEqual(recorded_phases, ["S0_Initial", "S1_PreMeasurement", "S2_PostMeasurement", "S3_PostCooldown"])

    # -------------------------------------------------------------------------
    # Stage 20.2 Remediation Tests (FIX-01 to FIX-04)
    # -------------------------------------------------------------------------
    def test_22_dynamic_node_discovery_success(self):
        """Dynamic node discovery must extract nodeName, verify Ready=True, and zone=us-east-1b."""
        orch = PatroniBenchmarkOrchestrator()
        def mock_k(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "get pod patroni-1" in cmd_str:
                return MagicMock(returncode=0, stdout="ip-10-0-2-111.ec2.internal\n", stderr="")
            if "get node ip-10-0-2-111.ec2.internal" in cmd_str and "Ready" in cmd_str:
                return MagicMock(returncode=0, stdout="True\n", stderr="")
            if "get node ip-10-0-2-111.ec2.internal" in cmd_str and "zone" in cmd_str:
                return MagicMock(returncode=0, stdout="us-east-1b\n", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(orch, "_run_kubectl", side_effect=mock_k):
            node = orch.discover_and_validate_client_node(target_pod="patroni-1", expected_zone="us-east-1b")
            self.assertEqual(node, "ip-10-0-2-111.ec2.internal")
            self.assertEqual(orch.node_target, "ip-10-0-2-111.ec2.internal")

    def test_23_dynamic_node_discovery_empty_or_error(self):
        """Dynamic node discovery must fail closed if pod lookup fails or returns empty."""
        orch = PatroniBenchmarkOrchestrator()
        def mock_k_err(args, **kwargs):
            return MagicMock(returncode=1, stdout="", stderr="Error from server (NotFound): pods 'patroni-1' not found")

        with patch.object(orch, "_run_kubectl", side_effect=mock_k_err):
            with self.assertRaises(RuntimeError) as ctx:
                orch.discover_and_validate_client_node()
            self.assertIn("Dynamic node discovery failed", str(ctx.exception))

        def mock_k_empty(args, **kwargs):
            return MagicMock(returncode=0, stdout="   \n", stderr="")

        with patch.object(orch, "_run_kubectl", side_effect=mock_k_empty):
            with self.assertRaises(RuntimeError) as ctx:
                orch.discover_and_validate_client_node()
            self.assertIn("Dynamic node discovery failed", str(ctx.exception))

    def test_24_dynamic_node_discovery_node_not_ready(self):
        """Dynamic node discovery must fail closed if the discovered node is not Ready."""
        orch = PatroniBenchmarkOrchestrator()
        def mock_k(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "get pod patroni-1" in cmd_str:
                return MagicMock(returncode=0, stdout="ip-10-0-2-111.ec2.internal\n", stderr="")
            if "get node" in cmd_str and "Ready" in cmd_str:
                return MagicMock(returncode=0, stdout="False\n", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(orch, "_run_kubectl", side_effect=mock_k):
            with self.assertRaises(RuntimeError) as ctx:
                orch.discover_and_validate_client_node()
            self.assertIn("is not Ready", str(ctx.exception))

    def test_25_dynamic_node_discovery_incorrect_zone(self):
        """Dynamic node discovery must fail closed if the discovered node is in the wrong AZ."""
        orch = PatroniBenchmarkOrchestrator()
        def mock_k(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "get pod patroni-1" in cmd_str:
                return MagicMock(returncode=0, stdout="ip-10-0-2-111.ec2.internal\n", stderr="")
            if "get node" in cmd_str and "Ready" in cmd_str:
                return MagicMock(returncode=0, stdout="True\n", stderr="")
            if "get node" in cmd_str and "zone" in cmd_str:
                return MagicMock(returncode=0, stdout="us-east-1a\n", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(orch, "_run_kubectl", side_effect=mock_k):
            with self.assertRaises(RuntimeError) as ctx:
                orch.discover_and_validate_client_node(expected_zone="us-east-1b")
            self.assertIn("does not match expected zone", str(ctx.exception))

    def test_26_readiness_wait_timeout_150s_passed(self):
        """Readiness wait must pass timeout=150 to _run_kubectl while specifying --timeout=120s in CLI."""
        orch = self._base_mock_orchestrator()
        wait_calls = []

        def mock_k(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "wait" in cmd_str and "--for=condition=Ready" in cmd_str:
                wait_calls.append({"args": args, "kwargs": kwargs})
                # Simulate timeout to abort early
                return MagicMock(returncode=1, stdout="", stderr="timed out waiting for the condition")
            return self._default_k_side(args, **kwargs)

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=self._get_mock_snapshots()), \
             patch.object(orch, "_run_kubectl", side_effect=mock_k):
            success = orch.execute_run(run_id="test-wait-timeout-150")
            self.assertFalse(success)
            self.assertEqual(len(wait_calls), 1)
            self.assertEqual(wait_calls[0]["kwargs"].get("timeout"), 150)
            self.assertIn("--timeout=120s", wait_calls[0]["args"])

    def test_27_ca_cert_provisioning_success(self):
        """CA certificate retrieval and ConfigMap apply must succeed on valid PEM data."""
        orch = PatroniBenchmarkOrchestrator()
        mock_pem = "-----BEGIN CERTIFICATE-----\nMIIB...VALID_MOCK_CERT\n-----END CERTIFICATE-----"
        applied_manifests = []

        def mock_k(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "cat /run/certs/server.crt" in cmd_str:
                return MagicMock(returncode=0, stdout=mock_pem + "\n", stderr="")
            if "apply -f -" in cmd_str:
                applied_manifests.append(kwargs.get("input"))
                return MagicMock(returncode=0, stdout="configmap/patroni-server-ca configured\n", stderr="")
            if "get configmap patroni-server-ca" in cmd_str:
                return MagicMock(returncode=0, stdout=mock_pem + "\n", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(orch, "_run_kubectl", side_effect=mock_k):
            res = orch.ensure_server_ca_configmap(primary_pod="patroni-0")
            self.assertTrue(res)
            self.assertEqual(len(applied_manifests), 1)
            parsed = json.loads(applied_manifests[0])
            self.assertEqual(parsed["kind"], "ConfigMap")
            self.assertEqual(parsed["metadata"]["name"], "patroni-server-ca")
            self.assertIn("server.crt", parsed["data"])

    def test_28_ca_cert_provisioning_invalid_or_missing_pem(self):
        """CA cert provisioning must fail closed on missing PEM boundaries, private keys, or extraction failure."""
        orch = PatroniBenchmarkOrchestrator()

        # Case A: Missing PEM boundaries
        with patch.object(orch, "_run_kubectl", return_value=MagicMock(returncode=0, stdout="not a valid cert", stderr="")):
            with self.assertRaises(ValueError) as ctx:
                orch.ensure_server_ca_configmap()
            self.assertIn("missing standard PEM certificate markers", str(ctx.exception))

        # Case B: Private key contamination
        bad_cert = "-----BEGIN CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----\nBAD\n-----END CERTIFICATE-----"
        with patch.object(orch, "_run_kubectl", return_value=MagicMock(returncode=0, stdout=bad_cert, stderr="")):
            with self.assertRaises(ValueError) as ctx:
                orch.ensure_server_ca_configmap()
            self.assertIn("contains private key data", str(ctx.exception))

        # Case C: Cat extraction failure
        with patch.object(orch, "_run_kubectl", return_value=MagicMock(returncode=1, stdout="", stderr="No such file")):
            with self.assertRaises(RuntimeError) as ctx:
                orch.ensure_server_ca_configmap()
            self.assertIn("Failed to retrieve CA certificate", str(ctx.exception))

    def test_29_ca_cert_provisioning_apply_or_verify_failure(self):
        """CA cert provisioning must fail closed if kubectl apply or verification check fails."""
        orch = PatroniBenchmarkOrchestrator()
        mock_pem = "-----BEGIN CERTIFICATE-----\nMIIB...VALID_MOCK_CERT\n-----END CERTIFICATE-----"

        # Apply fails
        def mock_k_apply_fail(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "cat" in cmd_str:
                return MagicMock(returncode=0, stdout=mock_pem, stderr="")
            if "apply" in cmd_str:
                return MagicMock(returncode=1, stdout="", stderr="Forbidden: cannot create configmap")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(orch, "_run_kubectl", side_effect=mock_k_apply_fail):
            with self.assertRaises(RuntimeError) as ctx:
                orch.ensure_server_ca_configmap()
            self.assertIn("Failed to apply ConfigMap", str(ctx.exception))

        # Verify fails
        def mock_k_verify_fail(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "cat" in cmd_str:
                return MagicMock(returncode=0, stdout=mock_pem, stderr="")
            if "apply" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            if "get configmap" in cmd_str:
                return MagicMock(returncode=1, stdout="", stderr="ConfigMap not found")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(orch, "_run_kubectl", side_effect=mock_k_verify_fail):
            with self.assertRaises(RuntimeError) as ctx:
                orch.ensure_server_ca_configmap()
            self.assertIn("ConfigMap verification failed", str(ctx.exception))

    def test_30_pod_failure_diagnostics_capture_success(self):
        """Pod failure diagnostics must write pod_failure_diagnostic.txt and pod_failure_events.txt."""
        orch = PatroniBenchmarkOrchestrator()
        with tempfile.TemporaryDirectory() as td:
            def mock_k(args, **kwargs):
                cmd_str = " ".join(str(a) for a in args)
                if "describe pod" in cmd_str:
                    return MagicMock(returncode=0, stdout="Events: 0/3 nodes available: 3 did not match affinity\n", stderr="")
                if "get events" in cmd_str:
                    return MagicMock(returncode=0, stdout="Warning FailedScheduling 0/3 nodes available\n", stderr="")
                return MagicMock(returncode=0, stdout="", stderr="")

            with patch.object(orch, "_run_kubectl", side_effect=mock_k):
                info = orch.capture_pod_failure_diagnostics(pod_name="test-fail-pod", run_dir=td)
                self.assertTrue(info["diagnostic_saved"])
                self.assertTrue(info["events_saved"])
                self.assertEqual(len(info["errors"]), 0)

                diag_file = os.path.join(td, "pod_failure_diagnostic.txt")
                events_file = os.path.join(td, "pod_failure_events.txt")
                self.assertTrue(os.path.exists(diag_file))
                self.assertTrue(os.path.exists(events_file))

                with open(diag_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    self.assertIn("0/3 nodes available", content)

    def test_31_pod_failure_diagnostics_handles_errors_gracefully(self):
        """Diagnostic capture must not raise exceptions or crash if kubectl describe fails."""
        orch = PatroniBenchmarkOrchestrator()
        with tempfile.TemporaryDirectory() as td:
            with patch.object(orch, "_run_kubectl", side_effect=RuntimeError("API Server offline")):
                info = orch.capture_pod_failure_diagnostics(pod_name="test-fail-pod", run_dir=td)
                self.assertFalse(info["diagnostic_saved"])
                self.assertFalse(info["events_saved"])
                self.assertEqual(len(info["errors"]), 2)

    def test_33_snapshot_completes_within_timeout(self):
        """Snapshot query must complete and parse within configured timeout."""
        orch = PatroniBenchmarkOrchestrator(config={"snapshot_timeout_sec": 120})
        raw_csv = "benchdb,postgres,f,5000000,939021,50,939021,500,939021,93146,0/37EC57D8,94835\n"
        called_timeouts = []

        def mock_psql(sql, target_pod="patroni-0", timeout=30):
            called_timeouts.append(timeout)
            return subprocess.CompletedProcess(args=[], returncode=0, stdout=raw_csv, stderr="")

        with patch.object(orch, "_run_psql", side_effect=mock_psql):
            snap = orch.get_database_snapshot("S1_PreMeasurement")
            self.assertEqual(snap["phase"], "S1_PreMeasurement")
            self.assertEqual(snap["accounts_count"], 5000000)
            self.assertEqual(snap["history_count"], 93146)
            self.assertEqual(called_timeouts, [120])

    def test_34_snapshot_exceeds_timeout(self):
        """Snapshot timeout must raise RuntimeError with diagnostic message."""
        orch = PatroniBenchmarkOrchestrator(config={"snapshot_timeout_sec": 120})

        def mock_psql(sql, target_pod="patroni-0", timeout=30):
            raise subprocess.TimeoutExpired(cmd=["kubectl", "exec"], timeout=timeout)

        with patch.object(orch, "_run_psql", side_effect=mock_psql):
            with self.assertRaises(RuntimeError) as ctx:
                orch.get_database_snapshot("S1_PreMeasurement")
            self.assertIn("timed out after 120s", str(ctx.exception))

    def test_35_snapshot_kubectl_nonzero_exit(self):
        """Non-zero exit code from kubectl exec snapshot query must raise RuntimeError."""
        orch = PatroniBenchmarkOrchestrator()
        with patch.object(orch, "_run_psql", return_value=subprocess.CompletedProcess(args=[], returncode=137, stdout="", stderr="OOMKilled")):
            with self.assertRaises(RuntimeError) as ctx:
                orch.get_database_snapshot("S1_PreMeasurement")
            self.assertIn("failed with exit code 137", str(ctx.exception))

    def test_36_snapshot_sql_malformed_output(self):
        """Malformed or incomplete snapshot output must fail closed with RuntimeError."""
        orch = PatroniBenchmarkOrchestrator()
        # Fewer than 12 tokens
        with patch.object(orch, "_run_psql", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="benchdb,postgres,f\n", stderr="")):
            with self.assertRaises(RuntimeError) as ctx:
                orch.get_database_snapshot("S1_PreMeasurement")
            self.assertIn("malformed: expected 12 tokens", str(ctx.exception))

    def test_37_snapshot_timeout_does_not_start_measurement(self):
        """If Snapshot S1 times out, measurement phase must never start."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-37-s1-timeout"

        snap_s0 = {
            "phase": "S0_Initial", "database": "benchdb", "user": "postgres", "is_recovery": False,
            "accounts_count": 5000000, "accounts_balance": 0, "branches_count": 50, "branches_balance": 0,
            "tellers_count": 500, "tellers_balance": 0, "history_count": 0,
            "wal_lsn": "0/2C000000", "transaction_id": 100000, "raw_output": "",
        }

        def mock_snapshot(phase_name, **kwargs):
            if phase_name == "S0_Initial":
                return snap_s0
            if phase_name == "S1_PreMeasurement":
                raise RuntimeError("Snapshot query for S1_PreMeasurement timed out after 120s")
            raise AssertionError(f"Unexpected snapshot call for {phase_name}")

        measurement_called = []
        def mock_k(args, **kwargs):
            cmd_str = " ".join(str(a) for a in args)
            if "-l --log-prefix" in cmd_str:
                measurement_called.append(True)
            return self._default_k_side(args, **kwargs)

        orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=mock_snapshot), \
             patch.object(orch, "_run_kubectl", side_effect=mock_k):
            passed = orch.execute_run(run_id=run_id)
            self.assertFalse(passed)
            self.assertEqual(len(measurement_called), 0, "Measurement pgbench was called after S1 timeout!")

    def test_38_timeout_diagnostics_preserved(self):
        """When S1 fails, failure diagnostics and manifest are written to disk."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-38-diagnostics"

        snap_s0 = {
            "phase": "S0_Initial", "database": "benchdb", "user": "postgres", "is_recovery": False,
            "accounts_count": 5000000, "accounts_balance": 0, "branches_count": 50, "branches_balance": 0,
            "tellers_count": 500, "tellers_balance": 0, "history_count": 0,
            "wal_lsn": "0/2C000000", "transaction_id": 100000, "raw_output": "",
        }

        def mock_snapshot(phase_name, **kwargs):
            if phase_name == "S0_Initial":
                return snap_s0
            raise RuntimeError("Snapshot query for S1_PreMeasurement timed out after 120s")

        orch._run_psql_client = lambda sql, **kw: MagicMock(returncode=0, stdout="t\n" if "ssl" in sql else "f\n")

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=mock_snapshot), \
             patch.object(orch, "_run_kubectl", side_effect=self._default_k_side):
            passed = orch.execute_run(run_id=run_id)
            self.assertFalse(passed)

            run_dir = os.path.join(self.output_dir, run_id)
            manifest_path = os.path.join(run_dir, f"{run_id}-manifest.json")
            self.assertTrue(os.path.exists(manifest_path))

            with open(manifest_path, "r", encoding="utf-8") as fm:
                manifest_data = json.load(fm)
            self.assertEqual(manifest_data["run_status"], "FAILED")
            self.assertIn("timed out after 120s", manifest_data["error"])

            diag_path = os.path.join(run_dir, "pod_failure_diagnostic.txt")
            events_path = os.path.join(run_dir, "pod_failure_events.txt")
            self.assertTrue(os.path.exists(diag_path))
            self.assertTrue(os.path.exists(events_path))

    def test_39_configurable_timeout_respected(self):
        """Orchestrator must respect custom snapshot_timeout_sec from config."""
        orch = PatroniBenchmarkOrchestrator(config={"snapshot_timeout_sec": 75})
        self.assertEqual(orch.snapshot_timeout_sec, 75)

        recorded_timeout = []
        def mock_psql(sql, target_pod="patroni-0", timeout=30):
            recorded_timeout.append(timeout)
            raw = "benchdb,postgres,f,5000000,0,50,0,500,0,0,0/2C000000,123456\n"
            return subprocess.CompletedProcess(args=[], returncode=0, stdout=raw, stderr="")

        with patch.object(orch, "_run_psql", side_effect=mock_psql):
            orch.get_database_snapshot("S2_PostMeasurement")
            self.assertEqual(recorded_timeout, [75])

    def test_40_s0_s3_snapshot_logic_consistency(self):
        """All snapshot phases (S0, S1, S2, S3) must parse consistently into 12 tokens."""
        orch = PatroniBenchmarkOrchestrator()
        raw = "benchdb,postgres,f,5000000,939021,50,939021,500,939021,93146,0/37EC57D8,94835\n"

        with patch.object(orch, "_run_psql", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=raw, stderr="")):
            for phase in ["S0_Initial", "S1_PreMeasurement", "S2_PostMeasurement", "S3_PostCooldown"]:
                snap = orch.get_database_snapshot(phase)
                self.assertEqual(snap["phase"], phase)
                self.assertEqual(snap["database"], "benchdb")
                self.assertEqual(snap["user"], "postgres")
                self.assertFalse(snap["is_recovery"])
                self.assertEqual(snap["accounts_count"], 5000000)
                self.assertEqual(snap["accounts_balance"], 939021)
                self.assertEqual(snap["branches_count"], 50)
                self.assertEqual(snap["branches_balance"], 939021)
                self.assertEqual(snap["tellers_count"], 500)
                self.assertEqual(snap["tellers_balance"], 939021)
                self.assertEqual(snap["history_count"], 93146)
                self.assertEqual(snap["wal_lsn"], "0/37EC57D8")
                self.assertEqual(snap["transaction_id"], 94835)

    def test_41_existing_dataset_history_handled_using_per_run_deltas(self):
        """Pre-existing history and non-zero balances must be handled via per-run deltas."""
        orch = PatroniBenchmarkOrchestrator()

        # Database state after Stage 20.13 warm-up (93,146 history records)
        s1 = {
            "accounts_count": 5000000, "accounts_balance": 939021,
            "branches_count": 50, "branches_balance": 939021,
            "tellers_count": 500, "tellers_balance": 939021,
            "history_count": 93146,
        }
        # After 10,000 measurement transactions
        s2 = {
            "accounts_count": 5000000, "accounts_balance": 939021 + 50000,
            "branches_count": 50, "branches_balance": 939021 + 50000,
            "tellers_count": 500, "tellers_balance": 939021 + 50000,
            "history_count": 93146 + 10000,
        }
        s3 = dict(s2)  # Cooldown stable

        client_out = {"successful_transactions": 10000, "failed_transactions": 0}
        tx_logs = {"ok": True, "numeric_records": 10000, "failed_records": 0, "errors": []}

        res = orch.reconcile_transaction_accounting(s1, s2, s3, client_out, tx_logs)
        self.assertTrue(res.passed, f"Expected delta reconciliation to pass: {res.message}")
        self.assertEqual(res.details["delta_history"], 10000)
        self.assertEqual(res.details["client_commits"], 10000)
        self.assertEqual(res.details["log_commits"], 10000)

    def test_42_no_automatic_benchmark_retry_occurs(self):
        """When snapshot fails, execute_run must fail closed without retry."""
        orch = self._base_mock_orchestrator()
        run_id = "test-run-42-no-retry"

        execution_attempts = []
        orig_execute = orch.execute_run

        def tracking_snapshot(phase_name, **kwargs):
            execution_attempts.append(phase_name)
            raise RuntimeError("Simulated Snapshot Failure")

        with patch.object(orch, "run_preflight_audit", return_value=True), \
             patch.object(orch, "get_database_snapshot", side_effect=tracking_snapshot), \
             patch.object(orch, "_run_kubectl", side_effect=self._default_k_side):
            passed = orch.execute_run(run_id=run_id)
            self.assertFalse(passed)
            # Only S0 was attempted; zero retry invocations
            self.assertEqual(execution_attempts, ["S0_Initial"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
