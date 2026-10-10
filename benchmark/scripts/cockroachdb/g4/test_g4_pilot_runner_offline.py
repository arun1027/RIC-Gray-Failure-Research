"""
test_g4_pilot_runner_offline.py - Offline regression tests for G4 CPU starvation runner.
Strictly offline and non-invasive. Uses mocks only. No live Kubernetes, cgroup writes, or network calls.
"""

import base64
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

import benchmark.scripts.cockroachdb.g4.g4_pilot_runner as g4_runner
from benchmark.scripts.cockroachdb.g4.g4_pilot_runner import (
    G4PilotExecutionCoordinator,
    ExecutionState,
    verify_and_consume_authorization,
    parse_stresschaos_manifest,
    parse_cgroup_cpu_stat,
    canonicalize_payload,
    compute_sha256,
    build_manifest,
    verify_manifest,
    LEVEL_SPECS,
    PROTOCOL_VERSION
)

class TestG4PilotRunnerOffline(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_g4_runner_")
        self.output_dir = os.path.join(self.test_dir, "evidence")
        self.keys_dir = os.path.join(self.test_dir, "keys")
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.keys_dir, exist_ok=True)

        if HAS_CRYPTOGRAPHY:
            self.priv_key = ed25519.Ed25519PrivateKey.generate()
            self.pub_key = self.priv_key.public_key()
            pub_bytes = self.pub_key.public_bytes_raw()
            self.pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
            self.pub_fingerprint = hashlib.sha256(pub_bytes).hexdigest()

            self.pub_key_file = os.path.join(self.keys_dir, "operator_pub.key")
            with open(self.pub_key_file, "w", encoding="utf-8") as f:
                f.write(self.pub_b64)
        else:
            self.pub_key_file = None
            self.pub_fingerprint = None

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_valid_token(
        self,
        run_id="crdb-g4l1-p01",
        level="L1",
        load=80,
        workers=1,
        duration_sec=180,
        runner_sha256="testrunnersha",
        manifest_sha256="testmanifestsha",
        target_pod_uid="test-pod-uid-1234",
        not_before=None,
        expires_at=None
    ) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        nb = not_before or (now - datetime.timedelta(minutes=5)).isoformat()
        exp = expires_at or (now + datetime.timedelta(hours=1)).isoformat()

        payload = {
            "authorization_id": f"auth-{run_id}-001",
            "authorized_run_id": run_id,
            "authorized_level": level,
            "parameters": {
                "load": load,
                "workers": workers,
                "fault_duration_sec": duration_sec,
                "max_fault_duration_sec": duration_sec
            },
            "runner_sha256": runner_sha256,
            "manifest_sha256": manifest_sha256,
            "target_pod_uid": target_pod_uid,
            "protocol_version": PROTOCOL_VERSION,
            "operator_identity": "test-operator",
            "nonce": "testnonce123456",
            "issued_at_utc": now.isoformat(),
            "not_before_utc": nb,
            "expires_at_utc": exp
        }
        canon_bytes = canonicalize_payload(payload)
        sig_bytes = self.priv_key.sign(canon_bytes)
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

        token_doc = {
            "payload": payload,
            "signature": sig_b64
        }
        token_path = os.path.join(self.test_dir, f"{run_id}_auth.json")
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_doc, f, indent=2)
        return token_path

    def test_01_parse_cgroup_cpu_stat(self):
        raw = "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\nnr_periods 50\nnr_throttled 5\nthrottled_usec 45000\n"
        stats = parse_cgroup_cpu_stat(raw)
        self.assertEqual(stats["usage_usec"], 123456)
        self.assertEqual(stats["nr_throttled"], 5)
        self.assertEqual(stats["throttled_usec"], 45000)

    def test_02_parse_stresschaos_manifest(self):
        manifest_path = "kubernetes/chaos/g4/g4-cpu-stress-l1.yaml"
        if os.path.exists(manifest_path):
            info = parse_stresschaos_manifest(manifest_path)
            self.assertEqual(info["name"], "g4-cpu-starvation-l1")
            self.assertEqual(info["load"], 80)
            self.assertEqual(info["workers"], 1)
            self.assertEqual(info["target_pod"], "cockroachdb-1")
            self.assertEqual(info["target_container"], "db")

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires cryptography library")
    def test_03_verify_and_consume_authorization_success(self):
        fake_runner = os.path.join(self.test_dir, "fake_runner.py")
        with open(fake_runner, "w") as f:
            f.write("# fake runner")
        runner_sha = compute_sha256(fake_runner)

        token_path = self._create_valid_token(
            runner_sha256=runner_sha,
            manifest_sha256="validmanifestsha",
            target_pod_uid="pod-uid-abc"
        )

        with patch.object(g4_runner, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.pub_fingerprint):
            auth = verify_and_consume_authorization(
                auth_file_path=token_path,
                run_id="crdb-g4l1-p01",
                level="L1",
                duration_sec=180,
                manifest_sha256="validmanifestsha",
                target_pod_uid="pod-uid-abc",
                runner_path=fake_runner,
                public_key_path=self.pub_key_file
            )
            self.assertTrue(auth["signature_verified"])
            self.assertEqual(auth["authorized_run_id"], "crdb-g4l1-p01")
            self.assertTrue(os.path.exists(f"{token_path}.consumed"))

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires cryptography library")
    def test_04_authorization_rejected_on_replay_consumed(self):
        fake_runner = os.path.join(self.test_dir, "fake_runner.py")
        with open(fake_runner, "w") as f:
            f.write("# fake runner")
        runner_sha = compute_sha256(fake_runner)

        token_path = self._create_valid_token(runner_sha256=runner_sha)
        with open(f"{token_path}.consumed", "w") as f:
            f.write('{"already": "consumed"}')

        with patch.object(g4_runner, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.pub_fingerprint):
            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=token_path,
                    run_id="crdb-g4l1-p01",
                    level="L1",
                    duration_sec=180,
                    manifest_sha256="testmanifestsha",
                    target_pod_uid="test-pod-uid-1234",
                    runner_path=fake_runner,
                    public_key_path=self.pub_key_file
                )
            self.assertIn("ALREADY BEEN CONSUMED", str(ctx.exception))

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires cryptography library")
    def test_05_authorization_rejected_on_runner_hash_mismatch(self):
        fake_runner = os.path.join(self.test_dir, "fake_runner.py")
        with open(fake_runner, "w") as f:
            f.write("# fake runner")

        token_path = self._create_valid_token(runner_sha256="wrong_hash")

        with patch.object(g4_runner, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.pub_fingerprint):
            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=token_path,
                    run_id="crdb-g4l1-p01",
                    level="L1",
                    duration_sec=180,
                    manifest_sha256="testmanifestsha",
                    target_pod_uid="test-pod-uid-1234",
                    runner_path=fake_runner,
                    public_key_path=self.pub_key_file
                )
            self.assertIn("Runner hash mismatch", str(ctx.exception))

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires cryptography library")
    def test_06_authorization_rejected_on_manifest_hash_mismatch(self):
        fake_runner = os.path.join(self.test_dir, "fake_runner.py")
        with open(fake_runner, "w") as f:
            f.write("# fake runner")
        runner_sha = compute_sha256(fake_runner)

        token_path = self._create_valid_token(
            runner_sha256=runner_sha,
            manifest_sha256="expected_manifest_sha"
        )

        with patch.object(g4_runner, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.pub_fingerprint):
            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=token_path,
                    run_id="crdb-g4l1-p01",
                    level="L1",
                    duration_sec=180,
                    manifest_sha256="different_manifest_sha",
                    target_pod_uid="test-pod-uid-1234",
                    runner_path=fake_runner,
                    public_key_path=self.pub_key_file
                )
            self.assertIn("Manifest hash mismatch", str(ctx.exception))

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires cryptography library")
    def test_07_authorization_rejected_on_pod_uid_mismatch(self):
        fake_runner = os.path.join(self.test_dir, "fake_runner.py")
        with open(fake_runner, "w") as f:
            f.write("# fake runner")
        runner_sha = compute_sha256(fake_runner)

        token_path = self._create_valid_token(
            runner_sha256=runner_sha,
            manifest_sha256="msha",
            target_pod_uid="pod-uid-expected"
        )

        with patch.object(g4_runner, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.pub_fingerprint):
            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=token_path,
                    run_id="crdb-g4l1-p01",
                    level="L1",
                    duration_sec=180,
                    manifest_sha256="msha",
                    target_pod_uid="pod-uid-migrated",
                    runner_path=fake_runner,
                    public_key_path=self.pub_key_file
                )
            self.assertIn("Target pod UID mismatch", str(ctx.exception))

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires cryptography library")
    def test_08_authorization_rejected_on_expired_token(self):
        fake_runner = os.path.join(self.test_dir, "fake_runner.py")
        with open(fake_runner, "w") as f:
            f.write("# fake runner")
        runner_sha = compute_sha256(fake_runner)

        now = datetime.datetime.now(datetime.timezone.utc)
        nb = (now - datetime.timedelta(hours=2)).isoformat()
        exp = (now - datetime.timedelta(hours=1)).isoformat()

        token_path = self._create_valid_token(
            runner_sha256=runner_sha,
            not_before=nb,
            expires_at=exp
        )

        with patch.object(g4_runner, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.pub_fingerprint):
            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=token_path,
                    run_id="crdb-g4l1-p01",
                    level="L1",
                    duration_sec=180,
                    manifest_sha256="testmanifestsha",
                    target_pod_uid="test-pod-uid-1234",
                    runner_path=fake_runner,
                    public_key_path=self.pub_key_file
                )
            self.assertIn("EXPIRED", str(ctx.exception))

    @patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd")
    def test_09_dry_run_preflight_read_only(self, mock_run_cmd):
        # Mock kubectl outputs for preflight
        mock_run_cmd.side_effect = [
            # get crd
            MagicMock(returncode=0, stdout="crd exists"),
            # get chaos-daemon pods
            MagicMock(returncode=0, stdout='{"items": [{"metadata": {"name": "chaos-daemon-1"}}]}'),
            # get stresschaos
            MagicMock(returncode=0, stdout='{"items": []}'),
            # get target pod
            MagicMock(returncode=0, stdout=json.dumps({
                "metadata": {"uid": "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67"},
                "spec": {"nodeName": "ip-10-0-1-160.ec2.internal", "containers": [{"name": "db"}]},
                "status": {"phase": "Running"}
            }))
        ]

        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=True
        )

        res = coordinator.execute()
        self.assertEqual(res["disposition"], "SIMULATED_SUCCESS")
        self.assertEqual(coordinator.current_state, ExecutionState.FINAL_DISPOSITION)

        # Confirm no kubectl apply or delete was invoked
        for call_args in mock_run_cmd.call_args_list:
            cmd = call_args[0][0]
            self.assertNotIn("apply", cmd)
            self.assertNotIn("delete", cmd)

    @patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd")
    def test_10_target_drift_triggers_emergency_rollback(self, mock_run_cmd):
        def fake_run_cmd(cmd, check=True, timeout=None):
            # Intercept based on command line arguments
            if "get" in cmd and "crd" in cmd:
                return MagicMock(returncode=0, stdout="crd exists")
            if "get" in cmd and "pods" in cmd and "chaos-daemon" in str(cmd):
                return MagicMock(returncode=0, stdout='{"items": [{"metadata": {"name": "chaos-daemon-1"}}]}')
            if "get" in cmd and "stresschaos" in cmd:
                return MagicMock(returncode=0, stdout='{"items": []}')
            if "get" in cmd and "pod" in cmd and "cockroachdb-1" in cmd:
                # First call is during target verification, subsequent calls during reverify
                if not hasattr(fake_run_cmd, "call_count"):
                    fake_run_cmd.call_count = 0
                fake_run_cmd.call_count += 1
                if fake_run_cmd.call_count == 1:
                    return MagicMock(returncode=0, stdout=json.dumps({
                        "metadata": {"uid": "expected-uid"},
                        "spec": {"nodeName": "ip-10-0-1-160.ec2.internal", "containers": [{"name": "db"}]},
                        "status": {"phase": "Running"}
                    }))
                else:
                    return MagicMock(returncode=0, stdout=json.dumps({
                        "metadata": {"uid": "migrated-uid-drifted"},
                        "spec": {"nodeName": "ip-10-0-1-160.ec2.internal", "containers": [{"name": "db"}]},
                        "status": {"phase": "Running"}
                    }))
            if "cat /tmp/pgbench" in " ".join(cmd):
                return MagicMock(returncode=0, stdout="12345\n")
            if "pgid.txt" in " ".join(cmd) or "setsid" in " ".join(cmd):
                return MagicMock(returncode=0, stdout="12345\n")
            if "ps -eo" in " ".join(cmd):
                return MagicMock(returncode=0, stdout="  PID  PGID STAT COMMAND\n")
            if "delete" in cmd:
                return MagicMock(returncode=0, stdout="deleted")
            return MagicMock(returncode=0, stdout="{}")

        mock_run_cmd.side_effect = fake_run_cmd

        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False,
            warmup_sec=0,
            baseline_sec=0
        )
        coordinator.target_spec["pod_uid"] = "expected-uid"
        coordinator.target_spec["node_name"] = "ip-10-0-1-160.ec2.internal"
        coordinator.auth_file = "dummy_auth.json"

        # Mock verify_and_consume_authorization
        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.verify_and_consume_authorization", return_value={"signature_verified": True}):
            with patch.object(coordinator, "_poll_and_wait_remote_workload", return_value=0):
                with self.assertRaises(RuntimeError) as ctx:
                    coordinator.execute()

                self.assertIn("Target pod migrated", str(ctx.exception))
                self.assertEqual(coordinator.disposition, "FAILED")

    def test_11_manifest_and_sha256_verification(self):
        # Create a test output directory with dummy files
        test_file = os.path.join(self.output_dir, "00_test.txt")
        with open(test_file, "w") as f:
            f.write("test evidence data")

        build_manifest(self.output_dir)
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "SHA256SUMS.txt")))
        self.assertTrue(verify_manifest(self.output_dir))

        # Tamper with file
        with open(test_file, "a") as f:
            f.write("tampered")
        self.assertFalse(verify_manifest(self.output_dir))

    @patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd")
    def test_12_isolated_cleanup_does_not_delete_all_resources(self, mock_run_cmd):
        deleted_commands = []
        def fake_run_cmd(cmd, check=True, timeout=None):
            if "delete" in cmd:
                deleted_commands.append(cmd)
                return MagicMock(returncode=0, stdout="deleted")
            return MagicMock(returncode=0, stdout="{}")

        mock_run_cmd.side_effect = fake_run_cmd

        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator._emergency_rollback()

        # Assert delete command targeted only g4-cpu-starvation-l1
        self.assertEqual(len(deleted_commands), 1)
        self.assertIn("g4-cpu-starvation-l1", deleted_commands[0])
        self.assertNotIn("--all", deleted_commands[0])

    @patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd")
    def test_13_fault_verification_fail_closed_if_not_injected(self, mock_run_cmd):
        # StressChaos condition never reaches Injected=True
        mock_run_cmd.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"status": {"conditions": [{"type": "Injected", "status": "False"}]}})
        )

        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )

        with patch("time.time", side_effect=[0, 10, 20, 31, 35]):
            with patch("time.sleep"):
                with self.assertRaises(RuntimeError) as ctx:
                    coordinator._state_fault_verification()
                self.assertIn("failed to reach Injected=True", str(ctx.exception))

    def test_14_telemetry_health_check_fail_closed(self):
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.telemetry_status["thread_alive"] = True
        coordinator.telemetry_status["error"] = "Telemetry connection dropped"
        with self.assertRaises(RuntimeError) as ctx:
            coordinator._check_telemetry_health()
        self.assertIn("Telemetry connection dropped", str(ctx.exception))

    def test_15_timing_model_reconciliation(self):
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        self.assertEqual(coordinator.warmup_sec, 120)
        self.assertEqual(coordinator.baseline_sec, 180)
        self.assertEqual(coordinator.fault_sec, 180)
        self.assertEqual(coordinator.recovery_sec, 300)
        total_measurement = coordinator.baseline_sec + coordinator.fault_sec + coordinator.recovery_sec
        self.assertEqual(total_measurement, 660)
        total_experiment = coordinator.warmup_sec + total_measurement
        self.assertEqual(total_experiment, 780)

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "Requires cryptography")
    def test_16_public_key_path_resolution(self):
        fake_runner = os.path.join(self.test_dir, "fake_runner.py")
        with open(fake_runner, "w") as f:
            f.write("# fake runner")
        runner_sha = compute_sha256(fake_runner)

        token_path = self._create_valid_token(
            runner_sha256=runner_sha,
            manifest_sha256="validmanifestsha",
            target_pod_uid="pod-uid-abc"
        )

        # Test path resolution when public_key_path is None, pointing DEFAULT to self.pub_key_file
        with patch.object(g4_runner, "DEFAULT_PUBLIC_KEY_PATH", self.pub_key_file):
            with patch.object(g4_runner, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.pub_fingerprint):
                auth = verify_and_consume_authorization(
                    auth_file_path=token_path,
                    run_id="crdb-g4l1-p01",
                    level="L1",
                    duration_sec=180,
                    manifest_sha256="validmanifestsha",
                    target_pod_uid="pod-uid-abc",
                    runner_path=fake_runner,
                    public_key_path=None
                )
                self.assertTrue(auth["signature_verified"])
                self.assertEqual(auth["public_key_fingerprint"], self.pub_fingerprint)

    @patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd")
    def test_17_warmup_failure_triggers_cleanup_and_prevents_baseline(self, mock_run_cmd):
        def fake_run_cmd(cmd, check=True, timeout=None):
            cmd_str = " ".join(cmd)
            if "pgid.txt" in cmd_str or "setsid" in cmd_str:
                return MagicMock(returncode=0, stdout="12345\n")
            if "get crd" in cmd_str or "crd stresschaos" in cmd_str:
                return MagicMock(returncode=0, stdout="crd exists")
            if "chaos-daemon" in cmd_str:
                return MagicMock(returncode=0, stdout='{"items": [{"metadata": {"name": "chaos-daemon-1"}}]}')
            if "stresschaos" in cmd_str:
                return MagicMock(returncode=0, stdout='{"items": []}')
            if "get pod" in cmd_str:
                return MagicMock(returncode=0, stdout=json.dumps({
                    "metadata": {"uid": "expected-uid"},
                    "spec": {"nodeName": "ip-10-0-1-160.ec2.internal", "containers": [{"name": "db"}]},
                    "status": {"phase": "Running"}
                }))
            if "cat /tmp/pgbench" in cmd_str:
                return MagicMock(returncode=0, stdout="12345\n")
            if "ps -eo" in cmd_str:
                return MagicMock(returncode=0, stdout="  PID  PGID STAT COMMAND\n")
            if "delete" in cmd_str:
                return MagicMock(returncode=0, stdout="deleted")
            return MagicMock(returncode=0, stdout="{}")

        mock_run_cmd.side_effect = fake_run_cmd

        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False,
            warmup_sec=1
        )
        coordinator.target_spec["pod_uid"] = "expected-uid"
        coordinator.target_spec["node_name"] = "ip-10-0-1-160.ec2.internal"
        coordinator.auth_file = "dummy_auth.json"

        # Mock verify_and_consume_authorization
        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.verify_and_consume_authorization", return_value={"signature_verified": True}):
            with patch.object(coordinator, "_poll_and_wait_remote_workload", return_value=1):
                with self.assertRaises(RuntimeError) as ctx:
                    coordinator.execute()

                self.assertIn("Warmup pgbench process failed", str(ctx.exception))
                self.assertEqual(coordinator.disposition, "FAILED")
                # Confirm we never entered BASELINE_MEASUREMENT or FAULT_APPLICATION
                states = [h["to"] for h in coordinator.state_history]
                self.assertNotIn("BASELINE_MEASUREMENT", states)
                self.assertNotIn("FAULT_APPLICATION", states)

    @patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd")
    def test_18_warmup_timeout_cleans_up_process(self, mock_run_cmd):
        def fake_run_cmd(cmd, check=True, timeout=None):
            cmd_str = " ".join(cmd)
            if "pgid.txt" in cmd_str or "setsid" in cmd_str:
                return MagicMock(returncode=0, stdout="12345\n")
            if "get crd" in cmd_str or "crd stresschaos" in cmd_str:
                return MagicMock(returncode=0, stdout="crd exists")
            if "chaos-daemon" in cmd_str:
                return MagicMock(returncode=0, stdout='{"items": [{"metadata": {"name": "chaos-daemon-1"}}]}')
            if "stresschaos" in cmd_str:
                return MagicMock(returncode=0, stdout='{"items": []}')
            if "get pod" in cmd_str:
                return MagicMock(returncode=0, stdout=json.dumps({
                    "metadata": {"uid": "expected-uid"},
                    "spec": {"nodeName": "ip-10-0-1-160.ec2.internal", "containers": [{"name": "db"}]},
                    "status": {"phase": "Running"}
                }))
            if "cat /tmp/pgbench" in cmd_str:
                return MagicMock(returncode=0, stdout="12345\n")
            if "ps -eo" in cmd_str:
                return MagicMock(returncode=0, stdout="  PID  PGID STAT COMMAND\n")
            if "delete" in cmd_str:
                return MagicMock(returncode=0, stdout="deleted")
            return MagicMock(returncode=0, stdout="{}")

        mock_run_cmd.side_effect = fake_run_cmd

        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False,
            warmup_sec=1
        )
        coordinator.target_spec["pod_uid"] = "expected-uid"
        coordinator.target_spec["node_name"] = "ip-10-0-1-160.ec2.internal"
        coordinator.auth_file = "dummy_auth.json"

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.verify_and_consume_authorization", return_value={"signature_verified": True}):
            with patch.object(coordinator, "_poll_and_wait_remote_workload", side_effect=subprocess.TimeoutExpired(cmd="warmup", timeout=31)):
                with patch.object(coordinator, "_terminate_workload_process") as mock_term:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        coordinator.execute()

                    self.assertEqual(coordinator.disposition, "FAILED")
                    mock_term.assert_called()

    def test_19_telemetry_remains_active_during_wrec_and_shutdown_after_validation(self):
        """Validates that telemetry is active during WREC and stopped only after WREC health check."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False,
            recovery_sec=1
        )
        coordinator._start_telemetry()
        self.assertTrue(coordinator.telemetry_status["thread_alive"])

        # Execute WREC observation
        coordinator._state_wrec_observation()
        # Telemetry MUST still be alive!
        self.assertTrue(coordinator.telemetry_status["thread_alive"])

        # Health check succeeds
        coordinator._check_telemetry_health("wrec_observation")

        # Now stop telemetry as executed in execute()
        coordinator._stop_telemetry()
        self.assertFalse(coordinator.telemetry_status["thread_alive"])

    def test_20_telemetry_stopped_safely_on_exception(self):
        """Validates that emergency rollback cleanly stops telemetry when exception occurs."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator._start_telemetry()
        self.assertTrue(coordinator.telemetry_status["thread_alive"])

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="deleted")
            coordinator._emergency_rollback()

        self.assertFalse(coordinator.telemetry_status["thread_alive"])

    def test_21_telemetry_worker_exception_causes_failed_run(self):
        """Validates that a fatal exception in telemetry worker marks status error and trips health check."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator._start_telemetry()
        # Simulate worker dying with error
        coordinator.telemetry_status["error"] = "Fatal telemetry worker exception: Connection reset"
        coordinator.telemetry_status["thread_alive"] = False

        with self.assertRaises(g4_runner.TelemetryContinuityError) as ctx:
            coordinator._check_telemetry_health("test_window")
        self.assertIn("Connection reset", str(ctx.exception))
        coordinator._stop_telemetry()

    def test_22_dead_telemetry_thread_causes_failed_run(self):
        """Validates that dead thread without error still triggers fail-closed health check."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.telemetry_status["thread_alive"] = False
        coordinator.telemetry_status["error"] = None
        with self.assertRaises(g4_runner.TelemetryContinuityError) as ctx:
            coordinator._check_telemetry_health("test_window")
        self.assertIn("poller thread is not running", str(ctx.exception))

    def test_23_continuity_gap_causes_failed_run(self):
        """Validates that telemetry gap > max_telemetry_gap_sec triggers fail-closed."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.telemetry_status["thread_alive"] = True
        coordinator.telemetry_status["last_sample_epoch"] = time.time() - 35.0  # 35s gap > 30s limit
        with self.assertRaises(g4_runner.TelemetryContinuityError) as ctx:
            coordinator._check_telemetry_health("test_window")
        self.assertIn("exceeded limit 30.0s", str(ctx.exception))

    def test_24_missed_samples_recorded_correctly(self):
        """Validates that missed samples increment and record errors without crashing."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.telemetry_interval = 0.1
        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Connection refused", stdout="")
            coordinator._start_telemetry()
            time.sleep(0.35)
            coordinator._stop_telemetry()

        self.assertGreater(coordinator.telemetry_status["missed_samples"], 0)
        self.assertGreater(len(coordinator.telemetry_data), 0)
        sample = coordinator.telemetry_data[0]
        self.assertIn("cgroup_error", sample)

    def test_25_measurement_workload_timeout_triggers_remote_cleanup(self):
        """Validates that workload wait timeout in WREC triggers remote process termination."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False,
            recovery_sec=0
        )
        coordinator.telemetry_status["thread_alive"] = True
        coordinator.telemetry_status["last_sample_epoch"] = 1000.0
        coordinator.remote_pgid = 54321
        mock_proc = MagicMock()
        mock_proc.pid = 9999
        mock_proc.poll.return_value = None  # Never exits on its own
        coordinator.workload_process = mock_proc

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.terminate_remote_process_group") as mock_term:
            mock_term.return_value = {"verified_dead": True, "escalated_to_sigkill": False}
            current_t = 1000.0
            calls = 0
            def fake_time():
                nonlocal current_t, calls
                calls += 1
                if calls >= 6:
                    current_t = 1080.0
                coordinator.telemetry_status["last_sample_epoch"] = current_t
                return current_t

            with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.time.time", side_effect=fake_time):
                with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.time.sleep"):
                    coordinator._state_wrec_observation()
            mock_term.assert_called_with("cockroachdb", "crdb-benchmark-client-hardened", 54321)

    def test_26_stresschaos_removed_after_normal_execution(self):
        """Validates that fault removal deletes StressChaos and verifies removal."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="deleted"),
                MagicMock(returncode=1, stderr="Error: NotFound", stdout="")
            ]
            coordinator._state_fault_removal()
            self.assertFalse(coordinator.fault_injected)

    def test_27_emergency_rollback_is_idempotent(self):
        """Validates that multiple calls to emergency rollback do not fail."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="deleted")
            rep1 = coordinator._emergency_rollback()
            rep2 = coordinator._emergency_rollback()
            self.assertTrue(rep1["stresschaos_deleted"])
            self.assertTrue(rep2["stresschaos_deleted"])

    def test_28_partial_evidence_preserved_after_failure(self):
        """Validates that partial evidence and incident record are created on failure."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.telemetry_data.append({"test": "data", "epoch_sec": 12345})
        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="deleted")
            coordinator._emergency_rollback()

        incident_file = os.path.join(self.output_dir, "00_incident_record.json")
        telemetry_file = os.path.join(self.output_dir, "02_telemetry_timeseries.jsonl")
        self.assertTrue(os.path.isfile(incident_file))
        self.assertTrue(os.path.isfile(telemetry_file))

    def test_29_existing_non_empty_output_directory_rejected(self):
        """Validates that an existing non-empty output directory triggers fail-closed abort."""
        with open(os.path.join(self.output_dir, "stray_file.txt"), "w") as f:
            f.write("content")
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        with self.assertRaises(RuntimeError) as ctx:
            coordinator._ensure_output_dir()
        self.assertIn("is not empty", str(ctx.exception))

    @patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd")
    def test_30_complete_successful_lifecycle_reaches_executed_validated(self, mock_run_cmd):
        """Validates complete mocked execution reaching EXECUTED_VALIDATED with full artifacts."""
        def fake_run_cmd(cmd, check=True, timeout=None):
            cmd_str = " ".join(cmd)
            if "pgid.txt" in cmd_str or "setsid" in cmd_str:
                return MagicMock(returncode=0, stdout="12345\n")
            if "get crd" in cmd_str or "crd stresschaos" in cmd_str:
                return MagicMock(returncode=0, stdout="crd exists")
            if "chaos-daemon" in cmd_str:
                return MagicMock(returncode=0, stdout='{"items": [{"metadata": {"name": "chaos-daemon-1"}}]}')
            if "stresschaos" in cmd_str and "get" in cmd_str:
                if "g4-cpu-starvation-l1" in cmd_str:
                    if not hasattr(fake_run_cmd, "sc_get_count"):
                        fake_run_cmd.sc_get_count = 0
                    fake_run_cmd.sc_get_count += 1
                    # In fault_verification return Injected=True, in restoration_verification return NotFound
                    if fake_run_cmd.sc_get_count == 1:
                        return MagicMock(returncode=0, stdout=json.dumps({"status": {"conditions": [{"type": "Injected", "status": "True"}]}}), stderr="")
                    else:
                        return MagicMock(returncode=1, stdout="", stderr="Error from server (NotFound): stresschaos.chaos-mesh.org 'g4-cpu-starvation-l1' not found")
                return MagicMock(returncode=0, stdout='{"items": []}', stderr="")
            if "get pod" in cmd_str:
                return MagicMock(returncode=0, stdout=json.dumps({
                    "metadata": {"uid": "expected-uid"},
                    "spec": {"nodeName": "ip-10-0-1-160.ec2.internal", "containers": [{"name": "db"}]},
                    "status": {"phase": "Running"}
                }))
            if "cat /tmp/pgbench" in cmd_str:
                return MagicMock(returncode=0, stdout="12345\n")
            if "pgid.txt" in cmd_str or "setsid" in cmd_str:
                return MagicMock(returncode=0, stdout="12345\n")
            if "ps -eo" in cmd_str:
                return MagicMock(returncode=0, stdout="  PID  PGID STAT COMMAND\n")
            if "top pod" in cmd_str:
                return MagicMock(returncode=0, stdout="cockroachdb-1  250m  512Mi\n")
            if "cat /sys/fs/cgroup/cpu.stat" in cmd_str:
                return MagicMock(returncode=0, stdout="usage_usec 1000\nuser_usec 500\nsystem_usec 500\nnr_periods 10\nnr_throttled 0\nthrottled_usec 0\n")
            if "apply" in cmd_str:
                return MagicMock(returncode=0, stdout="applied")
            if "delete" in cmd_str:
                return MagicMock(returncode=0, stdout="deleted")
            return MagicMock(returncode=0, stdout="{}")

        mock_run_cmd.side_effect = fake_run_cmd

        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False,
            warmup_sec=0,
            baseline_sec=0,
            fault_sec=0,
            recovery_sec=0
        )
        coordinator.target_spec["pod_uid"] = "expected-uid"
        coordinator.target_spec["node_name"] = "ip-10-0-1-160.ec2.internal"
        coordinator.auth_file = "dummy_auth.json"

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.verify_and_consume_authorization", return_value={"signature_verified": True}):
            with patch.object(coordinator, "_poll_and_wait_remote_workload", return_value=0):
                res = coordinator.execute()

        self.assertEqual(res["disposition"], "EXECUTED_VALIDATED")
        self.assertEqual(coordinator.disposition, "EXECUTED_VALIDATED")
        self.assertFalse(coordinator.telemetry_status["thread_alive"])
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "00_execution_record.json")))
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "01_preflight_audit.json")))
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "02_telemetry_timeseries.jsonl")))
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "SHA256SUMS.txt")))

    # --- Regression Tests for Durable Remote Workload Execution ---

    def test_31_remote_workload_normal_completion(self):
        """Scenario 1: Normal remote workload completion and exit status 0 parsing."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.remote_workload_dir = "/tmp/g4_test_warmup"
        coordinator.telemetry_status["thread_alive"] = True
        coordinator.telemetry_status["last_sample_epoch"] = time.time()
        local_out = os.path.join(self.output_dir, "test_out.txt")

        def fake_run_cmd(cmd, check=True, timeout=None):
            cmd_str = " ".join(cmd)
            if "test -f" in cmd_str:
                return MagicMock(returncode=0, stdout="0\n", stderr="")
            if "exit_code.txt" in cmd_str:
                return MagicMock(returncode=0, stdout="0\n", stderr="")
            if "stdout.log" in cmd_str:
                return MagicMock(returncode=0, stdout="transaction type: <builtin: TPC-B (sort of)>\ntps = 1250.5\n", stderr="")
            if "stderr.log" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="")

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd", side_effect=fake_run_cmd):
            rc = coordinator._poll_and_wait_remote_workload("warmup", duration_sec=1.0, output_local_file=local_out, poll_interval=0.1)

        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(local_out))
        with open(local_out, "r") as f:
            content = f.read()
        self.assertIn("tps = 1250.5", content)

    def test_32_remote_workload_nonzero_exit_status(self):
        """Scenario 2: Remote pgbench non-zero exit status fail-closed detection."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.remote_workload_dir = "/tmp/g4_test_warmup"
        coordinator.telemetry_status["thread_alive"] = True
        coordinator.telemetry_status["last_sample_epoch"] = time.time()
        local_out = os.path.join(self.output_dir, "test_out_fail.txt")

        def fake_run_cmd(cmd, check=True, timeout=None):
            cmd_str = " ".join(cmd)
            if "test -f" in cmd_str:
                return MagicMock(returncode=0, stdout="2\n", stderr="")
            if "exit_code.txt" in cmd_str:
                return MagicMock(returncode=0, stdout="2\n", stderr="")
            if "stdout.log" in cmd_str:
                return MagicMock(returncode=0, stdout="partial transactions\n", stderr="")
            if "stderr.log" in cmd_str:
                return MagicMock(returncode=0, stdout="FATAL: connection limit exceeded\n", stderr="")
            return MagicMock(returncode=0, stdout="")

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd", side_effect=fake_run_cmd):
            rc = coordinator._poll_and_wait_remote_workload("warmup", duration_sec=1.0, output_local_file=local_out, poll_interval=0.1)

        self.assertEqual(rc, 2)
        with open(local_out, "r") as f:
            content = f.read()
        self.assertIn("FATAL: connection limit exceeded", content)

    def test_33_connection_reset_resilience_during_polling(self):
        """Scenario 3: Local connection reset while remote continues (transient probe failure recovered)."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.remote_workload_dir = "/tmp/g4_test_warmup"
        coordinator.telemetry_status["thread_alive"] = True
        coordinator.telemetry_status["last_sample_epoch"] = time.time()
        local_out = os.path.join(self.output_dir, "test_reset_out.txt")

        probe_attempts = 0
        def fake_run_cmd(cmd, check=True, timeout=None):
            nonlocal probe_attempts
            cmd_str = " ".join(cmd)
            if "test -f" in cmd_str:
                probe_attempts += 1
                if probe_attempts <= 2:
                    # Simulate wsarecv connection drop
                    return MagicMock(returncode=1, stdout="", stderr="wsarecv: An existing connection was forcibly closed by the remote host.")
                elif probe_attempts == 3:
                    return MagicMock(returncode=0, stdout="PENDING\n", stderr="")
                else:
                    return MagicMock(returncode=0, stdout="0\n", stderr="")
            if "exit_code.txt" in cmd_str:
                return MagicMock(returncode=0, stdout="0\n", stderr="")
            if "stdout.log" in cmd_str:
                return MagicMock(returncode=0, stdout="tps = 999.0\n", stderr="")
            if "stderr.log" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="")

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd", side_effect=fake_run_cmd):
            rc = coordinator._poll_and_wait_remote_workload("warmup", duration_sec=1.0, output_local_file=local_out, poll_interval=0.05)

        self.assertEqual(rc, 0)
        self.assertGreater(probe_attempts, 2)

    def test_34_reconnection_and_successful_status_retrieval(self):
        """Scenario 4: Successful reconnection and status retrieval after network disruption."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.remote_workload_dir = "/tmp/g4_test_meas"
        local_out = os.path.join(self.output_dir, "05_measurement_wrapper_stdout.txt")

        def fake_run_cmd(cmd, check=True, timeout=None):
            cmd_str = " ".join(cmd)
            if "exit_code.txt" in cmd_str:
                return MagicMock(returncode=0, stdout="0\n", stderr="")
            if "stdout.log" in cmd_str:
                return MagicMock(returncode=0, stdout="progress: 660.0 s, 1100.0 tps\n", stderr="")
            if "stderr.log" in cmd_str:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="")

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd", side_effect=fake_run_cmd):
            exit_code = coordinator._retrieve_and_validate_remote_workload(local_out)

        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.isfile(local_out))
        with open(local_out, "r") as f:
            self.assertIn("progress: 660.0 s, 1100.0 tps", f.read())

    def test_35_missing_or_corrupted_remote_status_files(self):
        """Scenario 5: Missing or incomplete remote status files triggering fail-closed abort."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.remote_workload_dir = "/tmp/g4_test_missing"
        local_out = os.path.join(self.output_dir, "test_missing.txt")

        # 1. Missing exit_code.txt
        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="cat: /tmp/g4_test_missing/exit_code.txt: No such file")
            with self.assertRaises(RuntimeError) as ctx:
                coordinator._retrieve_and_validate_remote_workload(local_out)
            self.assertIn("Missing remote exit status file", str(ctx.exception))

        # 2. Corrupted exit_code.txt (non-integer)
        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="NOT_AN_INT\n")
            with self.assertRaises(RuntimeError) as ctx:
                coordinator._retrieve_and_validate_remote_workload(local_out)
            self.assertIn("Corrupted remote exit code", str(ctx.exception))

    def test_36_remote_cleanup_after_interruption(self):
        """Scenario 6: Remote process cleanup after local interruption."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.remote_pgid = 45678
        mock_proc = MagicMock()
        mock_proc.pid = 11111
        mock_proc.poll.return_value = 1  # Local wrapper already dead (like retry6 wsarecv)
        coordinator.workload_process = mock_proc

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.terminate_remote_process_group") as mock_term:
            mock_term.return_value = {"verified_dead": True, "escalated_to_sigkill": False, "surviving_live_count": 0}
            report = coordinator._terminate_workload_process()

        self.assertTrue(report["local_already_exited"])
        self.assertFalse(report["local_terminated"])
        self.assertEqual(report["remote_pgid"], 45678)
        self.assertTrue(report["remote_termination_result"]["verified_dead"])

    def test_37_workload_timeout_handling(self):
        """Scenario 7: Workload timeout triggers fail-closed abort and process termination."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.remote_workload_dir = "/tmp/g4_test_timeout"
        coordinator.remote_pgid = 98765
        coordinator.telemetry_status["thread_alive"] = True
        coordinator.telemetry_status["last_sample_epoch"] = time.time()
        local_out = os.path.join(self.output_dir, "test_timeout.txt")

        def fake_run_cmd(cmd, check=True, timeout=None):
            return MagicMock(returncode=0, stdout="PENDING\n", stderr="")

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd", side_effect=fake_run_cmd):
            with patch.object(coordinator, "_terminate_workload_process") as mock_term:
                with self.assertRaises(subprocess.TimeoutExpired):
                    coordinator._poll_and_wait_remote_workload(
                        "warmup",
                        duration_sec=0.1,
                        output_local_file=local_out,
                        poll_interval=0.05,
                        grace_period_sec=0.1
                    )
                mock_term.assert_called()

    def test_38_evidence_preservation_stdout_and_stderr(self):
        """Scenario 8: Preservation of stdout/stderr and evidence verification."""
        coordinator = G4PilotExecutionCoordinator(
            run_id="crdb-g4l1-p01",
            level="L1",
            output_dir=self.output_dir,
            dry_run=False
        )
        coordinator.remote_workload_dir = "/tmp/g4_test_evidence"
        local_out = os.path.join(self.output_dir, "04_warmup_stdout.txt")

        def fake_run_cmd(cmd, check=True, timeout=None):
            cmd_str = " ".join(cmd)
            if "exit_code.txt" in cmd_str:
                return MagicMock(returncode=0, stdout="0\n")
            if "stdout.log" in cmd_str:
                return MagicMock(returncode=0, stdout="scale: 10\nnumber of transactions: 5000\n")
            if "stderr.log" in cmd_str:
                return MagicMock(returncode=0, stdout="NOTICE: License notice\n")
            return MagicMock(returncode=0, stdout="")

        with patch("benchmark.scripts.cockroachdb.g4.g4_pilot_runner.run_cmd", side_effect=fake_run_cmd):
            rc = coordinator._retrieve_and_validate_remote_workload(local_out)

        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(local_out))
        with open(local_out, "r") as f:
            content = f.read()
        self.assertIn("scale: 10", content)
        self.assertIn("NOTICE: License notice", content)

if __name__ == "__main__":
    unittest.main()
