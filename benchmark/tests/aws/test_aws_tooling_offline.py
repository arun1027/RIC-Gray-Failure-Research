#!/usr/bin/env python3
"""
Hardened Offline Test Suite for Dynamic Kubernetes Configuration, Pilot Watchdog,
and Scoped Teardown Safeguards.
Mocks all external AWS CLI, subprocess, and filesystem boundaries.
Strictly offline; does not connect to AWS or any live infrastructure.
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import subprocess
from unittest.mock import patch, MagicMock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCRIPTS_AWS_DIR = os.path.join(REPO_ROOT, "scripts", "aws")
sys.path.insert(0, SCRIPTS_AWS_DIR)

from importlib.machinery import SourceFileLoader

# Dynamically load the target scripts
cfg_mod = SourceFileLoader("configure_k8s_endpoints", os.path.join(SCRIPTS_AWS_DIR, "configure-k8s-endpoints.py")).load_module()
wd_mod = SourceFileLoader("pilot_watchdog", os.path.join(SCRIPTS_AWS_DIR, "pilot-watchdog.py")).load_module()

class TestDynamicK8sEndpointsOffline(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_valid_endpoints_and_credentials_generation(self):
        """Must generate dynamic manifests correctly with valid endpoints and password using safe YAML."""
        writer = "ric-aurora-cluster.cluster-xyz987654321.us-east-1.rds.amazonaws.com"
        reader = "ric-aurora-cluster.cluster-ro-xyz987654321.us-east-1.rds.amazonaws.com"
        pw = "TestSecurePassword2026!"

        paths = cfg_mod.generate_kubernetes_manifests(
            writer_endpoint=writer,
            reader_endpoint=reader,
            password=pw,
            output_dir=self.test_dir
        )

        self.assertTrue(os.path.exists(paths["configmap"]))
        self.assertTrue(os.path.exists(paths["secret"]))

        with open(paths["configmap"], "r", encoding="utf-8") as f:
            cm = f.read()
        self.assertIn(writer, cm)
        self.assertIn(reader, cm)
        self.assertIn("verify-full", cm)

        with open(paths["secret"], "r", encoding="utf-8") as f:
            sec = f.read()
        self.assertIn(pw, sec)
        self.assertIn("database-user: postgres", sec)

    def test_02_fail_closed_on_missing_endpoints(self):
        """Must raise ConfigurationError if endpoints are empty or missing."""
        with self.assertRaises(cfg_mod.ConfigurationError):
            cfg_mod.validate_aurora_endpoints({"cluster_endpoint": ""})

        with self.assertRaises(cfg_mod.ConfigurationError):
            cfg_mod.validate_aurora_endpoints({})

    def test_03_fail_closed_on_placeholder_endpoint(self):
        """Must reject static development placeholder endpoints."""
        dummy_outputs = {
            "cluster_endpoint": "ric-aurora-cluster.cluster-c12345678901.us-east-1.rds.amazonaws.com",
            "reader_endpoint": "ric-aurora-cluster.cluster-ro-c12345678901.us-east-1.rds.amazonaws.com"
        }
        with self.assertRaises(cfg_mod.ConfigurationError) as ctx:
            cfg_mod.validate_aurora_endpoints(dummy_outputs)
        self.assertIn("template placeholder", str(ctx.exception))

    def test_04_fail_closed_on_invalid_endpoint_hostname(self):
        """Must reject invalid hostname formats or malicious domains."""
        invalid_outputs = {
            "cluster_endpoint": "evil-database.attacker.com",
            "reader_endpoint": "ric-aurora-cluster.cluster-ro-c1234.us-east-1.rds.amazonaws.com"
        }
        with self.assertRaises(cfg_mod.ConfigurationError) as ctx:
            cfg_mod.validate_aurora_endpoints(invalid_outputs)
        self.assertIn("Invalid Aurora writer endpoint hostname format", str(ctx.exception))

    def test_05_fail_closed_on_wrong_prefix(self):
        """Must reject endpoint hostname that does not match expected project prefix."""
        wrong_prefix_outputs = {
            "cluster_endpoint": "otherproject-cluster.cluster-xyz.us-east-1.rds.amazonaws.com",
            "reader_endpoint": "otherproject-cluster.cluster-ro-xyz.us-east-1.rds.amazonaws.com"
        }
        with self.assertRaises(cfg_mod.ConfigurationError) as ctx:
            cfg_mod.validate_aurora_endpoints(wrong_prefix_outputs, expected_prefix="ric-")
        self.assertIn("must start with expected project prefix", str(ctx.exception))

    def test_06_fail_closed_on_missing_password(self):
        """Must fail closed if database password is not provided."""
        old_val = os.environ.pop("AURORA_MASTER_PASSWORD", None)
        try:
            with self.assertRaises(cfg_mod.ConfigurationError):
                cfg_mod.get_database_credentials()
        finally:
            if old_val:
                os.environ["AURORA_MASTER_PASSWORD"] = old_val

    def test_07_reject_static_template_password(self):
        """Must reject the default static placeholder password."""
        old_val = os.environ.get("AURORA_MASTER_PASSWORD", None)
        os.environ["AURORA_MASTER_PASSWORD"] = "auroraPostgresSecureToken14!"
        try:
            with self.assertRaises(cfg_mod.ConfigurationError) as ctx:
                cfg_mod.get_database_credentials()
            self.assertIn("Rejected static placeholder password", str(ctx.exception))
        finally:
            if old_val is not None:
                os.environ["AURORA_MASTER_PASSWORD"] = old_val
            else:
                os.environ.pop("AURORA_MASTER_PASSWORD", None)

    def test_08_yaml_injection_safety(self):
        """PyYAML serialization must safely escape potential injection payloads."""
        pw = "pass123\n  hacked: true"

        paths = cfg_mod.generate_kubernetes_manifests(
            writer_endpoint="ric-aurora-cluster.cluster-xyz987654321.us-east-1.rds.amazonaws.com",
            reader_endpoint="ric-aurora-cluster.cluster-ro-xyz987654321.us-east-1.rds.amazonaws.com",
            password=pw,
            output_dir=self.test_dir
        )

        with open(paths["secret"], "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("\n  hacked: true\n", content)
        import yaml
        parsed = yaml.safe_load(content)
        self.assertEqual(parsed["stringData"]["database-password"], pw)

    def test_09_preserve_original_templates(self):
        """Original template files in kubernetes/aurora must remain unmodified."""
        tpl_cm = os.path.join(REPO_ROOT, "kubernetes", "aurora", "03-aurora-cluster-config.yaml")
        tpl_sec = os.path.join(REPO_ROOT, "kubernetes", "aurora", "02-aurora-secrets-template.yaml")

        self.assertTrue(os.path.exists(tpl_cm))
        self.assertTrue(os.path.exists(tpl_sec))

        with open(tpl_cm, "r", encoding="utf-8") as f:
            cm_text = f.read()
        with open(tpl_sec, "r", encoding="utf-8") as f:
            sec_text = f.read()

        self.assertIn("cluster-c12345678901.us-east-1.rds.amazonaws.com", cm_text)
        self.assertIn("auroraPostgresSecureToken14!", sec_text)

    def test_10_refuse_output_to_template_directory(self):
        """Must reject writing directly to the source template root directory."""
        template_dir = os.path.join(REPO_ROOT, "kubernetes", "aurora")
        with self.assertRaises(cfg_mod.ConfigurationError):
            cfg_mod.generate_kubernetes_manifests(
                writer_endpoint="ric-aurora-cluster.cluster-xyz.us-east-1.rds.amazonaws.com",
                reader_endpoint="ric-aurora-cluster.cluster-ro-xyz.us-east-1.rds.amazonaws.com",
                password="SecurePassword123!",
                output_dir=template_dir
            )

class TestPilotWatchdogOffline(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.report_path = os.path.join(self.test_dir, "test_report.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_validation_of_positive_parameters(self):
        """Watchdog must reject zero or negative duration or interval values."""
        with self.assertRaises(wd_mod.WatchdogValidationError):
            wd_mod.PilotWatchdog(max_duration_seconds=-1)
        with self.assertRaises(wd_mod.WatchdogValidationError):
            wd_mod.PilotWatchdog(poll_interval_seconds=0)
        with self.assertRaises(wd_mod.WatchdogValidationError):
            wd_mod.PilotWatchdog(subprocess_timeout=-10)

    def test_02_default_is_dry_run(self):
        """Watchdog default must be dry run without executing destruction."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=self.report_path
        )
        self.assertFalse(watchdog.execute_teardown)
        watchdog.start()
        success = watchdog.trigger_teardown()
        self.assertTrue(success)
        self.assertEqual(watchdog.cleanup_status, "SKIPPED_DRY_RUN_DEFAULT")
        self.assertEqual(watchdog.verification_status, "NOT_APPLICABLE_DRY_RUN")

    def test_03_teardown_requires_explicit_confirmation_phrase(self):
        """Active teardown must abort if confirmation phrase is absent or incorrect."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=self.report_path,
            execute_teardown=True,
            confirmation_phrase="WRONG_PHRASE"
        )
        watchdog.start()
        success = watchdog.trigger_teardown()
        self.assertFalse(success)
        self.assertEqual(watchdog.cleanup_status, "ABORTED_CONFIRMATION_REQUIRED")

    def test_04_timeout_trigger_logic(self):
        """Watchdog must trigger timeout when elapsed time exceeds max_duration."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=100,
            report_path=self.report_path
        )
        watchdog.start_time = 1000.0

        # Before timeout
        self.assertFalse(watchdog.check_timeout(current_time=1050.0))
        # At / after timeout
        self.assertTrue(watchdog.check_timeout(current_time=1100.0))
        self.assertIn("TIMEOUT", watchdog.termination_reason)

    def test_05_mocked_subprocess_nonzero_exit_prevents_false_success(self):
        """When subprocess returns non-zero, watchdog must report failure and not claim success."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=self.report_path,
            execute_teardown=True,
            confirmation_phrase="DESTROY_RIC_PILOT_RESOURCES"
        )
        watchdog.start()

        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stderr = "Terraform state locked or dependency error"

        with patch("os.path.exists", return_value=True), patch("subprocess.run", return_value=mock_res) as mock_sub:
            success = watchdog.trigger_teardown()
            self.assertFalse(success)
            self.assertEqual(watchdog.cleanup_status, "FAILED_EXIT_1")
            self.assertEqual(watchdog.verification_status, "TEARDOWN_SCRIPT_FAILED")
            mock_sub.assert_called_once()
            _, kwargs = mock_sub.call_args
            self.assertEqual(kwargs.get("cwd"), REPO_ROOT)

    def test_06_mocked_subprocess_timeout(self):
        """When subprocess exceeds timeout, watchdog must report timeout failure."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=self.report_path,
            execute_teardown=True,
            confirmation_phrase="DESTROY_RIC_PILOT_RESOURCES",
            subprocess_timeout=5
        )
        watchdog.start()

        with patch("os.path.exists", return_value=True), patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="bash", timeout=5)):
            success = watchdog.trigger_teardown()
            self.assertFalse(success)
            self.assertEqual(watchdog.cleanup_status, "FAILED_TIMEOUT")
            self.assertEqual(watchdog.verification_status, "TIMED_OUT")

    def test_07_independent_verification_detects_residual_resources(self):
        """Even if subprocess returns exit 0, if residual resources exist, teardown is NOT verified."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=self.report_path,
            execute_teardown=True,
            confirmation_phrase="DESTROY_RIC_PILOT_RESOURCES"
        )
        watchdog.start()

        mock_res = MagicMock()
        mock_res.returncode = 0

        # Mock independent verification returning remaining Aurora instance
        with patch("os.path.exists", return_value=True), \
             patch("subprocess.run", return_value=mock_res), \
             patch.object(watchdog, "perform_independent_verification", return_value=(False, ["AURORA_CLUSTER:available"])):
            success = watchdog.trigger_teardown()
            self.assertFalse(success)
            self.assertEqual(watchdog.cleanup_status, "INCOMPLETE_RESIDUAL_RESOURCES")
            self.assertEqual(watchdog.verification_status, "FAILED_RESIDUAL_DETECTED")
            self.assertIn("AURORA_CLUSTER:available", watchdog.remaining_resources)

    def test_08_independent_verification_confirms_clean_state(self):
        """When subprocess returns exit 0 AND verification confirms clean state, mark SUCCESS_INDEPENDENTLY_VERIFIED."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=self.report_path,
            execute_teardown=True,
            confirmation_phrase="DESTROY_RIC_PILOT_RESOURCES"
        )
        watchdog.start()

        mock_res = MagicMock()
        mock_res.returncode = 0

        with patch("os.path.exists", return_value=True), \
             patch("subprocess.run", return_value=mock_res), \
             patch.object(watchdog, "perform_independent_verification", return_value=(True, [])):
            success = watchdog.trigger_teardown()
            self.assertTrue(success)
            self.assertEqual(watchdog.cleanup_status, "SUCCESS_INDEPENDENTLY_VERIFIED")
            self.assertEqual(watchdog.verification_status, "VERIFIED_ZERO_RESOURCES")

        report = watchdog.write_report()
        self.assertEqual(report["cleanup_status"], "SUCCESS_INDEPENDENTLY_VERIFIED")
        self.assertEqual(report["verification_status"], "VERIFIED_ZERO_RESOURCES")
        self.assertEqual(report["subprocess_exit_code"], 0)

class TestTeardownScriptLogicOffline(unittest.TestCase):

    def setUp(self):
        self.script_path = os.path.join(REPO_ROOT, "scripts", "aws", "teardown-eks.sh")
        with open(self.script_path, "r", encoding="utf-8") as f:
            self.content = f.read()

    def test_01_script_precondition_rules_present(self):
        """teardown-eks.sh must contain mandatory precondition assertions."""
        self.assertTrue(os.path.exists(self.script_path))

        # P0: Kubernetes Context Protection
        self.assertIn("minikube", self.content)
        self.assertIn("docker-desktop", self.content)
        self.assertIn("CURRENT_K8S_CONTEXT", self.content)
        self.assertIn("EXPECTED_CLUSTER_NAME", self.content)

        # P0: Terraform State & Workspace Protection
        self.assertIn("EXPECTED_WORKSPACE", self.content)
        self.assertIn("CURRENT_WORKSPACE", self.content)
        self.assertIn("TF_STATE_LIST", self.content)
        self.assertIn("module.eks", self.content)
        self.assertIn("module.vpc", self.content)

        # P1: Resource-Scoped EBS Cleanup by Run ID
        self.assertIn("PILOT_RUN_ID", self.content)
        self.assertIn("Name=tag:PilotRunId,Values=$PILOT_RUN_ID", self.content)
        self.assertIn("PRE-CLEANUP INVENTORY", self.content)

        # P1: Multi-Resource Post-Teardown Verification
        self.assertIn("CLEANUP INCOMPLETE", self.content)
        self.assertIn("describe-cluster", self.content)
        self.assertIn("describe-db-clusters", self.content)
        self.assertIn("describe-nat-gateways", self.content)
        self.assertIn("describe-instances", self.content)
        self.assertIn("describe-volumes", self.content)

    def test_02_eks_arn_and_endpoint_cryptographic_verification_present(self):
        """Must verify cluster ARN and active kubeconfig server endpoint against actual AWS EKS API."""
        self.assertIn("EXPECTED_CLUSTER_ARN", self.content)
        self.assertIn("ACTUAL_CLUSTER_ARN", self.content)
        self.assertIn("ACTUAL_CLUSTER_ENDPOINT", self.content)
        self.assertIn("CURRENT_K8S_SERVER", self.content)
        self.assertIn("kubectl config view --minify", self.content)
        self.assertIn("CRITICAL SECURITY ERROR: Cluster ARN", self.content)
        self.assertIn("CRITICAL SECURITY ERROR: Active kubectl server endpoint", self.content)

    def test_03_terraform_backend_and_state_key_verification_present(self):
        """Must verify EXPECTED_BACKEND_TYPE and EXPECTED_BACKEND_KEY if set."""
        self.assertIn("EXPECTED_BACKEND_TYPE", self.content)
        self.assertIn("ACTUAL_BACKEND", self.content)
        self.assertIn("EXPECTED_BACKEND_KEY", self.content)
        self.assertIn("Configured Terraform backend", self.content)
        self.assertIn("Configured Terraform remote state key does not match", self.content)

    def test_04_watchdog_independent_verification_covers_all_resource_types(self):
        """PilotWatchdog independent verification must audit EKS, nodegroups, Aurora, instances, NAT, EBS."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=os.path.join(tempfile.gettempdir(), "test_wd_report.json"),
            pilot_run_id="run-test-123"
        )
        
        # Test detection of residual NAT Gateway
        with patch("subprocess.run") as mock_sub:
            # We mock subprocess.run to simulate finding a remaining NAT gateway
            def side_effect(cmd, **kwargs):
                mock_res = MagicMock()
                mock_res.returncode = 0
                if "describe-nat-gateways" in cmd:
                    mock_res.stdout = "nat-0123456789abcdef0"
                else:
                    mock_res.stdout = ""
                return mock_res

            mock_sub.side_effect = side_effect
            is_clean, residuals = watchdog.perform_independent_verification()
            self.assertFalse(is_clean)
            self.assertIn("NAT_GATEWAYS:nat-0123456789abcdef0", residuals)

    def test_05_watchdog_independent_verification_detects_residual_ebs_volume(self):
        """Watchdog independent verification must detect residual pilot-specific EBS volumes."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=os.path.join(tempfile.gettempdir(), "test_wd_report.json"),
            pilot_run_id="run-test-123"
        )
        
        with patch("subprocess.run") as mock_sub:
            def side_effect(cmd, **kwargs):
                mock_res = MagicMock()
                mock_res.returncode = 0
                if "describe-volumes" in cmd and "Name=tag:PilotRunId,Values=run-test-123" in cmd:
                    mock_res.stdout = "vol-0987654321fedcba0"
                else:
                    mock_res.stdout = ""
                return mock_res

            mock_sub.side_effect = side_effect
            is_clean, residuals = watchdog.perform_independent_verification()
            self.assertFalse(is_clean)
            self.assertIn("EBS_VOLUMES:vol-0987654321fedcba0", residuals)

    def test_06_watchdog_independent_verification_detects_residual_nodegroups(self):
        """Watchdog independent verification must detect remaining EKS node groups."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=os.path.join(tempfile.gettempdir(), "test_wd_report.json"),
            pilot_run_id="run-test-123"
        )
        
        with patch("subprocess.run") as mock_sub:
            def side_effect(cmd, **kwargs):
                mock_res = MagicMock()
                mock_res.returncode = 0
                if "list-nodegroups" in cmd:
                    mock_res.stdout = "ric-eks-ng-primary"
                else:
                    mock_res.stdout = ""
                return mock_res

            mock_sub.side_effect = side_effect
            is_clean, residuals = watchdog.perform_independent_verification()
            self.assertFalse(is_clean)
            self.assertIn("EKS_NODEGROUPS:ric-eks-ng-primary", residuals)

    def test_07_watchdog_independent_verification_fails_closed_on_api_error(self):
        """Watchdog independent verification must treat AWS API query errors as incomplete verification, not zero resources."""
        watchdog = wd_mod.PilotWatchdog(
            max_duration_seconds=300,
            report_path=os.path.join(tempfile.gettempdir(), "test_wd_report.json"),
            pilot_run_id="run-test-123"
        )
        
        with patch("subprocess.run") as mock_sub:
            mock_res = MagicMock()
            mock_res.returncode = 1
            mock_res.stderr = "RequestLimitExceeded: Rate exceeded"
            mock_res.stdout = ""
            mock_sub.return_value = mock_res

            is_clean, residuals = watchdog.perform_independent_verification()
            self.assertFalse(is_clean)
            # Must detect that query failed and record it in residual list
            self.assertTrue(any("QUERY_FAILED" in r or "VERIFICATION_ERROR" in r for r in residuals))

if __name__ == "__main__":
    unittest.main()
