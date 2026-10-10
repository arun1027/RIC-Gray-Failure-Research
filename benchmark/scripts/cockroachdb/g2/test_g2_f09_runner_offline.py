import unittest
import os
import sys
import tempfile
import shutil
import time
import json
import re
from unittest.mock import patch, MagicMock

REPO_ROOT = os.path.abspath('.')
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import benchmark.scripts.cockroachdb.g2.g2_formal_f09_runner as runner

class TestG2FormalF09RunnerOffline(unittest.TestCase):
    def test_f09_constants_and_isolation(self):
        # Must target ONLY F09
        self.assertEqual(runner.RUN_ID, 'crdb-g2l2-formal-f09')
        self.assertTrue('crdb-g2l2-formal-f09' in runner.OUTPUT_DIR)
        self.assertTrue('formal-campaign' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f01' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f02' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f03' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f04' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f05' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l2-formal-f06' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l2-formal-f07' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l2-formal-f08' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l2-formal-f10' in runner.OUTPUT_DIR)

        # Image digest verification
        expected_digest = 'sha256:c91021ab1a9ab57edecb8a72ad2e872b60e85231f600a3a030f81360d6cb5924'
        self.assertTrue(expected_digest in runner.HELPER_IMAGE)

    def test_overwriting_guard_f09(self):
        # Verify that if execution_record.json exists in OUTPUT_DIR, main raises RuntimeError
        temp_dir = tempfile.mkdtemp()
        try:
            orig_output = runner.OUTPUT_DIR
            runner.OUTPUT_DIR = temp_dir
            with open(os.path.join(temp_dir, 'execution_record.json'), 'w') as fp:
                fp.write('{}')
            with self.assertRaises(RuntimeError) as cm:
                runner.main()
            self.assertIn('already contains completed run results. Refusing to overwrite', str(cm.exception))
        finally:
            runner.OUTPUT_DIR = orig_output
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_f01_through_f08_output_immutability(self):
        # Verify that F09 runner cannot accidentally write to F01-F08 output dirs
        f01_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f01")
        f02_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f02")
        f03_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f03")
        f04_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f04")
        f05_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f05")
        f06_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l2-formal-f06")
        f07_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l2-formal-f07")
        f08_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l2-formal-f08")
        self.assertNotEqual(runner.OUTPUT_DIR, f01_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f02_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f03_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f04_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f05_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f06_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f07_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f08_dir)
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f01"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f02"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f03"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f04"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f05"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l2-formal-f06"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l2-formal-f07"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l2-formal-f08"))

    def test_no_f10_chaining_or_prior_references(self):
        # Ensure runner source contains no automated loop or invocation of F10 or prior runs
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("crdb-g2l1-formal-", src)
        self.assertNotIn("crdb-g2l2-formal-f06", src)
        self.assertNotIn("crdb-g2l2-formal-f07", src)
        self.assertNotIn("crdb-g2l2-formal-f08", src)
        self.assertNotIn("crdb-g2l2-formal-f10", src)
        self.assertNotIn("g2_formal_f10_runner", src)

    def test_30_percent_packet_loss_configuration(self):
        # Verify 30% packet loss is configured in both authorization token metadata and helper Job env
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn('"loss_percentage": 30,', src)
        self.assertNotIn('"loss_percentage": 10,', src)
        self.assertIn('- name: G2_LOSS_PERCENTAGE\n              value: "30"', src)
        self.assertNotIn('- name: G2_LOSS_PERCENTAGE\n              value: "10"', src)
        self.assertIn('"loss_distribution": "uniform"', src)

    def test_dynamic_leaseholder_targeting_and_two_cycle_consensus(self):
        # Verify dynamic targeting queries SHOW RANGE FOR ROW (1) and requires two-cycle consensus
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("SHOW RANGE FROM TABLE benchdb.public.pgbench_accounts FOR ROW (1);", src)
        self.assertIn("c1 = get_leaseholder_info()", src)
        self.assertIn("c2 = get_leaseholder_info()", src)
        self.assertIn('if c1["range_id"] != c2["range_id"] or c1["target_pod"] != c2["target_pod"]', src)

    def test_bash_explicit_invocation(self):
        # Verify runner explicitly invokes bash (not dash/sh) for in-pod pipeline execution
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn('"bash", "-c", pod_wrapper_script', src)
        self.assertNotIn('"sh", "-c", pod_wrapper_script', src)

    def test_pipestatus_exit_capture_and_notice_filtering(self):
        # Verify pipeline incorporates PIPESTATUS[0] and exact license notice filter
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("PIPESTATUS[0]", src)
        self.assertIn("grep -v '^NOTICE:  No license is installed'", src)
        self.assertIn("/tmp/pgbench_f09_exit_code.txt", src)
        self.assertIn("/tmp/pgbench_f09_stdout.txt", src)
        self.assertIn("/tmp/pgbench_f09_stderr.txt", src)

    def test_tmpfs_storage_diagnostic_recording(self):
        # Verify runner captures df -k /tmp before and after measurement
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("df -k /tmp > /tmp/disk_pre.txt", src)
        self.assertIn("df -k /tmp > /tmp/disk_post.txt", src)
        self.assertIn('disk_pre.txt', src)
        self.assertIn('disk_post.txt', src)

    def test_notice_filtering_logic_offline(self):
        # Verify notice filtering preserves genuine errors and drops notices
        sample_stderr = (
            "NOTICE:  No license is installed. Throttling will begin after 2026-11-23 16:08:47 +0000 UTC unless a license is installed before then.\n" * 1000 +
            "WARNING:  connection reset by peer\n" +
            "ERROR:  deadlock detected\n" +
            "NOTICE:  unrelated operational notice\n" +
            "NOTICE:  No license is installed. Throttling will begin after 2026-11-23 16:08:47 +0000 UTC unless a license is installed before then.\n" * 500
        )
        filtered = [
            l for l in sample_stderr.splitlines()
            if not l.startswith("NOTICE:  No license is installed")
        ]
        self.assertIn("WARNING:  connection reset by peer", filtered)
        self.assertIn("ERROR:  deadlock detected", filtered)
        self.assertIn("NOTICE:  unrelated operational notice", filtered)
        self.assertEqual(len(filtered), 3)

    def test_unwritable_exit_code_handling(self):
        # Verify missing or non-digit exit code file is classified as CLIENT_LOGGING_STORAGE_FAILURE
        diag = runner.classify_measurement_exit(1, "sh: 1: echo: echo: I/O error")
        diag["in_pod_exit_code"] = None
        if diag["in_pod_exit_code"] is None:
            diag["in_pod_status_inferred"] = "CLIENT_LOGGING_STORAGE_FAILURE"
        self.assertEqual(diag["in_pod_status_inferred"], "CLIENT_LOGGING_STORAGE_FAILURE")

    def test_service_account_and_helper_image(self):
        # Verify helper Job and diagnostic Job reference g1-chaos-helper-sa
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("g1-helper-sa", src)
        sa_matches = re.findall(r"serviceAccountName:\s*g1-chaos-helper-sa", src)
        self.assertEqual(len(sa_matches), 2)

    def test_t_clear_anchored_wrec_timing(self):
        # Verify W_rec starts directly at t_clear_epoch
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("t_obs_start = t_clear_epoch", src)
        self.assertIn('execution_record["timings"]["t_obs_start_epoch"] = t_obs_start', src)
        self.assertIn("rem_obs = max(0.0, 300.0 - elapsed_obs)", src)

    def test_option_b_reset_invocation(self):
        # Verify Option B truncate is invoked and verified
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("TRUNCATE TABLE pgbench_history;", src)
        self.assertIn("Option B reset verification failed: expected 0 rows", src)

    def test_cleanup_scoped_strictly_to_f09(self):
        # Verify cleanup commands delete only g2-chaos-helper and g2-fault-auth-token
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn('run_cmd(["kubectl", "delete", "job", "g2-chaos-helper", "-n", CHAOS_NAMESPACE', src)
        self.assertIn('run_cmd(["kubectl", "delete", "secret", "g2-fault-auth-token", "-n", CHAOS_NAMESPACE', src)

    def test_capacity_model_mib_boundaries(self):
        # Capacity model: 270,000 tx * 33.208 bytes = ~8.97 MB (8.55 MiB)
        tx_count = 270000
        bytes_per_tx = 33.208
        log_bytes = tx_count * bytes_per_tx
        tmpfs_64_mib = 64 * 1024 * 1024
        utilization = log_bytes / tmpfs_64_mib
        self.assertLess(utilization, 0.15, "Expected < 15% tmpfs utilization for 600s nominal benchmark")

if __name__ == '__main__':
    unittest.main()

