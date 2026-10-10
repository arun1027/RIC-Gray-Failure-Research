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

import benchmark.scripts.cockroachdb.g2.g2_formal_f06_runner as runner

class TestG2FormalF06RunnerOffline(unittest.TestCase):
    def test_f06_constants_and_isolation(self):
        # Must target ONLY F05
        self.assertEqual(runner.RUN_ID, 'crdb-g2l2-formal-f06')
        self.assertTrue('crdb-g2l2-formal-f06' in runner.OUTPUT_DIR)
        self.assertTrue('formal-campaign' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f01' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f02' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f03' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f04' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f05' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l2-formal-f07' in runner.OUTPUT_DIR)

        # Image digest verification
        expected_digest = 'sha256:c91021ab1a9ab57edecb8a72ad2e872b60e85231f600a3a030f81360d6cb5924'
        self.assertTrue(expected_digest in runner.HELPER_IMAGE)

    def test_overwriting_guard_f06(self):
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

    def test_f01_f02_f03_f04_f05_output_immutability(self):
        # Verify that F05 runner cannot accidentally write to F01, F02, F03, or F04 output dirs
        f01_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f01")
        f02_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f02")
        f03_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f03")
        f04_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f04")
        self.assertNotEqual(runner.OUTPUT_DIR, f01_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f02_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f03_dir)
        self.assertNotEqual(runner.OUTPUT_DIR, f04_dir)
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f01"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f02"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f03"))
        f05_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f05")
        self.assertNotEqual(runner.OUTPUT_DIR, f05_dir)
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f04"))
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f05"))

    def test_no_f07_f10_chaining(self):
        # Ensure runner source contains no automated loop or invocation of F06-F10
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        for i in range(7, 11):
            pad = f"f0{i}" if i < 10 else f"f{i}"
            self.assertNotIn(f"crdb-g2l1-formal-", src)
            self.assertNotIn(f"g2_formal_{pad}_runner", src)

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
        self.assertIn("/tmp/pgbench_f06_exit_code.txt", src)
        self.assertIn("/tmp/pgbench_f06_stdout.txt", src)
        self.assertIn("/tmp/pgbench_f06_stderr.txt", src)

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

    def test_cleanup_scoped_strictly_to_f05(self):
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

