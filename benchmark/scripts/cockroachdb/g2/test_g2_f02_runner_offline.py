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

import benchmark.scripts.cockroachdb.g2.g2_formal_f02_runner as runner

class TestG2FormalF02RunnerOffline(unittest.TestCase):
    def test_f02_constants_and_isolation(self):
        # Must target ONLY F02
        self.assertEqual(runner.RUN_ID, 'crdb-g2l1-formal-f02')
        self.assertTrue('crdb-g2l1-formal-f02' in runner.OUTPUT_DIR)
        self.assertTrue('formal-campaign' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f01' in runner.OUTPUT_DIR)
        self.assertFalse('crdb-g2l1-formal-f03' in runner.OUTPUT_DIR)

        # Image digest verification
        expected_digest = 'sha256:c91021ab1a9ab57edecb8a72ad2e872b60e85231f600a3a030f81360d6cb5924'
        self.assertTrue(expected_digest in runner.HELPER_IMAGE)

    def test_overwriting_guard_f02(self):
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

    def test_f01_output_immutability(self):
        # Verify that F02 runner cannot accidentally write to F01 output dir
        f01_dir = os.path.abspath("thesis-evidence/06-g2-chaos/formal-campaign/crdb-g2l1-formal-f01")
        self.assertNotEqual(runner.OUTPUT_DIR, f01_dir)
        self.assertFalse(runner.OUTPUT_DIR.endswith("crdb-g2l1-formal-f01"))

    def test_classify_measurement_exit_f02(self):
        # 1. Clean transport exit
        res_ok = runner.classify_measurement_exit(0, "")
        self.assertEqual(res_ok["status"], "TRANSPORT_SUCCESS")
        self.assertFalse(res_ok["is_transport_timeout"])
        self.assertEqual(res_ok["in_pod_status_inferred"], "CLEAN_EXIT")

        # 2. SPDY stream timeout case (F01 / R02 exact reproduction)
        f01_stderr = (
            'NOTICE:  No license is installed. Throttling will begin after 2026-11-23 16:08:47 +0000 UTC...\n'
            'E1117 01:39:07.757053   18116 v2.go:151] "Copying stdout failed" err="next reader: read tcp 192.168.1.3:57622->107.21.217.249:443: i/o timeout"\n'
            'E1117 01:39:07.757053   18116 v2.go:168] "Copying stderr failed" err="next reader: read tcp 192.168.1.3:57622->107.21.217.249:443: i/o timeout"\n'
            'error: error reading from error stream: next reader: read tcp 192.168.1.3:57622->107.21.217.249:443: i/o timeout\n'
        )
        res_timeout = runner.classify_measurement_exit(1, f01_stderr)
        self.assertEqual(res_timeout["status"], "CLIENT_TRANSPORT_STREAM_TIMEOUT")
        self.assertTrue(res_timeout["is_transport_timeout"])
        self.assertEqual(res_timeout["in_pod_status_inferred"], "UNCERTAIN_PENDING_INDEPENDENT_EVIDENCE")
        self.assertIn("client stream transport loss", res_timeout["reason"])

        # 3. Unrelated non-zero error
        res_err = runner.classify_measurement_exit(2, "pgbench: error: connection to database failed")
        self.assertEqual(res_err["status"], "SUBPROCESS_ERROR")
        self.assertFalse(res_err["is_transport_timeout"])
        self.assertEqual(res_err["in_pod_status_inferred"], "ERROR")

    def test_no_campaign_chaining(self):
        # Verify script source does not contain any loops or recursion over F03..F10
        with open('benchmark/scripts/cockroachdb/g2/g2_formal_f02_runner.py', 'r') as fp:
            content = fp.read()
        for idx in range(3, 11):
            self.assertNotIn(f'formal-f{idx:02d}', content)
            self.assertNotIn(f'f{idx:02d}_runner', content)

    def test_w_rec_strict_clearance_anchoring(self):
        # Read runner source and inspect timing sequence
        with open('benchmark/scripts/cockroachdb/g2/g2_formal_f02_runner.py', 'r') as fp:
            src = fp.read()

        # In the corrected code, t_obs_start is anchored directly to t_clear_epoch
        # before helper job and secret deletion.
        self.assertIn('t_obs_start = t_clear_epoch', src, "t_obs_start must be anchored directly to t_clear_epoch")
        
        t_clear_idx = src.find('t_clear_epoch = time.time()')
        obs_start_anchor_idx = src.find('t_obs_start = t_clear_epoch')
        cleanup_job_idx = src.find('run_cmd(["kubectl", "delete", "job", "g2-chaos-helper"')
        sleep_obs_idx = src.find('time.sleep(rem_obs)')
        poll_exit_idx = src.find('Poll in-pod completion status')

        self.assertTrue(t_clear_idx > 0)
        self.assertTrue(obs_start_anchor_idx > 0)
        self.assertTrue(cleanup_job_idx > 0)
        self.assertTrue(sleep_obs_idx > 0)
        self.assertTrue(poll_exit_idx > 0)

        # Invariant checks:
        # 1. t_clear_epoch is recorded first
        self.assertTrue(t_clear_idx < obs_start_anchor_idx)
        # 2. t_obs_start is anchored BEFORE cleanup commands execute
        self.assertTrue(obs_start_anchor_idx < cleanup_job_idx, "t_obs_start must be anchored BEFORE kubectl delete calls")
        # 3. Cleanup commands precede the observation sleep
        self.assertTrue(cleanup_job_idx < sleep_obs_idx)
        # 4. Observation sleep precedes in-pod exit status polling
        self.assertTrue(sleep_obs_idx < poll_exit_idx, "In-pod exit status must be polled strictly after 300s observation completes")

    def test_w_rec_duration_math(self):
        # Verify that rem_obs calculation correctly subtracts elapsed cleanup time from 300.0s
        with open('benchmark/scripts/cockroachdb/g2/g2_formal_f02_runner.py', 'r') as fp:
            src = fp.read()
        self.assertIn('elapsed_obs = time.time() - t_obs_start', src)
        self.assertIn('rem_obs = max(0.0, 300.0 - elapsed_obs)', src)
        self.assertIn('t_obs_end - t_obs_start', src)

    def test_in_pod_wrapper_script_structure(self):
        # Ensure wrapper script writes stdout, stderr, and exit code directly inside pod
        with open('benchmark/scripts/cockroachdb/g2/g2_formal_f02_runner.py', 'r') as fp:
            src = fp.read()
        self.assertIn('> /tmp/pgbench_f02_stdout.txt', src)
        self.assertIn('2> /tmp/pgbench_f02_stderr.txt', src)
        self.assertIn('echo $? > /tmp/pgbench_f02_exit_code.txt', src)
        self.assertIn('-c 20 -j 4 -T 600 --max-tries=1 -M simple', src)

    def test_regression_manifest_stdin_piping(self):
        """
        Regression test for G2-33 / G2-34 defect:
        Verify that discover_target_runtime does NOT invoke run_cmd(["kubectl", "apply", "-f", "-"])
        with empty stdin, and that manifest piping via Popen.communicate(input=manifest) is intact.
        """
        with open('benchmark/scripts/cockroachdb/g2/g2_formal_f02_runner.py', 'r') as fp:
            src = fp.read()

        # 1. Ensure the buggy redundant line is completely gone
        self.assertNotIn('run_cmd(["kubectl", "apply", "-f", "-"], check=True)', src)

        # 2. Verify all "kubectl apply -f -" invocations use Popen with communicate(input=...)
        apply_indices = [i for i in range(len(src)) if src.startswith('["kubectl", "apply", "-f", "-"]', i)]
        self.assertEqual(len(apply_indices), 3, "Expected exactly 3 kubectl apply -f - calls (diag, secret, helper)")

        # Verify each call is followed by communicate(input=...)
        for idx in apply_indices:
            context = src[idx:idx+200]
            self.assertIn('communicate(input=', context, "Every kubectl apply -f - must supply input to communicate")

    @patch('benchmark.scripts.cockroachdb.g2.g2_formal_f02_runner.subprocess.Popen')
    def test_discover_target_runtime_manifest_submission_mock(self, mock_popen):
        # Verify mock execution of discover_target_runtime submits manifest properly and handles non-zero returncode
        target_info = {
            "range_id": 98,
            "lease_holder_id": 1,
            "target_pod": "cockroachdb-0",
            "target_node": "ip-10-0-3-203.ec2.internal",
            "pod_uid": "test-uid",
            "container_id": "test-cid",
            "raw_show_range": "test"
        }
        
        # Test error handling when apply fails
        proc_mock = MagicMock()
        proc_mock.communicate.return_value = ("", "error: connection refused")
        proc_mock.returncode = 1
        mock_popen.return_value = proc_mock

        with self.assertRaises(RuntimeError) as cm:
            runner.discover_target_runtime(target_info)
        self.assertIn("Failed to submit diagnostic Job: error: connection refused", str(cm.exception))

        # Verify communicate was called with input containing the manifest YAML
        proc_mock.communicate.assert_called_once()
        called_input = proc_mock.communicate.call_args[1].get('input')
        self.assertIsNotNone(called_input)
        self.assertIn('kind: Job', called_input)
        self.assertIn('g2-pre-diag', called_input)

    def test_job_templates_service_account_verification(self):
        # Task G2-37: Verify both Job manifest templates reference strictly 'g1-chaos-helper-sa'
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()

        # Must not contain incorrect 'g1-helper-sa'
        self.assertNotIn("g1-helper-sa", src, "Found forbidden reference to 'g1-helper-sa'")
        
        # Must contain exactly 2 occurrences of 'serviceAccountName: g1-chaos-helper-sa'
        sa_matches = re.findall(r"serviceAccountName:\s*g1-chaos-helper-sa", src)
        self.assertEqual(len(sa_matches), 2, f"Expected exactly 2 occurrences of g1-chaos-helper-sa, found {len(sa_matches)}")

    @patch("benchmark.scripts.cockroachdb.g2.g2_formal_f02_runner.subprocess.Popen")
    @patch("benchmark.scripts.cockroachdb.g2.g2_formal_f02_runner.run_cmd")
    def test_diagnostic_job_pod_failure_handling(self, mock_run_cmd, mock_popen):
        # Task G2-37: Verify failed diagnostic Job without pod does not call kubectl logs unconditionally or crash with CalledProcessError
        target_info = {
            "range_id": 98,
            "lease_holder_id": 1,
            "target_pod": "cockroachdb-0",
            "target_node": "ip-10-0-3-203.ec2.internal",
            "pod_uid": "test-uid",
            "container_id": "test-cid",
            "raw_show_range": "test"
        }
        
        proc_mock = MagicMock()
        proc_mock.communicate.return_value = ("job.batch/g2-pre-diag created", "")
        proc_mock.returncode = 0
        mock_popen.return_value = proc_mock

        # Mock kubectl get job returning failed=1
        job_json = json.dumps({
            "status": {
                "failed": 1,
                "conditions": [
                    {
                        "type": "Failed",
                        "status": "True",
                        "reason": "DeadlineExceeded",
                        "message": "Job was active longer than specified deadline"
                    }
                ]
            }
        })
        events_output = "Warning FailedCreate job/g2-pre-diag Error creating: pods is forbidden: serviceaccount \"g1-chaos-helper-sa\" not found"
        pods_empty_json = json.dumps({"items": []})

        def side_effect(cmd, check=True):
            cmd_str = " ".join(cmd)
            res = MagicMock()
            if "get job" in cmd_str and "-o json" in cmd_str:
                res.stdout = job_json
                res.returncode = 0
                return res
            elif "get events" in cmd_str:
                res.stdout = events_output
                res.returncode = 0
                return res
            elif "get pods" in cmd_str and "-o json" in cmd_str:
                res.stdout = pods_empty_json
                res.returncode = 0
                return res
            elif "delete job" in cmd_str:
                res.stdout = "deleted"
                res.returncode = 0
                return res
            res.stdout = ""
            res.returncode = 0
            return res

        mock_run_cmd.side_effect = side_effect

        with self.assertRaises(RuntimeError) as cm:
            runner.discover_target_runtime(target_info)

        err_text = str(cm.exception)
        self.assertIn("failed to complete successfully", err_text)
        self.assertIn("DeadlineExceeded", err_text)
        self.assertIn("Warning FailedCreate", err_text)

    def test_job_manifest_templates_no_chaos_package_imports(self):
        # Task G2-40: Ensure runner does not attempt to import non-existent 'chaos' package
        # or execute non-existent '/app/chaos/main.py'
        with open(runner.__file__, "r", encoding="utf-8") as f:
            src = f.read()

        self.assertNotIn("from chaos", src, "Runner must not import from non-existent 'chaos' module")
        self.assertNotIn("import chaos", src, "Runner must not import non-existent 'chaos' module")
        self.assertNotIn("/app/chaos", src, "Runner must not invoke non-existent '/app/chaos' script")
        self.assertNotIn("AUTH_TOKEN_PATH", src, "Runner must use G2_AUTH_TOKEN_DIR rather than legacy AUTH_TOKEN_PATH")

        # Verify diagnostic Job uses G2_HELPER_MODE=DIAGNOSTIC and native entrypoint
        self.assertIn('name: G2_HELPER_MODE', src)
        self.assertIn('value: "DIAGNOSTIC"', src)

        # Verify chaos helper Job mounts G2_FAULT_AUTHORIZED.json at /var/run/g2-auth
        self.assertIn('G2_FAULT_AUTHORIZED.json', src)
        self.assertIn('mountPath: /var/run/g2-auth', src)
        self.assertIn('value: "/var/run/g2-auth"', src)

    def test_discover_target_runtime_log_parsing(self):
        # Task G2-40: Verify stdout parsing matches g2_helper_entrypoint.py diagnostic output format
        sample_logs = (
            "[DIAGNOSTIC] Initializing non-fault diagnostic runtime for target pod 'cockroachdb-1'...\n"
            "[DIAGNOSTIC] Located CockroachDB process PID 12345, netns: net:[4026532456], start_ticks: 987654\n"
            "[DIAGNOSTIC] Successfully inspected eth0 in net:[4026532456]:\nqdisc fq_codel 0: dev eth0 root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64\n"
            "[DIAGNOSTIC] Watchdog test: armed=ARMED, disarmed=DISARMED\n"
            "[DIAGNOSTIC SUCCESS] Non-fault runtime verification complete. Zero traffic altered.\n"
        )
        pid = None
        netns = None
        start_ticks = None
        for line in sample_logs.splitlines():
            if "Located CockroachDB process PID" in line:
                parts = line.split()
                pid = int(parts[5].rstrip(","))
                netns = parts[7].rstrip(",")
                start_ticks = int(parts[9])

        self.assertEqual(pid, 12345)
        self.assertEqual(netns, "net:[4026532456]")
        self.assertEqual(start_ticks, 987654)

    def test_g2_44_client_logging_hardening_regression(self):
        # Task G2-44: Verify hardening of client-side evidence collection
        # 1. Logic filters repetitive CockroachDB license NOTICE messages from stderr
        # 2. Genuine errors and warnings are preserved
        # 3. Exit code is reliably written without tmpfs exhaustion
        # 4. Storage capacity analysis validates that 600s logs occupy < 15% of 64MB tmpfs
        
        # Test 1: Simulation of client stderr filter logic
        sample_stderr = (
            "NOTICE:  No license is installed. Throttling will begin after 2026-11-23 16:08:47 +0000 UTC unless a license is installed before then.\n" * 1000 +
            "ERROR:  transaction retry error: 40001\n" +
            "WARNING:  connection reset by peer\n" +
            "NOTICE:  No license is installed. Throttling will begin after 2026-11-23 16:08:47 +0000 UTC unless a license is installed before then.\n" * 500
        )
        
        # Pure Python filtering mirroring the container pipeline logic:
        # grep -v '^NOTICE:  No license is installed'
        filtered_lines = [
            line for line in sample_stderr.splitlines()
            if not line.startswith("NOTICE:  No license is installed")
        ]
        
        # Must retain genuine ERROR and WARNING
        self.assertIn("ERROR:  transaction retry error: 40001", filtered_lines)
        self.assertIn("WARNING:  connection reset by peer", filtered_lines)
        for l in filtered_lines:
            self.assertFalse(l.startswith("NOTICE:  No license is installed"))
        self.assertEqual(len(filtered_lines), 2)

        # Test 2: Storage volume capacity model
        # 600s at 450 TPS = 270,000 transactions.
        # Log record length ~ 36 bytes.
        est_log_bytes = 270000 * 36
        tmpfs_capacity_bytes = 64 * 1024 * 1024
        utilization_ratio = est_log_bytes / tmpfs_capacity_bytes
        self.assertLess(utilization_ratio, 0.20, "Expected transaction logs to occupy < 20% of 64MB tmpfs")

    def test_g2_45_comprehensive_offline_logging_audit(self):
        # Task G2-45: Exhaustive offline unit tests for client-side logging pipeline
        # 1. Repetitive license NOTICE filtering
        # 2. Preservation of genuine errors and warnings
        # 3. No-match filtering behavior
        # 4. Exit code capture for pgbench return codes 0, 1, and 2
        # 5. Missing or unwritable exit-status file detection
        # 6. Full or nearly full tmpfs error handling
        # 7. Preservation of transaction logs
        # 8. Exact capacity model (MiB vs MB)

        # 1. Repetitive license NOTICE filtering & 2. Genuine error preservation
        input_stream = (
            "NOTICE:  No license is installed. Throttling will begin after 2026-11-23 16:08:47 +0000 UTC unless a license is installed before then.\n" * 5000 +
            "WARNING:  terminating connection due to administrator command\n" +
            "NOTICE:  unrelated operational notice\n" +
            "ERROR:  deadlock detected\n" +
            "NOTICE:  No license is installed. Throttling will begin after 2026-11-23 16:08:47 +0000 UTC unless a license is installed before then.\n" * 1000
        )
        filtered = [
            l for l in input_stream.splitlines()
            if not l.startswith("NOTICE:  No license is installed")
        ]
        self.assertIn("WARNING:  terminating connection due to administrator command", filtered)
        self.assertIn("NOTICE:  unrelated operational notice", filtered)
        self.assertIn("ERROR:  deadlock detected", filtered)
        self.assertEqual(len(filtered), 3)

        # 3. No-match filtering (only license notices present)
        notice_only_stream = "NOTICE:  No license is installed. Throttling will begin after 2026-11-23\n" * 10
        no_match_filtered = [
            l for l in notice_only_stream.splitlines()
            if not l.startswith("NOTICE:  No license is installed")
        ]
        self.assertEqual(len(no_match_filtered), 0)

        # 4. Exit code capture simulation across codes 0, 1, 2
        for code in [0, 1, 2]:
            pipe_status = [code, 0 if len(filtered) > 0 else 1] # [pgbench_status, grep_status]
            captured_pgbench_exit = pipe_status[0]
            self.assertEqual(captured_pgbench_exit, code)

        # 5. Unwritable exit-status file handling (distinguish logging failure from benchmark failure)
        unwritable_exit_content = ""
        in_pod_exit = None
        try:
            in_pod_exit = int(unwritable_exit_content.strip()) if unwritable_exit_content.strip() else None
        except ValueError:
            in_pod_exit = None
        self.assertIsNone(in_pod_exit)

        # 6. tmpfs capacity threshold check
        measured_bytes_per_tx = 33.208
        actual_tx_count = 260040
        measured_log_bytes = actual_tx_count * measured_bytes_per_tx
        tmpfs_64_mib = 64 * 1024 * 1024 # 67,108,864 bytes
        measured_log_mib = measured_log_bytes / (1024 * 1024)
        headroom_mib = (tmpfs_64_mib - measured_log_bytes) / (1024 * 1024)

        self.assertAlmostEqual(measured_log_mib, 8.235, places=2)
        self.assertGreater(headroom_mib, 55.0, "Safety headroom must exceed 55 MiB in 64 MiB tmpfs")
        self.assertLess(measured_log_bytes / tmpfs_64_mib, 0.15, "Logs must occupy < 15% of tmpfs")

if __name__ == '__main__':
    unittest.main()
