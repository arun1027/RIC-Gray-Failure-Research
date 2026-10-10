import unittest
import os
import sys

REPO_ROOT = os.path.abspath('.')
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import benchmark.scripts.cockroachdb.g2.g2_formal_f01_runner as runner

class TestG2FormalF01RunnerOffline(unittest.TestCase):
    def test_runner_constants(self):
        self.assertEqual(runner.RUN_ID, 'crdb-g2l1-formal-f01')
        self.assertTrue('formal-campaign' in runner.OUTPUT_DIR)
        self.assertTrue('crdb-g2l1-formal-f01' in runner.OUTPUT_DIR)
        self.assertEqual(runner.HELPER_IMAGE, '397916376204.dkr.ecr.us-east-1.amazonaws.com/ric-g2-helper@sha256:c91021ab1a9ab57edecb8a72ad2e872b60e85231f600a3a030f81360d6cb5924')

    def test_overwriting_guard(self):
        # Verify that if execution_record.json exists in OUTPUT_DIR, main raises RuntimeError
        import tempfile, shutil
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

    def test_classify_measurement_exit(self):
        # Success case
        res_ok = runner.classify_measurement_exit(0, "")
        self.assertEqual(res_ok["status"], "TRANSPORT_SUCCESS")
        self.assertFalse(res_ok["is_transport_timeout"])
        self.assertEqual(res_ok["in_pod_status_inferred"], "CLEAN_EXIT")

        # SPDY stream timeout case (F01 / R02 exact reproduction)
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

        # Unrelated non-zero error
        res_err = runner.classify_measurement_exit(2, "pgbench: error: connection to database failed")
        self.assertEqual(res_err["status"], "SUBPROCESS_ERROR")
        self.assertFalse(res_err["is_transport_timeout"])
        self.assertEqual(res_err["in_pod_status_inferred"], "ERROR")

if __name__ == '__main__':
    unittest.main()
