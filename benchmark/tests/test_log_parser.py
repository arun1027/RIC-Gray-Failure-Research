"""
Unit tests for the Unified pgbench Transaction Log Parser & Percentile Calculator
(benchmark/tests/common/test_log_parser.py)
"""

import unittest
import tempfile
import shutil
import os
import sys

BASE_SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if BASE_SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, BASE_SCRIPTS_DIR)

from log_parser import (
    calculate_nearest_rank_percentile,
    analyze_pgbench_logs,
    parse_percentiles_from_log_files,
)


class TestUnifiedLogParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="pgbench-log-test-")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_01_nearest_rank_percentile_calculation(self):
        """Test exact nearest-rank percentile calculation on known distributions."""
        # 100 values: 1000 to 100000 by 1000 (1ms to 100ms in microseconds)
        latencies = [i * 1000 for i in range(1, 101)]
        p95 = calculate_nearest_rank_percentile(latencies, 95.0)
        p99 = calculate_nearest_rank_percentile(latencies, 99.0)
        self.assertEqual(p95, 95000)  # 95 ms in us
        self.assertEqual(p99, 99000)  # 99 ms in us

        # Edge case: empty list returns None
        self.assertIsNone(calculate_nearest_rank_percentile([], 95.0))

    def test_02_valid_multithread_logs_parsing(self):
        """Test parsing valid multithreaded log files with exact reconciliation."""
        prefix = "pgbench_log"
        # Create 2 thread logs: thread 0 (pgbench_log.1234) and thread 1 (pgbench_log.1234.1)
        file0 = os.path.join(self.test_dir, f"{prefix}.1234")
        file1 = os.path.join(self.test_dir, f"{prefix}.1234.1")

        # 100 rows per file: client 0 in file0, client 1 in file1
        # 6 fields: client_id transaction_no time script_no time_epoch time_us
        lines0 = [f"0 {i} 10000 0 1690000000 {i*100}\n" for i in range(100)]
        lines1 = [f"1 {i} 20000 0 1690000000 {i*100}\n" for i in range(100)]

        with open(file0, "w", encoding="utf-8") as f:
            f.writelines(lines0)
        with open(file1, "w", encoding="utf-8") as f:
            f.writelines(lines1)

        res = parse_percentiles_from_log_files(
            log_dir=self.test_dir,
            prefix=prefix,
            expected_files=2,
            expected_clients=2,
            expected_transactions=200,
            expected_failed=0,
        )
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["errors"]), 0)
        # 100 samples of 10ms (10000us) and 100 samples of 20ms (20000us)
        # p95 and p99 should be 20.0 ms
        self.assertEqual(res["p95_ms"], 20.0)
        self.assertEqual(res["p99_ms"], 20.0)

    def test_03_missing_log_directory_and_empty_files(self):
        """Test fail-closed behavior when log directory is missing or log file is empty."""
        non_existent_dir = os.path.join(self.test_dir, "missing_dir")
        res_missing = parse_percentiles_from_log_files(log_dir=non_existent_dir, prefix="pgbench_log")
        self.assertFalse(res_missing["ok"])
        self.assertEqual(res_missing["p95_ms"], 0.0)
        self.assertEqual(res_missing["p99_ms"], 0.0)

        # Empty file
        prefix = "pgbench_log"
        empty_file = os.path.join(self.test_dir, f"{prefix}.5678")
        with open(empty_file, "w", encoding="utf-8") as f:
            pass  # 0 bytes

        res_empty = parse_percentiles_from_log_files(log_dir=self.test_dir, prefix=prefix)
        self.assertFalse(res_empty["ok"])
        self.assertEqual(res_empty["p95_ms"], 0.0)
        self.assertIn("log file 'pgbench_log.5678' is empty", res_empty["errors"])

    def test_04_truncated_and_malformed_logs(self):
        """Test fail-closed behavior on missing final newline and corrupted tokens."""
        prefix = "pgbench_log"
        # Truncated file (no newline at end)
        trunc_file = os.path.join(self.test_dir, f"{prefix}.9999")
        with open(trunc_file, "wb") as f:
            f.write(b"0 1 15000 0 1690000000 100")  # No trailing \n

        res_trunc = parse_percentiles_from_log_files(log_dir=self.test_dir, prefix=prefix)
        self.assertFalse(res_trunc["ok"])
        self.assertTrue(any("truncated" in err for err in res_trunc["errors"]))

        # Malformed tokens
        malformed_file = os.path.join(self.test_dir, f"{prefix}.8888")
        with open(malformed_file, "w", encoding="utf-8") as f:
            f.write("0 1 CORRUPTED_LATENCY 0 1690000000 100\n")

        res_malf = parse_percentiles_from_log_files(log_dir=self.test_dir, prefix=prefix)
        self.assertFalse(res_malf["ok"])
        self.assertTrue(any("malformed" in err for err in res_malf["errors"]))

    def test_05_failed_transactions_and_reconciliation_mismatch(self):
        """Test accounting of 'failed' transaction rows and summary count mismatches."""
        prefix = "pgbench_log"
        file0 = os.path.join(self.test_dir, f"{prefix}.7777")
        # 10 successful transactions, 2 failed transactions
        lines = [f"0 {i} 12000 0 1690000000 {i*100}\n" for i in range(10)]
        lines.append("0 10 failed 0 1690000000 1000\n")
        lines.append("0 11 failed 0 1690000000 1100\n")

        with open(file0, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Reconciled matching expected counts
        res = parse_percentiles_from_log_files(
            log_dir=self.test_dir,
            prefix=prefix,
            expected_files=1,
            expected_clients=1,
            expected_transactions=10,
            expected_failed=2,
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["p95_ms"], 12.0)
        self.assertEqual(res["p99_ms"], 12.0)

        # Mismatch in transaction count triggers fail-closed rejection
        res_mismatch = parse_percentiles_from_log_files(
            log_dir=self.test_dir,
            prefix=prefix,
            expected_files=1,
            expected_clients=1,
            expected_transactions=15,  # Claimed 15 but log only has 10
            expected_failed=2,
        )
        self.assertFalse(res_mismatch["ok"])
        self.assertEqual(res_mismatch["p95_ms"], 0.0)
        self.assertTrue(any("pgbench transactions processed" in err for err in res_mismatch["errors"]))


if __name__ == "__main__":
    unittest.main()
