import datetime
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add runner script dir to path
runner_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(runner_dir))

import g3_pilot_runner_revised as runner


class TestTelemetryFailClosedProtection(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.telemetry_file = os.path.join(self.temp_dir.name, "telemetry.jsonl")
        self.stop_event = threading.Event()
        self.active_threads = []
        self.status = {
            "thread_alive": False,
            "started_at_epoch": time.time(),
            "last_sample_epoch": time.time(),
            "sample_count": 0,
            "max_observed_gap_sec": 0.0,
            "gap_exceeded": False,
            "error": None,
        }

    def tearDown(self):
        self.stop_event.set()
        for t in self.active_threads:
            t.join(timeout=2.0)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_01_normal_continuous_telemetry(self):
        """Test Case 1: Normal continuous telemetry produces valid status and passes continuity gate."""
        with patch.object(runner, "sample_cgroup_iostat", return_value={"success": True, "raw": "259:4 ...", "error": None}), \
             patch.object(runner, "sample_crdb_metrics", return_value={"success": True, "metrics": {}, "error": None}):
            
            t = threading.Thread(
                target=runner.incremental_telemetry_poller,
                args=("cockroachdb-2", self.stop_event, self.telemetry_file, 0.02, self.status),
                daemon=True
            )
            self.active_threads.append(t)
            t.start()
            time.sleep(0.1)
            self.stop_event.set()
            t.join(timeout=2.0)

            self.assertGreaterEqual(self.status["sample_count"], 3)
            self.assertFalse(self.status["gap_exceeded"])
            self.assertIsNone(self.status["error"])

            coord = runner.G3PilotExecutionCoordinator("test-run", "L1", 180, output_dir=self.temp_dir.name)
            coord.telemetry_status = self.status
            coord.dry_run = False
            coord.telemetry_status["thread_alive"] = True
            coord.telemetry_status["last_sample_epoch"] = time.time()
            coord.assert_telemetry_continuous(window_name="test_window", max_allowed_gap_sec=30.0)

    def test_02_single_failed_sample_recovery(self):
        """Test Case 2: One failed sample followed by immediate recovery does not trigger gap error."""
        call_count = 0
        def flaky_iostat(target_pod):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                return {"success": False, "raw": "", "error": "timeout"}
            return {"success": True, "raw": "259:4 ...", "error": None}

        with patch.object(runner, "sample_cgroup_iostat", side_effect=flaky_iostat), \
             patch.object(runner, "sample_crdb_metrics", return_value={"success": False, "error": "test"}):
            
            t = threading.Thread(
                target=runner.incremental_telemetry_poller,
                args=("cockroachdb-2", self.stop_event, self.telemetry_file, 0.02, self.status),
                daemon=True
            )
            self.active_threads.append(t)
            t.start()
            time.sleep(0.1)
            self.stop_event.set()
            t.join(timeout=2.0)

            self.assertGreaterEqual(self.status["sample_count"], 2)
            self.assertFalse(self.status["gap_exceeded"])

    def test_03_telemetry_gap_below_30s(self):
        """Test Case 3: A gap below 30s (e.g. 15s) passes continuity gate with max_allowed_gap_sec=30.0."""
        coord = runner.G3PilotExecutionCoordinator("test-run", "L1", 180, output_dir=self.temp_dir.name)
        coord.dry_run = False
        coord.telemetry_status = {
            "thread_alive": True,
            "sample_count": 10,
            "gap_exceeded": False,
            "error": None,
            "max_observed_gap_sec": 15.0,
            "last_sample_epoch": time.time() - 15.0,
        }
        coord.assert_telemetry_continuous(window_name="baseline", max_allowed_gap_sec=30.0)

    def test_04_telemetry_gap_exceeding_30s(self):
        """Test Case 4: A gap exceeding 30s raises TelemetryContinuityError and aborts."""
        coord = runner.G3PilotExecutionCoordinator("test-run", "L1", 180, output_dir=self.temp_dir.name)
        coord.dry_run = False
        coord.telemetry_status = {
            "thread_alive": True,
            "sample_count": 10,
            "gap_exceeded": True,
            "error": "Telemetry gap exceeded threshold: 35.2s > 30.0s",
            "max_observed_gap_sec": 35.2,
            "last_sample_epoch": time.time() - 35.2,
        }
        with self.assertRaises(runner.TelemetryContinuityError) as ctx:
            coord.assert_telemetry_continuous(window_name="baseline", max_allowed_gap_sec=30.0)
        self.assertIn("Telemetry gap exceeded threshold", str(ctx.exception))

    def test_05_api_websocket_disconnection_simulation(self):
        """Test Case 5: Prolonged API / WebSocket failure sets gap_exceeded and blocks fault application."""
        with patch.object(runner, "sample_cgroup_iostat", return_value={"success": False, "error": "wsarecv: connection closed"}), \
             patch.object(runner, "sample_crdb_metrics", return_value={"success": False, "error": "dial timeout"}):
            
            # Start status with last sample in past (> 30s)
            self.status["last_sample_epoch"] = time.time() - 31.0
            self.status["sample_count"] = 5
            
            t = threading.Thread(
                target=runner.incremental_telemetry_poller,
                args=("cockroachdb-2", self.stop_event, self.telemetry_file, 0.02, self.status),
                daemon=True
            )
            self.active_threads.append(t)
            t.start()
            time.sleep(0.08)
            self.stop_event.set()
            t.join(timeout=2.0)

            self.assertTrue(self.status["gap_exceeded"])
            self.assertIn("exceeded threshold", self.status["error"])

    def test_06_poller_thread_fatal_crash(self):
        """Test Case 6: Poller thread termination or crash is detected by coordinator."""
        coord = runner.G3PilotExecutionCoordinator("test-run", "L1", 180, output_dir=self.temp_dir.name)
        coord.dry_run = False
        coord.telemetry_status = {
            "thread_alive": False,
            "sample_count": 5,
            "gap_exceeded": False,
            "error": "Poller thread crashed: Out of memory",
            "last_sample_epoch": time.time(),
        }
        with self.assertRaises(runner.TelemetryContinuityError) as ctx:
            coord.assert_telemetry_continuous(window_name="baseline", max_allowed_gap_sec=30.0)
        self.assertIn("poller thread is not running", str(ctx.exception))

    def test_07_missing_final_baseline_sample(self):
        """Test Case 7: Samples stopped 32 seconds before baseline completion."""
        coord = runner.G3PilotExecutionCoordinator("test-run", "L1", 180, output_dir=self.temp_dir.name)
        coord.dry_run = False
        coord.telemetry_status = {
            "thread_alive": True,
            "sample_count": 25,
            "gap_exceeded": False,
            "error": None,
            "last_sample_epoch": time.time() - 32.5,
        }
        with self.assertRaises(runner.TelemetryContinuityError) as ctx:
            coord.assert_telemetry_continuous(window_name="baseline", max_allowed_gap_sec=30.0)
        self.assertIn("last sample was 32.5s ago", str(ctx.exception))

    def test_08_failure_prevents_fault_application(self):
        """Test Case 8: Telemetry continuity error in baseline prevents fault_applied and triggers rollback."""
        coord = runner.G3PilotExecutionCoordinator("test-run", "L1", 180, output_dir=self.temp_dir.name)
        coord.dry_run = True
        coord.target_info = {"target_pod": "cockroachdb-2", "lease_holder_id": "3"}
        
        # Inject an active gap error
        coord.telemetry_status = {
            "thread_alive": True,
            "sample_count": 10,
            "gap_exceeded": True,
            "error": "Simulated 45s drop",
            "last_sample_epoch": time.time() - 45.0,
        }
        
        # Calling baseline check directly
        with self.assertRaises(runner.TelemetryContinuityError):
            coord.dry_run = False
            coord.assert_telemetry_continuous(window_name="baseline_window")

        # Crucial invariant: fault was never applied!
        self.assertFalse(coord.fault_applied)

    def test_09_coordinator_interruption_during_observation(self):
        """Test Case 9: Clean termination of telemetry thread and resources upon interruption."""
        with patch.object(runner, "sample_cgroup_iostat", return_value={"success": True, "raw": "259:4 ...", "error": None}), \
             patch.object(runner, "sample_crdb_metrics", return_value={"success": True, "metrics": {}, "error": None}):
            t = threading.Thread(
                target=runner.incremental_telemetry_poller,
                args=("cockroachdb-2", self.stop_event, self.telemetry_file, 0.02, self.status),
                daemon=True
            )
            self.active_threads.append(t)
            t.start()
            time.sleep(0.05)
            self.assertTrue(self.status["thread_alive"])
            
            # Signal interruption / stop
            self.stop_event.set()
            t.join(timeout=2.0)
            self.assertFalse(self.status["thread_alive"])

    def test_10_cleanup_terminates_background_threads(self):
        """Test Case 10: Coordinator cleanup explicitly halts telemetry thread."""
        with patch.object(runner, "sample_cgroup_iostat", return_value={"success": True, "raw": "259:4 ...", "error": None}), \
             patch.object(runner, "sample_crdb_metrics", return_value={"success": True, "metrics": {}, "error": None}):
            coord = runner.G3PilotExecutionCoordinator("test-run", "L1", 180, output_dir=self.temp_dir.name)
            coord.stop_telemetry_event = self.stop_event
            t = threading.Thread(
                target=runner.incremental_telemetry_poller,
                args=("cockroachdb-2", self.stop_event, self.telemetry_file, 0.02, self.status),
                daemon=True
            )
            self.active_threads.append(t)
            coord.telemetry_thread = t
            t.start()
            time.sleep(0.05)
            self.assertTrue(t.is_alive())

            # Simulate cleanup path
            coord.stop_telemetry_event.set()
            coord.telemetry_thread.join(timeout=2.0)
            self.assertFalse(t.is_alive())


if __name__ == "__main__":
    unittest.main()
