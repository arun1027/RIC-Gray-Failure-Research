"""
g1_evidence_collector.py - Evidence Collection, Metric Recalculation & Manifest Generator.

Features:
- Structured run metadata capture.
- Telemetry stream ingestion.
- Per-thread transaction log parsing and three-way reconciliation:
    Delta H == N_committed == sum(logged_successful)
- Metric Calculations:
  - Detection Time (DT): T1 - T0
  - Primary Recovery Time Objective (CA2 RTO): T2 - T0 (first successful transaction post-fault)
  - Supplementary Restoration Metric: rolling steady-state restoration to >=90% baseline TPS
- Cryptographic SHA-256 evidence manifest generation.
"""

from typing import Dict, Any, List, Optional, Tuple
import os
import hashlib
import json
import csv
import math
import datetime


class TransactionRecord:
    def __init__(self, client_id: int, tx_id: int, status: str, latency_us: int, timestamp_epoch: float):
        self.client_id = client_id
        self.tx_id = tx_id
        self.status = status  # 'ok' or 'failed'
        self.latency_us = latency_us
        self.timestamp_epoch = timestamp_epoch


class G1EvidenceCollector:
    """Collects and mathematically verifies all experimental evidence for G1."""

    def __init__(self, run_id: str, output_dir: str):
        self.run_id = run_id
        self.output_dir = output_dir
        self.telemetry_samples: List[Dict[str, Any]] = []
        self.target_events: List[Dict[str, Any]] = []
        self.fault_events: List[Dict[str, Any]] = []
        self.t0_epoch: Optional[float] = None
        self.t1_epoch: Optional[float] = None
        self.t2_epoch: Optional[float] = None
        self.t_clear_epoch: Optional[float] = None

    def record_target_discovery(self, target_data: Dict[str, Any]):
        self.target_events.append({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target": target_data
        })

    def record_fault_event(self, event_type: str, details: Dict[str, Any]):
        self.fault_events.append({
            "event_type": event_type,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "details": details
        })

    def ingest_telemetry_sample(self, sample: Dict[str, Any]):
        self.telemetry_samples.append(sample)

    @staticmethod
    def _validate_epoch(value: float, label: str) -> None:
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"Invalid {label} timestamp ({value}): must be a finite positive epoch.")

    def calculate_dt(self, t0: float, t1: float) -> float:
        """Detection Time: DT = T1 - T0 in seconds."""
        self._validate_epoch(t0, "T0")
        self._validate_epoch(t1, "T1")
        if t1 < t0:
            raise ValueError(f"Detection timestamp T1 ({t1}) cannot precede fault injection T0 ({t0}).")
        return round(t1 - t0, 3)

    def calculate_ca2_rto(self, t0: float, t2: float) -> float:
        """Primary CA2 Recovery Time Objective: RTO = T2 - T0 in seconds (First successful transaction post-fault)."""
        self._validate_epoch(t0, "T0")
        self._validate_epoch(t2, "T2")
        if t2 < t0:
            raise ValueError(f"Recovery timestamp T2 ({t2}) cannot precede fault injection T0 ({t0}).")
        return round(t2 - t0, 3)

    def calculate_supplementary_restoration(
        self,
        baseline_tps: float,
        rolling_samples: List[Tuple[float, float]], # List of (timestamp_epoch, tps)
        t_clear: float,
        recovery_ratio_threshold: float = 0.90
    ) -> Optional[float]:
        """
        Supplementary Metric: Elapsed time from fault clearance until rolling TPS recovers to >= 90% baseline.
        """
        if baseline_tps <= 0:
            raise ValueError(f"Invalid baseline_tps ({baseline_tps}): must be > 0.")
        self._validate_epoch(t_clear, "T_clear")
        target_tps = baseline_tps * recovery_ratio_threshold
        for ts, tps in sorted(rolling_samples, key=lambda x: x[0]):
            if ts >= t_clear and tps >= target_tps:
                return round(ts - t_clear, 3)
        return None

    def reconcile_transactions(
        self,
        s0_history_count: int,
        s2_history_count: int,
        warmup_successful: int,
        measurement_tx_records: List[TransactionRecord]
    ) -> Dict[str, Any]:
        """
        Reconciles database history row delta against client logs:
        delta H == (s2_history - s0_history) == (warmup_successful + measurement_successful)
        """
        if s0_history_count < 0 or s2_history_count < s0_history_count or warmup_successful < 0:
            raise ValueError(
                f"Invalid history/warmup counts: s0={s0_history_count}, s2={s2_history_count}, warmup={warmup_successful}."
            )
        if not measurement_tx_records:
            return {
                "reconciled": False,
                "missing_transaction_records": True,
                "total_history_delta": s2_history_count - s0_history_count,
                "warmup_successful": warmup_successful,
                "expected_measurement_successful": (s2_history_count - s0_history_count) - warmup_successful,
                "logged_successful": 0,
                "logged_failed": 0,
                "total_measurement_attempted": 0,
                "discrepancy": abs((s2_history_count - s0_history_count) - warmup_successful),
            }

        for tx in measurement_tx_records:
            if tx.status not in ("ok", "failed"):
                raise ValueError(f"Invalid transaction status '{tx.status}' for tx_id={tx.tx_id}.")
            self._validate_epoch(tx.timestamp_epoch, f"tx[{tx.tx_id}].timestamp_epoch")

        total_history_delta = s2_history_count - s0_history_count
        logged_successful = sum(1 for tx in measurement_tx_records if tx.status == "ok")
        logged_failed = sum(1 for tx in measurement_tx_records if tx.status != "ok")
        total_measurement_attempted = len(measurement_tx_records)

        expected_measurement_delta = total_history_delta - warmup_successful
        reconciled = (expected_measurement_delta == logged_successful)

        return {
            "reconciled": reconciled,
            "missing_transaction_records": False,
            "total_history_delta": total_history_delta,
            "warmup_successful": warmup_successful,
            "expected_measurement_successful": expected_measurement_delta,
            "logged_successful": logged_successful,
            "logged_failed": logged_failed,
            "total_measurement_attempted": total_measurement_attempted,
            "discrepancy": abs(expected_measurement_delta - logged_successful)
        }

    def calculate_rpo(
        self,
        s0_history_count: int,
        s2_history_count: int,
        warmup_successful: int,
        measurement_tx_records: List[TransactionRecord]
    ) -> Dict[str, Any]:
        """
        Calculates Recovery Point Objective (RPO): committed transactions acknowledged to client
        that are missing from durable database history.
        Never infers RPO from history counts alone when client transaction records are missing.
        """
        recon = self.reconcile_transactions(
            s0_history_count, s2_history_count, warmup_successful, measurement_tx_records
        )
        if recon.get("missing_transaction_records"):
            return {
                "rpo_valid": False,
                "rpo_lost_transactions": None,
                "zero_data_loss": False,
                "reason": "Missing client transaction records; cannot infer RPO from history counts alone.",
                "reconciliation": recon,
            }
        committed_data_lost = max(0, recon["logged_successful"] - recon["expected_measurement_successful"])
        return {
            "rpo_valid": True,
            "rpo_lost_transactions": committed_data_lost,
            "zero_data_loss": (committed_data_lost == 0 and recon["reconciled"]),
            "reconciliation": recon,
        }

    def generate_sha256_manifest(self, file_paths: List[str], manifest_out_path: str) -> Dict[str, str]:
        """Calculates SHA-256 for all generated files and writes a CSV manifest."""
        manifest = {}
        rows = []
        for p in file_paths:
            if not os.path.exists(p):
                raise FileNotFoundError(f"Artifact for manifest does not exist: {p}")
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            sha = h.hexdigest().upper()
            manifest[os.path.basename(p)] = sha
            rows.append({
                "filename": os.path.basename(p),
                "bytes": os.path.getsize(p),
                "sha256": sha
            })

        os.makedirs(os.path.dirname(os.path.abspath(manifest_out_path)), exist_ok=True)
        with open(manifest_out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["filename", "bytes", "sha256"])
            writer.writeheader()
            writer.writerows(rows)

        return manifest

    @classmethod
    def parse_pgbench_log_lines(cls, lines: List[str]) -> List[TransactionRecord]:
        """
        Parses raw pgbench per-transaction log lines into TransactionRecord objects.
        Supports both:
          1. Standard PostgreSQL pgbench --log format (6 columns):
             client_id tx_id latency_us_or_status file_no time_epoch time_us
             where time_us is fractional microseconds (0..999999) and latency may be
             'skipped' or 'failed' under --max-tries=1.
          2. Synthetic test format (5 or 6 columns):
             client_id tx_id latency_us file_no timestamp_epoch [ok|failed]
        Rejects malformed lines, duplicate (client_id, tx_id) records, and non-monotonic
        per-client timestamps so corrupted logs never silently pass.
        """
        records: List[TransactionRecord] = []
        seen_keys = set()
        last_ts_by_client: Dict[int, float] = {}
        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 5:
                raise ValueError(f"Malformed pgbench log line {idx}: '{line}' (expected >= 5 columns).")
            try:
                client_id = int(parts[0])
                tx_id = int(parts[1])
                raw_latency = parts[2]
                if raw_latency in ("failed", "skipped"):
                    latency_us = 0
                    inferred_status = "failed"
                else:
                    latency_us = int(raw_latency)
                    inferred_status = "ok"
                base_epoch = float(parts[4])
            except ValueError as exc:
                raise ValueError(f"Malformed numeric field in pgbench log line {idx}: '{line}'.") from exc
            if latency_us < 0:
                raise ValueError(f"Negative latency_us ({latency_us}) in pgbench log line {idx}.")

            if len(parts) >= 6:
                col6 = parts[5]
                if col6 in ("ok", "failed"):
                    status = col6
                    timestamp_epoch = base_epoch
                else:
                    try:
                        time_us = int(col6)
                    except ValueError as exc:
                        raise ValueError(f"Invalid status or time_us '{col6}' in pgbench log line {idx}.") from exc
                    if time_us < 0 or time_us >= 1_000_000:
                        raise ValueError(f"Out-of-range time_us '{col6}' in pgbench log line {idx}.")
                    timestamp_epoch = int(base_epoch) + (time_us / 1_000_000.0)
                    status = inferred_status
            else:
                status = inferred_status
                timestamp_epoch = base_epoch

            cls._validate_epoch(timestamp_epoch, f"line[{idx}].timestamp_epoch")
            key = (client_id, tx_id)
            if key in seen_keys:
                raise ValueError(f"Duplicate transaction record (client_id={client_id}, tx_id={tx_id}) at line {idx}.")
            seen_keys.add(key)
            prev_ts = last_ts_by_client.get(client_id)
            if prev_ts is not None and timestamp_epoch < prev_ts:
                raise ValueError(
                    f"Non-monotonic timestamp for client_id={client_id} at line {idx}: "
                    f"{timestamp_epoch} < {prev_ts}."
                )
            last_ts_by_client[client_id] = timestamp_epoch
            if status not in ("ok", "failed"):
                raise ValueError(f"Invalid status '{status}' in pgbench log line {idx}.")
            records.append(TransactionRecord(client_id, tx_id, status, latency_us, timestamp_epoch))
        return records

    @staticmethod
    def calculate_tps(records: List[TransactionRecord], window_sec: float) -> float:
        """Calculates committed transactions per second over a positive measurement window."""
        if window_sec <= 0:
            raise ValueError(f"Invalid measurement window_sec={window_sec}: must be > 0.")
        ok_count = sum(1 for r in records if r.status == "ok")
        return round(ok_count / window_sec, 3)

    @staticmethod
    def calculate_latency_percentiles(records: List[TransactionRecord]) -> Dict[str, float]:
        """Calculates p50, p95, p99, and max latency in milliseconds over successful transactions."""
        latencies_ms = sorted(r.latency_us / 1000.0 for r in records if r.status == "ok")
        if not latencies_ms:
            raise ValueError("Cannot compute latency percentiles: no successful transactions recorded.")

        def _pct(p: float) -> float:
            k = max(0, min(len(latencies_ms) - 1, math.ceil(p * len(latencies_ms)) - 1))
            return round(latencies_ms[k], 3)

        return {
            "p50_ms": _pct(0.50),
            "p95_ms": _pct(0.95),
            "p99_ms": _pct(0.99),
            "max_ms": round(latencies_ms[-1], 3),
        }

    def validate_telemetry_completeness(
        self,
        required_fields: Tuple[str, ...] = ("cpu_pct", "memory_bytes", "network_tx_bytes", "disk_io_ops"),
    ) -> Dict[str, Any]:
        """Fails closed when Prometheus/node telemetry samples are missing or incomplete."""
        if not self.telemetry_samples:
            raise ValueError("Missing telemetry: zero telemetry samples ingested.")
        missing_fields = [
            field for field in required_fields
            if not any(field in sample for sample in self.telemetry_samples)
        ]
        if missing_fields:
            raise ValueError(f"Incomplete telemetry: missing required fields {missing_fields}.")
        return {"telemetry_complete": True, "sample_count": len(self.telemetry_samples)}


class UnwiredLivePrometheusAdapter:
    """Explicit placeholder marking live Prometheus HTTP ingestion as NOT IMPLEMENTED."""
    STATUS = "NOT IMPLEMENTED"

    def fetch_range(self, query: str, start_epoch: float, end_epoch: float) -> List[Dict[str, Any]]:
        raise NotImplementedError("Live Prometheus telemetry ingestion is NOT IMPLEMENTED in Phase F.2.1.")


class UnwiredLivePgbenchRunner:
    """Explicit placeholder marking live in-cluster pgbench workload runner as NOT IMPLEMENTED."""
    STATUS = "NOT IMPLEMENTED"

    def execute_workload(self, pod_name: str, max_tries: int = 1) -> str:
        raise NotImplementedError("Live in-cluster pgbench execution is NOT IMPLEMENTED in Phase F.2.1.")


