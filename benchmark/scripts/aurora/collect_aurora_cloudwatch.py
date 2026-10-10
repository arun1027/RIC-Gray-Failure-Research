#!/usr/bin/env python3
"""
AWS CloudWatch Infrastructure Telemetry Collector for Amazon Aurora PostgreSQL
Retrieves RDS CloudWatch metrics across writer, reader, and cluster for a given execution window.
Outputs structured JSON and CSV formats.
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime, timezone

METRIC_QUERIES = [
    # Primary Writer Metrics
    {"Id": "w_cpu", "Metric": "CPUUtilization", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_mem", "Metric": "FreeableMemory", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_conn", "Metric": "DatabaseConnections", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_net_rx", "Metric": "NetworkReceiveThroughput", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_net_tx", "Metric": "NetworkTransmitThroughput", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_write_bytes", "Metric": "WriteThroughput", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_read_bytes", "Metric": "ReadThroughput", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_write_lat", "Metric": "WriteLatency", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_buffer_hit", "Metric": "BufferCacheHitRatio", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_cpu_credits", "Metric": "CPUCreditBalance", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    {"Id": "w_cpu_usage", "Metric": "CPUCreditUsage", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-writer", "Stat": "Average"},
    
    # Standby Reader Metrics
    {"Id": "r_cpu", "Metric": "CPUUtilization", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-reader", "Stat": "Average"},
    {"Id": "r_mem", "Metric": "FreeableMemory", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-reader", "Stat": "Average"},
    {"Id": "r_conn", "Metric": "DatabaseConnections", "DimName": "DBInstanceIdentifier", "DimVal": "ric-gray-failure-aurora-reader", "Stat": "Average"},
    
    # Cluster Storage Metrics
    {"Id": "c_storage_bytes", "Metric": "VolumeBytesUsed", "DimName": "DBClusterIdentifier", "DimVal": "ric-gray-failure-aurora-cluster", "Stat": "Average"},
    {"Id": "c_storage_write_iops", "Metric": "VolumeWriteIOPs", "DimName": "DBClusterIdentifier", "DimVal": "ric-gray-failure-aurora-cluster", "Stat": "Average"},
    {"Id": "c_storage_read_iops", "Metric": "VolumeReadIOPs", "DimName": "DBClusterIdentifier", "DimVal": "ric-gray-failure-aurora-cluster", "Stat": "Average"},
]


def collect_cloudwatch_metrics(start_iso, end_iso, output_dir, run_id, timeline_file=None):
    """
    Queries CloudWatch get-metric-data for the specified time window.
    Saves raw JSON and tabular CSV with phase labelling and metadata.
    """
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, f"{run_id}-cloudwatch-metrics.json")
    csv_path = os.path.join(output_dir, f"{run_id}-cloudwatch-metrics.csv")

    phase_timeline = {}
    if timeline_file and os.path.exists(timeline_file):
        try:
            with open(timeline_file, "r", encoding="utf-8") as f:
                phase_timeline = json.load(f)
        except Exception as exc:
            print(f"[WARNING] Failed to load timeline file {timeline_file}: {exc}", file=sys.stderr)

    queries = []
    for q in METRIC_QUERIES:
        queries.append({
            "Id": q["Id"],
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/RDS",
                    "MetricName": q["Metric"],
                    "Dimensions": [{"Name": q["DimName"], "Value": q["DimVal"]}]
                },
                "Period": 60,
                "Stat": q["Stat"]
            },
            "ReturnData": True
        })

    cmd = [
        "aws", "cloudwatch", "get-metric-data",
        "--metric-data-queries", json.dumps(queries),
        "--start-time", start_iso,
        "--end-time", end_iso,
        "--output", "json"
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        raw_data = json.loads(res.stdout)
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] AWS CloudWatch query failed: {exc.stderr}", file=sys.stderr)
        err_payload = {
            "error": exc.stderr,
            "queried_window": {"start_iso": start_iso, "end_iso": end_iso},
            "metric_resolution": "60 seconds (1 minute)",
            "metric_resolution_note": "Standard AWS RDS CloudWatch metrics are aggregated at 60-second intervals; not 10-second data."
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(err_payload, f, indent=2)
        return False
    except Exception as exc:
        print(f"[ERROR] Failed to execute CloudWatch collection: {exc}", file=sys.stderr)
        return False

    # Structure final JSON payload with academic metadata
    final_payload = {
        "metadata": {
            "run_id": run_id,
            "metric_resolution": "60 seconds (1 minute)",
            "metric_resolution_note": "Standard AWS RDS CloudWatch metrics are aggregated at 60-second intervals; not 10-second data. Zero interpolation applied.",
            "queried_window": {"start_utc": start_iso, "end_utc": end_iso},
            "phase_timeline": phase_timeline
        },
        "MetricDataResults": raw_data.get("MetricDataResults", [])
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(final_payload, f, indent=2)

    # Helper to determine phase label for a given timestamp
    def get_phase_for_timestamp(ts_str):
        if not phase_timeline:
            return "overall_window"
        # Compare ISO strings
        m_start = phase_timeline.get("measurement_start_utc", "")
        m_end = phase_timeline.get("measurement_end_utc", "")
        w_start = phase_timeline.get("warmup_start_utc", "")
        w_end = phase_timeline.get("warmup_end_utc", "")
        r_start = phase_timeline.get("recovery_start_utc", "")
        r_end = phase_timeline.get("recovery_end_utc", "")

        if m_start and m_end and m_start <= ts_str <= m_end:
            return "measurement"
        if w_start and w_end and w_start <= ts_str <= w_end:
            return "warmup"
        if r_start and r_end and r_start <= ts_str <= r_end:
            return "recovery"
        return "transition"

    # Flatten MetricDataResults into tabular records by timestamp
    results_by_time = {}
    metric_labels = [q["Id"] for q in METRIC_QUERIES]

    for item in raw_data.get("MetricDataResults", []):
        m_id = item["Id"]
        timestamps = item.get("Timestamps", [])
        values = item.get("Values", [])
        for ts, val in zip(timestamps, values):
            if ts not in results_by_time:
                results_by_time[ts] = {lbl: "" for lbl in metric_labels}
            results_by_time[ts][m_id] = val

    sorted_times = sorted(results_by_time.keys())
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("timestamp_utc,inferred_phase," + ",".join(metric_labels) + "\n")
        for ts in sorted_times:
            phase_lbl = get_phase_for_timestamp(ts)
            row = [ts, phase_lbl] + [str(results_by_time[ts].get(lbl, "")) for lbl in metric_labels]
            f.write(",".join(row) + "\n")

    print(f"[SUCCESS] CloudWatch metrics saved: {json_path} and {csv_path}")
    print(f"[INFO] Retrieved {len(sorted_times)} distinct 1-minute metric timestamps.")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect Aurora CloudWatch metrics")
    parser.add_argument("--start", required=True, help="Start time in UTC ISO format (e.g. 2026-11-11T02:00:00Z)")
    parser.add_argument("--end", required=True, help="End time in UTC ISO format (e.g. 2026-11-11T02:15:00Z)")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--run-id", default="aurora-baseline-r01-aws", help="Run identifier")
    parser.add_argument("--timeline-file", default=None, help="Path to JSON file containing phase timeline timestamps")
    args = parser.parse_args()

    ok = collect_cloudwatch_metrics(args.start, args.end, args.output_dir, args.run_id, args.timeline_file)
    sys.exit(0 if ok else 1)

