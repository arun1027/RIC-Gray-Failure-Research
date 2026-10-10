"""
Unified pgbench Transaction Log Parser & Percentile Calculator
Shared across CockroachDB, PostgreSQL Patroni, and Amazon Aurora PostgreSQL.

Mathematical Method: Nearest-Rank Percentile Method
Percentile calculation:
  For ordinal rank k = ceil(P/100 * N):
  index = max(0, min(k - 1, N - 1))
  percentile_value = sorted_latencies[index]

Units:
  Input in log files: microseconds (us)
  Reported output: milliseconds (ms), rounded to 3 decimal places (microsecond resolution).

Fail-Closed Safeguards:
  - If log directory or files are missing: returns ok=False, metrics unavailable (None / 0.0).
  - If logs are truncated (missing final newline) or malformed: returns ok=False.
  - If records do not reconcile with pgbench summary totals: returns ok=False.
  - Zero transaction records: returns ok=False, metrics unavailable.
"""

import os
import glob
import re
import math

PGBENCH_LOG_FIELDS = 6
PGBENCH_LOG_FIELDS_WITH_RETRIES = 7


def _is_uint(token):
    return token.isascii() and token.isdigit()


def calculate_nearest_rank_percentile(sorted_values, percentile):
    """
    Computes the nearest-rank percentile value from a sorted list of numeric values.
    percentile is a float between 0.0 and 100.0 (e.g. 95.0, 99.0).
    """
    if not sorted_values:
        return None
    n = len(sorted_values)
    k = int(math.ceil((percentile / 100.0) * n))
    idx = max(0, min(k - 1, n - 1))
    return sorted_values[idx]


def analyze_pgbench_logs(log_dir, prefix, expected_files=None, expected_clients=None,
                          expected_transactions=None, expected_failed=None,
                          expected_retries=None, expected_retried_transactions=None):
    """
    Validates pgbench per-transaction logs (-l) and computes nearest-rank p95 and p99
    only when evidence is strictly complete and reconciled.

    Returns dict with keys:
      ok: bool
      errors: list of error strings
      files: list of log filenames
      numeric_records: int
      failed_records: int
      skipped_records: int
      retried_records: int
      total_retries: int
      malformed_records: int
      client_ids: list of int
      p95_ms: float (or 0.0 if not ok)
      p99_ms: float (or 0.0 if not ok)
      reconciled: bool
    """
    result = {
        "ok": False,
        "errors": [],
        "files": [],
        "numeric_records": 0,
        "failed_records": 0,
        "skipped_records": 0,
        "retried_records": 0,
        "total_retries": 0,
        "malformed_records": 0,
        "unreadable_files": [],
        "client_ids": [],
        "p50_ms": 0.0,
        "p95_ms": 0.0,
        "p99_ms": 0.0,
        "reconciled": False,
    }
    errors = result["errors"]

    if not os.path.isdir(log_dir):
        errors.append(f"transaction log directory missing: {log_dir}")
        return result

    name_re = re.compile(r"^" + re.escape(prefix) + r"\.(\d+)(?:\.(\d+))?$")
    names = sorted(os.path.basename(p) for p in glob.glob(os.path.join(log_dir, f"{prefix}.*")))
    result["files"] = names
    if not names:
        errors.append("no transaction log files found")
        return result

    pids = set()
    thread_indexes = []
    bad_names = 0
    for n in names:
        m = name_re.match(n)
        if not m:
            errors.append(f"unexpected log file name '{n}'")
            bad_names += 1
            continue
        pids.add(m.group(1))
        thread_indexes.append(int(m.group(2)) if m.group(2) is not None else 0)

    if expected_files is not None:
        if len(names) != expected_files:
            errors.append(f"expected {expected_files} per-thread log files, found {len(names)}: {names}")
        elif bad_names == 0 and (len(pids) != 1 or sorted(thread_indexes) != list(range(expected_files))):
            errors.append(
                f"per-thread log file set is inconsistent (pids={sorted(pids)}, thread indexes={sorted(thread_indexes)}, "
                f"expected indexes 0..{expected_files - 1})"
            )

    latencies_us = []
    client_ids = set()
    expected_row_fields = None
    for n in names:
        path = os.path.join(log_dir, n)
        try:
            with open(path, "rb") as f:
                raw_bytes = f.read()
        except OSError as exc:
            result["unreadable_files"].append(n)
            errors.append(f"cannot read log file '{n}': {exc}")
            continue
        if not raw_bytes:
            errors.append(f"log file '{n}' is empty")
            continue
        if not raw_bytes.endswith(b"\n"):
            errors.append(f"log file '{n}' is truncated (no final newline)")
        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"log file '{n}' is not valid UTF-8")
            result["malformed_records"] += 1
            continue

        for lineno, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            parts = line.split()
            row_ok = False
            if (len(parts) in (PGBENCH_LOG_FIELDS, PGBENCH_LOG_FIELDS_WITH_RETRIES)
                    and (expected_row_fields is None or len(parts) == expected_row_fields)
                    and all(_is_uint(parts[i]) for i in (0, 1, 3, 4, 5))
                    and (len(parts) == PGBENCH_LOG_FIELDS or _is_uint(parts[6]))):
                token = parts[2]
                if _is_uint(token) and int(token) > 0:
                    latencies_us.append(int(token))
                    result["numeric_records"] += 1
                    row_ok = True
                elif token == "failed":
                    result["failed_records"] += 1
                    row_ok = True
                elif token == "skipped":
                    result["skipped_records"] += 1
                    row_ok = True
            if row_ok:
                if expected_row_fields is None:
                    expected_row_fields = len(parts)
                client_ids.add(int(parts[0]))
                if len(parts) == PGBENCH_LOG_FIELDS_WITH_RETRIES:
                    r_cnt = int(parts[6])
                    result["total_retries"] += r_cnt
                    if r_cnt > 0:
                        result["retried_records"] += 1
            else:
                result["malformed_records"] += 1
                if result["malformed_records"] <= 3:
                    errors.append(f"malformed row in '{n}' line {lineno}: {line[:80]!r}")

    result["client_ids"] = sorted(client_ids)
    if result["malformed_records"]:
        errors.append(f"{result['malformed_records']} malformed row(s)/file(s) in transaction logs (rows are never skipped)")
    if result["skipped_records"]:
        errors.append(f"{result['skipped_records']} 'skipped' row(s) found; not expected for this workload")
    if result["numeric_records"] == 0:
        errors.append("no valid transaction latency records")

    if expected_clients is not None:
        expected_set = set(range(expected_clients))
        missing = sorted(expected_set - client_ids)
        extra = sorted(client_ids - expected_set)
        if missing or extra:
            errors.append(f"client ids in logs differ from expected 0..{expected_clients - 1} (missing={missing}, unexpected={extra})")

    if expected_transactions is not None and result["numeric_records"] != expected_transactions:
        errors.append(
            f"valid latency records ({result['numeric_records']}) != pgbench transactions processed ({expected_transactions})"
        )
    if expected_failed is not None and result["failed_records"] != expected_failed:
        errors.append(
            f"'failed' rows ({result['failed_records']}) != pgbench failed transactions ({expected_failed})"
        )
    if expected_retries is not None and result["total_retries"] != expected_retries:
        errors.append(
            f"logged total retries ({result['total_retries']}) != pgbench total number of retries ({expected_retries})"
        )
    if expected_retried_transactions is not None and result["retried_records"] != expected_retried_transactions:
        errors.append(
            f"logged retried transactions ({result['retried_records']}) != pgbench transactions retried ({expected_retried_transactions})"
        )
    result["reconciled"] = expected_transactions is not None and expected_failed is not None

    if not errors and latencies_us:
        latencies_us.sort()
        p50_us = calculate_nearest_rank_percentile(latencies_us, 50.0)
        p95_us = calculate_nearest_rank_percentile(latencies_us, 95.0)
        p99_us = calculate_nearest_rank_percentile(latencies_us, 99.0)
        result["p50_ms"] = round(p50_us / 1000.0, 3) if p50_us is not None else 0.0
        result["p95_ms"] = round(p95_us / 1000.0, 3) if p95_us is not None else 0.0
        result["p99_ms"] = round(p99_us / 1000.0, 3) if p99_us is not None else 0.0
        result["ok"] = True
    return result


def parse_percentiles_from_log_files(log_dir, prefix, expected_files=None, expected_clients=None,
                                     expected_transactions=None, expected_failed=None,
                                     expected_retries=None, expected_retried_transactions=None):
    """
    Calculates nearest-rank p50, p95 and p99 (ms) from per-transaction pgbench logs.
    Returns dict: {"p50_ms": float, "p95_ms": float, "p99_ms": float, "ok": bool, "errors": list}.
    Returns 0.0 (never an unverified estimate) when logs are missing, malformed, or fail reconciliation.
    """
    analysis = analyze_pgbench_logs(
        log_dir, prefix,
        expected_files=expected_files, expected_clients=expected_clients,
        expected_transactions=expected_transactions, expected_failed=expected_failed,
        expected_retries=expected_retries,
        expected_retried_transactions=expected_retried_transactions,
    )
    return {
        "p50_ms": analysis.get("p50_ms", 0.0),
        "p95_ms": analysis["p95_ms"],
        "p99_ms": analysis["p99_ms"],
        "ok": analysis["ok"],
        "errors": analysis["errors"],
    }

