"""
g1_pgbench_runner.py - Live pgbench Workload Runner & Evidence Retrieval Interface for Scenario G1.

Workstream 5 Remediation:
- Replaces empty raw_log_lines=[] in SubprocessPgbenchExecutor with IPgbenchLogRetriever
  (KubectlCatLogRetriever for live pod log retrieval, MockPgbenchLogRetriever for offline tests).
- Preserves raw log text, records source path, UTC timestamps, exit status, and SHA-256 hash.
- Rejects missing, duplicate, malformed, or incomplete records and reconciles parsed transactions
  against pgbench stdout transaction counts (never inferring from unrelated history counts).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import datetime
import hashlib
import re
import subprocess
from typing import Callable, List, Optional

from .g1_evidence_collector import G1EvidenceCollector, TransactionRecord


class PgbenchRunnerError(Exception):
    """Raised when pgbench configuration, execution, log retrieval, or reconciliation fails."""
    pass


@dataclass(frozen=True)
class PgbenchConfig:
    """Approved CA2/G1 pgbench execution configuration."""
    client_pod_name: str = "crdb-benchmark-client"
    namespace: str = "cockroachdb"
    database: str = "benchdb"
    host: str = "cockroachdb-public.cockroachdb.svc.cluster.local"
    port: int = 26257
    user: str = "root"
    clients: int = 20
    threads: int = 4
    warmup_sec: int = 120
    measurement_sec: int = 600
    observation_sec: int = 300
    max_tries: int = 1
    simple_query: bool = True

    def validate(self) -> None:
        if self.clients != 20 or self.threads != 4:
            raise PgbenchRunnerError(
                f"Unapproved concurrency (clients={self.clients}, threads={self.threads}): CA2 requires 20 clients, 4 threads."
            )
        if self.warmup_sec != 120 or self.measurement_sec != 600 or self.observation_sec != 300:
            raise PgbenchRunnerError(
                f"Unapproved phase durations (warmup={self.warmup_sec}, measurement={self.measurement_sec}, "
                f"observation={self.observation_sec}): CA2 requires 120s / 600s / 300s."
            )
        if self.max_tries != 1:
            raise PgbenchRunnerError(
                f"Unapproved max_tries={self.max_tries}: CA2/G1 requires --max-tries=1 (no automatic tx retry)."
            )
        if not self.simple_query:
            raise PgbenchRunnerError("Simple-query protocol (-n / -M simple) must be preserved.")


@dataclass(frozen=True)
class RetrievedLogEvidence:
    """Raw per-transaction log evidence retrieved from the benchmark client."""
    source_path: str
    raw_lines: List[str]
    sha256_hex: str
    retrieved_utc: str


class IPgbenchLogRetriever(ABC):
    """Interface for retrieving raw per-transaction pgbench log files from the client pod."""

    @abstractmethod
    def retrieve_logs(self, namespace: str, pod_name: str, log_prefix: str) -> RetrievedLogEvidence:
        pass


class MockPgbenchLogRetriever(IPgbenchLogRetriever):
    def __init__(self, lines: Optional[List[str]] = None, fail_missing: bool = False):
        self._lines = lines if lines is not None else []
        self.fail_missing = fail_missing

    def retrieve_logs(self, namespace: str, pod_name: str, log_prefix: str) -> RetrievedLogEvidence:
        if self.fail_missing:
            raise PgbenchRunnerError(f"Mock log retrieval failed: '{log_prefix}*' not found on {namespace}/{pod_name}.")
        raw_bytes = "\n".join(self._lines).encode("utf-8")
        return RetrievedLogEvidence(
            source_path=f"k8s://{namespace}/{pod_name}:{log_prefix}*",
            raw_lines=list(self._lines),
            sha256_hex=hashlib.sha256(raw_bytes).hexdigest().upper(),
            retrieved_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )


class KubectlCatLogRetriever(IPgbenchLogRetriever):
    """Live log retriever reading pgbench per-thread log files from the client pod."""

    def retrieve_logs(self, namespace: str, pod_name: str, log_prefix: str) -> RetrievedLogEvidence:
        cmd = [
            "kubectl", "exec", "-n", namespace, pod_name, "--",
            "/bin/sh", "-c", f'cat "{log_prefix}"*',
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if proc.returncode != 0:
            raise PgbenchRunnerError(
                f"Failed to retrieve pgbench logs from {namespace}/{pod_name}:{log_prefix}*: {proc.stderr}"
            )
        lines = proc.stdout.splitlines()
        sha = hashlib.sha256(proc.stdout.encode("utf-8")).hexdigest().upper()
        return RetrievedLogEvidence(
            source_path=f"k8s://{namespace}/{pod_name}:{log_prefix}*",
            raw_lines=lines,
            sha256_hex=sha,
            retrieved_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )


@dataclass(frozen=True)
class PgbenchProcessOutput:
    """Raw output from an executed pgbench command."""
    exit_code: int
    stdout: str
    stderr: str
    raw_log_lines: List[str] = field(default_factory=list)
    log_sha256: str = ""
    log_source: str = ""
    timed_out: bool = False
    cancelled: bool = False


@dataclass(frozen=True)
class PgbenchRunResult:
    """Structured result of a single pgbench phase run."""
    phase: str
    command_argv: List[str]
    exit_code: int
    stdout: str
    stderr: str
    raw_log_lines: List[str]
    parsed_records: List[TransactionRecord]
    log_sha256: str
    log_source: str
    started_utc: str
    ended_utc: str
    timed_out: bool
    cancelled: bool
    complete: bool


class IPgbenchProcessExecutor(ABC):
    """Injectable process execution interface for offline testing vs. live kubectl exec."""

    @abstractmethod
    def run(self, argv: List[str], timeout_sec: int, log_path: str) -> PgbenchProcessOutput:
        pass


class MockPgbenchProcessExecutor(IPgbenchProcessExecutor):
    """Offline mock executor for unit tests."""

    def __init__(self, handler: Optional[Callable[[List[str], int, str], PgbenchProcessOutput]] = None):
        self.recorded_commands: List[List[str]] = []
        self._handler = handler

    def run(self, argv: List[str], timeout_sec: int, log_path: str) -> PgbenchProcessOutput:
        self.recorded_commands.append(list(argv))
        if self._handler is not None:
            return self._handler(argv, timeout_sec, log_path)
        return PgbenchProcessOutput(exit_code=0, stdout="tps = 100.0", stderr="", raw_log_lines=[])


class SubprocessPgbenchExecutor(IPgbenchProcessExecutor):
    """Live executor invoking kubectl exec and retrieving raw logs via IPgbenchLogRetriever."""

    def __init__(self, namespace: str, pod_name: str, log_retriever: IPgbenchLogRetriever):
        self.namespace = namespace
        self.pod_name = pod_name
        self.log_retriever = log_retriever

    def run(self, argv: List[str], timeout_sec: int, log_path: str) -> PgbenchProcessOutput:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_sec, check=False)
        except subprocess.TimeoutExpired as exc:
            return PgbenchProcessOutput(
                exit_code=-1,
                stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
                stderr=f"Process timed out after {timeout_sec}s.",
                raw_log_lines=[],
                timed_out=True,
            )

        retrieved = self.log_retriever.retrieve_logs(self.namespace, self.pod_name, log_path)
        return PgbenchProcessOutput(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            raw_log_lines=retrieved.raw_lines,
            log_sha256=retrieved.sha256_hex,
            log_source=retrieved.source_path,
        )


class LivePgbenchRunner:
    """
    Production-oriented, testable pgbench runner.
    Builds safe non-destructive commands, retrieves raw logs, validates & reconciles records,
    and fails closed on incomplete logs or process failures.
    """

    FORBIDDEN_FLAGS = ("-i", "--initialize", "truncate", "PGPASSWORD")
    TX_COUNT_RE = re.compile(r"number of transactions actually processed:\s*(\d+)")

    def __init__(self, config: PgbenchConfig, executor: IPgbenchProcessExecutor):
        self.config = config
        self.config.validate()
        self.executor = executor

    def build_command(self, phase: str, duration_sec: int, log_path: str) -> List[str]:
        if phase not in ("warmup", "measurement", "observation"):
            raise PgbenchRunnerError(f"Unsupported pgbench phase '{phase}'.")
        if duration_sec <= 0:
            raise PgbenchRunnerError(f"Invalid duration_sec={duration_sec}: must be > 0.")

        argv = [
            "kubectl", "exec", "-n", self.config.namespace, self.config.client_pod_name, "--",
            "pgbench",
            "-h", self.config.host,
            "-p", str(self.config.port),
            "-U", self.config.user,
            "-n",
            "-c", str(self.config.clients),
            "-j", str(self.config.threads),
            "-T", str(duration_sec),
            f"--max-tries={self.config.max_tries}",
            "--log", f"--log-prefix={log_path}",
            self.config.database,
        ]
        joined = " ".join(argv)
        for forbidden in self.FORBIDDEN_FLAGS:
            if forbidden in argv or (forbidden == "PGPASSWORD" and forbidden in joined):
                raise PgbenchRunnerError(f"Forbidden flag or secret token '{forbidden}' detected in pgbench command.")
        return argv

    def run_phase(self, phase: str, log_path: str, timeout_grace_sec: int = 30) -> PgbenchRunResult:
        self.config.validate()
        duration_map = {
            "warmup": self.config.warmup_sec,
            "measurement": self.config.measurement_sec,
            "observation": self.config.observation_sec,
        }
        if phase not in duration_map:
            raise PgbenchRunnerError(f"Unsupported pgbench phase '{phase}'.")

        duration_sec = duration_map[phase]
        argv = self.build_command(phase, duration_sec, log_path)
        started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            out = self.executor.run(argv, timeout_sec=duration_sec + timeout_grace_sec, log_path=log_path)
        except KeyboardInterrupt:
            ended_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
            raise PgbenchRunnerError(f"pgbench phase '{phase}' cancelled by operator/interrupt at {ended_utc}.")

        ended_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if out.timed_out:
            raise PgbenchRunnerError(f"pgbench phase '{phase}' timed out; refusing incomplete results.")
        if out.cancelled:
            raise PgbenchRunnerError(f"pgbench phase '{phase}' cancelled; refusing incomplete results.")
        if out.exit_code != 0:
            raise PgbenchRunnerError(
                f"pgbench phase '{phase}' exited with non-zero code {out.exit_code}: {out.stderr}"
            )
        if not out.raw_log_lines:
            raise PgbenchRunnerError(
                f"pgbench phase '{phase}' produced zero per-transaction log lines; refusing empty/incomplete log."
            )

        try:
            parsed_records = G1EvidenceCollector.parse_pgbench_log_lines(out.raw_log_lines)
        except ValueError as exc:
            raise PgbenchRunnerError(f"Malformed/duplicate pgbench log records: {exc}") from exc

        match = self.TX_COUNT_RE.search(out.stdout)
        if match:
            reported_tx = int(match.group(1))
            if reported_tx != len(parsed_records):
                raise PgbenchRunnerError(
                    f"pgbench stdout reported {reported_tx} transactions, but parsed {len(parsed_records)} records."
                )

        raw_sha = out.log_sha256 or hashlib.sha256("\n".join(out.raw_log_lines).encode("utf-8")).hexdigest().upper()

        return PgbenchRunResult(
            phase=phase,
            command_argv=argv,
            exit_code=out.exit_code,
            stdout=out.stdout,
            stderr=out.stderr,
            raw_log_lines=out.raw_log_lines,
            parsed_records=parsed_records,
            log_sha256=raw_sha,
            log_source=out.log_source or log_path,
            started_utc=started_utc,
            ended_utc=ended_utc,
            timed_out=False,
            cancelled=False,
            complete=True,
        )
