"""
g1_prometheus_adapter.py - Testable Prometheus HTTP Telemetry Adapter for Scenario G1.

Design & Integrity:
- Replaces UnwiredLivePrometheusAdapter with an injectable HTTP & secret-provider interface.
- Enforces TLS verification, connect/response timeouts, HTTP status validation, JSON schema validation,
  missing-data detection (reported explicitly as 'NOT AVAILABLE'), duplicate timestamp detection,
  UTC timestamp normalization, sample interval validation, and secret redaction in raw responses.
- Never uses CPU requests (kube_pod_container_resource_requests) as actual CPU utilization.
- Documents every query's source and notes 'verified_on_cluster=False' because monitoring/ and
  kubernetes/monitoring/ currently contain no deployed Prometheus metric inventory in this repo.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import datetime
import json
import ssl
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request


class PrometheusAdapterError(Exception):
    """Raised on Prometheus HTTP, TLS, authentication, JSON, or sample-integrity failures."""
    pass


class ISecretProvider(ABC):
    """External secret provider interface so bearer tokens are never hardcoded or logged."""

    @abstractmethod
    def get_bearer_token(self) -> Optional[str]:
        pass


class MockSecretProvider(ISecretProvider):
    def __init__(self, token: Optional[str] = None):
        self._token = token

    def get_bearer_token(self) -> Optional[str]:
        return self._token


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    body: str
    headers: Dict[str, str]


class IHttpClient(ABC):
    @abstractmethod
    def get(
        self,
        url: str,
        headers: Dict[str, str],
        timeout_sec: float,
        verify_tls: bool,
    ) -> HttpResponse:
        pass


class MockHttpClient(IHttpClient):
    """Offline mock HTTP client recording requests and returning deterministic responses."""

    def __init__(self, handler: Optional[Callable[[str, Dict[str, str], float, bool], HttpResponse]] = None):
        self.requests: List[Dict[str, Any]] = []
        self._handler = handler

    def get(
        self,
        url: str,
        headers: Dict[str, str],
        timeout_sec: float,
        verify_tls: bool,
    ) -> HttpResponse:
        self.requests.append({
            "url": url,
            "headers": dict(headers),
            "timeout_sec": timeout_sec,
            "verify_tls": verify_tls,
        })
        if self._handler is not None:
            return self._handler(url, headers, timeout_sec, verify_tls)
        return HttpResponse(status_code=200, body='{"status":"success","data":{"resultType":"matrix","result":[]}}', headers={})


class UrllibHttpClient(IHttpClient):
    """Live HTTP client using Python stdlib urllib with strict TLS verification."""

    def get(
        self,
        url: str,
        headers: Dict[str, str],
        timeout_sec: float,
        verify_tls: bool,
    ) -> HttpResponse:
        if url.startswith("https://") and not verify_tls:
            raise PrometheusAdapterError("Refusing HTTPS request with verify_tls=False.")
        ctx = ssl.create_default_context() if url.startswith("https://") else None
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec, context=ctx) as resp:
                return HttpResponse(
                    status_code=resp.status,
                    body=resp.read().decode("utf-8"),
                    headers=dict(resp.headers),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(status_code=exc.code, body=exc.read().decode("utf-8", errors="replace"), headers={})
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PrometheusAdapterError(f"Prometheus HTTP request failed or timed out: {exc}") from exc


@dataclass(frozen=True)
class PrometheusQueryDefinition:
    metric_key: str
    promql: str
    source: str
    semantics: str
    units: str = "unknown"
    aggregation: str = "raw"
    sampling_interval_sec: int = 5
    expected_labels: Tuple[str, ...] = ("namespace", "pod")
    missing_data_behavior: str = "Report NOT AVAILABLE; never substitute CPU requests or synthetic values."
    verification_status: str = "UNVERIFIED"
    verified_on_cluster: bool = False  # Must remain False until verified against live Prometheus /api/v1/label/__name__/values


def build_g1_metric_queries(namespace: str = "cockroachdb", pod_regex: str = "cockroachdb-[0-2]") -> Dict[str, PrometheusQueryDefinition]:
    """
    Standard cAdvisor / kubelet & CockroachDB metric definitions.
    NOTE: verified_on_cluster=False because monitoring/ in this repo is currently empty;
    live target endpoint must confirm metric availability before N=1.
    """
    return {
        "cpu_utilization_cores": PrometheusQueryDefinition(
            metric_key="cpu_utilization_cores",
            promql=f'rate(container_cpu_usage_seconds_total{{namespace="{namespace}",pod=~"{pod_regex}",container="cockroachdb"}}[1m])',
            source="kubelet/cAdvisor (actual CPU usage rate, NOT CPU requests)",
            semantics="Actual CPU cores consumed per second over 1m rate window.",
        ),
        "memory_working_set_bytes": PrometheusQueryDefinition(
            metric_key="memory_working_set_bytes",
            promql=f'container_memory_working_set_bytes{{namespace="{namespace}",pod=~"{pod_regex}",container="cockroachdb"}}',
            source="kubelet/cAdvisor",
            semantics="Container working set memory in bytes.",
        ),
        "network_receive_bytes_per_sec": PrometheusQueryDefinition(
            metric_key="network_receive_bytes_per_sec",
            promql=f'rate(container_network_receive_bytes_total{{namespace="{namespace}",pod=~"{pod_regex}"}}[1m])',
            source="kubelet/cAdvisor",
            semantics="Pod network receive rate in bytes/sec.",
        ),
        "network_transmit_bytes_per_sec": PrometheusQueryDefinition(
            metric_key="network_transmit_bytes_per_sec",
            promql=f'rate(container_network_transmit_bytes_total{{namespace="{namespace}",pod=~"{pod_regex}"}}[1m])',
            source="kubelet/cAdvisor",
            semantics="Pod network transmit rate in bytes/sec.",
        ),
        "disk_read_bytes_per_sec": PrometheusQueryDefinition(
            metric_key="disk_read_bytes_per_sec",
            promql=f'rate(container_fs_reads_bytes_total{{namespace="{namespace}",pod=~"{pod_regex}",container="cockroachdb"}}[1m])',
            source="kubelet/cAdvisor",
            semantics="Filesystem read throughput in bytes/sec.",
        ),
        "disk_write_bytes_per_sec": PrometheusQueryDefinition(
            metric_key="disk_write_bytes_per_sec",
            promql=f'rate(container_fs_writes_bytes_total{{namespace="{namespace}",pod=~"{pod_regex}",container="cockroachdb"}}[1m])',
            source="kubelet/cAdvisor",
            semantics="Filesystem write throughput in bytes/sec.",
        ),
        "disk_read_ops_per_sec": PrometheusQueryDefinition(
            metric_key="disk_read_ops_per_sec",
            promql=f'rate(container_fs_reads_total{{namespace="{namespace}",pod=~"{pod_regex}",container="cockroachdb"}}[1m])',
            source="kubelet/cAdvisor",
            semantics="Filesystem read IOPS.",
        ),
        "disk_write_ops_per_sec": PrometheusQueryDefinition(
            metric_key="disk_write_ops_per_sec",
            promql=f'rate(container_fs_writes_total{{namespace="{namespace}",pod=~"{pod_regex}",container="cockroachdb"}}[1m])',
            source="kubelet/cAdvisor",
            semantics="Filesystem write IOPS.",
        ),
        "cpu_throttled_periods_per_sec": PrometheusQueryDefinition(
            metric_key="cpu_throttled_periods_per_sec",
            promql=f'rate(container_cpu_cfs_throttled_periods_total{{namespace="{namespace}",pod=~"{pod_regex}",container="cockroachdb"}}[1m])',
            source="kubelet/cAdvisor",
            semantics="CFS CPU throttling periods/sec.",
        ),
        "cockroachdb_live_nodes": PrometheusQueryDefinition(
            metric_key="cockroachdb_live_nodes",
            promql='liveness_livenodes{job=~".*cockroach.*"}',
            source="CockroachDB /_status/vars (values-default.yaml ServiceMonitor)",
            semantics="Number of live CockroachDB nodes reported by cluster liveness.",
        ),
    }


class LivePrometheusAdapter:
    """Testable HTTP client for Prometheus /api/v1/query_range."""

    def __init__(
        self,
        base_url: str,
        http_client: IHttpClient,
        secret_provider: Optional[ISecretProvider] = None,
        timeout_sec: float = 10.0,
        verify_tls: bool = True,
        expected_step_sec: int = 5,
    ):
        self.base_url = base_url.rstrip("/")
        self.http_client = http_client
        self.secret_provider = secret_provider
        self.timeout_sec = timeout_sec
        self.verify_tls = verify_tls
        self.expected_step_sec = expected_step_sec

    @staticmethod
    def redact_secrets(text: str, token: Optional[str]) -> str:
        if token and token in text:
            return text.replace(token, "[REDACTED]")
        return text

    def query_range(
        self,
        promql: str,
        start_epoch: float,
        end_epoch: float,
        step_sec: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not self.verify_tls:
            raise PrometheusAdapterError("TLS verification cannot be disabled (verify_tls=False rejected).")
        if end_epoch <= start_epoch:
            raise PrometheusAdapterError(f"Invalid query range: end_epoch ({end_epoch}) <= start_epoch ({start_epoch}).")
        if "kube_pod_container_resource_requests" in promql:
            raise PrometheusAdapterError("Refusing query using CPU requests as CPU utilization.")

        step = step_sec or self.expected_step_sec
        params = urllib.parse.urlencode({
            "query": promql,
            "start": str(start_epoch),
            "end": str(end_epoch),
            "step": f"{step}s",
        })
        url = f"{self.base_url}/api/v1/query_range?{params}"

        headers: Dict[str, str] = {"Accept": "application/json"}
        token = self.secret_provider.get_bearer_token() if self.secret_provider else None
        if token:
            headers["Authorization"] = f"Bearer {token}"

        resp = self.http_client.get(url, headers=headers, timeout_sec=self.timeout_sec, verify_tls=self.verify_tls)
        redacted_body = self.redact_secrets(resp.body, token)

        if resp.status_code in (401, 403):
            raise PrometheusAdapterError(f"Prometheus authentication/authorization failed (HTTP {resp.status_code}).")
        if resp.status_code != 200:
            raise PrometheusAdapterError(f"Prometheus query_range failed with HTTP {resp.status_code}: {redacted_body}")

        try:
            payload = json.loads(resp.body)
        except json.JSONDecodeError as exc:
            raise PrometheusAdapterError(f"Invalid JSON returned by Prometheus: {exc}") from exc

        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise PrometheusAdapterError(f"Prometheus API returned non-success status: {payload}")

        data = payload.get("data", {})
        if data.get("resultType") != "matrix" or not isinstance(data.get("result"), list):
            raise PrometheusAdapterError(f"Unexpected Prometheus resultType/format: {data}")

        results = data["result"]
        if not results:
            return {
                "status": "NOT AVAILABLE",
                "promql": promql,
                "series": [],
                "raw_redacted": redacted_body,
            }

        normalized_series: List[Dict[str, Any]] = []
        for series in results:
            values = series.get("values", [])
            if not values:
                continue
            seen_ts = set()
            prev_ts: Optional[float] = None
            samples: List[Dict[str, Any]] = []
            for raw_ts, raw_val in values:
                ts = float(raw_ts)
                if ts in seen_ts:
                    raise PrometheusAdapterError(f"Duplicate timestamp {ts} detected in Prometheus series.")
                seen_ts.add(ts)
                if prev_ts is not None and round(ts - prev_ts, 3) != float(step):
                    raise PrometheusAdapterError(
                        f"Sample interval mismatch: expected {step}s, observed {round(ts - prev_ts, 3)}s."
                    )
                prev_ts = ts
                utc_iso = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
                samples.append({
                    "timestamp_epoch": ts,
                    "timestamp_utc": utc_iso,
                    "value": float(raw_val),
                })
            normalized_series.append({
                "metric": series.get("metric", {}),
                "samples": samples,
            })

        if not normalized_series:
            return {
                "status": "NOT AVAILABLE",
                "promql": promql,
                "series": [],
                "raw_redacted": redacted_body,
            }

        return {
            "status": "AVAILABLE",
            "promql": promql,
            "series": normalized_series,
            "raw_redacted": redacted_body,
        }

