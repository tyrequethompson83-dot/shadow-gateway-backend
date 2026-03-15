import threading
from collections import defaultdict
from typing import Dict, Iterable


LATENCY_BUCKETS_MS = [10, 25, 50, 100, 250, 500, 1000, 2000, 5000]


class MetricsStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests_total = defaultdict(int)  # (tenant, action, provider) -> count
        self._redactions_total = defaultdict(int)  # category -> count
        self._upstream_errors_total = defaultdict(int)  # (provider, status) -> count
        self._upstream_latency_count = defaultdict(int)  # provider -> count
        self._upstream_latency_sum = defaultdict(float)  # provider -> sum ms
        self._upstream_latency_buckets = defaultdict(lambda: defaultdict(int))  # provider -> bucket -> count

    def inc_request(self, *, tenant_id: int, action: str, provider: str) -> None:
        key = (str(int(tenant_id)), str(action), str(provider))
        with self._lock:
            self._requests_total[key] += 1

    def inc_redaction(self, category: str, delta: int = 1) -> None:
        c = str(category)
        d = max(0, int(delta))
        if not c or d <= 0:
            return
        with self._lock:
            self._redactions_total[c] += d

    def observe_latency_ms(self, *, provider: str, latency_ms: float) -> None:
        p = str(provider)
        value = max(0.0, float(latency_ms))
        with self._lock:
            self._upstream_latency_count[p] += 1
            self._upstream_latency_sum[p] += value
            for bucket in LATENCY_BUCKETS_MS:
                if value <= bucket:
                    self._upstream_latency_buckets[p][bucket] += 1
            self._upstream_latency_buckets[p]["+Inf"] += 1

    def inc_upstream_error(self, *, provider: str, status: int) -> None:
        key = (str(provider), str(int(status)))
        with self._lock:
            self._upstream_errors_total[key] += 1

    def render_prometheus(self) -> str:
        lines: list[str] = []
        with self._lock:
            lines.append("# HELP requests_total Total gateway chat requests")
            lines.append("# TYPE requests_total counter")
            for (tenant, action, provider), value in sorted(self._requests_total.items()):
                lines.append(
                    f'requests_total{{tenant="{tenant}",action="{action}",provider="{provider}"}} {value}'
                )

            lines.append("# HELP redactions_total Total redactions by category")
            lines.append("# TYPE redactions_total counter")
            for category, value in sorted(self._redactions_total.items()):
                lines.append(f'redactions_total{{category="{category}"}} {value}')

            lines.append("# HELP upstream_errors_total Total upstream call errors")
            lines.append("# TYPE upstream_errors_total counter")
            for (provider, status), value in sorted(self._upstream_errors_total.items()):
                lines.append(f'upstream_errors_total{{provider="{provider}",status="{status}"}} {value}')

            lines.append("# HELP upstream_latency_ms Upstream latency histogram in milliseconds")
            lines.append("# TYPE upstream_latency_ms histogram")
            for provider in sorted(set(self._upstream_latency_count.keys()) | set(self._upstream_latency_buckets.keys())):
                buckets = self._upstream_latency_buckets.get(provider, {})
                for bucket in LATENCY_BUCKETS_MS:
                    count = int(buckets.get(bucket, 0))
                    lines.append(
                        f'upstream_latency_ms_bucket{{provider="{provider}",le="{bucket}"}} {count}'
                    )
                lines.append(
                    f'upstream_latency_ms_bucket{{provider="{provider}",le="+Inf"}} {int(buckets.get("+Inf", 0))}'
                )
                lines.append(f'upstream_latency_ms_sum{{provider="{provider}"}} {self._upstream_latency_sum.get(provider, 0.0)}')
                lines.append(f'upstream_latency_ms_count{{provider="{provider}"}} {self._upstream_latency_count.get(provider, 0)}')
        return "\n".join(lines) + "\n"


METRICS = MetricsStore()
