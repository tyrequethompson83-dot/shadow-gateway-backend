import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Protocol

from fastapi import HTTPException, Request


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int
    remaining: int


class RateLimiterBackend(Protocol):
    def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
        ...


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = {}

    def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
        now = time.time()
        window = max(1, int(window_seconds))
        cap = max(1, int(limit))

        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            while bucket and bucket[0] <= now - window:
                bucket.popleft()
            if len(bucket) >= cap:
                retry_after = max(1, int(window - (now - bucket[0])))
                return RateLimitDecision(allowed=False, retry_after_seconds=retry_after, remaining=0)
            bucket.append(now)
            remaining = max(0, cap - len(bucket))
            return RateLimitDecision(allowed=True, retry_after_seconds=0, remaining=remaining)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


_backend: RateLimiterBackend = InMemoryRateLimiter()


def set_rate_limiter_backend(backend: RateLimiterBackend) -> None:
    global _backend
    _backend = backend


def reset_in_memory_rate_limiter() -> None:
    backend = _backend
    if isinstance(backend, InMemoryRateLimiter):
        backend.reset()


def client_ip_from_request(request: Request) -> str:
    forwarded = (request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded:
        first = forwarded.split(",", 1)[0].strip()
        if first:
            return first
    if request.client and request.client.host:
        return str(request.client.host)
    return "unknown"


def enforce_rate_limit_or_429(
    request: Request,
    *,
    bucket: str,
    limit: int,
    window_seconds: int,
    error_message: str,
) -> None:
    ip = client_ip_from_request(request)
    key = f"{bucket}:{ip}"
    decision = _backend.hit(key=key, limit=limit, window_seconds=window_seconds)
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "message": error_message,
                "bucket": bucket,
                "limit": int(limit),
                "window_seconds": int(window_seconds),
                "retry_after_seconds": int(decision.retry_after_seconds),
            },
        )
