"""Shared, scoped investigation context with correlation IDs and per-investigation telemetry cache."""

import logging
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.schemas import utc_now_iso
from fortigate_client import FortiGateClient
from write_authorization import WriteAuthorizationController

logger = logging.getLogger("FortiGateCore.Context")


class InvestigationContext:
    """
    Holds device/VDOM identity, client handle, write authorization controller,
    structured trace events, and a thread-safe per-investigation telemetry cache.
    """

    def __init__(
        self,
        fg_client: FortiGateClient,
        correlation_id: Optional[str] = None,
        auth_controller: Optional[WriteAuthorizationController] = None,
    ):
        self.fg_client = fg_client
        self.correlation_id = correlation_id or uuid.uuid4().hex[:16]
        self.device = fg_client.host or "mock_fortigate"
        self.vdom = fg_client.vdom
        self.auth_controller = auth_controller or WriteAuthorizationController()
        self._cache: Dict[Tuple[str, str], Any] = {}
        self._lock = threading.RLock()
        self.trace_events: List[Dict[str, Any]] = []

    def get_or_fetch(self, cache_key: str, fetcher: Callable[[], Any], cache_scope: str = "") -> Any:
        """
        Thread-safe per-investigation cache so concurrent specialist agents
        do not redundantly query the same FortiGate REST endpoint.
        """
        full_key = (cache_key, cache_scope)
        with self._lock:
            if full_key in self._cache:
                self.record_trace("cache_hit", {"key": cache_key, "scope": cache_scope})
                return self._cache[full_key]

        data = fetcher()
        with self._lock:
            self._cache[full_key] = data
            self.record_trace("cache_store", {"key": cache_key, "scope": cache_scope})
        return data

    def invalidate_cache(self) -> None:
        """Clears cached telemetry (e.g., after a remediation write before post-change verification)."""
        with self._lock:
            self._cache.clear()
            self.record_trace("cache_invalidated", {})

    def record_trace(self, event: str, details: Optional[Dict[str, Any]] = None) -> None:
        entry = {
            "timestamp": utc_now_iso(),
            "correlation_id": self.correlation_id,
            "device": self.device,
            "vdom": self.vdom,
            "event": event,
            "details": details or {},
        }
        with self._lock:
            self.trace_events.append(entry)
        logger.info(
            "[corr=%s device=%s vdom=%s] %s %s",
            self.correlation_id,
            self.device,
            self.vdom,
            event,
            details or {},
        )
