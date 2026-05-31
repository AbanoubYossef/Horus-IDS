"""capture/batcher.py — FlowBatcher thread and HTTP client for HORUS API."""

import logging
import queue
import threading
import time
from typing import Optional

import requests

import config

log = logging.getLogger("flow_capture")

# ══════════════════════════════════════════════════════════════════════════════
#  HTTP client with API key support
# ══════════════════════════════════════════════════════════════════════════════
_session = requests.Session()
if config.HORUS_API_KEY:
    _session.headers["X-API-Key"] = config.HORUS_API_KEY


def _post_batch(batch: list) -> Optional[dict]:
    """POST flow batch to /predict/batch. Returns JSON or None on error."""
    url = f"{config.HORUS_API_URL}/predict/batch"
    try:
        resp = _session.post(url, json=batch, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        log.error("POST /predict/batch failed: %s", exc)
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  Batcher thread
# ══════════════════════════════════════════════════════════════════════════════

class FlowBatcher(threading.Thread):
    """Batches flow dicts and flushes to /predict/batch."""

    def __init__(self):
        super().__init__(daemon=True, name="FlowBatcher")
        self._q: queue.Queue = queue.Queue()

    def submit(self, flow_dict: dict):
        self._q.put(flow_dict)

    def run(self):
        buf = []
        deadline = time.monotonic() + config.BATCH_TIMEOUT_S

        while True:
            timeout = max(0.0, deadline - time.monotonic())
            try:
                item = self._q.get(timeout=timeout)
                buf.append(item)
            except queue.Empty:
                item = None

            now   = time.monotonic()
            flush = (len(buf) >= config.BATCH_SIZE) or (now >= deadline and buf)

            if flush:
                self._flush(buf)
                buf = []
                deadline = time.monotonic() + config.BATCH_TIMEOUT_S

            if item is None and not flush:
                deadline = time.monotonic() + config.BATCH_TIMEOUT_S

    def _flush(self, buf: list):
        # Late import so tests can monkeypatch flow_capture.*
        import flow_capture as _fc

        log.debug("Flushing %d flows to HORUS API", len(buf))
        resp = _fc._post_batch(buf)
        if resp is None:
            return

        results = resp.get("results", [])
        attacks = resp.get("attacks", 0)
        if attacks:
            log.info("Batch: %d flows, %d attacks detected", len(results), attacks)

        for i, result in enumerate(results):
            if i < len(buf):
                result["vlan_id"]        = buf[i].get("vlan_id", 0)
                result["src_vlan"]       = buf[i].get("src_vlan", 0)
                result["dst_vlan"]       = buf[i].get("dst_vlan", 0)
                result["flow_direction"] = buf[i].get("flow_direction", "UNKNOWN")
                result["input_path"]     = buf[i].get("input_path", "rspan")

            _fc.dispatch(result)
            _fc.handle_result(result)
