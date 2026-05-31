"""capture/flow_capture.py — Entry point for multi-source flow ingestion."""

import logging

import config

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
)
log = logging.getLogger("flow_capture")

# ── Re-exports (tests import from flow_capture) ─────────────────────────────
from flow_mapper import (                                       # noqa: E402, F401
    _INTERNAL_NETS,
    _is_internal,
    get_flow_direction,
    _safe,
    _map_flow,
    _netflow_record_to_features,
)
from batcher import (                                           # noqa: E402, F401
    FlowBatcher,
    _post_batch,
    _session,
)
from alert_router import dispatch                               # noqa: E402, F401
from response import handle_result                              # noqa: E402, F401
from sources.netflow_source import (                            # noqa: E402, F401
    _parse_nf5,
    _parse_nf9,
    _parse_ipfix,
    _parse_nf9_templates,
    _decode_nf9_record,
    _nf9_templates,
    _nf9_lock,
    _NF5_HDR,
    _NF5_REC,
    _NF9_HDR,
    _IPFIX_HDR,
    _NF9_FIELDS,
    NetFlowListener,
)
from sources.syslog_source import SyslogReceiver                # noqa: E402, F401
from sources.snmp_source import SNMPTrapReceiver                # noqa: E402, F401


# ══════════════════════════════════════════════════════════════════════════════
#  Main RSPAN capture loop
# ══════════════════════════════════════════════════════════════════════════════

def run():
    """Start all listeners, then block on nfstream RSPAN capture."""
    from sources.nfstream_source import run_nfstream_capture

    log.info("Starting HORUS capture service")
    log.info("  RSPAN interface : %s", config.CAPTURE_IFACE)
    log.info("  HORUS API       : %s", config.HORUS_API_URL)
    log.info("  NetFlow port    : UDP %d", config.NETFLOW_PORT)
    log.info("  Syslog port     : UDP %d", config.SYSLOG_LISTEN_PORT)
    log.info("  SNMP port       : UDP %d", config.SNMP_PORT)
    log.info("  Response thresh : severity >= %s", config.RESPONSE_MIN_SEVERITY)
    log.info("  SSH user        : %s", config.SSH_USER)
    log.info("  Batch size/to   : %d / %.1fs", config.BATCH_SIZE, config.BATCH_TIMEOUT_S)

    batcher = FlowBatcher()
    batcher.start()

    NetFlowListener(batcher).start()
    SyslogReceiver().start()
    SNMPTrapReceiver().start()

    run_nfstream_capture(batcher)


if __name__ == "__main__":
    run()
