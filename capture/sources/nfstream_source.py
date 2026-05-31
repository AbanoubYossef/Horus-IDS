"""
capture/sources/nfstream_source.py — RSPAN/nfstream capture (main thread).

Reads raw packets from the RSPAN mirror interface (eth1) via nfstream,
maps each flow to CICFlowMeter features, and submits to FlowBatcher.
"""

import logging

import config
from flow_mapper import _safe, _map_flow, get_flow_direction

log = logging.getLogger("flow_capture")


def run_nfstream_capture(batcher):
    """Blocking RSPAN capture loop (main thread)."""
    try:
        from nfstream import NFStreamer
    except ImportError:
        log.critical("nfstream not installed. Run: pip install nfstream")
        raise

    streamer = NFStreamer(
        source=config.CAPTURE_IFACE,
        statistical_analysis=True,
        splt_analysis=0,
        n_dissections=0,
        promiscuous_mode=True,
        decode_tunnels=True,
        accounting_mode=3,
        # Short timeouts for live monitoring (defaults are too slow)
        idle_timeout=15,
        active_timeout=30,
    )

    total_flows = 0
    skipped     = 0

    for flow in streamer:
        total_flows += 1

        features = _map_flow(flow)
        if features is None:
            skipped += 1
            continue

        src_ip  = str(getattr(flow, "src_ip",  "") or "")
        dst_ip  = str(getattr(flow, "dst_ip",  "") or "")
        vlan_id = int(_safe(flow, "vlan_id", 0))
        # RSPAN: src and dst share the same VLAN tag
        src_vlan = vlan_id
        dst_vlan = vlan_id
        # Fallback to topology inference if tag was stripped
        if src_vlan == 0:
            src_vlan = config.vlan_from_ip(src_ip)
        if dst_vlan == 0:
            dst_vlan = config.vlan_from_ip(dst_ip)
        if vlan_id == 0:
            vlan_id = src_vlan or dst_vlan

        flow_dict = {
            "features_dict":  features,
            "src_ip":         src_ip,
            "dst_ip":         dst_ip,
            "src_port":       int(_safe(flow, "src_port", 0)),
            "dst_port":       int(_safe(flow, "dst_port", 0)),
            "protocol":       int(_safe(flow, "protocol", 0)),
            "vlan_id":        vlan_id,
            "src_vlan":       src_vlan,
            "dst_vlan":       dst_vlan,
            "flow_direction": get_flow_direction(src_ip, dst_ip),
            "input_path":     "rspan",
        }

        batcher.submit(flow_dict)

        if total_flows % 10_000 == 0:
            log.info("RSPAN flows: %d processed  %d skipped", total_flows, skipped)
