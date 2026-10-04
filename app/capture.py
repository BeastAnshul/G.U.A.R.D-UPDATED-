"""Optional metadata-only packet capture. Run only on an authorized interface."""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timezone

def main():
    parser = argparse.ArgumentParser(description="Capture IP flow metadata locally; packet payloads are never saved.")
    parser.add_argument("--interface", required=True, help="Network interface to capture on")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration in seconds (1–3600)")
    parser.add_argument("--output", default="data/captured_flows.csv", help="Output CSV path")
    args = parser.parse_args()
    if not 1 <= args.duration <= 3600:
        parser.error("--duration must be between 1 and 3600 seconds")
    try:
        from scapy.all import IP, TCP, UDP, sniff
    except ImportError as exc:
        raise SystemExit("Scapy is missing. Install it with: pip install -r requirements-capture.txt") from exc

    flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "syn": 0, "ack": 0, "first": None, "last": None})
    def record(packet):
        if IP not in packet:
            return
        ip = packet[IP]
        sport = dport = 0
        if TCP in packet:
            layer, proto = packet[TCP], "TCP"
        elif UDP in packet:
            layer, proto = packet[UDP], "UDP"
        else:
            layer, proto = None, str(ip.proto)
        if layer is not None:
            sport, dport = int(layer.sport), int(layer.dport)
        key = (ip.src, ip.dst, sport, dport, proto)
        item = flows[key]
        stamp = float(packet.time)
        item["packets"] += 1
        item["bytes"] += len(packet)
        item["first"] = stamp if item["first"] is None else min(item["first"], stamp)
        item["last"] = stamp if item["last"] is None else max(item["last"], stamp)
        if TCP in packet:
            flags = int(packet[TCP].flags)
            item["syn"] += int(bool(flags & 0x02))
            item["ack"] += int(bool(flags & 0x10))

    print(f"Capturing flow metadata on {args.interface} for {args.duration}s. Payloads are not stored.")
    try:
        sniff(iface=args.interface, timeout=args.duration, store=False, prn=record)
    except PermissionError as exc:
        raise SystemExit("Capture permission denied. Run with the required local interface permissions.") from exc
    except OSError as exc:
        raise SystemExit(f"Capture failed: {exc}") from exc
    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Packets", "Bytes", "Flow Duration", "SYN Flag Count", "ACK Flag Count"])
        for (src, dst, sport, dport, proto), item in flows.items():
            first = datetime.fromtimestamp(item["first"], tz=timezone.utc).isoformat()
            duration_ms = (item["last"] - item["first"]) * 1000.0
            writer.writerow([first, src, dst, sport, dport, proto, item["packets"], item["bytes"], round(duration_ms, 3), item["syn"], item["ack"]])
    print(f"Wrote {len(flows)} flow records to {args.output}")

if __name__ == "__main__":
    main()
