#!/usr/bin/env python3
GREEN = "\033[92m"
RESET = "\033[0m"

print(f"""{GREEN}
   ███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗███╗   ███╗ ██████╗██████╗
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝████╗ ████║██╔════╝██╔══██╗
   ███████╗███████║███████║██████╔╝█████╔╝ ██╔████╔██║██║     ██████╔╝
   ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ ██║╚██╔╝██║██║     ██╔═══╝
   ███████║██║  ██║██║  ██║██║  ██║██║  ██╗██║ ╚═╝ ██║╚██████╗██║
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝

                > SharkMCP : Bridge between Claude Desktop and Wireshark
                > made with ♥ by Sumedha Dawadi
{RESET}""")
import pyshark
import argparse
import time
import json
import re
import math
from collections import defaultdict, Counter
from datetime import datetime

# =========================
# Capture Layer
# =========================

class CaptureSource:
    def packets(self):
        raise NotImplementedError


class LiveCapture(CaptureSource):
    def __init__(self, interface, display_filter=None):
        self.capture = pyshark.LiveCapture(
            interface=interface,
            display_filter=display_filter
        )

    def packets(self):
        for pkt in self.capture.sniff_continuously():
            yield pkt


class FileCapture(CaptureSource):
    def __init__(self, pcap_path, display_filter=None):
        self.capture = pyshark.FileCapture(
            pcap_path,
            display_filter=display_filter,
            keep_packets=False
        )

    def packets(self):
        for pkt in self.capture:
            yield pkt

# =========================
# Parsing Layer
# =========================

def parse_packet(pkt):
    try:
        parsed = {
            "timestamp": datetime.fromtimestamp(float(pkt.sniff_timestamp)).isoformat(),
            "src_ip": getattr(pkt.ip, "src", None),
            "dst_ip": getattr(pkt.ip, "dst", None),
            "protocol": pkt.highest_layer,
            "length": int(pkt.length),
            "flags": {},
            "payload": "",
            "application": {}
        }

        if "TCP" in pkt:
            parsed["flags"] = {
                "syn": int(pkt.tcp.flags_syn),
                "ack": int(pkt.tcp.flags_ack),
                "fin": int(pkt.tcp.flags_fin),
                "rst": int(pkt.tcp.flags_reset)
            }

        if "HTTP" in pkt:
            parsed["application"] = {
                "method": getattr(pkt.http, "request_method", None),
                "host": getattr(pkt.http, "host", None),
                "uri": getattr(pkt.http, "request_uri", None),
                "status": getattr(pkt.http, "response_code", None)
            }

        if hasattr(pkt, "data"):
            parsed["payload"] = str(pkt.data)

        return parsed
    except Exception:
        return None

# =========================
# Flow Tracking
# =========================

class FlowTracker:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            "packets": 0,
            "bytes": 0,
            "start": None,
            "end": None,
            "protocol": None
        })

    def process(self, pkt):
        key = (pkt["src_ip"], pkt["dst_ip"], pkt["protocol"])
        flow = self.flows[key]

        ts = pkt["timestamp"]
        flow["packets"] += 1
        flow["bytes"] += pkt["length"]
        flow["protocol"] = pkt["protocol"]
        flow["start"] = flow["start"] or ts
        flow["end"] = ts

    def summary(self):
        summary = []
        for (src, dst, proto), v in self.flows.items():
            summary.append({
                "src_ip": src,
                "dst_ip": dst,
                "protocol": proto,
                "packets": v["packets"],
                "bytes": v["bytes"],
                "start": v["start"],
                "end": v["end"]
            })
        return summary

# =========================
# Detection Engines
# =========================

class BeaconDetector:
    def __init__(self):
        self.timestamps = defaultdict(list)
        self.alerts = []

    def process(self, pkt):
        key = (pkt["src_ip"], pkt["dst_ip"])
        now = time.time()
        self.timestamps[key].append(now)

        times = self.timestamps[key][-6:]
        if len(times) >= 6:
            deltas = [times[i+1] - times[i] for i in range(len(times)-1)]
            if max(deltas) - min(deltas) < 1:
                self.alerts.append({
                    "type": "Possible Malware Beaconing",
                    "src": pkt["src_ip"],
                    "dst": pkt["dst_ip"],
                    "confidence": "high"
                })

    def results(self):
        return self.alerts


class CredentialLeakDetector:
    REGEX = [
        r"password\s*=\s*\S+",
        r"api[_-]?key\s*=\s*\S+",
        r"authorization:\s*bearer\s+\S+"
    ]

    def scan(self, payload):
        alerts = []
        for r in self.REGEX:
            if re.search(r, payload, re.I):
                if self.entropy(payload) > 3.5:
                    alerts.append("Potential plaintext credential exposure")
        return alerts

    def entropy(self, s):
        if not s:
            return 0
        probs = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in probs)


class AnomalyDetector:
    def detect(self, packets):
        proto_counts = Counter(p["protocol"] for p in packets)
        alerts = []
        for proto, count in proto_counts.items():
            if count > 1000 and proto not in ("TCP", "UDP", "HTTP", "DNS"):
                alerts.append(f"Unusual volume of {proto} traffic")
        return alerts

# =========================
# Reporting
# =========================

def build_structured_output(packets, flows, alerts):
    return {
        "summary": {
            "total_packets": len(packets),
            "unique_ips": list(set(
                p["src_ip"] for p in packets if p["src_ip"]
            )),
            "protocol_distribution": dict(Counter(
                p["protocol"] for p in packets
            )),
            "suspicious_events": alerts
        },
        "flows": flows,
        "alerts": alerts
    }


def natural_language_explanation(report):
    s = report["summary"]

    explanation = [
        f"The capture contains {s['total_packets']} packets "
        f"communicating with {len(s['unique_ips'])} unique IP addresses.",
        f"Traffic consisted mainly of: "
        + ", ".join(f"{k} ({v})" for k, v in s["protocol_distribution"].items())
    ]

    if s["suspicious_events"]:
        explanation.append(
            f"{len(s['suspicious_events'])} suspicious behaviors were identified, "
            "including repeated, predictable communication patterns suggestive "
            "of command-and-control activity."
        )
    else:
        explanation.append("No high-confidence malicious behavior was detected.")

    return " ".join(explanation)

# =========================
# Main
# =========================

def main():
    parser = argparse.ArgumentParser(description="NetSpector Traffic Analyzer")
    parser.add_argument("--pcap", help="PCAP file to analyze")
    parser.add_argument("--live", help="Network interface for live capture")
    parser.add_argument("--filter", help="Display filter (Wireshark syntax)")
    args = parser.parse_args()

    if not args.pcap and not args.live:
        parser.error("Specify --pcap or --live")

    capture = (
        FileCapture(args.pcap, args.filter)
        if args.pcap else
        LiveCapture(args.live, args.filter)
    )

    packets = []
    flows = FlowTracker()
    beacon = BeaconDetector()
    credential = CredentialLeakDetector()

    alerts = []

    for raw in capture.packets():
        pkt = parse_packet(raw)
        if not pkt:
            continue

        packets.append(pkt)
        flows.process(pkt)
        beacon.process(pkt)

        if pkt["payload"]:
            alerts.extend(credential.scan(pkt["payload"]))

    alerts.extend(beacon.results())
    alerts.extend(AnomalyDetector().detect(packets))

    report = build_structured_output(
        packets,
        flows.summary(),
        alerts
    )

    print(json.dumps(report, indent=2))
    print("\n--- HUMAN READABLE EXPLANATION ---\n")
    print(natural_language_explanation(report))


if __name__ == "__main__":
    main()
