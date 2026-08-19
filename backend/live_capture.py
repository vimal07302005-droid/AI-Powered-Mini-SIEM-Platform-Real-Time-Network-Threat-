"""
backend/live_capture.py: Live Packet Capture & 5-Tuple Flow Extractor module for SENTRY SIEM.
Sniffs live network packets using Scapy, aggregates 5-tuple flows, extracts NSL-KDD
derivable features, and feeds real local/remote IP network flows into the ML inference engine.
"""

import time
import socket
import logging
import threading
import queue
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("sentry_live_capture")

PORT_SERVICE_MAP = {
    80: "http",
    443: "http_443",
    22: "ssh",
    21: "ftp",
    25: "smtp",
    53: "domain_u",
    110: "pop_3",
    143: "imap4",
    3306: "mysql",
    5432: "postgresql",
    8080: "http_8080",
    8443: "http_443",
}


def get_local_ip():
    """Returns the primary active local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


class LiveFlowTracker:
    def __init__(self, flow_timeout=2.0, max_packets=50):
        self.flow_timeout = flow_timeout
        self.max_packets = max_packets
        self.active_flows = {}
        self.completed_queue = queue.Queue()
        self.recent_dst_window = defaultdict(list)  # dst_ip -> list of timestamps
        self.recent_srv_window = defaultdict(list)  # (dst_ip, dst_port) -> list of timestamps

    def process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        protocol_name = "tcp"
        src_port = 0
        dst_port = 0
        tcp_flags = ""
        payload_len = len(pkt)

        if pkt.haslayer(TCP):
            protocol_name = "tcp"
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flags = str(tcp_layer.flags)
        elif pkt.haslayer(UDP):
            protocol_name = "udp"
            udp_layer = pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
        elif pkt.haslayer(ICMP):
            protocol_name = "icmp"

        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol_name)
        now = time.time()

        if flow_key not in self.active_flows:
            self.active_flows[flow_key] = {
                "start_time": now,
                "last_time": now,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol_name,
                "src_bytes": payload_len,
                "dst_bytes": 0,
                "packet_count": 1,
                "tcp_flags": set([tcp_flags]) if tcp_flags else set(),
            }
        else:
            flow = self.active_flows[flow_key]
            flow["last_time"] = now
            flow["src_bytes"] += payload_len
            flow["packet_count"] += 1
            if tcp_flags:
                flow["tcp_flags"].add(tcp_flags)

            # Check if flow exceeds packet threshold
            if flow["packet_count"] >= self.max_packets:
                completed = self.active_flows.pop(flow_key)
                self._finalize_and_enqueue(completed)

        # Periodically flush expired flows
        self.flush_expired(now)

    def flush_expired(self, now=None):
        if now is None:
            now = time.time()
        expired_keys = []
        for key, flow in list(self.active_flows.items()):
            if now - flow["last_time"] >= self.flow_timeout:
                expired_keys.append(key)

        for key in expired_keys:
            flow = self.active_flows.pop(key)
            self._finalize_and_enqueue(flow)

    def _finalize_and_enqueue(self, flow):
        now = flow["last_time"]
        duration = round(flow["last_time"] - flow["start_time"], 4)
        dst_ip = flow["dst_ip"]
        dst_port = flow["dst_port"]
        protocol = flow["protocol"]

        # Track connection window statistics
        self.recent_dst_window[dst_ip].append(now)
        self.recent_dst_window[dst_ip] = [t for t in self.recent_dst_window[dst_ip] if now - t <= 2.0]
        count = len(self.recent_dst_window[dst_ip])

        self.recent_srv_window[(dst_ip, dst_port)].append(now)
        self.recent_srv_window[(dst_ip, dst_port)] = [t for t in self.recent_srv_window[(dst_ip, dst_port)] if now - t <= 2.0]
        srv_count = len(self.recent_srv_window[(dst_ip, dst_port)])

        same_srv_rate = round(srv_count / max(1, count), 2)
        diff_srv_rate = round(1.0 - same_srv_rate, 2)

        # Derive TCP flag
        flag = "SF"
        flags_set = flow["tcp_flags"]
        if any("S" in f and "A" not in f for f in flags_set):
            flag = "S0"
        elif any("R" in f for f in flags_set):
            flag = "REJ"
        elif any("F" in f for f in flags_set):
            flag = "SF"

        service = PORT_SERVICE_MAP.get(dst_port, "private" if protocol == "tcp" else "other")

        # Build feature dict aligned with 41 NSL-KDD columns
        feature_dict = {
            "duration": duration,
            "protocol_type": protocol,
            "service": service,
            "flag": flag,
            "src_bytes": flow["src_bytes"],
            "dst_bytes": flow["dst_bytes"],
            "count": count,
            "srv_count": srv_count,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": min(255, count * 2),
            "dst_host_srv_count": min(255, srv_count * 2),
            "dst_host_same_srv_rate": same_srv_rate,
            "dst_host_diff_srv_rate": diff_srv_rate,
            "dst_host_same_src_port_rate": 0.1,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0,
            
            # --- DOCUMENTED LIMITATION / NEUTRAL DEFAULT VALUES ---
            # NOTE: The following 16 host/application-level features cannot be extracted
            # from raw un-decrypted IP/TCP/UDP packet headers alone without host endpoint agents.
            # They are defaulted to neutral values (0) as per NSL-KDD dataset specification.
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1 if dst_port in (80, 443, 8080) else 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            
            # Real metadata
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "dst_port": dst_port,
        }

        self.completed_queue.put(feature_dict)


class LiveCaptureSnifferThread(threading.Thread):
    def __init__(self, tracker: LiveFlowTracker, iface=None):
        super().__init__(daemon=True)
        self.tracker = tracker
        self.iface = iface
        self.running = False

    def run(self):
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is not installed. Live packet capture cannot start.")
            return

        self.running = True
        logger.info("Starting live packet capture thread (Scapy filter: IP)...")
        try:
            sniff(
                filter="ip",
                prn=self.tracker.process_packet,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            logger.error(f"Live packet capture stopped unexpectedly: {str(e)}")
            self.running = False

    def stop(self):
        self.running = False
