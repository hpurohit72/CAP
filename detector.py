from collections import defaultdict, deque
from logger import log_alert
from config import PORT_SCAN_THRESHOLD, ANOMALY_FEATURE_WINDOW, ANOMALY_THRESHOLD
import numpy as np
from reputation import check_ip_reputation

class IDSDetector:
    def __init__(self):
        self.port_scans = defaultdict(set)
        self.packet_sizes = deque(maxlen=ANOMALY_FEATURE_WINDOW)

    # ---------------------------
    # RULE-BASED DETECTION
    # ---------------------------
    def detect_port_scan(self, packet):
        if "IP" in packet and "TCP" in packet:
            src = packet["IP"].src
            dport = packet["TCP"].dport

            self.port_scans[src].add(dport)

            if len(self.port_scans[src]) > PORT_SCAN_THRESHOLD:
                log_alert(f"Port scan detected from IP: {src}, Ports: {list(self.port_scans[src])[:20]}")

    def detect_suspicious_flags(self, packet):
        if "TCP" in packet:
            flags = packet["TCP"].flags
            # FIN+URG+PSH scan detection
            if flags == 0x29:
                log_alert(f"Suspicious TCP packet (Xmas scan) from {packet['IP'].src}")

            # Null scan
            if flags == 0x00:
                log_alert(f"Null scan detected from {packet['IP'].src}")

    # ---------------------------
    # ANOMALY DETECTION
    # ---------------------------
    def detect_anomaly(self, packet):
        if "IP" in packet:
            size = len(packet)
            self.packet_sizes.append(size)

            if len(self.packet_sizes) >= ANOMALY_FEATURE_WINDOW:
                mean = np.mean(self.packet_sizes)
                std = np.std(self.packet_sizes)

                if std > 0 and abs(size - mean) > ANOMALY_THRESHOLD * std:
                    log_alert(
                        f"Traffic anomaly detected: packet size={size}, mean={mean:.1f}, std={std:.1f}"
                    )

    # ---------------------------
    # MAIN ENTRY POINT
    # ---------------------------
    def process_packet(self, packet):
        try:
            self.detect_port_scan(packet)
            self.detect_suspicious_flags(packet)
            self.detect_anomaly(packet)
            check_ip_reputation(src_ip)
        except Exception as e:
            print("Error processing packet:", e)
