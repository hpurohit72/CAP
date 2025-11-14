from scapy.all import sniff
from detector import IDSDetector
from config import INTERFACE

detector = IDSDetector()

def packet_handler(packet):
    detector.process_packet(packet)

def start_sniffer():
    print(f"[*] Starting packet capture on interface: {INTERFACE}")
    sniff(iface=INTERFACE, store=False, prn=packet_handler)
    
