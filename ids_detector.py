from scapy.all import sniff, IP, TCP
import time

class IntrusionDetectionSystem:
    """
    Real-time Port Scan Detector using Scapy.
    """
    def __init__(self, threshold=15, time_window=10):
        self.threshold = threshold       # Kitne packets (ports) scan karne par alert aaye
        self.time_window = time_window   # Kitne seconds ke andar scan hona chahiye
        self.scan_tracker = {}           # Hash map to track IPs

    def process_packet(self, packet):
        # Concept: Packet Parsing. Checking if packet has IP and TCP layers.
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        # Concept: Bitwise Operators. SYN flag is 0x02 (binary 00000010)
        # SYN + ACK is 0x12. We only want pure SYN packets (Connection Initiation)
        tcp_flags = packet[TCP].flags
        if tcp_flags == 0x02: 
            src_ip = packet[IP].src
            dest_port = packet[TCP].dport
            current_time = time.time()

            if src_ip not in self.scan_tracker:
                # First time seeing this IP
                self.scan_tracker[src_ip] = {"ports": set(), "start_time": current_time}

            ip_data = self.scan_tracker[src_ip]

            # Concept: Sliding Window (Time-based). Reset if time window expires.
            if current_time - ip_data["start_time"] > self.time_window:
                ip_data["ports"] = set()
                ip_data["start_time"] = current_time

            ip_data["ports"].add(dest_port)

            # Check if threshold breached
            if len(ip_data["ports"]) >= self.threshold:
                print(f"\n[!] ALERT: Possible Port Scan detected from IP: {src_ip}")
                print(f"[!] Scanned {len(ip_data['ports'])} ports in {self.time_window} seconds.")
                
                # Reset to avoid spamming alerts for the same IP
                del self.scan_tracker[src_ip]

    def start_sniffing(self, interface=None):
        print(f"[*] IDS Active. Monitoring network traffic... (Press Ctrl+C to stop)")
        try:
            # Concept: Callback function. 'prn' triggers process_packet for every captured packet.
            sniff(iface=interface, prn=self.process_packet, store=False)
        except PermissionError:
            print("[-] Error: Run this script as Administrator/Root to sniff packets.")
        except KeyboardInterrupt:
            print("\n[*] Stopping IDS...")

if __name__ == "__main__":
    # Note: On Windows, you need to install Npcap and run VS Code as Administrator.
    ids = IntrusionDetectionSystem()
    ids.start_sniffing()