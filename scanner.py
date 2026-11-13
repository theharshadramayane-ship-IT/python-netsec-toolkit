import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    """
    Advanced TCP Port Scanner using Multithreading.
    """
    def __init__(self, target, timeout=1.0):
        self.target_ip = self._resolve_target(target)
        self.timeout = timeout

    def _resolve_target(self, target):
        # Concept: DNS Resolution. Converting domain name to IP address.
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[-] Error: Cannot resolve hostname {target}")
            return None

    def _grab_banner(self, sock):
        # Concept: Banner Grabbing. Sending a blank request to see what service is running.
        try:
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner
        except Exception:
            return "Unknown Service"

    def scan_single_port(self, port):
        # Concept: Socket Connect. connect_ex() returns 0 if port is open.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                banner = self._grab_banner(sock)
                return (port, "OPEN", banner)
            return (port, "CLOSED", "")

    def start_scan(self, ports, max_workers=100):
        # Concept: Multithreading. Using ThreadPoolExecutor to scan 100 ports at the same time.
        print(f"[*] Starting scan on {self.target_ip} for {len(ports)} ports...")
        open_ports = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submitting tasks to thread pool
            future_to_port = {executor.submit(self.scan_single_port, port): port for port in ports}
            
            # Getting results as they complete (faster than waiting for all to finish)
            for future in as_completed(future_to_port):
                port, status, banner = future.result()
                if status == "OPEN":
                    print(f"[+] Port {port:<5} is OPEN | Service: {banner[:50]}")
                    open_ports.append(port)

        print(f"\n[*] Scan Complete. Total Open Ports: {len(open_ports)}")

def parse_ports(port_str):
    # Concept: String Parsing. Converts "1-100" or "80,443" into a Python list.
    if "-" in port_str:
        start, end = map(int, port_str.split("-"))
        return list(range(start, end + 1))
    return [int(p) for p in port_str.split(",")]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Python Port Scanner")
    parser.add_argument("host", help="Target IP or Domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1000 or 80,443)")
    args = parser.parse_args()

    scanner = NetworkScanner(args.host)
    if scanner.target_ip:
        target_ports = parse_ports(args.ports)
        scanner.start_scan(target_ports)