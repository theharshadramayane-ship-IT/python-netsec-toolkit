import re
from collections import Counter

class LogAnalyzer:
    """
    Analyzes auth.log for failed SSH brute-force attempts.
    """
    def __init__(self, log_file):
        self.log_file = log_file
        # Concept: Regex Compilation. Pre-compiling regex makes it run much faster.
        # It matches: "Failed password for root from 192.168.1.1"
        self.regex_pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")

    def analyze(self):
        # Concept: Hash Map (Dictionary). Used to count occurrences in O(1) time.
        failed_ips = Counter()
        targeted_users = {}

        try:
            # Concept: Generator/Streaming. Reading file line-by-line without loading whole file in RAM.
            with open(self.log_file, "r", errors="ignore") as file:
                for line in file:
                    match = self.regex_pattern.search(line)
                    if match:
                        user, ip = match.groups()
                        failed_ips[ip] += 1
                        if ip not in targeted_users:
                            targeted_users[ip] = set()
                        targeted_users[ip].add(user)

        except FileNotFoundError:
            print(f"[-] Error: File {self.log_file} not found.")
            return

        self._display_results(failed_ips, targeted_users)

    def _display_results(self, failed_ips, targeted_users):
        total_attempts = sum(failed_ips.values())
        print(f"[*] Total Failed SSH Attempts: {total_attempts}\n")

        if not failed_ips:
            print("[+] No failed logins found. System is secure.")
            return

        # Concept: Sorting. Sorting dictionary items based on values in Descending Order.
        sorted_ips = sorted(failed_ips.items(), key=lambda x: x[1], reverse=True)

        print(f"{'IP Address':<20} | {'Attempts':<10} | {'Targeted Users'}")
        print("-" * 65)
        # Concept: Slicing. Displaying only Top 5 attackers.
        for ip, count in sorted_ips[:5]:
            users = ", ".join(list(targeted_users[ip])[:3]) # Show max 3 users per IP
            print(f"{ip:<20} | {count:<10} | {users}")

if __name__ == "__main__":
    # Replace with your actual log file path
    analyzer = LogAnalyzer("samples/sample_auth.log")
    analyzer.analyze()