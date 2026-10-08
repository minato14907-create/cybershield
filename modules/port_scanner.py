import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanResult:
    port: int
    state: str
    service: str
    banner: Optional[str] = None


class PortScanner:
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    }

    def __init__(self, target: str, ports: Optional[list[int]] = None,
                 threads: int = 100, timeout: float = 1.0):
        self.target = target
        self.ports = ports or list(range(1, 1025))
        self.threads = threads
        self.timeout = timeout
        self.results: list[ScanResult] = []
        self._lock = threading.Lock()

    def _resolve_target(self) -> str:
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {self.target}")

    def _scan_port(self, port: int) -> Optional[ScanResult]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                service = self.COMMON_PORTS.get(port, "Unknown")
                banner = self._grab_banner(sock)
                return ScanResult(port=port, state="OPEN", service=service, banner=banner)
            return None
        except (socket.timeout, ConnectionRefusedError):
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner if banner else None
        except Exception:
            return None

    def _worker(self, port: int) -> None:
        result = self._scan_port(port)
        if result:
            with self._lock:
                self.results.append(result)

    def scan(self) -> list[ScanResult]:
        ip = self._resolve_target()
        self.target = ip
        self.results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._worker, self.ports)

        self.results.sort(key=lambda x: x.port)
        return self.results

    def get_summary(self) -> dict:
        open_ports = [r for r in self.results if r.state == "OPEN"]
        return {
            "target": self.target,
            "total_scanned": len(self.ports),
            "open_ports": len(open_ports),
            "results": [
                {"port": r.port, "state": r.state, "service": r.service, "banner": r.banner}
                for r in open_ports
            ],
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.get_summary(), indent=2)


if __name__ == "__main__":
    scanner = PortScanner("scanme.nmap.org", threads=50)
    results = scanner.scan()
    print(f"\n{'='*50}")
    print(f"Scan Results for {scanner.target}")
    print(f"{'='*50}")
    for r in results:
        print(f"  Port {r.port:>5} | {r.state:<6} | {r.service}")
        if r.banner:
            print(f"           Banner: {r.banner}")
    print(f"\nTotal open ports: {len(results)}")
