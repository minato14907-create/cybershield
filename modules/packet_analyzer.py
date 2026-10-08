import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PacketInfo:
    number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int = 0
    info: str = ""


class PacketAnalyzer:
    PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def __init__(self):
        self.packets: list[PacketInfo] = []
        self._count = 0

    def analyze_pcap(self, filepath: str) -> list[PacketInfo]:
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP
        except ImportError:
            raise ImportError("scapy is required: pip install scapy")

        packets = rdpcap(filepath)
        self.packets = []

        for pkt in packets:
            self._count += 1
            info = PacketInfo(
                number=self._count,
                timestamp=float(pkt.time),
                src_ip=pkt[IP].src if IP in pkt else "N/A",
                dst_ip=pkt[IP].dst if IP in pkt else "N/A",
                protocol=self._get_protocol(pkt),
                length=len(pkt),
            )

            if TCP in pkt:
                info.src_port = pkt[TCP].sport
                info.dst_port = pkt[TCP].dport
                info.info = self._analyze_tcp_flags(pkt[TCP])
            elif UDP in pkt:
                info.src_port = pkt[UDP].sport
                info.dst_port = pkt[UDP].dport
                info.info = f"UDP {pkt[UDP].sport} -> {pkt[UDP].dport}"
            elif ICMP in pkt:
                info.info = f"ICMP Type {pkt[ICMP].type} Code {pkt[ICMP].code}"

            self.packets.append(info)

        return self.packets

    def capture_live(self, interface: Optional[str] = None, count: int = 100) -> list[PacketInfo]:
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
        except ImportError:
            raise ImportError("scapy is required: pip install scapy")

        self.packets = []
        self._count = 0

        def process_packet(pkt):
            self._count += 1
            info = PacketInfo(
                number=self._count,
                timestamp=float(pkt.time),
                src_ip=pkt[IP].src if IP in pkt else "N/A",
                dst_ip=pkt[IP].dst if IP in pkt else "N/A",
                protocol=self._get_protocol(pkt),
                length=len(pkt),
            )
            if TCP in pkt:
                info.src_port = pkt[TCP].sport
                info.dst_port = pkt[TCP].dport
                info.info = self._analyze_tcp_flags(pkt[TCP])
            elif UDP in pkt:
                info.src_port = pkt[UDP].sport
                info.dst_port = pkt[UDP].dport
                info.info = f"UDP {pkt[UDP].sport} -> {pkt[UDP].dport}"
            elif ICMP in pkt:
                info.info = f"ICMP Type {pkt[ICMP].type}"
            self.packets.append(info)

        sniff(iface=interface, prn=process_packet, count=count)
        return self.packets

    def _get_protocol(self, pkt) -> str:
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            if ICMP in pkt:
                return "ICMP"
            if TCP in pkt:
                return "TCP"
            if UDP in pkt:
                return "UDP"
        except ImportError:
            pass
        return "OTHER"

    def _analyze_tcp_flags(self, tcp_layer) -> str:
        flags = []
        if tcp_layer.flags.S:
            flags.append("SYN")
        if tcp_layer.flags.A:
            flags.append("ACK")
        if tcp_layer.flags.F:
            flags.append("FIN")
        if tcp_layer.flags.R:
            flags.append("RST")
        if tcp_layer.flags.P:
            flags.append("PSH")
        return " | ".join(flags) if flags else "No Flags"

    def get_statistics(self) -> dict:
        if not self.packets:
            return {"total": 0}

        protocols = {}
        for pkt in self.packets:
            protocols[pkt.protocol] = protocols.get(pkt.protocol, 0) + 1

        top_talkers = {}
        for pkt in self.packets:
            top_talkers[pkt.src_ip] = top_talkers.get(pkt.src_ip, 0) + 1

        top_dst = {}
        for pkt in self.packets:
            top_dst[pkt.dst_ip] = top_dst.get(pkt.dst_ip, 0) + 1

        sorted_src = sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:10]
        sorted_dst = sorted(top_dst.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_packets": len(self.packets),
            "protocols": protocols,
            "top_sources": dict(sorted_src),
            "top_destinations": dict(sorted_dst),
            "total_bytes": sum(p.length for p in self.packets),
            "time_span": self.packets[-1].timestamp - self.packets[0].timestamp
            if len(self.packets) > 1
            else 0,
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.get_statistics(), indent=2)


if __name__ == "__main__":
    analyzer = PacketAnalyzer()
    print("Packet Analyzer Ready")
    print("Usage: analyzer.analyze_pcap('file.pcap')")
    print("       analyzer.capture_live(count=50)")
