import argparse
import sys
import threading
import time

from scapy.all import (
    sniff,
    rdpcap,
    get_if_list,
    AsyncSniffer
)

from scapy.sessions import TCPSession

from rich.console import Console

from config import (
    CAPTURE_DIR,
    REPORT_DIR
)

from packet_analyzer import (
    PacketAnalyzer
)

from flow_tracker import (
    FlowTracker
)

from statistics import (
    Statistics
)

from threat_detector import (
    ThreatDetector
)

from dashboard import (
    Dashboard
)

from exporters import (
    Exporter
)

from utils import (
    format_endpoint
)


console = Console()


class NetworkAnalyzer:

    def __init__(self):

        self.packet_analyzer = (
            PacketAnalyzer()
        )

        self.statistics = (
            Statistics()
        )

        self.flow_tracker = (
            FlowTracker()
        )

        self.detector = (
            ThreatDetector()
        )

        self.exporter = (
            Exporter()
        )

        self.dashboard = (
            Dashboard(
                self.statistics,
                self.flow_tracker,
                self.detector
            )
        )

        self.packets = []

        self.running = True

        self.show_dashboard = False

    # ========================================================
    # PACKET PROCESSING
    # ========================================================

    def process_packet(
        self,
        packet
    ):

        if not self.running:
            return

        self.packets.append(
            packet
        )

        info = (
            self.packet_analyzer.analyze(
                packet
            )
        )

        self.statistics.update(
            info
        )

        self.flow_tracker.update(
            packet,
            info
        )

        self.detector.analyze(
            info
        )

        if self.exporter.csv_writer:

            self.exporter.write_csv(
                info
            )

        if not self.show_dashboard and self.running:

            src = format_endpoint(
                info.get("source"),
                info.get("source_port")
            )

            dst = format_endpoint(
                info.get("destination"),
                info.get("destination_port")
            )

            proto = info.get("protocol", "OTHER")

            length = info.get("length", 0)

            console.print(
                f"[dim][{proto}][/dim] {src} -> {dst} ({length} bytes)"
            )

    # ========================================================
    # LIVE CAPTURE
    # ========================================================

    def capture(
        self,
        interface=None,
        packet_count=0,
        timeout=None,
        bpf_filter=None,
        use_session=False,
        show_dashboard=False
    ):

        self.show_dashboard = show_dashboard

        console.print(
            "\n[bold cyan]"
            "Starting packet capture..."
            "[/bold cyan]"
        )

        console.print(
            "[yellow]"
            "Press CTRL+C to stop."
            "[/yellow]\n"
        )

        session = (
            TCPSession
            if use_session
            else None
        )

        try:

            sniffer_kwargs = {
                "iface": interface,
                "filter": bpf_filter,
                "prn": self.process_packet,
                "count": packet_count,
                "store": False,
                "session": session
            }

            self.sniffer = AsyncSniffer(
                **sniffer_kwargs
            )

            self.sniffer.start()

            start_time = time.time()

            def is_active():

                if not self.running:
                    return False

                if (
                    hasattr(self, "sniffer")
                    and self.sniffer
                    and not self.sniffer.running
                ):
                    return False

                if (
                    timeout
                    and (time.time() - start_time) >= timeout
                ):
                    return False

                return True

            if show_dashboard:

                self.dashboard.run(is_active)

            else:

                while is_active():

                    time.sleep(0.2)

            self.stop()

        except KeyboardInterrupt:

            console.print(
                "\n[yellow]"
                "Stopping capture..."
                "[/yellow]"
            )

            self.stop()

        except PermissionError:

            console.print(
                "[red]"
                "Permission denied. "
                "Run with appropriate privileges."
                "[/red]"
            )

            self.stop()

        except Exception as error:

            console.print(
                f"[red]Capture error: "
                f"{error}[/red]"
            )

            self.stop()

    # ========================================================
    # OFFLINE PCAP
    # ========================================================

    def analyze_pcap(
        self,
        path
    ):

        console.print(
            f"[cyan]"
            f"Loading PCAP: {path}"
            f"[/cyan]"
        )

        try:

            packets = rdpcap(
                path
            )

            console.print(
                f"Loaded {len(packets)} packets."
            )

            for packet in packets:

                self.process_packet(
                    packet
                )

        except Exception as error:

            console.print(
                f"[red]"
                f"Could not read PCAP: "
                f"{error}"
                f"[/red]"
            )

    # ========================================================
    # STOP
    # ========================================================

    def stop(self):

        self.running = False

        self.dashboard.stop()

        try:

            if (
                hasattr(self, "sniffer")
                and self.sniffer
            ):

                if self.sniffer.running:

                    self.sniffer.stop()

        except Exception:
            pass

    # ========================================================
    # REPORT
    # ========================================================

    def save_reports(
        self,
        pcap_path=None,
        csv_path=None,
        json_path=None
    ):

        if pcap_path:

            self.exporter.save_pcap(
                pcap_path,
                self.packets
            )

            console.print(
                f"[green]"
                f"PCAP saved: {pcap_path}"
                f"[/green]"
            )

        if json_path:

            summary = (
                self.statistics.summary(
                    self.flow_tracker.count()
                )
            )

            flows = [

                flow.to_dict()

                for flow
                in self.flow_tracker.flows.values()
            ]

            self.exporter.save_json(

                json_path,

                summary,

                flows,

                self.detector.alerts
            )

            console.print(
                f"[green]"
                f"JSON saved: {json_path}"
                f"[/green]"
            )

        self.exporter.close_csv()

    # ========================================================
    # FINAL REPORT
    # ========================================================

    def print_report(self):

        stats = self.statistics.summary(
            self.flow_tracker.count()
        )

        console.print(
            "\n[bold cyan]"
            "FINAL ANALYSIS"
            "[/bold cyan]\n"
        )

        console.print(
            f"Packets: "
            f"{stats['packets']}"
        )

        console.print(
            f"Bytes: "
            f"{stats['bytes']}"
        )

        console.print(
            f"Duration: "
            f"{stats['duration']} sec"
        )

        console.print(
            f"Packet rate: "
            f"{stats['packets_per_second']} pkt/s"
        )

        console.print(
            f"Bandwidth: "
            f"{stats['bytes_per_second']:.2f} B/s"
        )

        console.print(
            f"Flows: "
            f"{stats['flows']}"
        )

        console.print(
            "\n[bold green]"
            "Protocols"
            "[/bold green]"
        )

        for protocol, count in (
            stats["protocols"].items()
        ):

            console.print(
                f"  {protocol}: "
                f"{count}"
            )

        console.print(
            "\n[bold yellow]"
            "Security alerts"
            "[/bold yellow]"
        )

        if not self.detector.alerts:

            console.print(
                "  No alerts."
            )

        else:

            for alert in (
                self.detector.alerts
            ):

                console.print(
                    f"  [{alert['severity']}] "
                    f"{alert['type']} - "
                    f"{alert['message']}"
                )


def parse_arguments():

    parser = argparse.ArgumentParser(

        description=(
            "Advanced Python Network "
            "Analyzer / Lightweight IDS"
        )
    )

    parser.add_argument(
        "-i",
        "--interface"
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int
    )

    parser.add_argument(
        "-f",
        "--filter"
    )

    parser.add_argument(
        "--read"
    )

    parser.add_argument(
        "--pcap"
    )

    parser.add_argument(
        "--csv"
    )

    parser.add_argument(
        "--json"
    )

    parser.add_argument(
        "--dashboard",
        action="store_true"
    )

    parser.add_argument(
        "--tcp-session",
        action="store_true"
    )

    parser.add_argument(
        "--interfaces",
        action="store_true"
    )

    return parser.parse_args()


def main():

    args = parse_arguments()

    if args.interfaces:

        print(
            "\nAvailable interfaces:\n"
        )

        for interface in get_if_list():

            print(
                f"  {interface}"
            )

        return

    analyzer = NetworkAnalyzer()

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    if args.csv:

        analyzer.exporter.open_csv(
            args.csv
        )

    # --------------------------------------------------------
    # OFFLINE
    # --------------------------------------------------------

    if args.read:

        analyzer.analyze_pcap(
            args.read
        )

    else:

        try:

            analyzer.capture(
                interface=args.interface,
                packet_count=args.count,
                timeout=args.timeout,
                bpf_filter=args.filter,
                use_session=args.tcp_session,
                show_dashboard=args.dashboard
            )

        except KeyboardInterrupt:

            analyzer.stop()

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    analyzer.save_reports(

        pcap_path=args.pcap,

        csv_path=args.csv,

        json_path=args.json
    )

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    analyzer.print_report()


if __name__ == "__main__":

    main()
