import time
from threading import Lock

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from config import TOP_N
from utils import format_endpoint


class Dashboard:

    def __init__(
        self,
        statistics,
        flow_tracker,
        detector
    ):

        self.statistics = statistics

        self.flow_tracker = flow_tracker

        self.detector = detector

        self.running = True

        self.lock = Lock()

    # ========================================================
    # MAIN PANEL
    # ========================================================

    def render(self):

        stats = self.statistics

        # ----------------------------------------------------
        # OVERVIEW
        # ----------------------------------------------------

        overview = Table(
            show_header=False
        )

        overview.add_row(
            "Packets",
            str(stats.total_packets)
        )

        overview.add_row(
            "Traffic",
            f"{stats.total_bytes / 1024:.2f} KB"
        )

        overview.add_row(
            "Packet Rate",
            f"{stats.packet_rate():.2f} pkt/s"
        )

        overview.add_row(
            "Bandwidth",
            f"{stats.byte_rate() / 1024:.2f} KB/s"
        )

        overview.add_row(
            "Active Flows",
            str(
                self.flow_tracker.count()
            )
        )

        # ----------------------------------------------------
        # PROTOCOL TABLE
        # ----------------------------------------------------

        protocols = Table(
            title="Protocols"
        )

        protocols.add_column(
            "Protocol"
        )

        protocols.add_column(
            "Packets",
            justify="right"
        )

        protocols.add_column(
            "%",
            justify="right"
        )

        total = max(
            stats.total_packets,
            1
        )

        for protocol, count in (
            stats.protocols.most_common(
                TOP_N
            )
        ):

            percentage = (
                count / total
            ) * 100

            protocols.add_row(
                protocol,
                str(count),
                f"{percentage:.1f}%"
            )

        # ----------------------------------------------------
        # DESTINATIONS
        # ----------------------------------------------------

        destinations = Table(
            title="Top Destinations"
        )

        destinations.add_column(
            "IP"
        )

        destinations.add_column(
            "Packets",
            justify="right"
        )

        for ip, count in (
            stats.destination_ips.most_common(
                TOP_N
            )
        ):

            destinations.add_row(
                ip,
                str(count)
            )

        # ----------------------------------------------------
        # PORTS
        # ----------------------------------------------------

        ports = Table(
            title="Top Ports"
        )

        ports.add_column(
            "Port"
        )

        ports.add_column(
            "Packets",
            justify="right"
        )

        for port, count in (
            stats.destination_ports.most_common(
                TOP_N
            )
        ):

            ports.add_row(
                str(port),
                str(count)
            )

        # ----------------------------------------------------
        # FLOWS
        # ----------------------------------------------------

        flows = Table(
            title="Top Active Flows"
        )

        flows.add_column(
            "Source"
        )

        flows.add_column(
            "Destination"
        )

        flows.add_column(
            "Protocol"
        )

        flows.add_column(
            "Packets",
            justify="right"
        )

        flows.add_column(
            "Bytes",
            justify="right"
        )

        for flow in self.flow_tracker.top_flows(
            TOP_N
        ):

            flows.add_row(
                format_endpoint(
                    flow.source,
                    flow.source_port
                ),
                format_endpoint(
                    flow.destination,
                    flow.destination_port
                ),
                flow.protocol,
                str(flow.packet_count),
                str(flow.byte_count)
            )

        # ----------------------------------------------------
        # ALERTS
        # ----------------------------------------------------

        alerts = Table(
            title="Security Alerts"
        )

        alerts.add_column(
            "Severity"
        )

        alerts.add_column(
            "Type"
        )

        alerts.add_column(
            "Message"
        )

        for alert in (
            self.detector.alerts[-TOP_N:]
        ):

            alerts.add_row(

                alert["severity"],

                alert["type"],

                alert["message"]
            )

        return Group(

            Panel(
                overview,
                title="Network Overview"
            ),

            protocols,

            destinations,

            ports,

            flows,

            alerts
        )

    # ========================================================
    # RUN
    # ========================================================

    def run(self, is_active=None):

        with Live(
            self.render(),
            refresh_per_second=2
        ) as live:

            while self.running:

                if is_active and not is_active():
                    break

                time.sleep(0.5)

                with self.lock:

                    self.flow_tracker.expire()

                    live.update(
                        self.render()
                    )

    def stop(self):

        self.running = False
