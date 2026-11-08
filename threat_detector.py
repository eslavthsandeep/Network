from collections import defaultdict, deque
from datetime import datetime, timedelta

from config import (
    LARGE_PACKET_THRESHOLD,
    PORT_SCAN_WINDOW,
    PORT_SCAN_THRESHOLD,
    SYN_SCAN_THRESHOLD,
    CONNECTION_BURST_WINDOW,
    CONNECTION_BURST_THRESHOLD,
    DNS_BURST_WINDOW,
    DNS_BURST_THRESHOLD
)


class ThreatDetector:

    def __init__(self):

        self.alerts = []

        self.port_history = defaultdict(
            deque
        )

        self.syn_history = defaultdict(
            deque
        )

        self.connection_history = defaultdict(
            deque
        )

        self.dns_history = defaultdict(
            deque
        )

        self.rst_history = defaultdict(
            deque
        )

        self.icmp_history = defaultdict(
            deque
        )

        self.reported = set()

    # ========================================================
    # HELPER
    # ========================================================

    def _cleanup(
        self,
        queue,
        now,
        window
    ):

        cutoff = (
            now -
            timedelta(
                seconds=window
            )
        )

        while (
            queue
            and queue[0] < cutoff
        ):

            queue.popleft()

    # ========================================================
    # ALERT
    # ========================================================

    def alert(
        self,
        alert_type,
        severity,
        message,
        source=None,
        destination=None
    ):

        key = (
            alert_type,
            source,
            destination
        )

        if key in self.reported:

            return

        self.reported.add(key)

        alert = {

            "time":
                datetime.now().isoformat(),

            "type":
                alert_type,

            "severity":
                severity,

            "source":
                source,

            "destination":
                destination,

            "message":
                message
        }

        self.alerts.append(
            alert
        )

        return alert

    # ========================================================
    # ANALYZE
    # ========================================================

    def analyze(
        self,
        info
    ):

        now = datetime.now()

        alerts = []

        source = info.get(
            "source"
        )

        destination = info.get(
            "destination"
        )

        protocol = info.get(
            "protocol"
        )

        port = info.get(
            "destination_port"
        )

        length = info.get(
            "length",
            0
        )

        flags = info.get(
            "tcp_flags"
        )

        # ----------------------------------------------------
        # LARGE PACKET
        # ----------------------------------------------------

        if length >= LARGE_PACKET_THRESHOLD:

            result = self.alert(
                "LARGE_PACKET",
                "LOW",
                (
                    f"Large packet detected "
                    f"({length} bytes)"
                ),
                source,
                destination
            )

            if result:
                alerts.append(result)

        # ----------------------------------------------------
        # SENSITIVE PORTS
        # ----------------------------------------------------

        sensitive_ports = {

            21: "FTP",

            23: "Telnet",

            139: "NetBIOS",

            445: "SMB",

            3389: "RDP",

            5900: "VNC"
        }

        if port in sensitive_ports:

            service = sensitive_ports[
                port
            ]

            result = self.alert(
                "SENSITIVE_SERVICE",
                "MEDIUM",
                (
                    f"Traffic to "
                    f"{service} on port {port}"
                ),
                source,
                destination
            )

            if result:
                alerts.append(result)

        # ----------------------------------------------------
        # SYN
        # ----------------------------------------------------

        if (
            protocol in ("TCP", "HTTP", "TLS")
            and flags
            and "S" in flags
            and "A" not in flags
            and source
        ):

            queue = self.syn_history[
                source
            ]

            queue.append(now)

            self._cleanup(
                queue,
                now,
                PORT_SCAN_WINDOW
            )

            if len(queue) >= SYN_SCAN_THRESHOLD:

                result = self.alert(
                    "SYN_BURST",
                    "MEDIUM",
                    (
                        f"High SYN rate from "
                        f"{source}: "
                        f"{len(queue)} SYNs"
                    ),
                    source,
                    destination
                )

                if result:
                    alerts.append(result)

        # ----------------------------------------------------
        # PORT SCAN
        # ----------------------------------------------------

        if (
            source
            and port is not None
        ):

            queue = self.port_history[
                source
            ]

            queue.append(
                (now, port)
            )

            cutoff = (
                now -
                timedelta(
                    seconds=PORT_SCAN_WINDOW
                )
            )

            while (
                queue
                and queue[0][0] < cutoff
            ):

                queue.popleft()

            unique_ports = {
                item[1]
                for item in queue
            }

            if (
                len(unique_ports)
                >= PORT_SCAN_THRESHOLD
            ):

                result = self.alert(
                    "POSSIBLE_PORT_SCAN",
                    "HIGH",
                    (
                        f"{source} contacted "
                        f"{len(unique_ports)} "
                        f"different ports within "
                        f"{PORT_SCAN_WINDOW} seconds"
                    ),
                    source,
                    destination
                )

                if result:
                    alerts.append(result)

        # ----------------------------------------------------
        # CONNECTION BURST
        # ----------------------------------------------------

        if source:

            queue = self.connection_history[
                source
            ]

            queue.append(now)

            self._cleanup(
                queue,
                now,
                CONNECTION_BURST_WINDOW
            )

            if (
                len(queue)
                >= CONNECTION_BURST_THRESHOLD
            ):

                result = self.alert(
                    "CONNECTION_BURST",
                    "MEDIUM",
                    (
                        f"High connection activity "
                        f"from {source}"
                    ),
                    source,
                    destination
                )

                if result:
                    alerts.append(result)

        # ----------------------------------------------------
        # DNS BURST
        # ----------------------------------------------------

        if (
            protocol == "DNS"
            and source
        ):

            queue = self.dns_history[
                source
            ]

            queue.append(now)

            self._cleanup(
                queue,
                now,
                DNS_BURST_WINDOW
            )

            if (
                len(queue)
                >= DNS_BURST_THRESHOLD
            ):

                result = self.alert(
                    "DNS_BURST",
                    "MEDIUM",
                    (
                        f"High DNS query rate "
                        f"from {source}"
                    ),
                    source,
                    destination
                )

                if result:
                    alerts.append(result)

        # ----------------------------------------------------
        # TCP RESET BURST
        # ----------------------------------------------------

        if (
            protocol in ("TCP", "HTTP", "TLS")
            and flags
            and "R" in flags
            and source
        ):

            queue = self.rst_history[
                source
            ]

            queue.append(now)

            self._cleanup(
                queue,
                now,
                10
            )

            if len(queue) >= 20:

                result = self.alert(
                    "TCP_RESET_BURST",
                    "MEDIUM",
                    (
                        f"High TCP RST rate "
                        f"from {source}"
                    ),
                    source,
                    destination
                )

                if result:
                    alerts.append(result)

        # ----------------------------------------------------
        # ICMP BURST
        # ----------------------------------------------------

        if (
            protocol in (
                "ICMP",
                "ICMPv6"
            )
            and source
        ):

            queue = self.icmp_history[
                source
            ]

            queue.append(now)

            self._cleanup(
                queue,
                now,
                10
            )

            if len(queue) >= 50:

                result = self.alert(
                    "ICMP_BURST",
                    "MEDIUM",
                    (
                        f"High ICMP rate "
                        f"from {source}"
                    ),
                    source,
                    destination
                )

                if result:
                    alerts.append(result)

        return alerts

    # ========================================================
    # SUMMARY
    # ========================================================

    def summary(self):

        result = defaultdict(int)

        for alert in self.alerts:

            result[
                alert["severity"]
            ] += 1

        return dict(result)
