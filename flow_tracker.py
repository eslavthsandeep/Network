from collections import OrderedDict
from datetime import datetime


class Flow:

    def __init__(
        self,
        source,
        source_port,
        destination,
        destination_port,
        protocol
    ):

        self.source = source

        self.source_port = source_port

        self.destination = destination

        self.destination_port = destination_port

        self.protocol = protocol

        self.start_time = datetime.now()

        self.last_seen = self.start_time

        self.packet_count = 0

        self.byte_count = 0

        self.forward_packets = 0

        self.reverse_packets = 0

        self.forward_bytes = 0

        self.reverse_bytes = 0

        self.syn_count = 0

        self.syn_ack_count = 0

        self.fin_count = 0

        self.rst_count = 0

        self.ack_count = 0

    # ========================================================
    # UPDATE
    # ========================================================

    def update(
        self,
        packet,
        direction
    ):

        now = datetime.now()

        self.last_seen = now

        self.packet_count += 1

        size = len(packet)

        self.byte_count += size

        if direction == "forward":

            self.forward_packets += 1

            self.forward_bytes += size

        else:

            self.reverse_packets += 1

            self.reverse_bytes += size

        if hasattr(
            packet,
            "haslayer"
        ):

            from scapy.all import TCP

            if TCP in packet:

                flags = str(
                    packet[TCP].flags
                )

                if "S" in flags:
                    self.syn_count += 1

                if (
                    "S" in flags
                    and "A" in flags
                ):

                    self.syn_ack_count += 1

                if "F" in flags:
                    self.fin_count += 1

                if "R" in flags:
                    self.rst_count += 1

                if "A" in flags:
                    self.ack_count += 1

    # ========================================================
    # DURATION
    # ========================================================

    @property
    def duration(self):

        return (
            self.last_seen -
            self.start_time
        ).total_seconds()

    # ========================================================
    # SERIALIZATION
    # ========================================================

    def to_dict(self):

        return {

            "source":
                self.source,

            "source_port":
                self.source_port,

            "destination":
                self.destination,

            "destination_port":
                self.destination_port,

            "protocol":
                self.protocol,

            "start":
                self.start_time.isoformat(),

            "last_seen":
                self.last_seen.isoformat(),

            "duration":
                round(
                    self.duration,
                    3
                ),

            "packets":
                self.packet_count,

            "bytes":
                self.byte_count,

            "forward_packets":
                self.forward_packets,

            "reverse_packets":
                self.reverse_packets,

            "forward_bytes":
                self.forward_bytes,

            "reverse_bytes":
                self.reverse_bytes,

            "syn":
                self.syn_count,

            "syn_ack":
                self.syn_ack_count,

            "fin":
                self.fin_count,

            "rst":
                self.rst_count,

            "ack":
                self.ack_count
        }


class FlowTracker:

    def __init__(
        self,
        timeout=120
    ):

        self.timeout = timeout

        self.flows = OrderedDict()

    # ========================================================
    # KEY
    # ========================================================

    def _key(
        self,
        source,
        source_port,
        destination,
        destination_port,
        protocol
    ):

        endpoint_a = (
            str(source),
            str(source_port)
        )

        endpoint_b = (
            str(destination),
            str(destination_port)
        )

        ordered = sorted([
            endpoint_a,
            endpoint_b
        ])

        transport = (
            "TCP"
            if protocol in ("TCP", "HTTP", "TLS")
            else (
                "UDP"
                if protocol in ("UDP", "DNS")
                else protocol
            )
        )

        return (
            ordered[0],
            ordered[1],
            transport
        )

    # ========================================================
    # UPDATE
    # ========================================================

    def update(
        self,
        packet,
        info
    ):

        source = info.get(
            "source"
        )

        destination = info.get(
            "destination"
        )

        source_port = info.get(
            "source_port"
        )

        destination_port = info.get(
            "destination_port"
        )

        protocol = info.get(
            "protocol"
        )

        if not source or not destination:
            return None

        key = self._key(
            source,
            source_port,
            destination,
            destination_port,
            protocol
        )

        if key not in self.flows:

            self.flows[key] = Flow(
                source,
                source_port,
                destination,
                destination_port,
                protocol
            )

            direction = "forward"

        else:

            flow = self.flows[key]

            if flow.protocol in ("TCP", "UDP") and protocol not in ("TCP", "UDP", "OTHER"):
                flow.protocol = protocol

            if (
                flow.source == source
                and
                flow.source_port == source_port
            ):

                direction = "forward"

            else:

                direction = "reverse"

        flow = self.flows[key]

        flow.update(
            packet,
            direction
        )

        return flow

    # ========================================================
    # EXPIRE
    # ========================================================

    def expire(self):

        now = datetime.now()

        expired = []

        for key, flow in self.flows.items():

            age = (
                now - flow.last_seen
            ).total_seconds()

            if age > self.timeout:

                expired.append(key)

        for key in expired:

            del self.flows[key]

    # ========================================================
    # TOP FLOWS
    # ========================================================

    def top_flows(
        self,
        count=10
    ):

        return sorted(
            self.flows.values(),
            key=lambda f: f.byte_count,
            reverse=True
        )[:count]

    def count(self):

        return len(self.flows)
