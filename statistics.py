from collections import Counter
from datetime import datetime


class Statistics:

    def __init__(self):

        self.started = datetime.now()

        self.total_packets = 0

        self.total_bytes = 0

        self.protocols = Counter()

        self.source_ips = Counter()

        self.destination_ips = Counter()

        self.destination_ports = Counter()

        self.source_ports = Counter()

        self.tcp_flags = Counter()

        self.dns_queries = Counter()

        self.http_hosts = Counter()

        self.tls_servers = Counter()

        self.icmp_types = Counter()

        self.packet_sizes = []

    # ========================================================
    # UPDATE
    # ========================================================

    def update(
        self,
        info
    ):

        self.total_packets += 1

        length = info.get(
            "length",
            0
        )

        self.total_bytes += length

        self.packet_sizes.append(
            length
        )

        protocol = info.get(
            "protocol",
            "OTHER"
        )

        self.protocols[
            protocol
        ] += 1

        source = info.get(
            "source"
        )

        destination = info.get(
            "destination"
        )

        if source:

            self.source_ips[
                source
            ] += 1

        if destination:

            self.destination_ips[
                destination
            ] += 1

        source_port = info.get(
            "source_port"
        )

        destination_port = info.get(
            "destination_port"
        )

        if source_port is not None:

            self.source_ports[
                source_port
            ] += 1

        if destination_port is not None:

            self.destination_ports[
                destination_port
            ] += 1

        flags = info.get(
            "tcp_flags"
        )

        if flags:

            self.tcp_flags[
                flags
            ] += 1

        query = info.get(
            "dns_query"
        )

        if query:

            self.dns_queries[
                query
            ] += 1

        host = info.get(
            "http_host"
        )

        if host:

            self.http_hosts[
                host
            ] += 1

        server = info.get(
            "tls_server_name"
        )

        if server:

            self.tls_servers[
                server
            ] += 1

        icmp_type = info.get(
            "icmp_type"
        )

        if icmp_type is not None:

            self.icmp_types[
                icmp_type
            ] += 1

    # ========================================================
    # RATE
    # ========================================================

    def elapsed(self):

        return (
            datetime.now() -
            self.started
        ).total_seconds()

    def packet_rate(self):

        elapsed = self.elapsed()

        if elapsed <= 0:
            return 0

        return (
            self.total_packets /
            elapsed
        )

    def byte_rate(self):

        elapsed = self.elapsed()

        if elapsed <= 0:
            return 0

        return (
            self.total_bytes /
            elapsed
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    def summary(
        self,
        flow_count=0
    ):

        return {

            "packets":
                self.total_packets,

            "bytes":
                self.total_bytes,

            "duration":
                round(
                    self.elapsed(),
                    2
                ),

            "packets_per_second":
                round(
                    self.packet_rate(),
                    2
                ),

            "bytes_per_second":
                round(
                    self.byte_rate(),
                    2
                ),

            "flows":
                flow_count,

            "protocols":
                dict(
                    self.protocols
                ),

            "top_sources":
                self.source_ips.most_common(10),

            "top_destinations":
                self.destination_ips.most_common(10),

            "top_ports":
                self.destination_ports.most_common(10),

            "tcp_flags":
                dict(
                    self.tcp_flags
                ),

            "dns_queries":
                self.dns_queries.most_common(20),

            "http_hosts":
                self.http_hosts.most_common(20),

            "tls_servers":
                self.tls_servers.most_common(20),

            "icmp_types":
                dict(
                    self.icmp_types
                )
        }