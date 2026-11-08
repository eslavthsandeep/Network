from scapy.all import (
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ARP,
    DNS,
    DNSQR,
    Raw
)

from scapy.layers.http import (
    HTTPRequest,
    HTTPResponse
)

from scapy.layers.tls.handshake import (
    TLSClientHello,
    TLSServerHello
)

from utils import (
    normalize_bytes,
    safe_decode
)


class PacketAnalyzer:

    def analyze(self, packet):

        info = {

            "timestamp":
                packet.time,

            "length":
                len(packet),

            "protocol":
                "OTHER",

            "source":
                None,

            "destination":
                None,

            "source_mac":
                None,

            "destination_mac":
                None,

            "source_port":
                None,

            "destination_port":
                None,

            "ttl":
                None,

            "tcp_flags":
                None,

            "tcp_seq":
                None,

            "tcp_ack":
                None,

            "icmp_type":
                None,

            "icmp_code":
                None,

            "dns_query":
                None,

            "dns_response":
                None,

            "http_method":
                None,

            "http_host":
                None,

            "http_path":
                None,

            "http_status":
                None,

            "tls_server_name":
                None,

            "payload":
                None,

            "payload_ascii":
                None,

            "payload_hex":
                None
        }

        # ====================================================
        # ETHERNET
        # ====================================================

        if packet.haslayer("Ether"):

            ethernet = packet["Ether"]

            info["source_mac"] = ethernet.src

            info["destination_mac"] = ethernet.dst

        # ====================================================
        # ARP
        # ====================================================

        if ARP in packet:

            arp = packet[ARP]

            info["protocol"] = "ARP"

            info["source"] = arp.psrc

            info["destination"] = arp.pdst

            return info

        # ====================================================
        # IPV4
        # ====================================================

        if IP in packet:

            ip = packet[IP]

            info["source"] = ip.src

            info["destination"] = ip.dst

            info["ttl"] = ip.ttl

        # ====================================================
        # IPV6
        # ====================================================

        elif IPv6 in packet:

            ip = packet[IPv6]

            info["source"] = ip.src

            info["destination"] = ip.dst

            info["ttl"] = ip.hlim

        else:

            return info

        # ====================================================
        # TCP
        # ====================================================

        if TCP in packet:

            tcp = packet[TCP]

            info["protocol"] = "TCP"

            info["source_port"] = tcp.sport

            info["destination_port"] = tcp.dport

            info["tcp_flags"] = str(
                tcp.flags
            )

            info["tcp_seq"] = tcp.seq

            info["tcp_ack"] = tcp.ack

        # ====================================================
        # UDP
        # ====================================================

        elif UDP in packet:

            udp = packet[UDP]

            info["protocol"] = "UDP"

            info["source_port"] = udp.sport

            info["destination_port"] = udp.dport

        # ====================================================
        # ICMP
        # ====================================================

        elif ICMP in packet:

            icmp = packet[ICMP]

            info["protocol"] = "ICMP"

            info["icmp_type"] = icmp.type

            info["icmp_code"] = icmp.code

        elif (
            ICMPv6EchoRequest in packet
            or ICMPv6EchoReply in packet
        ):

            info["protocol"] = "ICMPv6"

        # ====================================================
        # DNS
        # ====================================================

        if DNS in packet:

            info["protocol"] = "DNS"

            dns = packet[DNS]

            info["dns_response"] = bool(
                dns.qr
            )

            if dns.qd is not None:

                try:

                    query = dns[DNSQR].qname

                    info["dns_query"] = (
                        normalize_bytes(
                            query
                        ).rstrip(".")
                    )

                except Exception:
                    pass

        # ====================================================
        # HTTP REQUEST
        # ====================================================

        if HTTPRequest in packet:

            info["protocol"] = "HTTP"

            http = packet[
                HTTPRequest
            ]

            try:

                info["http_method"] = (
                    normalize_bytes(
                        http.Method
                    )
                )

                info["http_host"] = (
                    normalize_bytes(
                        http.Host
                    )
                )

                info["http_path"] = (
                    normalize_bytes(
                        http.Path
                    )
                )

            except Exception:
                pass

        # ====================================================
        # HTTP RESPONSE
        # ====================================================

        if HTTPResponse in packet:

            info["protocol"] = "HTTP"

            http = packet[
                HTTPResponse
            ]

            try:

                info["http_status"] = (
                    normalize_bytes(
                        http.Status_Code
                    )
                )

            except Exception:
                pass

        # ====================================================
        # TLS
        # ====================================================

        if TLSClientHello in packet:

            info["protocol"] = "TLS"

            try:

                hello = packet[
                    TLSClientHello
                ]

                extensions = getattr(
                    hello,
                    "ext",
                    []
                )

                for extension in extensions:

                    servernames = getattr(
                        extension,
                        "servernames",
                        None
                    )

                    if servernames:

                        for servername in servernames:

                            value = getattr(
                                servername,
                                "servername",
                                None
                            )

                            if value:

                                info[
                                    "tls_server_name"
                                ] = normalize_bytes(
                                    value
                                )

                                break

            except Exception:
                pass

        elif TLSServerHello in packet:

            info["protocol"] = "TLS"

        # ====================================================
        # RAW PAYLOAD
        # ====================================================

        if Raw in packet:

            try:

                payload = packet[
                    Raw
                ].load

                info["payload"] = payload

                info["payload_ascii"] = (
                    safe_decode(
                        payload,
                        512
                    )
                )

                info["payload_hex"] = (
                    payload[
                        :512
                    ].hex()
                )

            except Exception:
                pass

        return info