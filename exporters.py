import csv
import json
from pathlib import Path

from scapy.all import wrpcap


class Exporter:

    def __init__(self):

        self.csv_file = None

        self.csv_writer = None

    # ========================================================
    # PCAP
    # ========================================================

    def save_pcap(
        self,
        path,
        packets
    ):

        path = Path(path)

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        wrpcap(
            str(path),
            packets
        )

    # ========================================================
    # CSV
    # ========================================================

    def open_csv(
        self,
        path
    ):

        path = Path(path)

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.csv_file = open(
            path,
            "w",
            newline="",
            encoding="utf-8"
        )

        fields = [

            "timestamp",

            "source",
            "destination",

            "source_mac",
            "destination_mac",

            "protocol",

            "source_port",
            "destination_port",

            "length",

            "ttl",

            "tcp_flags",

            "tcp_seq",
            "tcp_ack",

            "icmp_type",
            "icmp_code",

            "dns_query",
            "dns_response",

            "http_method",
            "http_host",
            "http_path",
            "http_status",

            "tls_server_name",

            "payload_ascii",
            "payload_hex"
        ]

        self.csv_writer = csv.DictWriter(
            self.csv_file,
            fieldnames=fields
        )

        self.csv_writer.writeheader()

    def write_csv(
        self,
        info
    ):

        if not self.csv_writer:
            return

        self.csv_writer.writerow({

            key:
                info.get(key)

            for key in self.csv_writer.fieldnames
        })

        self.csv_file.flush()

    def close_csv(self):

        if self.csv_file:

            self.csv_file.close()

            self.csv_file = None

            self.csv_writer = None

    # ========================================================
    # JSON
    # ========================================================

    def save_json(
        self,
        path,
        statistics,
        flows,
        alerts
    ):

        path = Path(path)

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        report = {

            "statistics":
                statistics,

            "flows":
                flows,

            "alerts":
                alerts
        }

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                default=str
            )