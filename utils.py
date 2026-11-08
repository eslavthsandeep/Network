from datetime import datetime
import ipaddress


def timestamp():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def is_private_ip(value):

    try:
        return ipaddress.ip_address(
            value
        ).is_private

    except ValueError:
        return False


def safe_decode(data, limit=200):

    if not data:
        return ""

    return data[:limit].decode(
        "utf-8",
        errors="replace"
    )


def hex_dump(data, width=16, limit=128):

    if not data:
        return ""

    data = data[:limit]

    lines = []

    for offset in range(
        0,
        len(data),
        width
    ):

        chunk = data[
            offset:
            offset + width
        ]

        hex_part = " ".join(
            f"{byte:02x}"
            for byte in chunk
        )

        ascii_part = "".join(
            chr(byte)
            if 32 <= byte <= 126
            else "."
            for byte in chunk
        )

        lines.append(
            f"{offset:04x}  "
            f"{hex_part:<48}  "
            f"{ascii_part}"
        )

    return "\n".join(lines)


def format_endpoint(
    ip,
    port=None
):

    if not ip:
        return "-"

    if port is None:
        return ip

    return f"{ip}:{port}"


def normalize_bytes(value):

    if isinstance(value, bytes):

        return value.decode(
            "utf-8",
            errors="replace"
        )

    if value is None:

        return None

    return str(value)