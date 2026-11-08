from pathlib import Path


# ============================================================
# DIRECTORIES
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

CAPTURE_DIR = BASE_DIR / "captures"
REPORT_DIR = BASE_DIR / "reports"

CAPTURE_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)


# ============================================================
# PACKET SETTINGS
# ============================================================

MAX_PAYLOAD_DISPLAY = 128

MAX_PAYLOAD_STORE = 512

LARGE_PACKET_THRESHOLD = 1400


# ============================================================
# FLOW SETTINGS
# ============================================================

FLOW_TIMEOUT = 120

TCP_CLOSED_TIMEOUT = 30


# ============================================================
# DETECTION SETTINGS
# ============================================================

PORT_SCAN_WINDOW = 10

PORT_SCAN_THRESHOLD = 20

SYN_SCAN_THRESHOLD = 15

CONNECTION_BURST_WINDOW = 10

CONNECTION_BURST_THRESHOLD = 50

DNS_BURST_WINDOW = 10

DNS_BURST_THRESHOLD = 30


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_REFRESH = 1.0

TOP_N = 10