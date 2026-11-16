"""Independent offline feature contract. No UNSW-NB15 compatibility is claimed."""

from dataclasses import asdict, dataclass
from decimal import Decimal
import math


SCHEMA_VERSION = "sipymes.offline.ipv4.v1"
EXTRACTOR_VERSION = "1.0.1"
TCP_FLAGS = {"fin": 1, "syn": 2, "rst": 4, "psh": 8,
             "ack": 16, "urg": 32, "ece": 64, "cwr": 128}


@dataclass(frozen=True)
class ExtractionConfig:
    tcp_idle_seconds: float = 120.0
    udp_idle_seconds: float = 30.0
    active_timeout_seconds: float = 300.0
    tshark_timeout_seconds: float = 120.0
    max_packets: int = 1_000_000
    max_active_flows: int = 50_000
    max_flows: int = 100_000

    def __post_init__(self):
        for name in ("tcp_idle_seconds", "udp_idle_seconds", "active_timeout_seconds",
                     "tshark_timeout_seconds"):
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value <= 0):
                raise ValueError(f"{name} must be finite and positive")
            if value > 31_536_000:
                raise ValueError(f"{name} must be at most one year")
            nanoseconds = Decimal(str(value)) * 1_000_000_000
            if nanoseconds < 1:
                raise ValueError(f"{name} must be at least one nanosecond")
            if nanoseconds != nanoseconds.to_integral_value():
                raise ValueError(f"{name} must have nanosecond precision")
        for name in ("max_packets", "max_active_flows", "max_flows"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def to_dict(self):
        return asdict(self)


def feature(value=None, *, reason=None):
    return {"value": value, "status": "ok" if reason is None else "unavailable",
            "reason": reason}


def feature_definitions():
    definitions = {
        "observed_duration_seconds": "last observed timestamp minus first; singleton = 0",
        "transport_protocol": "IPv4 protocol: tcp or udp",
    }
    for direction in ("forward", "reverse"):
        definitions[f"{direction}_packet_count"] = "number of accepted captured packets (including retransmissions)"
        definitions[f"{direction}_ipv4_byte_count"] = "sum of IPv4 total lengths; includes IPv4 and transport headers, excludes Ethernet"
        for stat in ("min", "max", "mean", "population_std"):
            definitions[f"{direction}_ipv4_size_{stat}_bytes"] = f"{stat} of IPv4 total lengths; unavailable without packets"
            definitions[f"{direction}_iat_{stat}_seconds"] = f"{stat} of consecutive same-direction timestamp differences; requires two packets"
        for flag in TCP_FLAGS:
            definitions[f"{direction}_tcp_{flag}_count"] = f"captured TCP packets with {flag.upper()} set; unavailable for UDP"
    return definitions
