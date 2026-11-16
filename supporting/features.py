import numpy as np
import pandas as pd


WINDOW_SECONDS = 10


FEATURES = [
    "connection_count",
    "connections_per_second",
    "unique_destination_ips",
    "unique_destination_ports",
    "destination_ip_entropy",
    "destination_port_entropy",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "S0_count",
    "REJ_count",
    "SF_count",
    "RST_count",
    "S0_ratio",
    "REJ_ratio",
    "no_response_ratio",
    "total_orig_pkts",
    "total_resp_pkts",
    "total_orig_bytes",
    "total_resp_bytes",
    "mean_duration",
    "median_duration",
]


def entropy(series):

    counts = series.value_counts()

    if len(counts) <= 1:
        return 0.0

    p = counts / counts.sum()

    return float(
        -(p * np.log2(p)).sum()
    )


def build_window(g):

    total = len(g)

    states = (
        g["conn_state"]
        .fillna("unknown")
        .astype(str)
    )

    proto = (
        g["proto"]
        .fillna("unknown")
        .astype(str)
    )

    resp_pkts = pd.to_numeric(
        g["resp_pkts"],
        errors="coerce",
    ).fillna(0)

    return {
        "connection_count":
            total,

        "connections_per_second":
            total / WINDOW_SECONDS,

        "unique_destination_ips":
            g["dest_ip_zeek"].nunique(),

        "unique_destination_ports":
            g["dest_port_zeek"].nunique(),

        "destination_ip_entropy":
            entropy(g["dest_ip_zeek"]),

        "destination_port_entropy":
            entropy(g["dest_port_zeek"]),

        "tcp_count":
            int((proto == "tcp").sum()),

        "udp_count":
            int((proto == "udp").sum()),

        "icmp_count":
            int((proto == "icmp").sum()),

        "S0_count":
            int((states == "S0").sum()),

        "REJ_count":
            int((states == "REJ").sum()),

        "SF_count":
            int((states == "SF").sum()),

        "RST_count":
            int(
                states.str.startswith(
                    "RST"
                ).sum()
            ),

        "S0_ratio":
            float(
                (states == "S0").mean()
            ),

        "REJ_ratio":
            float(
                (states == "REJ").mean()
            ),

        "no_response_ratio":
            float(
                (resp_pkts == 0).mean()
            ),

        "total_orig_pkts":
            float(
                pd.to_numeric(
                    g["orig_pkts"],
                    errors="coerce",
                )
                .fillna(0)
                .sum()
            ),

        "total_resp_pkts":
            float(
                resp_pkts.sum()
            ),

        "total_orig_bytes":
            float(
                pd.to_numeric(
                    g["orig_bytes"],
                    errors="coerce",
                )
                .fillna(0)
                .sum()
            ),

        "total_resp_bytes":
            float(
                pd.to_numeric(
                    g["resp_bytes"],
                    errors="coerce",
                )
                .fillna(0)
                .sum()
            ),

        "mean_duration":
            float(
                pd.to_numeric(
                    g["duration"],
                    errors="coerce",
                )
                .fillna(0)
                .mean()
            ),

        "median_duration":
            float(
                pd.to_numeric(
                    g["duration"],
                    errors="coerce",
                )
                .fillna(0)
                .median()
            ),
    }
