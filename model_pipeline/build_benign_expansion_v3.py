from pathlib import Path

import numpy as np
import pandas as pd


BASE = Path.home() / "ai-ids"

INPUT_DIR = (
    BASE
    / "calibration"
    / "isolated_lab_v2"
    / "benign_expansion_train"
)

OUTPUT = (
    BASE
    / "simple_ids"
    / "data"
    / "v4_windows"
    / "local"
    / "benign_expansion_v3_windows.csv"
)

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
    "no_response_ratio",
    "total_orig_pkts",
    "total_resp_pkts",
    "total_orig_bytes",
    "total_resp_bytes",
    "mean_duration",
    "median_duration",
]

ZEEK_COLUMNS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
    "ip_proto",
]


def entropy(series):
    counts = series.value_counts()

    if len(counts) <= 1:
        return 0.0

    p = counts / counts.sum()

    return float(
        -(p * np.log2(p)).sum()
    )


def load_zeek(path):
    df = pd.read_csv(
        path,
        sep="\t",
        comment="#",
        header=None,
        names=ZEEK_COLUMNS,
        dtype=str,
        low_memory=False,
    )

    for col in [
        "ts",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "id.resp_p",
    ]:
        df[col] = pd.to_numeric(
            df[col],
            errors="coerce",
        )

    df = df.dropna(
        subset=[
            "ts",
            "id.orig_h",
            "id.resp_h",
        ]
    ).copy()

    for col in [
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
    ]:
        df[col] = df[col].fillna(0)

    df["proto_norm"] = (
        df["proto"]
        .fillna("unknown")
        .astype(str)
        .str.lower()
    )

    df["window_start"] = (
        (df["ts"] // 10) * 10
    ).astype("int64")

    return df


def build_windows(path):
    df = load_zeek(path)

    rows = []

    workload = (
        path.stem
        .replace("_conn", "")
    )

    for (src, window), g in df.groupby(
        [
            "id.orig_h",
            "window_start",
        ],
        sort=False,
    ):
        proto = g["proto_norm"]

        rows.append(
            {
                "dataset": "LOCAL_EXPANSION_V3",
                "src_ip": src,
                "window_start": int(window),

                "connection_count":
                    len(g),

                "connections_per_second":
                    len(g) / 10,

                "unique_destination_ips":
                    g["id.resp_h"].nunique(),

                "unique_destination_ports":
                    g["id.resp_p"].nunique(),

                "destination_ip_entropy":
                    entropy(g["id.resp_h"]),

                "destination_port_entropy":
                    entropy(g["id.resp_p"]),

                "tcp_count":
                    int((proto == "tcp").sum()),

                "udp_count":
                    int((proto == "udp").sum()),

                "icmp_count":
                    int(
                        proto.str
                        .startswith("icmp")
                        .sum()
                    ),

                "no_response_ratio":
                    float(
                        (g["resp_pkts"] == 0)
                        .mean()
                    ),

                "total_orig_pkts":
                    float(
                        g["orig_pkts"].sum()
                    ),

                "total_resp_pkts":
                    float(
                        g["resp_pkts"].sum()
                    ),

                "total_orig_bytes":
                    float(
                        g["orig_bytes"].sum()
                    ),

                "total_resp_bytes":
                    float(
                        g["resp_bytes"].sum()
                    ),

                "mean_duration":
                    float(
                        g["duration"].mean()
                    ),

                "median_duration":
                    float(
                        g["duration"].median()
                    ),

                "label_binary": 0,
                "workload": workload,
                "source_file": path.name,
                "split_group":
                    f"EXPANSION_TRAIN::{path.name}",
            }
        )

    return pd.DataFrame(rows)


def main():
    files = sorted(
        INPUT_DIR.glob(
            "*_conn.log"
        )
    )

    if not files:
        raise SystemExit(
            "No expansion training logs found."
        )

    frames = []

    for path in files:
        windows = build_windows(path)

        frames.append(windows)

        print(
            f"{path.name}: "
            f"{len(windows)} windows"
        )

    out = pd.concat(
        frames,
        ignore_index=True,
    )

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    out.to_csv(
        OUTPUT,
        index=False,
    )

    print()
    print("=" * 80)
    print("BENIGN EXPANSION V3")
    print("=" * 80)

    print(
        "Connections represented:",
        sum(
            pd.read_csv(
                p,
                sep="\t",
                comment="#",
                header=None,
            ).shape[0]
            for p in files
        )
    )

    print(
        "Windows:",
        len(out)
    )

    print()
    print("By workload:")

    print(
        out.groupby("workload")
        .agg(
            windows=("label_binary", "size"),
            median_connections=(
                "connection_count",
                "median",
            ),
            median_dest_ips=(
                "unique_destination_ips",
                "median",
            ),
            median_dest_ports=(
                "unique_destination_ports",
                "median",
            ),
            max_connections=(
                "connection_count",
                "max",
            ),
        )
        .to_string()
    )

    print()
    print("All windows:")

    print(
        out[
            [
                "workload",
                "src_ip",
                "window_start",
                "connection_count",
                "unique_destination_ips",
                "unique_destination_ports",
                "destination_ip_entropy",
                "destination_port_entropy",
                "total_orig_bytes",
                "total_resp_bytes",
                "mean_duration",
            ]
        ]
        .round(6)
        .to_string(index=False)
    )

    print()
    print(
        "Saved:",
        OUTPUT,
    )


if __name__ == "__main__":
    main()
