from pathlib import Path

import numpy as np
import pandas as pd


WINDOW_SECONDS = 10

BASE = Path.home() / "ai-ids"
RAW = BASE / "data" / "unsw-nb15" / "raw"
OUT = BASE / "simple_ids" / "data" / "v4_windows" / "unsw"

FEATURE_NAMES = [
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

COLUMNS = [
    "srcip",
    "sport",
    "dstip",
    "dsport",
    "proto",
    "state",
    "dur",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
    "sloss",
    "dloss",
    "service",
    "Sload",
    "Dload",
    "Spkts",
    "Dpkts",
    "swin",
    "dwin",
    "stcpb",
    "dtcpb",
    "smeansz",
    "dmeansz",
    "trans_depth",
    "res_bdy_len",
    "Sjit",
    "Djit",
    "Stime",
    "Ltime",
    "Sintpkt",
    "Dintpkt",
    "tcprtt",
    "synack",
    "ackdat",
    "is_sm_ips_ports",
    "ct_state_ttl",
    "ct_flw_http_mthd",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_srv_src",
    "ct_srv_dst",
    "ct_dst_ltm",
    "ct_src_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "attack_cat",
    "Label",
]


def entropy(series):
    counts = series.value_counts()

    if len(counts) <= 1:
        return 0.0

    p = counts / counts.sum()

    return float(
        -(p * np.log2(p)).sum()
    )


def load_unsw():
    frames = []

    for i in range(1, 5):
        path = RAW / f"UNSW-NB15_{i}.csv"

        print("Loading:", path.name)

        df = pd.read_csv(
            path,
            names=COLUMNS,
            header=None,
            low_memory=False,
        )

        df["source_file"] = path.name

        frames.append(df)

    return pd.concat(
        frames,
        ignore_index=True,
    )


def build_windows(df):
    df = df.copy()

    numeric_cols = [
        "dur",
        "sbytes",
        "dbytes",
        "Spkts",
        "Dpkts",
        "Stime",
        "dsport",
        "Label",
    ]

    for col in numeric_cols:
        df[col] = pd.to_numeric(
            df[col],
            errors="coerce",
        )

    df = df.dropna(
        subset=[
            "srcip",
            "dstip",
            "Stime",
            "Label",
        ]
    )

    df["Label"] = (
        df["Label"]
        .astype(int)
    )

    df["window"] = (
        df["Stime"]
        // WINDOW_SECONDS
    ).astype("int64")

    rows = []

    groups = df.groupby(
        [
            "srcip",
            "window",
        ],
        sort=False,
    )

    for (src_ip, window), g in groups:

        total = len(g)

        if total == 0:
            continue

        proto = (
            g["proto"]
            .fillna("unknown")
            .astype(str)
            .str.lower()
        )

        resp_pkts = (
            pd.to_numeric(
                g["Dpkts"],
                errors="coerce",
            )
            .fillna(0)
        )

        row = {
            "dataset":
                "UNSW-NB15",

            "src_ip":
                src_ip,

            "window_start":
                int(
                    window
                    * WINDOW_SECONDS
                ),

            "connection_count":
                total,

            "connections_per_second":
                total
                / WINDOW_SECONDS,

            "unique_destination_ips":
                g["dstip"].nunique(),

            "unique_destination_ports":
                g["dsport"].nunique(),

            "destination_ip_entropy":
                entropy(
                    g["dstip"]
                ),

            "destination_port_entropy":
                entropy(
                    g["dsport"]
                ),

            "tcp_count":
                int(
                    (proto == "tcp")
                    .sum()
                ),

            "udp_count":
                int(
                    (proto == "udp")
                    .sum()
                ),

            "icmp_count":
                int(
                    proto.str.startswith(
                        "icmp"
                    ).sum()
                ),

            "no_response_ratio":
                float(
                    (resp_pkts == 0)
                    .mean()
                ),

            "total_orig_pkts":
                float(
                    pd.to_numeric(
                        g["Spkts"],
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
                        g["sbytes"],
                        errors="coerce",
                    )
                    .fillna(0)
                    .sum()
                ),

            "total_resp_bytes":
                float(
                    pd.to_numeric(
                        g["dbytes"],
                        errors="coerce",
                    )
                    .fillna(0)
                    .sum()
                ),

            "mean_duration":
                float(
                    pd.to_numeric(
                        g["dur"],
                        errors="coerce",
                    )
                    .fillna(0)
                    .mean()
                ),

            "median_duration":
                float(
                    pd.to_numeric(
                        g["dur"],
                        errors="coerce",
                    )
                    .fillna(0)
                    .median()
                ),

            "label_binary":
                int(
                    g["Label"].max()
                ),

            "attack_categories":
                "|".join(
                    sorted(
                        {
                            str(x).strip()
                            for x
                            in g[
                                "attack_cat"
                            ].dropna()
                            if str(x).strip()
                        }
                    )
                ),
        }

        rows.append(row)

    return pd.DataFrame(rows)


def main():
    OUT.mkdir(
        parents=True,
        exist_ok=True,
    )

    df = load_unsw()

    print()
    print("=" * 70)
    print("UNSW CONNECTION DATA")
    print("=" * 70)

    print(
        "Connections:",
        f"{len(df):,}"
    )

    print(
        "BENIGN:",
        f"{int((pd.to_numeric(df['Label'], errors='coerce') == 0).sum()):,}"
    )

    print(
        "ATTACK:",
        f"{int((pd.to_numeric(df['Label'], errors='coerce') == 1).sum()):,}"
    )

    windows = build_windows(df)

    out_file = (
        OUT
        / "UNSW-NB15_binary_windows_10s.csv"
    )

    windows.to_csv(
        out_file,
        index=False,
    )

    print()
    print("=" * 70)
    print("UNSW 10-SECOND WINDOWS")
    print("=" * 70)

    print(
        "Windows:",
        f"{len(windows):,}"
    )

    print(
        "BENIGN windows:",
        f"{int((windows['label_binary'] == 0).sum()):,}"
    )

    print(
        "ATTACK windows:",
        f"{int((windows['label_binary'] == 1).sum()):,}"
    )

    print()
    print(
        "Feature count:",
        len(FEATURE_NAMES)
    )

    print(
        "Saved:",
        out_file
    )


if __name__ == "__main__":
    main()
