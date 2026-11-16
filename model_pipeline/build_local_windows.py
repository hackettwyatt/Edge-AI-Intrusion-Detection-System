from pathlib import Path

import numpy as np
import pandas as pd


WINDOW_SECONDS = 10

BASE = Path.home() / "ai-ids"

CAMPAIGN_DIR = (
    BASE
    / "data"
    / "experiment"
    / "edge_vs_central_evidence"
)

BENIGN_LOGS = [
    (
        (
            BASE
            / "calibration"
            / "isolated_lab_v1"
            / "unified_ids_v3"
            / "benign_multisource_v3_conn.log"
        ),
        "benign_multisource",
    ),
    (
        (
            BASE
            / "calibration"
            / "isolated_lab_v1"
            / "realistic_baselines"
            / "multisource_benign_recon_domainshift_v1_conn.log"
        ),
        "benign_multisource",
    ),
    (
        (
            BASE
            / "calibration"
            / "isolated_lab_v1"
            / "benign_conn.log"
        ),
        "benign_http_normal",
    ),
]

OUT = (
    BASE
    / "simple_ids"
    / "data"
    / "v4_windows"
    / "local"
    / "local_v4_binary_windows_10s.csv"
)

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


def classify_campaign(path):
    name = path.name.lower()

    if "benign_http" in name:
        return 0, "benign_http"

    if "slowsyn20" in name:
        return 1, "slowsyn20"

    if "syn200" in name:
        return 1, "syn200"

    if "syn20" in name:
        return 1, "syn20"

    if "udp50" in name:
        return 1, "udp50"

    return None, None


def normalize(df):
    out = pd.DataFrame()

    out["ts"] = pd.to_numeric(
        df["ts"],
        errors="coerce",
    )

    out["src_ip"] = (
        df["id.orig_h"]
        .astype(str)
    )

    out["dest_ip"] = (
        df["id.resp_h"]
        .astype(str)
    )

    out["dest_port"] = pd.to_numeric(
        df["id.resp_p"],
        errors="coerce",
    )

    out["proto"] = (
        df["proto"]
        .fillna("unknown")
        .astype(str)
        .str.lower()
    )

    for src, dst in [
        ("duration", "duration"),
        ("orig_bytes", "orig_bytes"),
        ("resp_bytes", "resp_bytes"),
        ("orig_pkts", "orig_pkts"),
        ("resp_pkts", "resp_pkts"),
    ]:
        out[dst] = pd.to_numeric(
            df[src],
            errors="coerce",
        ).fillna(0)

    return out.dropna(
        subset=[
            "ts",
            "src_ip",
            "dest_ip",
        ]
    )


def build_windows(
    df,
    label,
    workload,
    source_file,
):
    df = df.copy()

    df["window"] = (
        df["ts"]
        // WINDOW_SECONDS
    ).astype("int64")

    rows = []

    for (src_ip, window), g in df.groupby(
        ["src_ip", "window"],
        sort=False,
    ):
        total = len(g)

        if total == 0:
            continue

        proto = g["proto"]
        resp_pkts = g["resp_pkts"]

        rows.append(
            {
                "dataset": "LOCAL",

                "src_ip": src_ip,

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
                    g["dest_ip"].nunique(),

                "unique_destination_ports":
                    g["dest_port"].nunique(),

                "destination_ip_entropy":
                    entropy(
                        g["dest_ip"]
                    ),

                "destination_port_entropy":
                    entropy(
                        g["dest_port"]
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
                        proto
                        .str
                        .startswith("icmp")
                        .sum()
                    ),

                "no_response_ratio":
                    float(
                        (resp_pkts == 0)
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

                "label_binary":
                    int(label),

                "workload":
                    workload,

                "source_file":
                    source_file,
            }
        )

    return rows


def load_zeek_ascii(path):
    return pd.read_csv(
        path,
        sep="\t",
        comment="#",
        header=None,
        names=ZEEK_COLUMNS,
        dtype=str,
        low_memory=False,
    )


def main():
    rows = []
    used = 0

    # Controlled campaign CSVs
    for path in sorted(
        CAMPAIGN_DIR.glob(
            "*_zeek_source_window.csv"
        )
    ):
        label, workload = classify_campaign(
            path
        )

        if label is None:
            continue

        print(
            f"Campaign: {path.name} "
            f"-> {workload} "
            f"label={label}"
        )

        df = pd.read_csv(
            path,
            low_memory=False,
        )

        normalized = normalize(df)

        rows.extend(
            build_windows(
                normalized,
                label,
                workload,
                path.name,
            )
        )

        used += 1

    # Additional benign raw Zeek captures
    for path, workload in BENIGN_LOGS:
        if not path.exists():
            print(
                "Missing benign log:",
                path
            )
            continue

        print(
            f"Benign log: {path.name} "
            f"-> {workload} "
            f"label=0"
        )

        df = load_zeek_ascii(path)

        normalized = normalize(df)

        rows.extend(
            build_windows(
                normalized,
                0,
                workload,
                path.name,
            )
        )

        used += 1

    if not rows:
        raise RuntimeError(
            "No local V4 windows created."
        )

    out = pd.DataFrame(rows)

    OUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    out.to_csv(
        OUT,
        index=False,
    )

    print()
    print("=" * 70)
    print("LOCAL V4 WINDOWS")
    print("=" * 70)

    print(
        "Source files used:",
        used,
    )

    print(
        "Windows:",
        len(out),
    )

    print()
    print("Labels:")
    print(
        out["label_binary"]
        .value_counts()
        .sort_index()
    )

    print()
    print("By workload:")
    print(
        pd.crosstab(
            out["workload"],
            out["label_binary"],
        )
    )

    print()
    print("Files per workload:")
    print(
        out.groupby(
            "workload"
        )["source_file"]
        .nunique()
    )

    print()
    print(
        "Saved:",
        OUT,
    )


if __name__ == "__main__":
    main()
