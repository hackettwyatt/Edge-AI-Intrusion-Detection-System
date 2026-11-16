from pathlib import Path

import pandas as pd


BASE = Path.home() / "ai-ids"

UWF = (
    BASE
    / "simple_ids"
    / "data"
    / "v4_windows"
    / "uwf_binary_windows_10s_all.csv"
)

UNSW = (
    BASE
    / "simple_ids"
    / "data"
    / "v4_windows"
    / "unsw"
    / "UNSW-NB15_binary_windows_10s.csv"
)

OUT = (
    BASE
    / "simple_ids"
    / "data"
    / "v4_windows"
    / "combined_v4_binary_windows_10s.csv"
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


def main():

    uwf = pd.read_csv(UWF)
    unsw = pd.read_csv(UNSW)

    print("=" * 70)
    print("INPUT DATASETS")
    print("=" * 70)

    print(
        "UWF:",
        f"{len(uwf):,}"
    )

    print(
        "UNSW:",
        f"{len(unsw):,}"
    )

    required = (
        FEATURES
        + [
            "dataset",
            "src_ip",
            "window_start",
            "label_binary",
        ]
    )

    for name, df in [
        ("UWF", uwf),
        ("UNSW", unsw),
    ]:

        missing = [
            col
            for col in required
            if col not in df.columns
        ]

        if missing:
            raise RuntimeError(
                f"{name} missing columns: "
                f"{missing}"
            )

    uwf_out = uwf[
        required
    ].copy()

    unsw_out = unsw[
        required
    ].copy()

    combined = pd.concat(
        [
            uwf_out,
            unsw_out,
        ],
        ignore_index=True,
    )

    combined.to_csv(
        OUT,
        index=False,
    )

    print()
    print("=" * 70)
    print("COMBINED V4 DATASET")
    print("=" * 70)

    print(
        "Rows:",
        f"{len(combined):,}"
    )

    print()
    print("Labels:")
    print(
        combined[
            "label_binary"
        ]
        .value_counts()
        .sort_index()
    )

    print()
    print("By dataset:")
    print(
        pd.crosstab(
            combined["dataset"],
            combined[
                "label_binary"
            ],
        )
    )

    print()
    print(
        "Feature count:",
        len(FEATURES)
    )

    print(
        "Saved:",
        OUT
    )


if __name__ == "__main__":
    main()
