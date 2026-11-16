"""Prepare the UNSW-NB15 training input consumed by the final V4 trainer.

The output filename is retained for compatibility with the frozen V4 training
script. UWF datasets are not needed to build or train the final V4 model.
"""

import os
from pathlib import Path

import pandas as pd


BASE = Path(
    os.environ.get("AI_IDS_PROJECT_ROOT") or str(Path.home() / "ai-ids")
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
    unsw = pd.read_csv(UNSW, low_memory=False)

    print("=" * 70)
    print("FINAL V4 EXTERNAL TRAINING SOURCE")
    print("=" * 70)

    print(
        "UNSW-NB15:",
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

    missing = [column for column in required if column not in unsw.columns]
    if missing:
        raise RuntimeError(f"UNSW-NB15 missing columns: {missing}")

    if not unsw["dataset"].eq("UNSW-NB15").all():
        raise RuntimeError("Expected only UNSW-NB15 rows in the input CSV.")

    # Keep the original column ordering and row ordering from the old combiner.
    # The V4 trainer already filtered the old combined CSV to these rows.
    training_input = unsw[required].copy()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    training_input.to_csv(OUT, index=False)

    print()
    print("=" * 70)
    print("V4 TRAINING INPUT (UNSW-NB15 ONLY)")
    print("=" * 70)

    print(
        "Rows:",
        f"{len(training_input):,}"
    )

    print()
    print("Labels:")
    print(
        training_input[
            "label_binary"
        ]
        .value_counts()
        .sort_index()
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
