from pathlib import Path

import numpy as np
import pandas as pd

from supporting.features import (
    FEATURES,
    WINDOW_SECONDS,
    build_window,
)


BASE = (
    Path.home()
    / "ai-ids"
    / "data"
    / "uwf-v2"
)

OUT_DIR = (
    Path.home()
    / "ai-ids"
    / "simple_ids"
    / "data"
    / "v4_windows"
)

DATASETS = [
    "UWF-ZeekData24",
    "UWF-ZeekDataFall24-2",
    "UWF-ZeekDataFall22",
    "UWF-ZeekDataSum25-1",
]

USECOLS = [
    "ts",
    "src_ip_zeek",
    "dest_ip_zeek",
    "dest_port_zeek",
    "proto",
    "conn_state",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
]


def load_dataset(dataset):

    root = BASE / dataset / "csv"

    if not root.exists():
        print(
            f"SKIP {dataset}: "
            f"{root} does not exist"
        )
        return None

    frames = []

    for tactic_dir in sorted(
        root.iterdir()
    ):

        if not tactic_dir.is_dir():
            continue

        tactic = tactic_dir.name

        for csv_file in sorted(
            tactic_dir.glob("*.csv")
        ):

            print(
                f"{dataset}: "
                f"{tactic}: "
                f"{csv_file.name}"
            )

            df = pd.read_csv(
                csv_file,
                usecols=lambda c:
                    c in USECOLS,
                low_memory=False,
            )

            for column in USECOLS:
                if column not in df.columns:
                    df[column] = np.nan

            # UWF Benign directory = BENIGN.
            # Every other tactic directory = ATTACK.
            df["label_binary"] = int(
                tactic.lower()
                != "benign"
            )

            df["tactic"] = tactic
            df["dataset"] = dataset

            frames.append(df)

    if not frames:
        return None

    return pd.concat(
        frames,
        ignore_index=True,
    )


def build_windows(df):

    df = df.copy()

    df["ts"] = pd.to_numeric(
        df["ts"],
        errors="coerce",
    )

    df = df.dropna(
        subset=[
            "ts",
            "src_ip_zeek",
        ]
    )

    numeric_columns = [
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "dest_port_zeek",
    ]

    for column in numeric_columns:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce",
        ).fillna(0)

    # Fixed 10-second bucket.
    df["window"] = (
        df["ts"]
        // WINDOW_SECONDS
    ).astype("int64")

    rows = []

    groups = df.groupby(
        [
            "dataset",
            "src_ip_zeek",
            "window",
        ],
        sort=False,
    )

    for (
        dataset,
        src_ip,
        window,
    ), group in groups:

        if len(group) == 0:
            continue

        features = build_window(
            group
        )

        row = {
            "dataset":
                dataset,

            "src_ip":
                src_ip,

            "window_start":
                int(
                    window
                    * WINDOW_SECONDS
                ),

            **features,

            # Binary window:
            # attack if ANY attack-labeled
            # connection occurs in this
            # source/window.
            "label_binary":
                int(
                    group[
                        "label_binary"
                    ].max()
                ),

            # Useful metadata only.
            "tactics":
                "|".join(
                    sorted(
                        set(
                            group[
                                "tactic"
                            ]
                            .dropna()
                            .astype(str)
                        )
                    )
                ),
        }

        rows.append(row)

    return pd.DataFrame(
        rows
    )


def main():

    OUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    all_windows = []

    for dataset in DATASETS:

        print()
        print("=" * 70)
        print(dataset)
        print("=" * 70)

        df = load_dataset(
            dataset
        )

        if df is None:
            continue

        print()
        print(
            "Connections:",
            f"{len(df):,}"
        )

        print(
            "BENIGN connections:",
            f"{int((df['label_binary'] == 0).sum()):,}"
        )

        print(
            "ATTACK connections:",
            f"{int((df['label_binary'] == 1).sum()):,}"
        )

        windows = build_windows(
            df
        )

        if windows.empty:
            continue

        output_file = (
            OUT_DIR
            / f"{dataset}_binary_windows_10s.csv"
        )

        windows.to_csv(
            output_file,
            index=False,
        )

        print()
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

        print(
            "Saved:",
            output_file
        )

        all_windows.append(
            windows
        )

    if not all_windows:
        raise RuntimeError(
            "No V4 window datasets "
            "were created."
        )

    combined = pd.concat(
        all_windows,
        ignore_index=True,
    )

    combined_file = (
        OUT_DIR
        / "uwf_binary_windows_10s_all.csv"
    )

    combined.to_csv(
        combined_file,
        index=False,
    )

    print()
    print("=" * 70)
    print("COMBINED V4 BINARY WINDOW DATASET")
    print("=" * 70)

    print(
        "Rows:",
        f"{len(combined):,}"
    )

    print(
        "BENIGN:",
        f"{int((combined['label_binary'] == 0).sum()):,}"
    )

    print(
        "ATTACK:",
        f"{int((combined['label_binary'] == 1).sum()):,}"
    )

    print()
    print(
        "Feature count:",
        len(FEATURES)
    )

    print(
        "Saved:",
        combined_file
    )


if __name__ == "__main__":
    main()
