import os
from pathlib import Path
import re

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    average_precision_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.utils.class_weight import compute_sample_weight


BASE = Path(
    os.environ.get("AI_IDS_PROJECT_ROOT") or str(Path.home() / "ai-ids")
)

COMBINED = (
    BASE
    / "simple_ids"
    / "data"
    / "v4_windows"
    / "combined_v4_binary_windows_10s.csv"
)

LOCAL = (
    BASE
    / "simple_ids"
    / "data"
    / "v4_windows"
    / "local"
    / "local_v4_binary_windows_10s.csv"
)

MODEL_OUT = (
    BASE
    / "simple_ids"
    / "model"
    / "zeek_ids_final_candidate_v2.joblib"
)

REPORT_OUT = (
    BASE
    / "simple_ids"
    / "reports"
    / "final_candidate_v2.txt"
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

RANDOM_STATE = 42
THRESHOLD = 0.50


def local_group(row):
    source_file = str(row.get("source_file", ""))
    workload = str(row.get("workload", ""))

    # Keep all edge/central views of the same experiment run together.
    match = re.search(
        r"(benign_http|slowsyn20|syn200|syn20|udp50)_r(\d+)",
        source_file,
    )

    if match:
        attack_type = match.group(1)
        run_number = match.group(2)

        return (
            f"LOCAL_CAMPAIGN::"
            f"{attack_type}_r{run_number}"
        )

    # Raw benign captures remain independent groups.
    return f"LOCAL_RAW::{source_file}"


def prepare_data():
    external = pd.read_csv(
        COMBINED,
        low_memory=False,
    )

    # Final candidate trains on UNSW only.
    unsw = external[
        external["dataset"] == "UNSW-NB15"
    ].copy()

    unsw["source_file"] = ""
    unsw["workload"] = ""

    unsw["split_group"] = (
        "UNSW::"
        + (
            pd.to_numeric(
                unsw["window_start"],
                errors="coerce",
            )
            // 3600
        )
        .astype("Int64")
        .astype(str)
    )

    local = pd.read_csv(
        LOCAL,
        low_memory=False,
    )

    local["split_group"] = local.apply(
        local_group,
        axis=1,
    )

    return unsw, local


def grouped_split(part):
    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=RANDOM_STATE,
    )

    train_idx, val_idx = next(
        splitter.split(
            part,
            groups=part["split_group"],
        )
    )

    return (
        part.iloc[train_idx].copy(),
        part.iloc[val_idx].copy(),
    )


def main():
    unsw, local = prepare_data()

    print("=" * 78)
    print("CORRECTED FINAL CANDIDATE")
    print("=" * 78)

    print("\nLOCAL GROUPS:")
    for group, g in (
        local.groupby("split_group")
    ):
        print(
            f"{group:35s} "
            f"rows={len(g):4d} "
            f"label={int(g['label_binary'].max())}"
        )

    unsw_train, unsw_val = grouped_split(
        unsw
    )

    local_train, local_val = grouped_split(
        local
    )

    # benign_conn.log supplies representative normal HTTP
    # training examples.
    # benign_holdout_conn.log is NOT part of this dataset.
    force_train = (
        local["source_file"]
        .astype(str)
        .eq("benign_conn.log")
    )

    forced = local[
        force_train
    ].copy()

    local_train = pd.concat(
        [
            local_train[
                local_train["source_file"]
                .astype(str)
                .ne("benign_conn.log")
            ],
            forced,
        ],
        ignore_index=False,
    )

    local_val = local_val[
        local_val["source_file"]
        .astype(str)
        .ne("benign_conn.log")
    ].copy()

    # De-duplicate indexes in case forced rows were already
    # selected by GroupShuffleSplit.
    local_train = (
        local_train[
            ~local_train.index.duplicated(
                keep="first"
            )
        ]
        .copy()
    )

    train = pd.concat(
        [
            unsw_train,
            local_train,
        ],
        ignore_index=True,
    )

    val = pd.concat(
        [
            unsw_val,
            local_val,
        ],
        ignore_index=True,
    )

    print("\n" + "=" * 78)
    print("SPLIT")
    print("=" * 78)

    print(
        f"UNSW train: {len(unsw_train):,}"
    )
    print(
        f"UNSW validation: {len(unsw_val):,}"
    )
    print(
        f"LOCAL train: {len(local_train):,}"
    )
    print(
        f"LOCAL validation: {len(local_val):,}"
    )

    print("\nLocal train groups:")
    print(
        local_train[
            "split_group"
        ]
        .value_counts()
        .sort_index()
        .to_string()
    )

    print("\nLocal validation groups:")
    print(
        local_val[
            "split_group"
        ]
        .value_counts()
        .sort_index()
        .to_string()
    )

    X_train = (
        train[FEATURES]
        .apply(
            pd.to_numeric,
            errors="coerce",
        )
        .fillna(0)
    )

    y_train = (
        train["label_binary"]
        .astype(int)
        .to_numpy()
    )

    X_val = (
        val[FEATURES]
        .apply(
            pd.to_numeric,
            errors="coerce",
        )
        .fillna(0)
    )

    y_val = (
        val["label_binary"]
        .astype(int)
        .to_numpy()
    )

    weights = compute_sample_weight(
        class_weight="balanced",
        y=y_train,
    )

    model = HistGradientBoostingClassifier(
        learning_rate=0.05,
        max_iter=200,
        max_leaf_nodes=31,
        min_samples_leaf=30,
        l2_regularization=1.0,
        early_stopping=False,
        random_state=RANDOM_STATE,
    )

    print("\n" + "=" * 78)
    print("TRAINING")
    print("=" * 78)

    print(
        f"Train rows: {len(train):,}"
    )
    print(
        f"Validation rows: {len(val):,}"
    )

    print("\nTrain labels:")
    print(
        pd.Series(
            y_train
        )
        .value_counts()
        .sort_index()
    )

    model.fit(
        X_train,
        y_train,
        sample_weight=weights,
    )

    prob = model.predict_proba(
        X_val
    )[:, 1]

    pred = (
        prob >= THRESHOLD
    ).astype(int)

    print("\n" + "=" * 78)
    print("VALIDATION")
    print("=" * 78)

    print(
        classification_report(
            y_val,
            pred,
            target_names=[
                "BENIGN",
                "ATTACK",
            ],
            digits=4,
            zero_division=0,
        )
    )

    cm = confusion_matrix(
        y_val,
        pred,
        labels=[0, 1],
    )

    print("Confusion matrix:")
    print(cm)

    tn, fp, fn, tp = cm.ravel()

    print(
        "Benign FPR:",
        f"{fp / (tn + fp):.6f}"
    )

    print(
        "Attack recall:",
        f"{tp / (tp + fn):.6f}"
    )

    print(
        "PR-AUC:",
        f"{average_precision_score(y_val, prob):.6f}"
    )

    print(
        "ROC-AUC:",
        f"{roc_auc_score(y_val, prob):.6f}"
    )

    print("\n" + "=" * 78)
    print("LOCAL VALIDATION")
    print("=" * 78)

    local_mask = (
        val["dataset"] == "LOCAL"
    ).to_numpy()

    local_y = y_val[local_mask]
    local_prob = prob[local_mask]
    local_pred = pred[local_mask]

    if len(local_y):
        print(
            classification_report(
                local_y,
                local_pred,
                target_names=[
                    "BENIGN",
                    "ATTACK",
                ],
                digits=4,
                zero_division=0,
            )
        )

        print(
            "Local confusion matrix:"
        )

        print(
            confusion_matrix(
                local_y,
                local_pred,
                labels=[0, 1],
            )
        )

        tmp = val[
            val["dataset"] == "LOCAL"
        ][
            [
                "workload",
                "source_file",
                "split_group",
                "label_binary",
            ]
        ].copy()

        tmp[
            "attack_probability"
        ] = local_prob

        tmp["prediction"] = (
            local_pred
        )

        print(
            "\nLocal validation by workload:"
        )

        for workload, g in (
            tmp.groupby("workload")
        ):
            print()
            print(workload)

            print(
                pd.crosstab(
                    g["label_binary"],
                    g["prediction"],
                    margins=True,
                )
            )

    MODEL_OUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    artifact = {
        "model": model,
        "features": FEATURES,
        "threshold": THRESHOLD,
        "variant":
            "UNSW_LOCAL_CORRECTED_GROUPING",
        "datasets": [
            "UNSW-NB15",
            "LOCAL",
        ],
        "train_rows": len(train),
        "validation_rows": len(val),
        "grouping":
            "UNSW one-hour groups; "
            "LOCAL workload+rNN campaign groups",
    }

    joblib.dump(
        artifact,
        MODEL_OUT,
    )

    print("\n" + "=" * 78)
    print("SAVED")
    print("=" * 78)

    print(
        "Model:",
        MODEL_OUT,
    )


if __name__ == "__main__":
    main()
