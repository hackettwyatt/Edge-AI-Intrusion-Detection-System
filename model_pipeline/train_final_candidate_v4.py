from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    average_precision_score,
    roc_auc_score,
)
from sklearn.utils.class_weight import compute_sample_weight

from model_pipeline.train_final_candidate_v2 import (
    BASE,
    FEATURES,
    RANDOM_STATE,
    THRESHOLD,
    prepare_data,
    grouped_split,
)


V3_EXPANSION = (
    BASE
    / "simple_ids/data/v4_windows/local/"
      "benign_expansion_v3_windows.csv"
)

V4_UDP = (
    BASE
    / "simple_ids/data/v4_windows/local/"
      "benign_udp_v4_windows.csv"
)

MODEL_OUT = (
    BASE
    / "simple_ids/model/"
      "zeek_ids_final_candidate_v4.joblib"
)

REPORT_OUT = (
    BASE
    / "simple_ids/reports/"
      "final_candidate_v4_validation_predictions.csv"
)


def main():

    # ========================================================
    # Recreate exact V2/V3 split
    # ========================================================

    unsw, local = prepare_data()

    unsw_train, unsw_val = grouped_split(
        unsw
    )

    local_train, local_val = grouped_split(
        local
    )

    # Same V2/V3 rule:
    # benign_conn.log forced into training only.
    forced = local[
        local["source_file"]
        .astype(str)
        .eq("benign_conn.log")
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

    local_train = (
        local_train[
            ~local_train.index.duplicated(
                keep="first"
            )
        ]
        .copy()
    )


    # ========================================================
    # Load training-only expansions
    # ========================================================

    v3 = pd.read_csv(
        V3_EXPANSION,
        low_memory=False,
    )

    udp = pd.read_csv(
        V4_UDP,
        low_memory=False,
    )

    if not (v3["label_binary"] == 0).all():
        raise RuntimeError(
            "V3 expansion contains non-benign labels."
        )

    if not (udp["label_binary"] == 0).all():
        raise RuntimeError(
            "V4 UDP expansion contains non-benign labels."
        )


    # ========================================================
    # Build V4 train / unchanged validation
    # ========================================================

    train = pd.concat(
        [
            unsw_train,
            local_train,
            v3,
            udp,
        ],
        ignore_index=True,
        sort=False,
    )

    val = pd.concat(
        [
            unsw_val,
            local_val,
        ],
        ignore_index=True,
        sort=False,
    )


    print("=" * 84)
    print("FINAL CANDIDATE V4")
    print("=" * 84)

    print()
    print("TRAINING SOURCES")
    print("-" * 84)

    print(
        f"UNSW train:             {len(unsw_train):,}"
    )
    print(
        f"Original LOCAL train:   {len(local_train):,}"
    )
    print(
        f"V3 benign expansion:    {len(v3):,}"
    )
    print(
        f"V4 UDP expansion:       {len(udp):,}"
    )
    print(
        f"TOTAL TRAIN:            {len(train):,}"
    )

    print()
    print("VALIDATION")
    print("-" * 84)

    print(
        f"UNSW validation:        {len(unsw_val):,}"
    )
    print(
        f"LOCAL validation:       {len(local_val):,}"
    )
    print(
        f"TOTAL VALIDATION:       {len(val):,}"
    )

    print()
    print("Train labels:")

    print(
        train["label_binary"]
        .astype(int)
        .value_counts()
        .sort_index()
    )


    # ========================================================
    # Feature matrices
    # ========================================================

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


    # ========================================================
    # SAME HGB MODEL
    # ========================================================

    model = HistGradientBoostingClassifier(
        learning_rate=0.05,
        max_iter=200,
        max_leaf_nodes=31,
        min_samples_leaf=30,
        l2_regularization=1.0,
        early_stopping=False,
        random_state=RANDOM_STATE,
    )

    print()
    print("=" * 84)
    print("TRAINING")
    print("=" * 84)

    model.fit(
        X_train,
        y_train,
        sample_weight=weights,
    )


    # ========================================================
    # Validation
    # ========================================================

    prob = model.predict_proba(
        X_val
    )[:, 1]

    pred = (
        prob >= THRESHOLD
    ).astype(int)

    print()
    print("=" * 84)
    print("UNCHANGED VALIDATION SET")
    print("=" * 84)

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
        f"{fp / (tn + fp):.6f}",
    )

    print(
        "Attack recall:",
        f"{tp / (tp + fn):.6f}",
    )

    print(
        "PR-AUC:",
        f"{average_precision_score(y_val, prob):.6f}",
    )

    print(
        "ROC-AUC:",
        f"{roc_auc_score(y_val, prob):.6f}",
    )


    # ========================================================
    # Original LOCAL validation
    # ========================================================

    local_mask = (
        val["dataset"]
        .astype(str)
        .eq("LOCAL")
        .to_numpy()
    )

    local_y = y_val[
        local_mask
    ]

    local_pred = pred[
        local_mask
    ]

    print()
    print("=" * 84)
    print("ORIGINAL LOCAL VALIDATION")
    print("=" * 84)

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


    # ========================================================
    # TRAINING sanity checks only
    # ========================================================

    print()
    print("=" * 84)
    print("V4 UDP TRAINING SANITY CHECK")
    print("=" * 84)

    udp_X = (
        udp[FEATURES]
        .apply(
            pd.to_numeric,
            errors="coerce",
        )
        .fillna(0)
    )

    udp_prob = (
        model.predict_proba(
            udp_X
        )[:, 1]
    )

    udp_pred = (
        udp_prob >= THRESHOLD
    ).astype(int)

    check = udp[
        [
            "workload",
            "connection_count",
            "unique_destination_ips",
            "unique_destination_ports",
            "no_response_ratio",
        ]
    ].copy()

    check[
        "attack_probability"
    ] = udp_prob

    check[
        "prediction"
    ] = udp_pred

    print(
        check
        .round(6)
        .to_string(
            index=False
        )
    )

    print()
    print(
        "V4 UDP expansion predicted benign:",
        int((udp_pred == 0).sum()),
        "/",
        len(udp_pred),
    )


    # ========================================================
    # Save validation predictions
    # ========================================================

    result = val.copy()

    result[
        "attack_probability"
    ] = prob

    result[
        "prediction"
    ] = pred

    REPORT_OUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    result.to_csv(
        REPORT_OUT,
        index=False,
    )


    # ========================================================
    # Save model
    # ========================================================

    artifact = {
        "model": model,
        "features": FEATURES,
        "threshold": THRESHOLD,
        "variant":
            "UNSW_LOCAL_EXPANDED_V4_UDP",
        "datasets": [
            "UNSW-NB15",
            "LOCAL",
            "LOCAL_EXPANSION_V3",
            "LOCAL_UDP_EXPANSION_V4",
        ],
        "train_rows":
            len(train),
        "validation_rows":
            len(val),
        "v3_expansion_windows":
            len(v3),
        "v4_udp_windows":
            len(udp),
        "grouping":
            "Same V2/V3 grouped split; "
            "all expansion data training-only.",
    }

    MODEL_OUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        artifact,
        MODEL_OUT,
    )

    print()
    print("=" * 84)
    print("SAVED")
    print("=" * 84)

    print(
        "Model:",
        MODEL_OUT,
    )

    print(
        "Validation:",
        REPORT_OUT,
    )


if __name__ == "__main__":
    main()
