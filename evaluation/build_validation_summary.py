from pathlib import Path

import pandas as pd


BASE = Path.home() / "ai-ids"

RUN_FILE = (
    BASE
    / "data"
    / "validation"
    / "test_runs.csv"
)

RESULT_FILE = (
    BASE
    / "data"
    / "validation"
    / "validation_results.csv"
)

OUT_FILE = (
    BASE
    / "data"
    / "validation"
    / "validation_summary.csv"
)


if not RUN_FILE.exists():
    raise SystemExit(
        f"Missing: {RUN_FILE}"
    )

if not RESULT_FILE.exists():
    raise SystemExit(
        f"Missing: {RESULT_FILE}"
    )


runs = pd.read_csv(
    RUN_FILE,
    dtype={
        "source_ip": str,
        "target_ip": str,
    },
)

results = pd.read_csv(
    RESULT_FILE,
    dtype={
        "source_ip": str,
        "target_ip": str,
    },
)


# ------------------------------------------------------------
# validation_results.csv may contain multiple evaluations of
# the same run while the validator was being developed.
#
# Keep only the most recent result for each run_id.
# ------------------------------------------------------------

results = (
    results
    .drop_duplicates(
        subset=["run_id"],
        keep="last",
    )
    .copy()
)


merged = runs.merge(
    results,
    on="run_id",
    how="left",
    suffixes=(
        "_run",
        "_result",
    ),
)


def clean_bool(value):

    if pd.isna(value):
        return ""

    try:
        return (
            "PASS"
            if int(value) == 1
            else "FAIL"
        )
    except Exception:
        return str(value)


def classify_status(row):

    expected = str(
        row.get(
            "expected_status_run",
            "",
        )
    ).upper()

    observed = str(
        row.get(
            "observed_statuses",
            "",
        )
    ).upper()

    if not expected:
        return ""

    values = {
        x.strip()
        for x in observed.split(";")
        if x.strip()
    }

    return (
        "PASS"
        if expected in values
        else "FAIL"
    )


def classify_behavior(row):

    expected = str(
        row.get(
            "expected_behavior_run",
            "",
        )
    ).upper()

    observed = str(
        row.get(
            "observed_behaviors",
            "",
        )
    ).upper()

    if not expected:
        return ""

    values = {
        x.strip()
        for x in observed.split(";")
        if x.strip()
    }

    return (
        "PASS"
        if expected in values
        else "FAIL"
    )


merged[
    "status_detection"
] = merged.apply(
    classify_status,
    axis=1,
)

merged[
    "behavior_detection"
] = merged.apply(
    classify_behavior,
    axis=1,
)


merged[
    "overall_result"
] = merged[
    "passed"
].apply(
    clean_bool
)


summary = pd.DataFrame({
    "run_id":
        merged[
            "run_id"
        ],

    "test_name":
        merged[
            "test_name_run"
        ],

    "expected_status":
        merged[
            "expected_status_run"
        ],

    "observed_statuses":
        merged[
            "observed_statuses"
        ],

    "status_detection":
        merged[
            "status_detection"
        ],

    "expected_behavior":
        merged[
            "expected_behavior_run"
        ],

    "observed_behaviors":
        merged[
            "observed_behaviors"
        ],

    "behavior_detection":
        merged[
            "behavior_detection"
        ],

    "overall_result":
        merged[
            "overall_result"
        ],

    "max_binary_probability":
        merged[
            "max_binary_probability"
        ],

    "max_recon_probability":
        merged[
            "max_recon_probability"
        ],

    "max_connections":
        merged[
            "max_connections"
        ],

    "max_unique_destination_ports":
        merged[
            "max_unique_destination_ports"
        ],

    "rule_hits":
        merged[
            "rule_hits"
        ],

    "source_ip":
        merged[
            "source_ip_run"
        ],

    "target_ip":
        merged[
            "target_ip_run"
        ],

    "notes":
        merged[
            "notes"
        ],
})


summary.to_csv(
    OUT_FILE,
    index=False,
)


print()
print("======================================")
print("UNIFIED IDS VALIDATION SUMMARY")
print("======================================")
print()


display_cols = [
    "test_name",
    "expected_status",
    "status_detection",
    "expected_behavior",
    "behavior_detection",
    "overall_result",
]


print(
    summary[
        display_cols
    ]
    .to_string(
        index=False
    )
)


total = len(
    summary
)

overall_pass = (
    summary[
        "overall_result"
    ]
    == "PASS"
).sum()

status_pass = (
    summary[
        "status_detection"
    ]
    == "PASS"
).sum()

behavior_pass = (
    summary[
        "behavior_detection"
    ]
    == "PASS"
).sum()


print()
print("======================================")
print("COUNTS")
print("======================================")

print(
    f"Total validation runs: {total}"
)

print(
    f"Overall PASS: {overall_pass}/{total}"
)

print(
    f"Status detection PASS: "
    f"{status_pass}/{total}"
)

print(
    f"Behavior detection PASS: "
    f"{behavior_pass}/{total}"
)


if total:

    print()
    print("======================================")
    print("RATES")
    print("======================================")

    print(
        "Overall pass rate:",
        f"{overall_pass / total:.2%}",
    )

    print(
        "Status detection rate:",
        f"{status_pass / total:.2%}",
    )

    print(
        "Behavior detection rate:",
        f"{behavior_pass / total:.2%}",
    )


failures = summary[
    summary[
        "overall_result"
    ]
    == "FAIL"
]


if not failures.empty:

    print()
    print("======================================")
    print("FAILED VALIDATIONS")
    print("======================================")

    print(
        failures[
            display_cols
        ]
        .to_string(
            index=False
        )
    )


print()
print(
    "Saved:",
    OUT_FILE,
)
