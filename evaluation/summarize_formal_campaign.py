#!/usr/bin/env python3

from pathlib import Path
import pandas as pd


BASE = Path.home() / "ai-ids"

SOURCE = (
    BASE
    / "data"
    / "experiment"
    / "post_freeze_latency_runs.csv"
)

OUT = (
    BASE
    / "data"
    / "experiment"
    / "formal_campaign_summary.csv"
)


def workload_name(test_name):
    name = str(test_name)

    # Order matters: syn200 before syn20.
    mappings = [
        ("formal_syn200_", "SYN 200"),
        ("formal_syn20_", "SYN 20"),
        ("formal_syn10_", "SYN 10"),
        ("formal_tcpconnect200_", "TCP Connect 200"),
        ("formal_udp50_", "UDP 50"),
        ("formal_udp2burst_", "UDP Two-Burst"),
        ("formal_slowsyn20_", "Slow SYN 20"),
        ("formal_benign_http", "Benign HTTP"),
        ("formal_mixed_http", "Mixed HTTP + SYN"),
    ]

    for prefix, label in mappings:
        if name.startswith(prefix):
            return label

    return None


df = pd.read_csv(SOURCE)

df["workload"] = df["test_name"].apply(
    workload_name
)

formal = df[
    df["workload"].notna()
].copy()


numeric_columns = [
    "attack_detection_latency_ms",
    "binary_inference_ms",
    "recon_inference_ms",
    "processing_delay_sec",

    "zues_cpu_mean_percent",
    "zues_cpu_max_percent",
    "zues_memory_mean_percent",
    "zues_memory_max_percent",

    "apollo_cpu_mean_percent",
    "apollo_cpu_max_percent",
    "apollo_memory_mean_percent",
    "apollo_memory_max_percent",

    "resource_sample_count",
]

for col in numeric_columns:
    if col in formal.columns:
        formal[col] = pd.to_numeric(
            formal[col],
            errors="coerce",
        )


formal["accepted"] = (
    formal["run_validity"].eq("VALID")
    & formal["traffic_isolation"].eq("PASS")
    & formal["resource_collection"].eq("PASS")
)


order = [
    "SYN 10",
    "SYN 20",
    "SYN 200",
    "TCP Connect 200",
    "UDP 50",
    "UDP Two-Burst",
    "Slow SYN 20",
    "Benign HTTP",
    "Mixed HTTP + SYN",
]


results = []


for workload in order:

    attempted = formal[
        formal["workload"].eq(workload)
    ].copy()

    if attempted.empty:
        continue

    valid = attempted[
        attempted["accepted"]
    ].copy()

    n_attempted = len(attempted)
    n_valid = len(valid)
    n_invalid = n_attempted - n_valid

    status_pass = (
        valid["status_detection"]
        .eq("PASS")
        .sum()
    )

    behavior_pass = (
        valid["behavior_detection"]
        .eq("PASS")
        .sum()
    )

    overall_pass = (
        valid["overall_result"]
        .eq("PASS")
        .sum()
    )

    def mean(col):
        if (
            col not in valid
            or valid[col].dropna().empty
        ):
            return None

        return valid[col].mean()


    def median(col):
        if (
            col not in valid
            or valid[col].dropna().empty
        ):
            return None

        return valid[col].median()


    def std(col):
        if (
            col not in valid
            or len(valid[col].dropna()) < 2
        ):
            return None

        return valid[col].std(ddof=1)


    results.append({
        "workload":
            workload,

        "attempted_runs":
            n_attempted,

        "valid_runs":
            n_valid,

        "invalid_runs":
            n_invalid,

        "status_pass":
            status_pass,

        "behavior_pass":
            behavior_pass,

        "overall_pass":
            overall_pass,

        "status_detection_rate":
            (
                status_pass / n_valid
                if n_valid
                else None
            ),

        "behavior_detection_rate":
            (
                behavior_pass / n_valid
                if n_valid
                else None
            ),

        "overall_pass_rate":
            (
                overall_pass / n_valid
                if n_valid
                else None
            ),

        "mean_e2e_latency_ms":
            mean(
                "attack_detection_latency_ms"
            ),

        "median_e2e_latency_ms":
            median(
                "attack_detection_latency_ms"
            ),

        "sd_e2e_latency_ms":
            std(
                "attack_detection_latency_ms"
            ),

        "mean_binary_inference_ms":
            mean(
                "binary_inference_ms"
            ),

        "mean_recon_inference_ms":
            mean(
                "recon_inference_ms"
            ),

        "mean_processing_delay_sec":
            mean(
                "processing_delay_sec"
            ),

        "mean_zues_cpu_percent":
            mean(
                "zues_cpu_mean_percent"
            ),

        "peak_zues_cpu_percent":
            (
                valid[
                    "zues_cpu_max_percent"
                ].max()
                if n_valid
                else None
            ),

        "mean_zues_ram_percent":
            mean(
                "zues_memory_mean_percent"
            ),

        "mean_apollo_cpu_percent":
            mean(
                "apollo_cpu_mean_percent"
            ),

        "peak_apollo_cpu_percent":
            (
                valid[
                    "apollo_cpu_max_percent"
                ].max()
                if n_valid
                else None
            ),

        "mean_apollo_ram_percent":
            mean(
                "apollo_memory_mean_percent"
            ),
    })


summary = pd.DataFrame(
    results
)

summary.to_csv(
    OUT,
    index=False,
)


print()
print(
    "=============================================="
)
print(
    "FORMAL UNIFIED IDS CAMPAIGN SUMMARY"
)
print(
    "=============================================="
)
print()


display_columns = [
    "workload",
    "attempted_runs",
    "valid_runs",
    "invalid_runs",
    "status_pass",
    "behavior_pass",
    "overall_pass",
    "mean_e2e_latency_ms",
]

print(
    summary[
        display_columns
    ].to_string(
        index=False
    )
)

print()
print(
    "=============================================="
)
print(
    "VALID RUN REQUIREMENT"
)
print(
    "=============================================="
)

for _, row in summary.iterrows():

    valid = int(
        row["valid_runs"]
    )

    if valid >= 5:
        state = "COMPLETE"
    else:
        state = (
            f"NEEDS {5 - valid} MORE"
        )

    print(
        f"{row['workload']:<20} "
        f"{valid}/5  {state}"
    )


print()
print(
    "=============================================="
)
print(
    "DETECTION RESULTS"
)
print(
    "=============================================="
)

for _, row in summary.iterrows():

    valid = int(
        row["valid_runs"]
    )

    if not valid:
        continue

    print()
    print(
        row["workload"]
    )

    print(
        f"  Status:   "
        f"{int(row['status_pass'])}/{valid} "
        f"({row['status_detection_rate']:.1%})"
    )

    print(
        f"  Behavior: "
        f"{int(row['behavior_pass'])}/{valid} "
        f"({row['behavior_detection_rate']:.1%})"
    )

    print(
        f"  Overall:  "
        f"{int(row['overall_pass'])}/{valid} "
        f"({row['overall_pass_rate']:.1%})"
    )

    if pd.notna(
        row["mean_e2e_latency_ms"]
    ):
        print(
            f"  Mean E2E latency: "
            f"{row['mean_e2e_latency_ms']:.3f} ms"
        )

        print(
            f"  Median latency:   "
            f"{row['median_e2e_latency_ms']:.3f} ms"
        )

    if pd.notna(
        row["mean_binary_inference_ms"]
    ):
        print(
            f"  Binary inference: "
            f"{row['mean_binary_inference_ms']:.3f} ms"
        )

    if pd.notna(
        row["mean_recon_inference_ms"]
    ):
        print(
            f"  Recon inference:  "
            f"{row['mean_recon_inference_ms']:.3f} ms"
        )

    if pd.notna(
        row["mean_zues_cpu_percent"]
    ):
        print(
            f"  Zues CPU mean:    "
            f"{row['mean_zues_cpu_percent']:.3f}%"
        )

    if pd.notna(
        row["mean_apollo_cpu_percent"]
    ):
        print(
            f"  Apollo CPU mean:  "
            f"{row['mean_apollo_cpu_percent']:.3f}%"
        )


invalid = formal[
    ~formal["accepted"]
].copy()

print()
print(
    "=============================================="
)
print(
    "EXCLUDED / INVALID FORMAL RUNS"
)
print(
    "=============================================="
)

if invalid.empty:
    print(
        "None"
    )

else:
    for _, row in invalid.iterrows():

        print(
            row.get(
                "run_id",
                ""
            )
        )

        print(
            "  Test:",
            row.get(
                "test_name",
                ""
            )
        )

        print(
            "  Reason:",
            row.get(
                "invalid_reason",
                ""
            )
            or "measurement validity check"
        )


print()
print(
    "Saved:"
)
print(
    OUT
)
