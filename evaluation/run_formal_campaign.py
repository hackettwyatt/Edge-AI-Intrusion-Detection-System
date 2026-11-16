#!/usr/bin/env python3

import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path


BASE = Path(
    os.environ.get("AI_IDS_PROJECT_ROOT") or str(Path.home() / "ai-ids")
)

TIMING_SCRIPT = (
    BASE
    / "tools"
    / "experiment_timing.py"
)

RESULTS_FILE = (
    BASE
    / "data"
    / "experiment"
    / "post_freeze_latency_runs.csv"
)

ACTIVE_FILE = (
    BASE
    / "data"
    / "experiment"
    / "active_experiment.json"
)

REMOTE_LOG_DIR = (
    BASE
    / "data"
    / "experiment"
    / "remote_logs"
)

SUMMARY_DIR = (
    BASE
    / "data"
    / "experiment"
    / "summaries"
)

def required_lab_setting(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Set {name} for the authorized experiment environment."
        )
    return value


APOLLO = required_lab_setting("AI_IDS_APOLLO_SSH")
SOURCE_IP = required_lab_setting("AI_IDS_SOURCE_IP")
TARGET_IP = required_lab_setting("AI_IDS_TARGET_IP")

# Recon temporal policy uses 60 seconds.
# Keep independent repetitions farther apart.
COOLDOWN_FROM_LAST_TRAFFIC = 70


TESTS = {
    "syn20": {
        "label": "TCP SYN 20 ports",
        "expected_status": "ATTACK",
        "expected_behavior": "RECONNAISSANCE",
        "expected_connections": 20,
        "post_wait": 20,
        "timeout": 120,
        "remote": (
            "sudo -n nmap "
            "-n -sS -Pn "
            "-p 1-20 "
            "--max-retries 0 "
            f"{TARGET_IP}"
        ),
    },

    "syn200": {
        "label": "TCP SYN 200 ports",
        "expected_status": "ATTACK",
        "expected_behavior": "RECONNAISSANCE",
        "expected_connections": 200,
        "post_wait": 20,
        "timeout": 180,
        "remote": (
            "sudo -n nmap "
            "-n -sS -Pn "
            "-p 1-200 "
            "--max-retries 0 "
            f"{TARGET_IP}"
        ),
    },

    "tcpconnect200": {
        "label": "TCP connect 200 ports",
        "expected_status": "ATTACK",
        "expected_behavior": "RECONNAISSANCE",
        "expected_connections": 200,
        "post_wait": 20,
        "timeout": 180,
        "remote": (
            "sudo -n nmap "
            "-n -sT -Pn "
            "-p 1-200 "
            "--max-retries 0 "
            f"{TARGET_IP}"
        ),
    },

    "udp50": {
        "label": "UDP scan 50 ports",
        "expected_status": "ATTACK",
        "expected_behavior": "RECONNAISSANCE",
        "expected_connections": 50,
        # Zeek may finalize UDP much later.
        "post_wait": 90,
        "timeout": 180,
        "remote": (
            "sudo -n nmap "
            "-n -sU -Pn "
            "-p 1-50 "
            "--max-retries 0 "
            f"{TARGET_IP}"
        ),
    },

    "udp2burst": {
        "label": "Two-burst UDP reconnaissance",
        "expected_status": "ATTACK",
        "expected_behavior": "RECONNAISSANCE",
        "expected_connections": 20,
        "post_wait": 90,
        "timeout": 240,
        "remote": (
            "sudo -n nmap "
            "-n -sU -Pn "
            "-p 1-10 "
            "--max-retries 0 "
            f"{TARGET_IP}"
            " ; sleep 12 ; "
            "sudo -n nmap "
            "-n -sU -Pn "
            "-p 1-10 "
            "--max-retries 0 "
            f"{TARGET_IP}"
        ),
    },

    "benign_http": {
        "label": "Benign HTTP",
        "expected_status": "NORMAL",
        "expected_behavior": "NORMAL",
        "expected_connections": 10,
        "integrity_mode": "unique_5tuple",
        "post_wait": 20,
        "timeout": 120,
        "remote": (
            "sudo -n /tmp/aiids_benign_http.sh"
        ),
    },

    "mixed_http_syn": {
        "label": "Mixed HTTP + SYN",
        "expected_status": "ATTACK",
        "expected_behavior": "RECONNAISSANCE",
        "expected_connections": 20,
        "integrity_mode": "unique_5tuple",
        "post_wait": 20,
        "timeout": 120,
        "remote": (
            "sudo -n /tmp/aiids_mixed_http_syn.sh"
        ),
    },

    "slowsyn20": {
        "label": "Slow TCP SYN 20 ports",
        "expected_status": "ATTACK",
        "expected_behavior": "RECONNAISSANCE",
        "expected_connections": 20,
        "integrity_mode": "unique_ports",
        "integrity_mode": "unique_ports",
        "post_wait": 20,
        "timeout": 240,
        "remote": (
            "sudo -n /tmp/aiids_slowsyn_isolated.sh"
        ),
    },
}


SUITE = [
    "syn20",
    "syn200",
    "tcpconnect200",
    "udp50",
    "udp2burst",
    "slowsyn20",
]


def run(
    command,
    timeout=None,
    print_output=False,
):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if print_output:
        if result.stdout:
            print(
                result.stdout,
                end="",
            )

        if result.stderr:
            print(
                result.stderr,
                end="",
                file=sys.stderr,
            )

    return result


def service_active(name):
    result = subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            name,
        ]
    )

    return result.returncode == 0


def check_frozen():
    checks = [
        (
            BASE / "processor/live_ids_v1.py",
            BASE / "frozen/unified_ids_v1_final/live_ids_v1.py",
        ),
        (
            BASE / "processor/live_recon_v1.py",
            BASE / "frozen/unified_ids_v1_final/live_recon_v1.py",
        ),
        (
            BASE / "processor/live_recon_monitor_v3.py",
            BASE / "frozen/unified_ids_v1_final/live_recon_monitor_v3.py",
        ),
        (
            BASE / "model/uwf_zeek_binary_v2.joblib",
            BASE / "frozen/unified_ids_v1_final/uwf_zeek_binary_v2.joblib",
        ),
        (
            BASE / "model/uwf_recon_window_10s_v3_localw25.joblib",
            BASE / "frozen/unified_ids_v1_final/uwf_recon_window_10s_v3_localw25.joblib",
        ),
    ]

    for active, frozen in checks:

        result = subprocess.run(
            [
                "cmp",
                "-s",
                str(active),
                str(frozen),
            ]
        )

        if result.returncode != 0:
            raise SystemExit(
                "\nFROZEN DETECTOR CHECK FAILED:\n"
                f"{active}\n"
            )


def preflight():
    print()
    print(
        "======================================"
    )
    print(
        "FORMAL CAMPAIGN PREFLIGHT"
    )
    print(
        "======================================"
    )

    if not service_active(
        "unified-ai-ids.service"
    ):
        raise SystemExit(
            "Unified IDS service is not active."
        )

    print(
        "Unified IDS:       active"
    )

    if not service_active(
        "unified-ids-metrics.service"
    ):
        raise SystemExit(
            "Metrics exporter is not active."
        )

    print(
        "Metrics exporter:  active"
    )

    if ACTIVE_FILE.exists():
        raise SystemExit(
            "\nAn experiment is already active:\n"
            f"{ACTIVE_FILE}"
        )

    print(
        "Experiment state:  clear"
    )

    check_frozen()

    print(
        "Frozen detector:   verified"
    )

    ssh = run(
        [
            "ssh",
            APOLLO,
            (
                "hostname && "
                "sudo -n true"
            ),
        ],
        timeout=15,
    )

    if ssh.returncode != 0:
        raise SystemExit(
            "\nApollo SSH/sudo preflight failed.\n"
            + ssh.stderr
        )

    print(
        "Apollo SSH/sudo:   ready"
    )


def start_experiment(
    test_name,
    spec,
):
    command = [
        sys.executable,
        str(TIMING_SCRIPT),
        "start",
        test_name,

        "--expected-status",
        spec["expected_status"],

        "--expected-behavior",
        spec["expected_behavior"],

        "--source-ip",
        SOURCE_IP,

        "--target-ip",
        TARGET_IP,

        "--notes",
        (
            f"Automated formal campaign: "
            f"{spec['label']}"
        ),
    ]

    result = run(
        command,
        print_output=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Experiment start failed."
        )

    if not ACTIVE_FILE.exists():
        raise RuntimeError(
            "Experiment marker was not created."
        )

    metadata = json.loads(
        ACTIVE_FILE.read_text()
    )

    return metadata["run_id"]


def run_apollo_workload(
    run_id,
    spec,
):
    REMOTE_LOG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_file = (
        REMOTE_LOG_DIR
        / f"{run_id}.log"
    )

    print()
    print(
        "Running workload on Apollo:"
    )

    print(
        spec["remote"]
    )

    print()

    started = time.time()

    result = run(
        [
            "ssh",
            APOLLO,
            spec["remote"],
        ],
        timeout=spec["timeout"],
    )

    ended = time.time()

    text = (
        f"controller_start={started:.6f}\n"
        f"controller_end={ended:.6f}\n"
        f"return_code={result.returncode}\n"
        "\n"
        "===== STDOUT =====\n"
        f"{result.stdout}"
        "\n"
        "===== STDERR =====\n"
        f"{result.stderr}"
    )

    log_file.write_text(
        text
    )

    print(
        result.stdout
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Apollo workload command failed. "
            f"See {log_file}"
        )

    print(
        "Remote log:",
        log_file,
    )


def stop_experiment(
    retry_count=6,
    retry_wait=20,
):
    for attempt in range(
        1,
        retry_count + 1,
    ):

        result = run(
            [
                sys.executable,
                str(TIMING_SCRIPT),
                "stop",
            ],
            print_output=True,
        )

        if result.returncode == 0:
            return

        if not ACTIVE_FILE.exists():
            raise RuntimeError(
                "Experiment stop failed and "
                "active marker disappeared."
            )

        if attempt == retry_count:
            raise RuntimeError(
                "Experiment stop failed after retries."
            )

        print()
        print(
            f"Stop collection not ready "
            f"(attempt {attempt}/{retry_count})."
        )

        print(
            f"Retrying in {retry_wait} seconds..."
        )

        time.sleep(
            retry_wait
        )


def load_result(run_id):
    if not RESULTS_FILE.exists():
        raise RuntimeError(
            "Experiment result CSV does not exist."
        )

    with RESULTS_FILE.open(
        newline=""
    ) as f:

        rows = list(
            csv.DictReader(f)
        )

    matches = [
        row
        for row in rows
        if row.get("run_id")
        == run_id
    ]

    if not matches:
        raise RuntimeError(
            f"No result row found for {run_id}"
        )

    return matches[-1]


def mark_invalid(
    run_id,
    reason,
):
    with RESULTS_FILE.open(
        newline=""
    ) as f:

        rows = list(
            csv.DictReader(f)
        )

        if not rows:
            return

        fields = list(
            rows[0].keys()
        )

    for row in rows:
        if row.get("run_id") != run_id:
            continue

        row["run_validity"] = "INVALID"

        old = row.get(
            "invalid_reason",
            "",
        ).strip()

        row["invalid_reason"] = (
            f"{old}; {reason}"
            if old
            else reason
        )

    tmp = RESULTS_FILE.with_suffix(
        ".campaign.tmp"
    )

    with tmp.open(
        "w",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )

        writer.writeheader()

        writer.writerows(
            rows
        )

    tmp.replace(
        RESULTS_FILE
    )


def validate_measurement(
    run_id,
    spec,
):
    row = load_result(
        run_id
    )

    expected = spec[
        "expected_connections"
    ]

    integrity_mode = spec.get(
        "integrity_mode",
        "connection_count",
    )

    if integrity_mode in ("unique_ports", "unique_5tuple"):

        zeek_file = (
            BASE
            / "data"
            / "experiment"
            / "evidence"
            / f"{run_id}_zeek.csv"
        )

        if not zeek_file.exists():
            observed = 0

        else:
            with zeek_file.open(
                newline=""
            ) as f:
                zeek_rows = list(
                    csv.DictReader(f)
                )

            if integrity_mode == "unique_ports":

                ports = {
                    r.get("id.resp_p")
                    for r in zeek_rows
                    if r.get("id.resp_p")
                }

                observed = len(ports)

            else:

                five_tuples = {
                    (
                        r.get("id.orig_h"),
                        r.get("id.orig_p"),
                        r.get("id.resp_h"),
                        r.get("id.resp_p"),
                        r.get("proto"),
                    )
                    for r in zeek_rows
                }

                observed = len(five_tuples)

        if observed != expected:

            unit = (
                "unique target ports"
                if integrity_mode == "unique_ports"
                else "unique target 5-tuples"
            )

            reason = (
                f"Workload integrity failure: "
                f"expected {expected} {unit}; "
                f"observed {observed}"
            )

            mark_invalid(
                run_id,
                reason,
            )

            row = load_result(
                run_id
            )

    else:

        try:
            observed = int(
                float(
                    row.get(
                        "zeek_connection_count",
                        "0",
                    )
                )
            )

        except ValueError:
            observed = 0

        if observed != expected:

            reason = (
                f"Workload integrity failure: "
                f"expected {expected} target "
                f"connections; observed {observed}"
            )

            mark_invalid(
                run_id,
                reason,
            )

            row = load_result(
                run_id
            )

    if (
        row.get(
            "resource_collection"
        )
        != "PASS"
    ):

        reason = (
            "Resource collection did not PASS"
        )

        mark_invalid(
            run_id,
            reason,
        )

        row = load_result(
            run_id
        )

    accepted = (
        row.get(
            "run_validity"
        )
        == "VALID"
        and
        row.get(
            "traffic_isolation"
        )
        == "PASS"
        and
        row.get(
            "resource_collection"
        )
        == "PASS"
    )

    return row, accepted


def cooldown(row):
    try:
        last_traffic = float(
            row["last_zeek_epoch"]
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        last_traffic = time.time()

    elapsed = (
        time.time()
        - last_traffic
    )

    remaining = (
        COOLDOWN_FROM_LAST_TRAFFIC
        - elapsed
    )

    if remaining <= 0:
        return

    print()
    print(
        "Recon-state cooldown:"
        f" {remaining:.1f} seconds remaining"
    )

    time.sleep(
        remaining
    )


def number(
    row,
    field,
):
    try:
        return float(
            row[field]
        )
    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return None


def average(values):
    values = [
        v
        for v in values
        if v is not None
    ]

    if not values:
        return None

    return statistics.mean(
        values
    )


def median(values):
    values = [
        v
        for v in values
        if v is not None
    ]

    if not values:
        return None

    return statistics.median(
        values
    )


def fmt(
    value,
    digits=3,
):
    if value is None:
        return "N/A"

    return f"{value:.{digits}f}"


def write_summary(
    test_key,
    spec,
    rows,
):
    SUMMARY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    status_pass = sum(
        row.get(
            "status_detection"
        )
        == "PASS"
        for row in rows
    )

    behavior_pass = sum(
        row.get(
            "behavior_detection"
        )
        == "PASS"
        for row in rows
    )

    overall_pass = sum(
        row.get(
            "overall_result"
        )
        == "PASS"
        for row in rows
    )

    attack_latency = [
        number(
            row,
            "attack_detection_latency_ms",
        )
        for row in rows
    ]

    binary_ms = [
        number(
            row,
            "binary_inference_ms",
        )
        for row in rows
    ]

    recon_ms = [
        number(
            row,
            "recon_inference_ms",
        )
        for row in rows
    ]

    zues_cpu = [
        number(
            row,
            "zues_cpu_mean_percent",
        )
        for row in rows
    ]

    apollo_cpu = [
        number(
            row,
            "apollo_cpu_mean_percent",
        )
        for row in rows
    ]

    summary = [
        "======================================",
        f"FORMAL CAMPAIGN SUMMARY: {spec['label']}",
        "======================================",
        "",
        f"Accepted valid runs: {len(rows)}",
        (
            f"Status detection: "
            f"{status_pass}/{len(rows)}"
        ),
        (
            f"Behavior detection: "
            f"{behavior_pass}/{len(rows)}"
        ),
        (
            f"Overall detector PASS: "
            f"{overall_pass}/{len(rows)}"
        ),
        "",
        (
            "Mean E2E attack latency: "
            f"{fmt(average(attack_latency))} ms"
        ),
        (
            "Median E2E attack latency: "
            f"{fmt(median(attack_latency))} ms"
        ),
        (
            "Mean Binary inference: "
            f"{fmt(average(binary_ms))} ms"
        ),
        (
            "Mean Recon inference: "
            f"{fmt(average(recon_ms))} ms"
        ),
        "",
        (
            "Mean Zues CPU: "
            f"{fmt(average(zues_cpu))} %"
        ),
        (
            "Mean Apollo CPU: "
            f"{fmt(average(apollo_cpu))} %"
        ),
        "",
        "Accepted run IDs:",
    ]

    for row in rows:
        summary.append(
            f"  {row['run_id']}"
        )

    text = "\n".join(
        summary
    ) + "\n"

    path = (
        SUMMARY_DIR
        / f"{test_key}_summary.txt"
    )

    path.write_text(
        text
    )

    print()
    print(
        text
    )

    print(
        "Summary saved:",
        path,
    )


def run_test(
    test_key,
    valid_runs,
    max_attempts_per_run,
):
    spec = TESTS[
        test_key
    ]

    accepted_rows = []

    print()
    print(
        "======================================"
    )
    print(
        f"FORMAL WORKLOAD: {spec['label']}"
    )
    print(
        "======================================"
    )

    repetition = 1

    while repetition <= valid_runs:

        accepted = False

        for attempt in range(
            1,
            max_attempts_per_run + 1,
        ):

            test_name = (
                f"formal_{test_key}_"
                f"r{repetition:02d}_"
                f"a{attempt:02d}"
            )

            print()
            print(
                "======================================"
            )
            print(
                f"{spec['label']} "
                f"repetition {repetition}/{valid_runs} "
                f"attempt {attempt}"
            )
            print(
                "======================================"
            )

            run_id = None

            try:
                run_id = start_experiment(
                    test_name,
                    spec,
                )

                run_apollo_workload(
                    run_id,
                    spec,
                )

                print()
                print(
                    "Post-workload processing wait:"
                    f" {spec['post_wait']} seconds"
                )

                time.sleep(
                    spec["post_wait"]
                )

                stop_experiment()

                row, accepted = (
                    validate_measurement(
                        run_id,
                        spec,
                    )
                )

            except Exception as exc:

                print()
                print(
                    "CAMPAIGN ERROR:",
                    exc,
                )

                if ACTIVE_FILE.exists():
                    run(
                        [
                            sys.executable,
                            str(TIMING_SCRIPT),
                            "cancel",
                        ],
                        print_output=True,
                    )

                time.sleep(
                    COOLDOWN_FROM_LAST_TRAFFIC
                )

                continue

            print()
            print(
                "TRIAL DECISION"
            )
            print(
                "--------------------------------------"
            )

            print(
                "Run ID:",
                row.get("run_id"),
            )

            print(
                "Detector result:",
                row.get("overall_result"),
            )

            print(
                "Run validity:",
                row.get("run_validity"),
            )

            print(
                "Traffic isolation:",
                row.get("traffic_isolation"),
            )

            print(
                "Resource collection:",
                row.get("resource_collection"),
            )

            print(
                "Target connections:",
                row.get("zeek_connection_count"),
            )

            if accepted:

                print()
                print(
                    "ACCEPTED FORMAL TRIAL"
                )

                accepted_rows.append(
                    row
                )

                cooldown(
                    row
                )

                repetition += 1

                break

            print()
            print(
                "INVALID MEASUREMENT — "
                "repeating this repetition."
            )

            print(
                "Reason:",
                row.get(
                    "invalid_reason",
                    "",
                )
                or "measurement validity check",
            )

            cooldown(
                row
            )

        if not accepted:
            raise SystemExit(
                "\nUnable to obtain a valid "
                f"{spec['label']} repetition "
                f"after {max_attempts_per_run} attempts."
            )

    write_summary(
        test_key,
        spec,
        accepted_rows,
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Automated formal Unified IDS "
            "experiment campaign"
        )
    )

    choices = (
        list(TESTS.keys())
        + ["all-scans"]
    )

    parser.add_argument(
        "test",
        choices=choices,
    )

    parser.add_argument(
        "--valid-runs",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--max-attempts-per-run",
        type=int,
        default=4,
    )

    args = parser.parse_args()

    preflight()

    if args.test == "all-scans":

        for test_key in SUITE:
            run_test(
                test_key,
                args.valid_runs,
                args.max_attempts_per_run,
            )

    else:
        run_test(
            args.test,
            args.valid_runs,
            args.max_attempts_per_run,
        )


if __name__ == "__main__":
    main()
