#!/usr/bin/env python3

import csv
import io
import json
import os
import signal
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from urllib.request import Request, urlopen

import numpy as np
import pandas as pd

from defense.defense_controller import (
    DefenseController,
)


# ============================================================
# SETTINGS
# ============================================================

BASE = Path(
    os.environ.get("AI_IDS_PROJECT_ROOT") or str(Path.home() / "ai-ids")
)

ZEEK_POD = "zeek-apollo"
ZEEK_LOG = "/var/log/zeek/conn.log"

WINDOW_SECONDS = 10
POLL_SECONDS = 2
SETTLE_SECONDS = 5

STARTUP_LOOKBACK_SECONDS = 30

EVENT_LOG = (
    BASE
    / "simple_ids"
    / "reports"
    / "live_v4_events.csv"
)

STATE_LOG = (
    BASE
    / "simple_ids"
    / "reports"
    / "live_v4_controller.log"
)

SERVICE_IP = os.environ.get(
    "AI_IDS_V4_SERVICE_IP"
)

SERVICE_PORT = os.environ.get(
    "AI_IDS_V4_SERVICE_PORT",
    "9105",
)

if not SERVICE_IP:
    raise RuntimeError(
        "AI_IDS_V4_SERVICE_IP is not set."
    )

PREDICT_URL = (
    f"http://{SERVICE_IP}:{SERVICE_PORT}/predict"
)

DEFENSE_URL = (
    f"http://{SERVICE_IP}:{SERVICE_PORT}/defense"
)


# ============================================================
# ZEEK COLUMNS
# ============================================================

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


# ============================================================
# STATE
# ============================================================

running = True

buckets = defaultdict(list)

bucket_last_update = {}

processed = set()

enforced_until = {}

lab_ips = set()

# Kubernetes infrastructure sources that should not be scored
# by the behavioral IDS.
excluded_source_ips = set()

last_lab_refresh = 0.0
last_exclusion_refresh = 0.0

# Last time the current-block gauge was published.
last_block_metric_publish = 0.0


# ============================================================
# DEFENSE
#
# Policy is active for all observed sources.
# Firewall enforcement is performed only for current
# ids-defense-lab pod IPs.
# ============================================================

controller = DefenseController(
    threshold=0.50,
    hits_required=2,
    hit_window_seconds=60,
    block_seconds=300,

    # We enforce manually below after checking
    # that the source belongs to the lab namespace.
    enforce=False,
)


# ============================================================
# HELPERS
# ============================================================

def log(
    message,
):
    stamp = time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    text = (
        f"[{stamp}] {message}"
    )

    print(
        text,
        flush=True,
    )


def stop_handler(
    signum,
    frame,
):
    global running

    running = False

    log(
        f"Stopping on signal {signum}"
    )


signal.signal(
    signal.SIGTERM,
    stop_handler,
)

signal.signal(
    signal.SIGINT,
    stop_handler,
)


def run_kubectl(
    args,
    timeout=20,
):
    result = subprocess.run(
        [
            "kubectl",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
        )

    return result.stdout


def post_json(
    url,
    payload,
    timeout=10,
):
    request = Request(
        url,
        data=json.dumps(
            payload
        ).encode(),
        headers={
            "Content-Type":
                "application/json"
        },
        method="POST",
    )

    with urlopen(
        request,
        timeout=timeout,
    ) as response:

        return json.load(
            response
        )


# ============================================================
# LAB ENFORCEMENT SCOPE
# ============================================================

def refresh_lab_ips():

    global lab_ips
    global last_lab_refresh

    now = time.time()

    if (
        now - last_lab_refresh
        < 15
    ):
        return


    output = run_kubectl(
        [
            "get",
            "pods",
            "-n",
            "ids-defense-lab",
            "-o",
            "json",
        ]
    )


    data = json.loads(
        output
    )


    current = set()


    for item in data.get(
        "items",
        [],
    ):

        phase = (
            item.get(
                "status",
                {},
            )
            .get(
                "phase",
                "",
            )
        )

        ip = (
            item.get(
                "status",
                {},
            )
            .get(
                "podIP"
            )
        )

        if (
            phase == "Running"
            and ip
        ):
            current.add(
                ip
            )


    lab_ips = current

    last_lab_refresh = now


def refresh_excluded_sources():
    """
    Exclude Kubernetes infrastructure sources from ML scoring.

    Excluded:
      - monitoring namespace
      - logging namespace
      - kube-system namespace
      - ai-ids namespace
      - Kubernetes node InternalIPs
      - Apollo Calico tunl0 address

    Controlled attack/benign workloads in ids-defense-lab
    remain eligible for scoring.
    """

    global excluded_source_ips
    global last_exclusion_refresh

    now = time.time()

    if (
        now - last_exclusion_refresh
        < 30
    ):
        return


    excluded = set()


    # --------------------------------------------------------
    # INFRASTRUCTURE POD IPS
    # --------------------------------------------------------

    output = run_kubectl(
        [
            "get",
            "pods",
            "-A",
            "-o",
            "json",
        ]
    )

    data = json.loads(
        output
    )


    excluded_namespaces = {
        "monitoring",
        "logging",
        "kube-system",
        "ai-ids",
        "influxdb",
    }


    for item in data.get(
        "items",
        [],
    ):

        namespace = (
            item.get(
                "metadata",
                {},
            )
            .get(
                "namespace",
                "",
            )
        )

        if namespace not in excluded_namespaces:
            continue


        status = item.get(
            "status",
            {},
        )


        ip = status.get(
            "podIP"
        )

        if ip:
            excluded.add(
                ip
            )


        for entry in status.get(
            "podIPs",
            [],
        ):

            value = entry.get(
                "ip"
            )

            if value:
                excluded.add(
                    value
                )


    # --------------------------------------------------------
    # KUBERNETES NODE IPS
    # --------------------------------------------------------

    output = run_kubectl(
        [
            "get",
            "nodes",
            "-o",
            "json",
        ]
    )

    nodes = json.loads(
        output
    )


    for node in nodes.get(
        "items",
        [],
    ):

        addresses = (
            node.get(
                "status",
                {},
            )
            .get(
                "addresses",
                [],
            )
        )


        for address in addresses:

            if (
                address.get(
                    "type"
                )
                == "InternalIP"
            ):

                value = address.get(
                    "address"
                )

                if value:
                    excluded.add(
                        value
                    )


    # --------------------------------------------------------
    # APOLLO CALICO TUNNEL
    #
    # Zeek is running on Apollo and sees traffic associated
    # with this tunnel endpoint. It is infrastructure traffic,
    # not an endpoint to classify.
    # --------------------------------------------------------

    # Operators should configure the specific infrastructure address
    # to exclude before running the controller in their own network.
    tunnel_ip = os.environ.get("AI_IDS_INFRA_TUNNEL_IP")
    if tunnel_ip:
        excluded.add(tunnel_ip)


    excluded_source_ips = (
        excluded
    )

    last_exclusion_refresh = (
        now
    )


    log(
        "Infrastructure exclusions refreshed: "
        f"{len(excluded_source_ips)} IPs"
    )



def active_enforced_count():

    now = time.time()

    expired = [
        ip
        for ip, until
        in enforced_until.items()
        if until <= now
    ]


    for ip in expired:
        enforced_until.pop(
            ip,
            None,
        )


    return len(
        enforced_until
    )


def publish_blocked_source_count():
    """
    Refresh the Prometheus gauge even when no
    new Zeek windows arrive.

    This prevents ai_ids_blocked_sources from
    remaining at 1 after the 5-minute timeout.
    """

    global last_block_metric_publish

    now = time.time()

    if (
        now
        - last_block_metric_publish
        < 10
    ):
        return


    blocked = (
        active_enforced_count()
    )


    try:

        post_json(
            DEFENSE_URL,
            {
                "action":
                    "ALLOW",

                "new_block":
                    False,

                "enforced":
                    False,

                "blocked_sources":
                    blocked,
            },
        )


        last_block_metric_publish = now


    except Exception as e:

        log(
            "BLOCK METRIC ERROR: "
            f"{type(e).__name__}: {e}"
        )


# ============================================================
# ZEEK INGESTION
# ============================================================

def zeek_line_count():

    output = run_kubectl(
        [
            "exec",
            ZEEK_POD,
            "--",
            "sh",
            "-c",
            (
                f"wc -l < "
                f"{ZEEK_LOG}"
            ),
        ]
    )

    return int(
        output.strip()
    )


def read_zeek_from_line(
    start_line,
):

    output = run_kubectl(
        [
            "exec",
            ZEEK_POD,
            "--",
            "tail",
            "-n",
            f"+{start_line}",
            ZEEK_LOG,
        ],
        timeout=30,
    )

    return output


def parse_zeek_line(
    line,
):

    if (
        not line
        or line.startswith("#")
    ):
        return None


    fields = line.rstrip(
        "\n"
    ).split(
        "\t"
    )


    if len(fields) < len(
        ZEEK_COLUMNS
    ):
        return None


    row = dict(
        zip(
            ZEEK_COLUMNS,
            fields,
        )
    )


    try:
        ts = float(
            row["ts"]
        )

    except Exception:
        return None


    row["_ts_float"] = ts

    return row


def ingest_text(
    text,
):

    added = 0

    now = time.time()


    for line in text.splitlines():

        row = parse_zeek_line(
            line
        )

        if row is None:
            continue


        ts = row[
            "_ts_float"
        ]


        window_start = int(
            ts // WINDOW_SECONDS
            * WINDOW_SECONDS
        )


        src_ip = row.get(
            "id.orig_h",
            "",
        )


        if not src_ip:
            continue


        if src_ip in excluded_source_ips:
            continue


        key = (
            src_ip,
            window_start,
        )


        # If a very late Zeek record arrives after a
        # window was already finalized, do not count
        # the window a second time.
        if key in processed:
            continue


        buckets[
            key
        ].append(
            row
        )

        bucket_last_update[
            key
        ] = now

        added += 1


    return added


# ============================================================
# FEATURE BUILDING
# ============================================================

def number(
    value,
):

    if value in {
        None,
        "",
        "-",
    }:
        return 0.0


    try:
        return float(
            value
        )

    except Exception:
        return 0.0


def entropy(
    values,
):

    series = pd.Series(
        values,
        dtype=str,
    )

    counts = (
        series
        .value_counts()
    )


    if len(counts) <= 1:
        return 0.0


    p = (
        counts
        / counts.sum()
    )


    return float(
        -(
            p
            * np.log2(p)
        ).sum()
    )


def build_features(
    rows,
):

    dest_ips = [
        str(
            row[
                "id.resp_h"
            ]
        )
        for row in rows
    ]

    dest_ports = [
        str(
            row[
                "id.resp_p"
            ]
        )
        for row in rows
    ]

    protocols = [
        str(
            row.get(
                "proto",
                "",
            )
        ).lower()
        for row in rows
    ]


    orig_pkts = [
        number(
            row.get(
                "orig_pkts"
            )
        )
        for row in rows
    ]

    resp_pkts = [
        number(
            row.get(
                "resp_pkts"
            )
        )
        for row in rows
    ]

    orig_bytes = [
        number(
            row.get(
                "orig_bytes"
            )
        )
        for row in rows
    ]

    resp_bytes = [
        number(
            row.get(
                "resp_bytes"
            )
        )
        for row in rows
    ]

    durations = [
        number(
            row.get(
                "duration"
            )
        )
        for row in rows
    ]


    count = len(
        rows
    )


    features = {

        "connection_count":
            count,

        "connections_per_second":
            count
            / WINDOW_SECONDS,

        "unique_destination_ips":
            len(
                set(
                    dest_ips
                )
            ),

        "unique_destination_ports":
            len(
                set(
                    dest_ports
                )
            ),

        "destination_ip_entropy":
            entropy(
                dest_ips
            ),

        "destination_port_entropy":
            entropy(
                dest_ports
            ),

        "tcp_count":
            sum(
                proto == "tcp"
                for proto in protocols
            ),

        "udp_count":
            sum(
                proto == "udp"
                for proto in protocols
            ),

        "icmp_count":
            sum(
                proto.startswith(
                    "icmp"
                )
                for proto
                in protocols
            ),

        "no_response_ratio":
            (
                sum(
                    value == 0
                    for value
                    in resp_pkts
                )
                / count
                if count
                else 0.0
            ),

        "total_orig_pkts":
            sum(
                orig_pkts
            ),

        "total_resp_pkts":
            sum(
                resp_pkts
            ),

        "total_orig_bytes":
            sum(
                orig_bytes
            ),

        "total_resp_bytes":
            sum(
                resp_bytes
            ),

        "mean_duration":
            float(
                np.mean(
                    durations
                )
            )
            if durations
            else 0.0,

        "median_duration":
            float(
                np.median(
                    durations
                )
            )
            if durations
            else 0.0,
    }


    return features


# ============================================================
# EVENT LOG
# ============================================================

EVENT_FIELDS = [
    "processed_at",
    "src_ip",
    "window_start",
    "connection_count",
    "unique_destination_ips",
    "unique_destination_ports",
    "no_response_ratio",
    "attack_probability",
    "prediction",
    "inference_latency_ms",
    "defense_action",
    "new_block",
    "enforced",
    "defense_latency_ms",
    "blocked_sources",
]


def write_event(
    record,
):

    EVENT_LOG.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    write_header = (
        not EVENT_LOG.exists()
        or EVENT_LOG.stat().st_size == 0
    )


    with EVENT_LOG.open(
        "a",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=EVENT_FIELDS,
        )

        if write_header:
            writer.writeheader()

        writer.writerow(
            {
                key:
                    record.get(
                        key,
                        "",
                    )
                for key
                in EVENT_FIELDS
            }
        )


# ============================================================
# SCORE + DEFEND
# ============================================================

def process_bucket(
    key,
    rows,
):

    src_ip, window_start = key


    features = build_features(
        rows
    )


    prediction_result = post_json(
        PREDICT_URL,
        {
            "features":
                features
        },
    )


    probability = float(
        prediction_result[
            "attack_probability"
        ]
    )

    prediction = str(
        prediction_result[
            "prediction"
        ]
    ).upper()

    inference_latency = float(
        prediction_result[
            "inference_latency_seconds"
        ]
    )


    defense_start = (
        time.perf_counter()
    )


    # Use processing time for the temporal policy.
    # This keeps the 60-second strike window and
    # 300-second firewall timeout aligned with
    # actual enforcement time.
    decision = controller.process(
        src_ip=src_ip,
        timestamp=time.time(),
        attack_probability=probability,
    )


    enforced = False


    if (
        decision[
            "action"
        ] == "BLOCK"
        and decision[
            "new_block"
        ]
    ):

        refresh_lab_ips()


        if src_ip in lab_ips:

            result = (
                controller
                .enforcer
                .block(
                    src_ip=src_ip,
                    timeout_seconds=300,
                )
            )

            enforced = bool(
                result[
                    "enforced"
                ]
            )


            if enforced:

                enforced_until[
                    src_ip
                ] = (
                    time.time()
                    + 300
                )


    defense_latency = (
        time.perf_counter()
        - defense_start
    )


    blocked_sources = (
        active_enforced_count()
    )


    # Publish defense outcome to Athena.
    post_json(
        DEFENSE_URL,
        {
            "action":
                decision[
                    "action"
                ],

            "new_block":
                decision[
                    "new_block"
                ],

            "enforced":
                enforced,

            "blocked_sources":
                blocked_sources,

            "defense_latency_seconds":
                defense_latency,
        },
    )


    record = {

        "processed_at":
            time.time(),

        "src_ip":
            src_ip,

        "window_start":
            window_start,

        "connection_count":
            features[
                "connection_count"
            ],

        "unique_destination_ips":
            features[
                "unique_destination_ips"
            ],

        "unique_destination_ports":
            features[
                "unique_destination_ports"
            ],

        "no_response_ratio":
            features[
                "no_response_ratio"
            ],

        "attack_probability":
            probability,

        "prediction":
            prediction,

        "inference_latency_ms":
            inference_latency
            * 1000,

        "defense_action":
            decision[
                "action"
            ],

        "new_block":
            int(
                bool(
                    decision[
                        "new_block"
                    ]
                )
            ),

        "enforced":
            int(
                enforced
            ),

        "defense_latency_ms":
            defense_latency
            * 1000,

        "blocked_sources":
            blocked_sources,
    }


    write_event(
        record
    )


    log(
        "WINDOW "
        f"src={src_ip} "
        f"start={window_start} "
        f"conn={features['connection_count']} "
        f"ports={features['unique_destination_ports']} "
        f"p={probability:.6f} "
        f"prediction={prediction} "
        f"action={decision['action']} "
        f"new_block={decision['new_block']} "
        f"enforced={enforced} "
        f"inference_ms="
        f"{inference_latency * 1000:.3f} "
        f"defense_ms="
        f"{defense_latency * 1000:.3f}"
    )


# ============================================================
# COMPLETE BUCKETS
# ============================================================

def finalize_ready_buckets():

    now = time.time()

    ready = []


    for key in list(
        buckets.keys()
    ):

        src_ip, window_start = key


        if (
            now
            < window_start
            + WINDOW_SECONDS
        ):
            continue


        last_update = (
            bucket_last_update.get(
                key,
                now,
            )
        )


        if (
            now - last_update
            < SETTLE_SECONDS
        ):
            continue


        ready.append(
            key
        )


    ready.sort(
        key=lambda item:
            item[1]
    )


    for key in ready:

        rows = buckets.pop(
            key,
            [],
        )

        bucket_last_update.pop(
            key,
            None,
        )


        if not rows:
            continue


        try:

            process_bucket(
                key,
                rows,
            )

            processed.add(
                key
            )


        except Exception as e:

            # Put the bucket back so a temporary
            # network failure does not lose it.
            buckets[
                key
            ] = rows

            bucket_last_update[
                key
            ] = time.time()

            log(
                "ERROR scoring "
                f"{key}: "
                f"{type(e).__name__}: {e}"
            )


# ============================================================
# MAIN LOOP
# ============================================================

def main():

    log(
        "=" * 72
    )

    log(
        "AI IDS LIVE V4 CONTROLLER"
    )

    log(
        "=" * 72
    )

    log(
        f"Athena predict: "
        f"{PREDICT_URL}"
    )

    log(
        f"Athena defense metrics: "
        f"{DEFENSE_URL}"
    )

    log(
        "Policy: "
        "2 ATTACK windows / 60 sec"
    )

    log(
        "Firewall timeout: "
        "300 sec"
    )

    log(
        "Enforcement scope: "
        "running pods in ids-defense-lab only"
    )


    # --------------------------------------------------------
    # Connectivity check to Athena
    # --------------------------------------------------------

    health_url = (
        f"http://{SERVICE_IP}:{SERVICE_PORT}/health"
    )


    with urlopen(
        health_url,
        timeout=10,
    ) as response:

        health = json.load(
            response
        )


    log(
        "Athena health: "
        f"{health}"
    )


    # --------------------------------------------------------
    # Load infrastructure exclusions before reading Zeek.
    # --------------------------------------------------------

    refresh_excluded_sources()


    # --------------------------------------------------------
    # Start near the end of conn.log so we do not replay
    # historical traffic.
    # --------------------------------------------------------

    total_lines = (
        zeek_line_count()
    )


    lookback_lines = 3000


    next_line = max(
        1,
        total_lines
        - lookback_lines
        + 1,
    )


    startup_cutoff = (
        time.time()
        - STARTUP_LOOKBACK_SECONDS
    )


    initial = read_zeek_from_line(
        next_line
    )


    # Only retain recent-started connections
    # during initial startup.
    recent_lines = []


    for line in initial.splitlines():

        row = parse_zeek_line(
            line
        )

        if (
            row is not None
            and row[
                "_ts_float"
            ] >= startup_cutoff
        ):
            recent_lines.append(
                line
            )


    ingest_text(
        "\n".join(
            recent_lines
        )
    )


    total_lines = (
        zeek_line_count()
    )

    next_line = (
        total_lines + 1
    )


    log(
        f"Starting at Zeek line "
        f"{next_line}"
    )


    while running:

        try:

            refresh_lab_ips()

            refresh_excluded_sources()

            publish_blocked_source_count()


            current_lines = (
                zeek_line_count()
            )


            # conn.log rotated or was replaced.
            if current_lines < (
                next_line - 1
            ):

                log(
                    "Zeek conn.log rotation "
                    "detected."
                )

                next_line = 1


            if current_lines >= next_line:

                text = (
                    read_zeek_from_line(
                        next_line
                    )
                )

                added = ingest_text(
                    text
                )

                next_line = (
                    current_lines
                    + 1
                )


                if added:

                    log(
                        f"Ingested "
                        f"{added} Zeek rows"
                    )


            finalize_ready_buckets()


        except Exception as e:

            log(
                "LOOP ERROR: "
                f"{type(e).__name__}: {e}"
            )


        time.sleep(
            POLL_SECONDS
        )


    log(
        "Controller stopped."
    )


if __name__ == "__main__":
    main()
