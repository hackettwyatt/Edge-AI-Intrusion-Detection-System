#!/usr/bin/env python3

import argparse
import csv
import json
import math
import os
import random
import re
import statistics
import subprocess
import time

from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen


ROOT = Path(
    os.environ.get("AI_IDS_PROJECT_ROOT") or str(Path.home() / "ai-ids")
)

EVENT_FILE = (
    ROOT
    / "simple_ids"
    / "reports"
    / "live_v4_events.csv"
)

NAMESPACE = "ids-defense-lab"
FIREWALL_POD = "ai-ids-firewall"

CONTROLLER_SERVICE = (
    "ai-ids-v4-controller.service"
)

RANDOM_SEED_DEFAULT = 20261010


NODES = {
    "apollo": os.environ.get("AI_IDS_APOLLO_EXPORTER", ""),
    "athena": os.environ.get("AI_IDS_ATHENA_EXPORTER", ""),
    "zues": os.environ.get("AI_IDS_ZUES_EXPORTER", ""),
}


SCENARIOS = {
    "01": {
        "name": "Benign HTTP",
        "truth": "BENIGN",
        "settle": 25,
        "max_wait": 180,
    },
    "02": {
        "name": "Benign UDP",
        "truth": "BENIGN",
        "settle": 90,
        "max_wait": 180,
    },
    "03": {
        "name": "TCP Reconnaissance",
        "truth": "ATTACK",
        "settle": 35,
        "max_wait": 240,
    },
    "04": {
        "name": "Slow TCP Reconnaissance",
        "truth": "ATTACK",
        "settle": 35,
        "max_wait": 240,
    },
    "05": {
        "name": "SYN-Heavy Traffic",
        "truth": "ATTACK",
        "settle": 35,
        "max_wait": 240,
    },
    "06": {
        "name": "Responsive UDP Multi-Port Recon",
        "truth": "ATTACK",
        "settle": 90,
        "max_wait": 240,
    },
    "07": {
        "name": "TCP Connection Flood",
        "truth": "ATTACK",
        "settle": 35,
        "max_wait": 300,
    },
    "08": {
        "name": "UDP Single-Service Flood",
        "truth": "ATTACK",
        "settle": 90,
        "max_wait": 240,
    },
    "09": {
        "name": "Closed-Port UDP Recon",
        "truth": "ATTACK",
        "settle": 90,
        "max_wait": 240,
    },
    "10": {
        "name": "ICMP Burst",
        "truth": "ATTACK",
        "settle": 105,
        "max_wait": 240,
    },
}


MASTER_FIELDS = [
    "trial_order",
    "scenario_id",
    "scenario_name",
    "replicate",
    "ground_truth",
    "source_ip",
    "traffic_start_epoch",
    "traffic_end_epoch",
    "windows",
    "benign_predictions",
    "attack_predictions",
    "allow_actions",
    "alert_actions",
    "block_actions",
    "enforced_blocks",
    "correct_outcome",
    "detected",
    "false_positive",
    "enforcement_success",
    "max_attack_probability",
    "mean_inference_ms",
    "median_inference_ms",
    "p95_inference_ms",
    "first_attack_delay_ms",
    "first_enforcement_delay_ms",
    "apollo_cpu_avg_pct",
    "apollo_cpu_peak_pct",
    "apollo_mem_avg_pct",
    "apollo_mem_peak_pct",
    "athena_cpu_avg_pct",
    "athena_cpu_peak_pct",
    "athena_mem_avg_pct",
    "athena_mem_peak_pct",
    "zues_cpu_avg_pct",
    "zues_cpu_peak_pct",
    "zues_mem_avg_pct",
    "zues_mem_peak_pct",
    "client_log",
    "status",
    "error",
]


def run(
    command,
    input_text=None,
    check=True,
    timeout=None,
):
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
    )

    if check and result.returncode != 0:
        raise RuntimeError(
            "Command failed:\n"
            + " ".join(command)
            + "\n"
            + result.stdout
            + "\n"
            + result.stderr
        )

    return result


def kubectl(
    args,
    input_text=None,
    check=True,
    timeout=None,
):
    return run(
        ["kubectl"] + list(args),
        input_text=input_text,
        check=check,
        timeout=timeout,
    )


def apply_yaml(text):
    kubectl(
        ["apply", "-f", "-"],
        input_text=text,
    )


def delete_pod(name):
    kubectl(
        [
            "delete",
            "pod",
            name,
            "-n",
            NAMESPACE,
            "--ignore-not-found",
            "--wait=true",
        ],
        check=False,
        timeout=120,
    )


def wait_ready(name):
    kubectl(
        [
            "wait",
            "--for=condition=Ready",
            f"pod/{name}",
            "-n",
            NAMESPACE,
            "--timeout=120s",
        ],
        timeout=130,
    )


def pod_ip(name):
    return kubectl(
        [
            "get",
            "pod",
            name,
            "-n",
            NAMESPACE,
            "-o",
            "jsonpath={.status.podIP}",
        ]
    ).stdout.strip()


# ============================================================
# PERSISTENT TEST TARGETS
# ============================================================

TARGET_YAML = r"""
apiVersion: v1
kind: Pod
metadata:
  name: repeat-http-target
  namespace: ids-defense-lab
spec:
  nodeName: apollo
  restartPolicy: Never
  containers:
  - name: server
    image: python:3.13-alpine
    command:
      - python3
      - -u
      - -m
      - http.server
      - "8088"
---
apiVersion: v1
kind: Pod
metadata:
  name: repeat-udp-echo
  namespace: ids-defense-lab
spec:
  nodeName: apollo
  restartPolicy: Never
  containers:
  - name: server
    image: python:3.13-alpine
    command:
      - python3
      - -u
      - -c
      - |
        import socket

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        s.bind(
            ("0.0.0.0", 9999)
        )

        print(
            "UDP echo target ready",
            flush=True,
        )

        while True:
            data, addr = s.recvfrom(2048)
            s.sendto(b"OK", addr)
---
apiVersion: v1
kind: Pod
metadata:
  name: repeat-udp-multi
  namespace: ids-defense-lab
spec:
  nodeName: apollo
  restartPolicy: Never
  containers:
  - name: server
    image: python:3.13-alpine
    command:
      - python3
      - -u
      - -c
      - |
        import select
        import socket

        sockets = []

        for port in range(9000, 9020):

            s = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            )

            s.bind(
                ("0.0.0.0", port)
            )

            sockets.append(s)

        print(
            "UDP multi-port target ready",
            flush=True,
        )

        while True:

            readable, _, _ = select.select(
                sockets,
                [],
                [],
                1.0,
            )

            for sock in readable:
                data, addr = sock.recvfrom(2048)
                sock.sendto(b"OK", addr)
---
apiVersion: v1
kind: Pod
metadata:
  name: repeat-udp-sink
  namespace: ids-defense-lab
spec:
  nodeName: apollo
  restartPolicy: Never
  containers:
  - name: server
    image: python:3.13-alpine
    command:
      - python3
      - -u
      - -c
      - |
        import socket

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        s.bind(
            ("0.0.0.0", 9998)
        )

        count = 0

        print(
            "UDP sink target ready",
            flush=True,
        )

        while True:

            data, addr = s.recvfrom(2048)

            count += 1

            if count % 100 == 0:
                print(
                    f"received={count}",
                    flush=True,
                )
"""


def ensure_targets():

    apply_yaml(
        TARGET_YAML
    )

    targets = [
        "repeat-http-target",
        "repeat-udp-echo",
        "repeat-udp-multi",
        "repeat-udp-sink",
    ]

    for name in targets:
        wait_ready(name)

    return {
        "http":
            pod_ip(
                "repeat-http-target"
            ),

        "udp_echo":
            pod_ip(
                "repeat-udp-echo"
            ),

        "udp_multi":
            pod_ip(
                "repeat-udp-multi"
            ),

        "udp_sink":
            pod_ip(
                "repeat-udp-sink"
            ),
    }


# ============================================================
# CLIENT POD BUILDERS
# ============================================================

def python_pod(
    name,
    script,
):

    body = "\n".join(
        "        " + line
        for line
        in script.strip().splitlines()
    )

    return f"""
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {NAMESPACE}
spec:
  nodeName: athena
  restartPolicy: Never
  containers:
  - name: client
    image: python:3.13-alpine
    command:
      - python3
      - -u
      - -c
      - |
{body}
"""


def netshoot_pod(
    name,
    script,
):

    body = "\n".join(
        "        " + line
        for line
        in script.strip().splitlines()
    )

    return f"""
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {NAMESPACE}
spec:
  nodeName: athena
  restartPolicy: Never
  containers:
  - name: client
    image: nicolaka/netshoot:latest
    securityContext:
      capabilities:
        add:
          - NET_RAW
    command:
      - /bin/sh
      - -c
      - |
{body}
"""


def build_client(
    scenario_id,
    pod_name,
    targets,
):

    http = targets[
        "http"
    ]

    udp_echo = targets[
        "udp_echo"
    ]

    udp_multi = targets[
        "udp_multi"
    ]

    udp_sink = targets[
        "udp_sink"
    ]


    # ========================================================
    # 01 - BENIGN HTTP
    # ========================================================

    if scenario_id == "01":

        script = f"""
import time
import urllib.request

time.sleep(20)

start = int(time.time())

print(
    f"TRAFFIC_START epoch={{start}}",
    flush=True,
)

success = 0
failed = 0

for i in range(30):

    try:

        with urllib.request.urlopen(
            "http://{http}:8088/",
            timeout=3,
        ) as response:

            response.read(64)

        success += 1

    except Exception:

        failed += 1

    time.sleep(1)

end = int(time.time())

print(
    f"BENIGN_HTTP "
    f"success={{success}} "
    f"failed={{failed}}",
    flush=True,
)

print(
    f"TRAFFIC_DONE epoch={{end}}",
    flush=True,
)

time.sleep(180)
"""

        return python_pod(
            pod_name,
            script,
        )


    # ========================================================
    # 02 - BENIGN UDP
    # ========================================================

    if scenario_id == "02":

        script = f"""
import socket
import time

time.sleep(20)

start = int(time.time())

print(
    f"TRAFFIC_START epoch={{start}}",
    flush=True,
)

success = 0
failed = 0

for i in range(30):

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    s.settimeout(3)

    try:

        s.sendto(
            f"benign-udp-{{i}}".encode(),
            ("{udp_echo}", 9999),
        )

        data, _ = s.recvfrom(
            2048
        )

        if data == b"OK":
            success += 1
        else:
            failed += 1

    except Exception:

        failed += 1

    finally:

        s.close()

    time.sleep(1)

end = int(time.time())

print(
    f"BENIGN_UDP "
    f"success={{success}} "
    f"failed={{failed}}",
    flush=True,
)

print(
    f"TRAFFIC_DONE epoch={{end}}",
    flush=True,
)

time.sleep(180)
"""

        return python_pod(
            pod_name,
            script,
        )


    # ========================================================
    # 03 - TCP RECONNAISSANCE
    # ========================================================

    if scenario_id == "03":

        script = f"""
import socket
import time

time.sleep(20)

start = int(time.time())

print(
    f"TRAFFIC_START epoch={{start}}",
    flush=True,
)

attempted = 0
open_ports = 0
errors = 0

for port in range(8000, 8120):

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    s.settimeout(0.35)

    try:

        rc = s.connect_ex(
            (
                "{http}",
                port,
            )
        )

        attempted += 1

        if rc == 0:
            open_ports += 1

    except Exception:
        errors += 1

    finally:
        s.close()

    time.sleep(0.25)

end = int(time.time())

print(
    f"TCP_RECON "
    f"attempted={{attempted}} "
    f"open={{open_ports}} "
    f"errors={{errors}}",
    flush=True,
)

print(
    f"TRAFFIC_DONE epoch={{end}}",
    flush=True,
)

time.sleep(180)
"""

        return python_pod(
            pod_name,
            script,
        )


    # ========================================================
    # 04 - SLOW TCP RECONNAISSANCE
    # ========================================================

    if scenario_id == "04":

        script = f"""
import socket
import time

time.sleep(20)

start = int(time.time())

print(
    f"TRAFFIC_START epoch={{start}}",
    flush=True,
)

attempted = 0
open_ports = 0
closed_or_filtered = 0
errors = 0

for port in range(8060, 8120):

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    s.settimeout(0.75)

    try:

        rc = s.connect_ex(
            (
                "{http}",
                port,
            )
        )

        attempted += 1

        if rc == 0:
            open_ports += 1
        else:
            closed_or_filtered += 1

    except Exception:
        errors += 1

    finally:
        s.close()

    time.sleep(1.0)

end = int(time.time())

print(
    f"SLOW_TCP_RECON "
    f"attempted={{attempted}} "
    f"open={{open_ports}} "
    f"closed_or_filtered={{closed_or_filtered}} "
    f"errors={{errors}}",
    flush=True,
)

print(
    f"TRAFFIC_DONE epoch={{end}}",
    flush=True,
)

time.sleep(180)
"""

        return python_pod(
            pod_name,
            script,
        )


    # ========================================================
    # 05 - SYN-HEAVY TRAFFIC
    # ========================================================

    if scenario_id == "05":

        script = f"""
sleep 20

echo "TRAFFIC_START epoch=$(date +%s)"

nping \
  --tcp \
  --flags syn \
  -p 8088 \
  --rate 10 \
  -c 400 \
  {http}

NPING_EXIT=$?

echo "SYN_HEAVY nping_exit=$NPING_EXIT"

echo "TRAFFIC_DONE epoch=$(date +%s)"

sleep 180
"""

        return netshoot_pod(
            pod_name,
            script,
        )


    # ========================================================
    # 06 - RESPONSIVE UDP MULTI-PORT RECONNAISSANCE
    # ========================================================

    if scenario_id == "06":

        script = f"""
import socket
import time

time.sleep(20)

start = int(time.time())

print(
    f"TRAFFIC_START epoch={{start}}",
    flush=True,
)

success = 0
timeouts = 0
errors = 0

for i in range(80):

    port = (
        9000
        + (i % 20)
    )

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    s.settimeout(1)

    try:

        s.sendto(
            f"probe-{{i}}".encode(),
            (
                "{udp_multi}",
                port,
            ),
        )

        data, _ = s.recvfrom(
            2048
        )

        if data == b"OK":
            success += 1

    except socket.timeout:

        timeouts += 1

    except Exception:

        errors += 1

    finally:

        s.close()

    time.sleep(0.5)

end = int(time.time())

print(
    f"UDP_RESPONSIVE_RECON "
    f"success={{success}} "
    f"timeouts={{timeouts}} "
    f"errors={{errors}}",
    flush=True,
)

print(
    f"TRAFFIC_DONE epoch={{end}}",
    flush=True,
)

time.sleep(180)
"""

        return python_pod(
            pod_name,
            script,
        )


    # ========================================================
    # 07 - TCP CONNECTION FLOOD
    # ========================================================

    if scenario_id == "07":

        script = f"""
import socket
import time

time.sleep(20)

start = int(time.time())
print(f"TRAFFIC_START epoch={{start}}", flush=True)

success = 0
failed = 0

for i in range(400):

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    s.settimeout(0.25)

    try:

        rc = s.connect_ex(
            ("{http}", 8088)
        )

        if rc == 0:
            success += 1

            try:
                s.sendall(
                    b"GET / HTTP/1.0\\r\\n"
                    b"Host: repeated-test\\r\\n"
                    b"\\r\\n"
                )
            except Exception:
                pass

        else:
            failed += 1

    except Exception:
        failed += 1

    finally:
        s.close()

    time.sleep(0.1)

end = int(time.time())

print(
    f"TCP_CONNECTION_FLOOD "
    f"success={{success}} "
    f"failed={{failed}}",
    flush=True,
)

print(
    f"TRAFFIC_DONE epoch={{end}}",
    flush=True,
)

time.sleep(180)
"""

        return python_pod(
            pod_name,
            script,
        )


    # ========================================================
    # 08 - UDP SINGLE-SERVICE FLOOD
    # ========================================================

    if scenario_id == "08":

        script = f"""
import socket
import time

time.sleep(20)

start = int(time.time())
print(f"TRAFFIC_START epoch={{start}}", flush=True)

sent = 0
errors = 0

for i in range(600):

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    try:

        s.sendto(
            f"udp-flood-{{i}}".encode(),
            ("{udp_sink}", 9998),
        )

        sent += 1

    except Exception:
        errors += 1

    finally:
        s.close()

    time.sleep(0.05)

end = int(time.time())

print(
    f"UDP_SINGLE_SERVICE_FLOOD "
    f"sent={{sent}} "
    f"errors={{errors}}",
    flush=True,
)

print(
    f"TRAFFIC_DONE epoch={{end}}",
    flush=True,
)

time.sleep(180)
"""

        return python_pod(
            pod_name,
            script,
        )


    # ========================================================
    # 09 - CLOSED-PORT UDP RECONNAISSANCE
    # ========================================================

    if scenario_id == "09":

        script = f"""
import socket
import time

time.sleep(20)

start = int(time.time())
print(f"TRAFFIC_START epoch={{start}}", flush=True)

sent = 0
errors = 0

for i in range(80):

    port = 9100 + (i % 20)

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    try:

        s.sendto(
            f"closed-port-probe-{{i}}".encode(),
            ("{http}", port),
        )

        sent += 1

    except Exception:
        errors += 1

    finally:
        s.close()

    time.sleep(0.5)

end = int(time.time())

print(
    f"UDP_CLOSED_PORT_RECON "
    f"sent={{sent}} "
    f"errors={{errors}}",
    flush=True,
)

print(
    f"TRAFFIC_DONE epoch={{end}}",
    flush=True,
)

time.sleep(180)
"""

        return python_pod(
            pod_name,
            script,
        )


    # ========================================================
    # 10 - ICMP BURST
    # ========================================================

    if scenario_id == "10":

        script = f"""
sleep 20

echo "TRAFFIC_START epoch=$(date +%s)"

ping \
  -c 300 \
  -i 0.1 \
  {http}

PING_EXIT=$?

echo "ICMP_BURST ping_exit=$PING_EXIT"

echo "TRAFFIC_DONE epoch=$(date +%s)"

sleep 180
"""

        return netshoot_pod(
            pod_name,
            script,
        )


    raise ValueError(
        f"Unknown scenario: {scenario_id}"
    )


# ============================================================
# RESET BETWEEN TRIALS
# ============================================================

def clear_firewall():

    result = kubectl(
        [
            "exec",
            "-n",
            "ai-ids",
            FIREWALL_POD,
            "--",
            "nft",
            "flush",
            "set",
            "inet",
            "ai_ids_defense",
            "blocked_ipv4",
        ],
        check=False,
        timeout=30,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not clear Apollo nftables "
            "blocked_ipv4 set through "
            "ai-ids-firewall."
        )

    print(
        "Firewall block set cleared."
    )

def reset_trial_state():

    # Do not restart the live controller between trials.
    # Each trial uses a fresh client pod. The firewall set
    # is cleared, then we allow the 60-second detection
    # history from the previous trial to expire naturally.
    clear_firewall()

    state = run(
        [
            "systemctl",
            "is-active",
            CONTROLLER_SERVICE,
        ],
        check=False,
    )

    if state.stdout.strip() != "active":
        raise RuntimeError(
            "AI IDS controller is not active."
        )

    print(
        "Controller remains active."
    )

    print(
        "Waiting 65 seconds for previous "
        "defense history to expire..."
    )

    time.sleep(65)



# ============================================================
# CLIENT LOGS
# ============================================================

def get_logs(name):

    return kubectl(
        [
            "logs",
            "-n",
            NAMESPACE,
            name,
        ],
        check=False,
    ).stdout


def wait_for_done(
    name,
    timeout,
):

    deadline = time.time() + timeout

    while time.time() < deadline:

        logs = get_logs(name)

        if "TRAFFIC_DONE epoch=" in logs:
            return logs

        time.sleep(2)

    raise TimeoutError(
        f"Timed out waiting for {name}"
    )


def parse_epoch(
    logs,
    marker,
):

    match = re.search(
        rf"{marker} epoch=(\d+)",
        logs,
    )

    if not match:
        return None

    return int(
        match.group(1)
    )


# ============================================================
# READ IDS EVENTS
# ============================================================

def read_events(
    source_ip,
    traffic_start,
    traffic_end,
):

    if not EVENT_FILE.exists():

        raise RuntimeError(
            f"Missing IDS event file: {EVENT_FILE}"
        )

    lower = (
        math.floor(
            traffic_start / 10
        )
        * 10
        - 10
    )

    upper = (
        math.floor(
            traffic_end / 10
        )
        * 10
        + 20
    )

    rows = []

    with EVENT_FILE.open(
        newline=""
    ) as f:

        for row in csv.DictReader(f):

            if row.get("src_ip") != source_ip:
                continue

            try:

                start = float(
                    row.get(
                        "window_start",
                        0,
                    )
                )

            except Exception:
                continue

            if lower <= start <= upper:
                rows.append(row)

    rows.sort(
        key=lambda x:
        float(
            x.get(
                "window_start",
                0,
            )
        )
    )

    return rows


# ============================================================
# STATISTICS
# ============================================================

def number(value):

    try:
        return float(value)

    except Exception:
        return None


def avg(values):

    values = [
        x for x in values
        if x is not None
    ]

    if not values:
        return None

    return statistics.mean(values)


def med(values):

    values = [
        x for x in values
        if x is not None
    ]

    if not values:
        return None

    return statistics.median(values)


def percentile(
    values,
    fraction,
):

    values = sorted(
        x for x in values
        if x is not None
    )

    if not values:
        return None

    if len(values) == 1:
        return values[0]

    pos = (
        (len(values) - 1)
        * fraction
    )

    low = math.floor(pos)
    high = math.ceil(pos)

    if low == high:
        return values[low]

    return (
        values[low]
        + (
            values[high]
            - values[low]
        )
        * (pos - low)
    )


# ============================================================
# ANALYZE ONE TRIAL
# ============================================================

def analyze(
    events,
    truth,
    traffic_start,
):

    benign = sum(
        x.get("prediction") == "BENIGN"
        for x in events
    )

    attack = sum(
        x.get("prediction") == "ATTACK"
        for x in events
    )

    alerts = sum(
        x.get("defense_action") == "ALERT"
        for x in events
    )

    blocks = sum(
        x.get("defense_action") == "BLOCK"
        for x in events
    )

    enforced_rows = [
        x for x in events
        if str(
            x.get(
                "enforced",
                ""
            )
        ).lower()
        in {
            "1",
            "true",
            "yes",
        }
    ]

    probs = [
        number(
            x.get(
                "attack_probability"
            )
        )
        for x in events
    ]

    inference = [
        number(
            x.get(
                "inference_latency_ms"
            )
        )
        for x in events
    ]

    detected = attack > 0

    false_positive = (
        truth == "BENIGN"
        and detected
    )

    if truth == "BENIGN":

        correct = (
            len(events) > 0
            and attack == 0
        )

    else:

        correct = detected


    first_attack_delay = None

    attack_rows = [
        x for x in events
        if x.get("prediction") == "ATTACK"
    ]

    if attack_rows:

        processed = number(
            attack_rows[0].get(
                "processed_at"
            )
        )

        if processed is not None:

            first_attack_delay = (
                processed
                - traffic_start
            ) * 1000


    first_block_delay = None

    if enforced_rows:

        processed = number(
            enforced_rows[0].get(
                "processed_at"
            )
        )

        if processed is not None:

            first_block_delay = (
                processed
                - traffic_start
            ) * 1000


    return {
        "windows":
            len(events),

        "benign_predictions":
            benign,

        "attack_predictions":
            attack,

        "alert_actions":
            alerts,

        "block_actions":
            blocks,

        "enforced_blocks":
            len(enforced_rows),

        "correct_outcome":
            int(correct),

        "detected":
            int(detected),

        "false_positive":
            int(false_positive),

        "enforcement_success":
            int(
                truth == "ATTACK"
                and detected
                and len(enforced_rows) > 0
            ),

        "max_attack_probability":
            max(
                [
                    x for x in probs
                    if x is not None
                ],
                default=None,
            ),

        "mean_inference_ms":
            avg(inference),

        "median_inference_ms":
            med(inference),

        "p95_inference_ms":
            percentile(
                inference,
                0.95,
            ),

        "first_attack_delay_ms":
            first_attack_delay,

        "first_enforcement_delay_ms":
            first_block_delay,
    }


# ============================================================
# PROMETHEUS
# ============================================================

def prometheus_address():

    address = os.environ.get("AI_IDS_PROMETHEUS_URL")
    if not address:
        raise RuntimeError(
            "Set AI_IDS_PROMETHEUS_URL for resource measurement."
        )
    return address


def query_range(
    prometheus,
    query,
    start,
    end,
):

    url = (
        prometheus
        + "/api/v1/query_range?"
        + urlencode(
            {
                "query": query,
                "start": start,
                "end": end,
                "step": 15,
            }
        )
    )

    with urlopen(
        url,
        timeout=30,
    ) as response:

        payload = json.loads(
            response.read()
        )

    values = []

    for result in (
        payload
        .get("data", {})
        .get("result", [])
    ):

        for _, value in result.get(
            "values",
            []
        ):

            try:
                values.append(
                    float(value)
                )
            except Exception:
                pass

    return values


def resource_metrics(
    prometheus,
    start,
    end,
):

    output = {}

    for node, instance in NODES.items():
        if not instance:
            raise RuntimeError(
                f"Configure the node-exporter endpoint for {node}."
            )

        cpu_query = (
            "100 * (1 - avg("
            "rate(node_cpu_seconds_total{"
            'job="node-exporter",'
            f'instance="{instance}",'
            'mode="idle"}[1m])))'
        )

        mem_query = (
            "100 * (1 - "
            "node_memory_MemAvailable_bytes{"
            'job="node-exporter",'
            f'instance="{instance}"}}'
            " / "
            "node_memory_MemTotal_bytes{"
            'job="node-exporter",'
            f'instance="{instance}"}})'
        )

        try:

            cpu = query_range(
                prometheus,
                cpu_query,
                start,
                end,
            )

            mem = query_range(
                prometheus,
                mem_query,
                start,
                end,
            )

        except Exception:

            cpu = []
            mem = []

        output[
            f"{node}_cpu_avg_pct"
        ] = avg(cpu)

        output[
            f"{node}_cpu_peak_pct"
        ] = (
            max(cpu)
            if cpu
            else None
        )

        output[
            f"{node}_mem_avg_pct"
        ] = avg(mem)

        output[
            f"{node}_mem_peak_pct"
        ] = (
            max(mem)
            if mem
            else None
        )

    return output


# ============================================================
# CSV
# ============================================================

def append_master(
    path,
    row,
):

    exists = path.exists()

    with path.open(
        "a",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=MASTER_FIELDS,
            extrasaction="ignore",
        )

        if not exists:
            writer.writeheader()

        writer.writerow(
            {
                key:
                    row.get(
                        key,
                        ""
                    )
                for key
                in MASTER_FIELDS
            }
        )


def completed_trials(path):

    completed = set()

    if not path.exists():
        return completed

    with path.open(
        newline=""
    ) as f:

        for row in csv.DictReader(f):

            if row.get("status") != "COMPLETE":
                continue

            completed.add(
                (
                    row["scenario_id"],
                    int(
                        row["replicate"]
                    ),
                )
            )

    return completed


# ============================================================
# RUN ONE TRIAL
# ============================================================

def run_trial(
    scenario_id,
    replicate,
    order,
    targets,
    prometheus,
    output_dir,
):

    scenario = SCENARIOS[
        scenario_id
    ]

    pod_name = (
        f"rt-{scenario_id}-"
        f"{replicate:02d}"
    )

    log_dir = (
        output_dir
        / "client_logs"
    )

    log_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_path = (
        log_dir
        / f"{scenario_id}_rep{replicate:02d}.log"
    )

    row = {
        "trial_order": order,
        "scenario_id": scenario_id,
        "scenario_name":
            scenario["name"],
        "replicate": replicate,
        "ground_truth":
            scenario["truth"],
        "status": "ERROR",
        "error": "",
    }


    print()
    print("=" * 72)

    print(
        f"TRIAL {order} | "
        f"{scenario_id} | "
        f"{scenario['name']} | "
        f"REP {replicate}"
    )

    print("=" * 72)


    try:

        delete_pod(
            pod_name
        )

        apply_yaml(
            build_client(
                scenario_id,
                pod_name,
                targets,
            )
        )

        wait_ready(
            pod_name
        )

        source_ip = pod_ip(
            pod_name
        )

        row["source_ip"] = source_ip

        print(
            f"Source IP: {source_ip}"
        )


        reset_trial_state()


        logs = wait_for_done(
            pod_name,
            scenario[
                "max_wait"
            ],
        )

        log_path.write_text(
            logs
        )


        start = parse_epoch(
            logs,
            "TRAFFIC_START",
        )

        end = parse_epoch(
            logs,
            "TRAFFIC_DONE",
        )

        if start is None or end is None:

            raise RuntimeError(
                "Missing traffic timestamps."
            )


        row[
            "traffic_start_epoch"
        ] = start

        row[
            "traffic_end_epoch"
        ] = end

        row[
            "client_log"
        ] = str(log_path)


        print(
            f"Traffic: {start} -> {end}"
        )

        print(
            f"Waiting {scenario['settle']} "
            "seconds for IDS processing..."
        )

        time.sleep(
            scenario["settle"]
        )


        events = read_events(
            source_ip,
            start,
            end + scenario["settle"],
        )

        row.update(
            analyze(
                events,
                scenario["truth"],
                start,
            )
        )


        row.update(
            resource_metrics(
                prometheus,
                start - 15,
                end
                + scenario[
                    "settle"
                ]
                + 15,
            )
        )


        row["status"] = "COMPLETE"


        print(
            f"Windows={row['windows']} | "
            f"BENIGN={row['benign_predictions']} | "
            f"ATTACK={row['attack_predictions']} | "
            f"Enforced={row['enforced_blocks']}"
        )

        print(
            "RESULT: "
            + (
                "CORRECT"
                if row[
                    "correct_outcome"
                ]
                else "INCORRECT"
            )
        )


        return row


    except Exception as exc:

        row["error"] = str(exc)

        print(
            f"TRIAL ERROR: {exc}"
        )

        return row


    finally:

        delete_pod(
            pod_name
        )

        try:
            clear_firewall()
        except Exception:
            pass


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--trials",
        type=int,
        default=10,
    )

    parser.add_argument(
        "--scenarios",
        default="all",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=RANDOM_SEED_DEFAULT,
    )

    parser.add_argument(
        "--out",
        default=str(
            ROOT
            / "simple_ids"
            / "reports"
            / "repeated_trials"
        ),
    )

    parser.add_argument(
        "--resume",
        action="store_true",
    )

    parser.add_argument(
        "--no-randomize",
        action="store_true",
    )

    args = parser.parse_args()


    if args.scenarios == "all":

        selected = list(
            SCENARIOS.keys()
        )

    else:

        selected = [
            x.strip()
            for x in
            args.scenarios.split(",")
        ]


    invalid = [
        x for x in selected
        if x not in SCENARIOS
    ]

    if invalid:

        raise SystemExit(
            "Invalid scenarios: "
            + ", ".join(invalid)
        )


    output_dir = Path(
        args.out
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )


    master = (
        output_dir
        / "master_trials.csv"
    )


    if (
        master.exists()
        and not args.resume
    ):

        raise SystemExit(
            f"{master} already exists. "
            "Use --resume or another "
            "--out directory."
        )


    print(
        "Preparing target pods..."
    )

    targets = ensure_targets()


    print(
        "Targets:",
        targets,
    )


    prometheus = (
        prometheus_address()
    )

    print(
        f"Prometheus: {prometheus}"
    )


    schedule = [
        (
            scenario,
            replicate,
        )
        for scenario in selected
        for replicate in range(
            1,
            args.trials + 1,
        )
    ]


    if not args.no_randomize:

        rng = random.Random(
            args.seed
        )

        rng.shuffle(
            schedule
        )


    completed = (
        completed_trials(
            master
        )
        if args.resume
        else set()
    )


    print(
        f"Scheduled trials: "
        f"{len(schedule)}"
    )

    print(
        f"Random seed: "
        f"{args.seed}"
    )


    for order, item in enumerate(
        schedule,
        start=1,
    ):

        scenario_id, replicate = item


        if (
            scenario_id,
            replicate,
        ) in completed:

            print(
                f"Skipping "
                f"{scenario_id}/"
                f"{replicate}"
            )

            continue


        row = run_trial(
            scenario_id,
            replicate,
            order,
            targets,
            prometheus,
            output_dir,
        )


        append_master(
            master,
            row,
        )


    print()
    print("=" * 72)
    print("RUN COMPLETE")
    print("=" * 72)

    print(
        f"Results: {master}"
    )


if __name__ == "__main__":
    main()
