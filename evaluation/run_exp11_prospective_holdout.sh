#!/bin/bash
set -euo pipefail

if [[ "${AI_IDS_ALLOW_LAB_TESTS:-}" != "YES" ]]; then
    echo "Refusing lab tests: set AI_IDS_ALLOW_LAB_TESTS=YES only in an authorized testbed." >&2
    exit 2
fi
AI_IDS_PROJECT_ROOT="${AI_IDS_PROJECT_ROOT:?Set AI_IDS_PROJECT_ROOT to the original full ai-ids checkout}"
cd "$AI_IDS_PROJECT_ROOT"

NS="ids-defense-lab"
DURATION=1800
DRAIN=150

STAMP="$(date +%Y%m%d_%H%M%S)"

OUTDIR="simple_ids/reports/final_experiments/11_prospective_${STAMP}"

mkdir -p \
"$OUTDIR/logs"

SEED="$(
    od \
    -An \
    -N4 \
    -tu4 \
    /dev/urandom \
    | tr -d ' '
)"

echo "$SEED" \
> "$OUTDIR/random_seed.txt"

MODEL="simple_ids/model/zeek_ids_final_candidate_v4.joblib"

sha256sum "$MODEL" \
| tee \
"$OUTDIR/model_sha256_before.txt"

SERVICE_IP="$(
    kubectl get svc \
    ai-ids-v4-metrics \
    -n ai-ids \
    -o jsonpath='{.spec.clusterIP}'
)"

echo
echo "============================================================"
echo "EXPERIMENT 11 - PROSPECTIVE MIXED-TRAFFIC HOLDOUT"
echo "============================================================"

echo "Random seed: $SEED"
echo "Duration:    $DURATION seconds"
echo "Model:       $MODEL"
echo "V4 service:  $SERVICE_IP"

echo
echo "============================================================"
echo "PREFLIGHT"
echo "============================================================"

systemctl is-active \
ai-ids-v4-controller.service

kubectl get pod \
athena-v4-runtime \
-n ai-ids

curl -fsS \
"http://${SERVICE_IP}:9105/health"

echo

kubectl delete pod \
-n "$NS" \
-l experiment=exp11 \
--ignore-not-found \
--wait=true >/dev/null 2>&1 || true

kubectl exec \
-n ai-ids \
ai-ids-firewall -- \
nft flush set \
inet ai_ids_defense blocked_ipv4 \
2>/dev/null || true

# ============================================================
# TARGET 1 - HTTP SERVER A
# ============================================================

cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: exp11-http-a
  namespace: ids-defense-lab
  labels:
    experiment: exp11
    role: target
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
    - --bind
    - 0.0.0.0
YAML


# ============================================================
# TARGET 2 - HTTP SERVER B
# ============================================================

cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: exp11-http-b
  namespace: ids-defense-lab
  labels:
    experiment: exp11
    role: target
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
    - --bind
    - 0.0.0.0
YAML


# ============================================================
# TARGET 3 - UDP ECHO SERVER
# Ports 10000-10007
# ============================================================

cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: exp11-udp-target
  namespace: ids-defense-lab
  labels:
    experiment: exp11
    role: target
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

      for port in range(10000, 10008):
          s = socket.socket(
              socket.AF_INET,
              socket.SOCK_DGRAM,
          )

          s.bind(
              ("0.0.0.0", port)
          )

          sockets.append(s)

      print(
          "UDP echo target ready",
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
              data, address = sock.recvfrom(
                  4096
              )

              sock.sendto(
                  data,
                  address,
              )
YAML

# ============================================================
# WAIT FOR TARGETS
# ============================================================

echo
echo "Waiting for Experiment 11 targets..."

for POD in \
exp11-http-a \
exp11-http-b \
exp11-udp-target
do
    kubectl wait \
    --for=condition=Ready \
    "pod/$POD" \
    -n "$NS" \
    --timeout=180s >/dev/null
done


# ============================================================
# TARGET IP ADDRESSES
# ============================================================

HTTP_A="$(
    kubectl get pod \
    exp11-http-a \
    -n "$NS" \
    -o jsonpath='{.status.podIP}'
)"

HTTP_B="$(
    kubectl get pod \
    exp11-http-b \
    -n "$NS" \
    -o jsonpath='{.status.podIP}'
)"

UDP_TARGET="$(
    kubectl get pod \
    exp11-udp-target \
    -n "$NS" \
    -o jsonpath='{.status.podIP}'
)"

echo
echo "============================================================"
echo "TARGETS"
echo "============================================================"

echo "HTTP target A: $HTTP_A"
echo "HTTP target B: $HTTP_B"
echo "UDP target:    $UDP_TARGET"


# ============================================================
# CREATE FRESH RANDOMIZED ATTACK SCHEDULE
#
# These values are generated after the frozen model
# checksum was recorded.
# ============================================================

SEED="$SEED" \
python3 - <<'PY' \
> "$OUTDIR/schedule.env"

import os
import random

seed = int(
    os.environ["SEED"]
)

r = random.Random(
    seed
)

# Approximate attack locations during the 30-minute run.
# Jitter prevents us from repeatedly using identical timing.

bases = [
    240,
    430,
    610,
    790,
    970,
    1150,
    1330,
    1510,
]

delays = [
    max(
        180,
        base + r.randint(-35, 35),
    )
    for base in bases
]

for i, delay in enumerate(
    delays,
    1,
):
    print(
        f"D{i}={delay}"
    )

# Independent seeds for each attack generator.

for i in range(
    1,
    9,
):
    print(
        f"S{i}={r.randrange(1, 2**31)}"
    )
PY


source \
"$OUTDIR/schedule.env"


echo
echo "============================================================"
echo "RANDOMIZED ATTACK SCHEDULE"
echo "============================================================"

cat \
"$OUTDIR/schedule.env"


# ============================================================
# BEGIN EXPERIMENT CLOCK
# ============================================================

START_EPOCH="$(
    date +%s
)"

echo "$START_EPOCH" \
> "$OUTDIR/start_epoch.txt"

echo
echo "Experiment start epoch: $START_EPOCH"

# ============================================================
# BENIGN SOURCE 1
# IRREGULAR HTTP BROWSING
# ============================================================

cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: exp11-benign-http
  namespace: ids-defense-lab
  labels:
    experiment: exp11
    role: benign
    scenario: benign-http
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
      import http.client
      import random
      import time

      r = random.Random(
          ${SEED} + 101
      )

      targets = [
          "${HTTP_A}",
          "${HTTP_B}",
      ]

      stop = (
          time.time()
          + ${DURATION}
      )

      success = 0
      failed = 0

      while time.time() < stop:

          host = r.choice(
              targets
          )

          try:

              conn = http.client.HTTPConnection(
                  host,
                  8088,
                  timeout=3,
              )

              conn.request(
                  "GET",
                  "/",
                  headers={
                      "User-Agent":
                          "Exp11Browser/"
                          + str(
                              r.randint(
                                  1,
                                  99,
                              )
                          )
                  },
              )

              response = (
                  conn.getresponse()
              )

              response.read()

              conn.close()

              success += 1

          except Exception:

              failed += 1

          if r.random() < 0.04:

              time.sleep(
                  r.uniform(
                      4.0,
                      9.0,
                  )
              )

          else:

              time.sleep(
                  r.uniform(
                      0.45,
                      2.7,
                  )
              )

      print(
          "BENIGN_HTTP_DONE "
          f"success={success} "
          f"failed={failed}",
          flush=True,
      )
YAML

# ============================================================
# BENIGN SOURCE 2
# VARIABLE UDP APPLICATION TRAFFIC
# ============================================================

cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: exp11-benign-udp
  namespace: ids-defense-lab
  labels:
    experiment: exp11
    role: benign
    scenario: benign-udp
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
      import os
      import random
      import socket
      import time

      r = random.Random(
          ${SEED} + 202
      )

      stop = (
          time.time()
          + ${DURATION}
      )

      success = 0
      failed = 0

      while time.time() < stop:

          port = r.randint(
              10000,
              10007,
          )

          payload = os.urandom(
              r.randint(
                  24,
                  220,
              )
          )

          sock = socket.socket(
              socket.AF_INET,
              socket.SOCK_DGRAM,
          )

          sock.settimeout(
              2
          )

          try:

              sock.sendto(
                  payload,
                  (
                      "${UDP_TARGET}",
                      port,
                  ),
              )

              data, _ = sock.recvfrom(
                  4096
              )

              if data == payload:
                  success += 1
              else:
                  failed += 1

          except Exception:

              failed += 1

          finally:

              sock.close()

          time.sleep(
              r.uniform(
                  0.25,
                  1.9,
              )
          )

      print(
          "BENIGN_UDP_DONE "
          f"success={success} "
          f"failed={failed}",
          flush=True,
      )
YAML

# ============================================================
# GENERIC EXP11 TRAFFIC GENERATOR
# ============================================================

cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: exp11-generator
  namespace: ids-defense-lab
data:
  generator.py: |
    import http.client
    import os
    import random
    import socket
    import time

    MODE = os.environ["MODE"]
    HTTP_A = os.environ["HTTP_A"]
    HTTP_B = os.environ["HTTP_B"]
    UDP_TARGET = os.environ["UDP_TARGET"]

    SEED = int(os.environ.get("SEED", "1"))
    DELAY = float(os.environ.get("DELAY", "0"))
    DURATION = int(os.environ.get("DURATION", "1800"))

    r = random.Random(SEED)

    time.sleep(DELAY)

    def marker(kind):
        print(
            f"{kind} scenario={MODE} "
            f"epoch={int(time.time())}",
            flush=True,
        )

    # ========================================================
    # BENIGN MIXED TRAFFIC
    # ========================================================

    if MODE == "benign_mixed":

        stop = time.time() + DURATION
        events = 0

        while time.time() < stop:

            if r.random() < 0.58:

                host = r.choice(
                    [HTTP_A, HTTP_B]
                )

                try:
                    c = http.client.HTTPConnection(
                        host,
                        8088,
                        timeout=2,
                    )

                    c.request(
                        "GET",
                        "/",
                    )

                    c.getresponse().read()
                    c.close()

                except Exception:
                    pass

            else:

                s = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_DGRAM,
                )

                s.settimeout(2)

                try:
                    payload = os.urandom(
                        r.randint(16, 96)
                    )

                    s.sendto(
                        payload,
                        (
                            UDP_TARGET,
                            r.randint(
                                10000,
                                10007,
                            ),
                        ),
                    )

                    s.recvfrom(2048)

                except Exception:
                    pass

                finally:
                    s.close()

            events += 1

            if events % 45 == 0:

                for _ in range(
                    r.randint(3, 7)
                ):

                    try:
                        c = http.client.HTTPConnection(
                            HTTP_A,
                            8088,
                            timeout=2,
                        )

                        c.request(
                            "GET",
                            "/",
                        )

                        c.getresponse().read()
                        c.close()

                    except Exception:
                        pass

                    time.sleep(
                        r.uniform(
                            0.08,
                            0.25,
                        )
                    )

            time.sleep(
                r.uniform(
                    0.8,
                    4.2,
                )
            )

        print(
            f"BENIGN_MIXED_DONE events={events}",
            flush=True,
        )

    # ========================================================
    # RANDOMIZED TCP RECON
    # ========================================================

    elif MODE == "tcp_random_scan":

        marker("ATTACK_START")

        ports = r.sample(
            range(2000, 12000),
            61,
        )

        for port in ports:

            s = socket.socket()
            s.settimeout(0.25)

            try:
                s.connect_ex(
                    (
                        HTTP_A,
                        port,
                    )
                )
            finally:
                s.close()

            time.sleep(
                r.uniform(
                    0.20,
                    0.90,
                )
            )

        marker("ATTACK_END")
        time.sleep(240)

    # ========================================================
    # TCP CONNECTION FLOOD
    # ========================================================

    elif MODE == "tcp_flood":

        marker("ATTACK_START")

        ok = 0
        fail = 0

        for _ in range(550):

            s = socket.socket()
            s.settimeout(0.30)

            try:
                rc = s.connect_ex(
                    (
                        HTTP_B,
                        8088,
                    )
                )

                if rc == 0:
                    ok += 1
                else:
                    fail += 1

            except Exception:
                fail += 1

            finally:
                s.close()

            time.sleep(
                r.uniform(
                    0.03,
                    0.12,
                )
            )

        print(
            f"TCP_FLOOD_COUNTS "
            f"ok={ok} fail={fail}",
            flush=True,
        )

        marker("ATTACK_END")
        time.sleep(240)

    # ========================================================
    # CLOSED-PORT UDP RECON
    # ========================================================

    elif MODE == "udp_closed_recon":

        marker("ATTACK_START")

        ports = r.sample(
            range(12000, 20000),
            47,
        )

        for _ in range(120):

            s = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            )

            try:
                s.sendto(
                    os.urandom(
                        r.randint(
                            12,
                            90,
                        )
                    ),
                    (
                        HTTP_A,
                        r.choice(ports),
                    ),
                )
            finally:
                s.close()

            time.sleep(
                r.uniform(
                    0.20,
                    0.60,
                )
            )

        marker("ATTACK_END")
        time.sleep(240)

    # ========================================================
    # UDP SINGLE-SERVICE FLOOD
    # ========================================================

    elif MODE == "udp_flood":

        marker("ATTACK_START")

        for _ in range(900):

            s = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            )

            try:
                s.sendto(
                    os.urandom(
                        r.randint(
                            20,
                            180,
                        )
                    ),
                    (
                        UDP_TARGET,
                        10000,
                    ),
                )
            finally:
                s.close()

            time.sleep(
                r.uniform(
                    0.015,
                    0.060,
                )
            )

        marker("ATTACK_END")
        time.sleep(240)

    # ========================================================
    # RESPONSIVE UDP MULTI-PORT RECON
    # ========================================================

    elif MODE == "udp_responsive_recon":

        marker("ATTACK_START")

        ok = 0
        fail = 0

        for _ in range(150):

            s = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            )

            s.settimeout(1)

            try:
                payload = os.urandom(
                    r.randint(
                        16,
                        96,
                    )
                )

                s.sendto(
                    payload,
                    (
                        UDP_TARGET,
                        r.randint(
                            10000,
                            10007,
                        ),
                    ),
                )

                response, _ = s.recvfrom(
                    2048
                )

                if response == payload:
                    ok += 1

            except Exception:
                fail += 1

            finally:
                s.close()

            time.sleep(
                r.uniform(
                    0.25,
                    0.75,
                )
            )

        print(
            f"UDP_RESPONSIVE "
            f"ok={ok} fail={fail}",
            flush=True,
        )

        marker("ATTACK_END")
        time.sleep(240)

    # ========================================================
    # MIXED TCP / UDP SWEEP
    # ========================================================

    elif MODE == "mixed_protocol_sweep":

        marker("ATTACK_START")

        tcp_ports = r.sample(
            range(21000, 26000),
            40,
        )

        udp_ports = r.sample(
            range(27000, 32000),
            40,
        )

        for i in range(160):

            if i % 2 == 0:

                s = socket.socket()
                s.settimeout(0.20)

                try:
                    s.connect_ex(
                        (
                            HTTP_A,
                            r.choice(
                                tcp_ports
                            ),
                        )
                    )
                finally:
                    s.close()

            else:

                s = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_DGRAM,
                )

                try:
                    s.sendto(
                        os.urandom(
                            r.randint(
                                8,
                                72,
                            )
                        ),
                        (
                            HTTP_B,
                            r.choice(
                                udp_ports
                            ),
                        ),
                    )
                finally:
                    s.close()

            time.sleep(
                r.uniform(
                    0.20,
                    0.70,
                )
            )

        marker("ATTACK_END")
        time.sleep(240)
YAML


# ============================================================
# GENERIC PYTHON POD FUNCTION
# ============================================================

make_generator () {

    NAME="$1"
    ROLE="$2"
    SCENARIO="$3"
    MODE="$4"
    DELAY="$5"
    PODSEED="$6"

cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${NAME}
  namespace: ${NS}
  labels:
    experiment: exp11
    role: ${ROLE}
    scenario: ${SCENARIO}
spec:
  nodeName: athena
  restartPolicy: Never
  containers:
  - name: generator
    image: python:3.13-alpine
    command:
    - python3
    - -u
    - /generator/generator.py
    env:
    - name: MODE
      value: "${MODE}"
    - name: HTTP_A
      value: "${HTTP_A}"
    - name: HTTP_B
      value: "${HTTP_B}"
    - name: UDP_TARGET
      value: "${UDP_TARGET}"
    - name: SEED
      value: "${PODSEED}"
    - name: DELAY
      value: "${DELAY}"
    - name: DURATION
      value: "${DURATION}"
    volumeMounts:
    - name: generator
      mountPath: /generator
  volumes:
  - name: generator
    configMap:
      name: exp11-generator
YAML
}


# ============================================================
# BENIGN MIXED SOURCE
# ============================================================

make_generator \
exp11-benign-mixed \
benign \
benign-mixed \
benign_mixed \
0 \
"$((SEED + 303))"


# ============================================================
# ATTACK GENERATORS
# ============================================================

make_generator \
exp11-atk-tcp-scan \
attack \
tcp-random-scan \
tcp_random_scan \
"$D1" \
"$S1"

make_generator \
exp11-atk-tcp-flood \
attack \
tcp-flood \
tcp_flood \
"$D3" \
"$S3"

make_generator \
exp11-atk-udp-closed \
attack \
udp-closed-recon \
udp_closed_recon \
"$D4" \
"$S4"

make_generator \
exp11-atk-udp-flood \
attack \
udp-flood \
udp_flood \
"$D5" \
"$S5"

make_generator \
exp11-atk-udp-responsive \
attack \
udp-responsive-recon \
udp_responsive_recon \
"$D6" \
"$S6"

make_generator \
exp11-atk-mixed-sweep \
attack \
mixed-protocol-sweep \
mixed_protocol_sweep \
"$D8" \
"$S8"


# ============================================================
# ATTACK 2 - RAW SYN BURST
# ============================================================

cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: exp11-atk-syn
  namespace: ${NS}
  labels:
    experiment: exp11
    role: attack
    scenario: syn-burst
spec:
  nodeName: athena
  restartPolicy: Never
  containers:
  - name: attacker
    image: nicolaka/netshoot:latest
    securityContext:
      capabilities:
        add:
        - NET_RAW
    command:
    - /bin/sh
    - -c
    - |
      sleep ${D2}

      echo "ATTACK_START scenario=syn_burst epoch=\$(date +%s)"

      nping \
        --tcp \
        --flags syn \
        -p 8088 \
        --rate 13 \
        -c 377 \
        ${HTTP_A} \
        >/tmp/nping.log 2>&1 || true

      tail -n 8 /tmp/nping.log

      echo "ATTACK_END scenario=syn_burst epoch=\$(date +%s)"

      sleep 240
YAML


# ============================================================
# ATTACK 7 - ICMP BURST
# ============================================================

cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: exp11-atk-icmp
  namespace: ${NS}
  labels:
    experiment: exp11
    role: attack
    scenario: icmp-burst
spec:
  nodeName: athena
  restartPolicy: Never
  containers:
  - name: attacker
    image: nicolaka/netshoot:latest
    securityContext:
      capabilities:
        add:
        - NET_RAW
    command:
    - /bin/sh
    - -c
    - |
      sleep ${D7}

      echo "ATTACK_START scenario=icmp_burst epoch=\$(date +%s)"

      ping \
        -c 260 \
        -i 0.11 \
        ${HTTP_B} \
        >/tmp/ping.log 2>&1 || true

      tail -n 6 /tmp/ping.log

      echo "ATTACK_END scenario=icmp_burst epoch=\$(date +%s)"

      sleep 240
YAML


# ============================================================
# WAIT FOR SOURCE POD IPS
# ============================================================

echo
echo "Waiting for Experiment 11 sources..."

sleep 20

kubectl get pods \
-n "$NS" \
-l experiment=exp11 \
-o wide


# ============================================================
# SAVE GROUND TRUTH SOURCE MAP
# ============================================================

kubectl get pods \
-n "$NS" \
-l experiment=exp11 \
-o json \
> "$OUTDIR/pods.json"


OUTDIR="$OUTDIR" \
python3 - <<'PY'
import csv
import json
import os
from pathlib import Path

out = Path(
    os.environ["OUTDIR"]
)

with (
    out / "pods.json"
).open() as f:
    data = json.load(f)

rows = []

for pod in data["items"]:

    labels = (
        pod["metadata"]
        .get("labels", {})
    )

    role = labels.get(
        "role",
        ""
    )

    if role not in {
        "attack",
        "benign",
    }:
        continue

    rows.append(
        {
            "pod":
                pod["metadata"]["name"],

            "role":
                role,

            "scenario":
                labels.get(
                    "scenario",
                    "",
                ),

            "src_ip":
                pod.get(
                    "status",
                    {},
                ).get(
                    "podIP",
                    "",
                ),
        }
    )

path = (
    out
    / "ground_truth_sources.csv"
)

with path.open(
    "w",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "pod",
            "role",
            "scenario",
            "src_ip",
        ],
    )

    writer.writeheader()
    writer.writerows(rows)

print()
print("GROUND TRUTH")
print("=" * 80)

for row in rows:
    print(
        row["role"],
        row["scenario"],
        row["src_ip"],
    )
PY


# ============================================================
# EXPERIMENT METADATA
# ============================================================

cat > "$OUTDIR/metadata.txt" <<EOF
Experiment:
Prospective mixed-traffic live holdout

Start epoch:
$START_EPOCH

Requested traffic duration:
$DURATION seconds

Post-test Zeek drain:
$DRAIN seconds

Random seed:
$SEED

Traffic provenance:
All experiment traffic was freshly generated after model freeze.
No training CSV, validation CSV, PCAP, UWF, UNSW, or replay file
was used as experiment traffic.

HTTP target A:
$HTTP_A

HTTP target B:
$HTTP_B

UDP target:
$UDP_TARGET

Frozen model:
$(cat "$OUTDIR/model_sha256_before.txt")
EOF


echo
echo "============================================================"
echo "EXPERIMENT 11 RUNNING"
echo "============================================================"

echo "Continuous benign background traffic is active."
echo "Eight attacks will occur during the 30-minute test."
echo
echo "Do not retrain or change thresholds during this run."


# ============================================================
# WAIT FOR THE FULL TRAFFIC PERIOD
# ============================================================

sleep "$DURATION"

END_TRAFFIC_EPOCH="$(
    date +%s
)"

echo "$END_TRAFFIC_EPOCH" \
> "$OUTDIR/end_traffic_epoch.txt"

echo
echo "Traffic period complete."
echo "Waiting $DRAIN seconds for Zeek finalization..."

sleep "$DRAIN"

FINAL_EPOCH="$(
    date +%s
)"

echo "$FINAL_EPOCH" \
> "$OUTDIR/final_epoch.txt"


# ============================================================
# COLLECT POD LOGS
# ============================================================

for POD in $(
    kubectl get pods \
    -n "$NS" \
    -l experiment=exp11 \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
)
do

    kubectl logs \
    -n "$NS" \
    "$POD" \
    > "$OUTDIR/logs/${POD}.log" \
    2>&1 || true

done


# ============================================================
# VERIFY MODEL INTEGRITY
# ============================================================

sha256sum "$MODEL" \
| tee \
"$OUTDIR/model_sha256_after.txt"

if cmp -s \
"$OUTDIR/model_sha256_before.txt" \
"$OUTDIR/model_sha256_after.txt"
then
    echo "MODEL_INTEGRITY=PASS"
else
    echo "MODEL_INTEGRITY=FAIL"
fi \
| tee \
"$OUTDIR/model_integrity.txt"


# ============================================================
# SCORE THE LIVE HOLDOUT
# ============================================================

GROUND="$OUTDIR/ground_truth_sources.csv" \
START_EPOCH="$START_EPOCH" \
FINAL_EPOCH="$FINAL_EPOCH" \
OUTDIR="$OUTDIR" \
~/ids-env/bin/python - <<'PY'
import csv
import os
from pathlib import Path
from statistics import mean

ground_file = Path(
    os.environ["GROUND"]
)

events_file = Path(
    "simple_ids/reports/live_v4_events.csv"
)

outdir = Path(
    os.environ["OUTDIR"]
)

start = float(
    os.environ["START_EPOCH"]
)

end = float(
    os.environ["FINAL_EPOCH"]
)

with ground_file.open() as f:
    truth = list(
        csv.DictReader(f)
    )

with events_file.open() as f:
    reader = csv.DictReader(f)

    fields = (
        reader.fieldnames
        or []
    )

    all_events = list(reader)


def choose(*names):

    for name in names:
        if name in fields:
            return name

    return None


time_col = choose(
    "processed_at",
    "timestamp",
    "event_time",
)

src_col = choose(
    "src_ip",
    "source_ip",
)

pred_col = choose(
    "prediction",
    "predicted_label",
)

prob_col = choose(
    "attack_probability",
    "probability",
)

lat_col = choose(
    "inference_latency_ms",
    "inference_ms",
)

action_col = choose(
    "defense_action",
    "action",
)

enforced_col = choose(
    "enforced",
    "block_enforced",
)


if time_col is None:
    time_col = fields[0]


def number(row, column):

    if not column:
        return 0.0

    try:
        return float(
            row.get(
                column,
                0,
            )
            or 0
        )
    except Exception:
        return 0.0


events = [
    row
    for row in all_events
    if (
        start - 15
        <= number(
            row,
            time_col,
        )
        <= end + 15
    )
]


summary = []


for item in truth:

    ip = item["src_ip"]

    rows = [
        row
        for row in events
        if (
            src_col
            and
            row.get(src_col) == ip
        )
    ]

    attack_rows = [
        row
        for row in rows
        if (
            pred_col
            and
            str(
                row.get(
                    pred_col,
                    "",
                )
            ).upper()
            == "ATTACK"
        )
    ]

    benign_rows = [
        row
        for row in rows
        if (
            pred_col
            and
            str(
                row.get(
                    pred_col,
                    "",
                )
            ).upper()
            == "BENIGN"
        )
    ]

    alerts = sum(
        str(
            row.get(
                action_col,
                "",
            )
        ).upper()
        == "ALERT"
        for row in rows
    ) if action_col else 0

    blocks = sum(
        "BLOCK"
        in str(
            row.get(
                action_col,
                "",
            )
        ).upper()
        for row in rows
    ) if action_col else 0

    enforced = 0

    if enforced_col:

        for row in rows:

            value = str(
                row.get(
                    enforced_col,
                    "",
                )
            ).lower()

            if value in {
                "1",
                "true",
                "yes",
            }:
                enforced += 1

    probabilities = [
        number(
            row,
            prob_col,
        )
        for row in rows
    ]

    latencies = [
        number(
            row,
            lat_col,
        )
        for row in rows
        if lat_col
    ]

    detected = (
        len(attack_rows) > 0
    )

    if item["role"] == "attack":

        outcome = (
            "DETECTED"
            if detected
            else "MISSED"
        )

    else:

        outcome = (
            "FALSE_POSITIVE"
            if detected
            else "CORRECT_BENIGN"
        )

    summary.append(
        {
            **item,

            "windows":
                len(rows),

            "attack_windows":
                len(attack_rows),

            "benign_windows":
                len(benign_rows),

            "alerts":
                alerts,

            "block_actions":
                blocks,

            "enforced_blocks":
                enforced,

            "max_probability":
                max(probabilities)
                if probabilities
                else 0,

            "mean_inference_ms":
                mean(latencies)
                if latencies
                else 0,

            "outcome":
                outcome,
        }
    )


fields_out = [
    "pod",
    "role",
    "scenario",
    "src_ip",
    "windows",
    "attack_windows",
    "benign_windows",
    "alerts",
    "block_actions",
    "enforced_blocks",
    "max_probability",
    "mean_inference_ms",
    "outcome",
]

summary_file = (
    outdir
    / "prospective_holdout_summary.csv"
)

with summary_file.open(
    "w",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=fields_out,
    )

    writer.writeheader()
    writer.writerows(summary)


print()
print("=" * 120)
print("EXPERIMENT 11 - PROSPECTIVE HOLDOUT RESULTS")
print("=" * 120)

for row in summary:

    print(
        f"{row['role']:<8} "
        f"{row['scenario']:<24} "
        f"windows={row['windows']:<4} "
        f"attack={row['attack_windows']:<4} "
        f"benign={row['benign_windows']:<4} "
        f"max_p={row['max_probability']:.4f} "
        f"enforced={row['enforced_blocks']:<3} "
        f"{row['outcome']}"
    )


attacks = [
    row
    for row in summary
    if row["role"] == "attack"
]

benign = [
    row
    for row in summary
    if row["role"] == "benign"
]

detected = sum(
    row["attack_windows"] > 0
    for row in attacks
)

fp_sources = sum(
    row["attack_windows"] > 0
    for row in benign
)


print()
print("=" * 120)
print("PROSPECTIVE GENERALIZATION SUMMARY")
print("=" * 120)

print(
    f"Attack episodes tested:       "
    f"{len(attacks)}"
)

print(
    f"Attack episodes detected:     "
    f"{detected}"
)

print(
    f"Attack episodes missed:       "
    f"{len(attacks) - detected}"
)

if attacks:
    print(
        f"Episode detection rate:       "
        f"{detected / len(attacks) * 100:.2f}%"
    )

print()

print(
    f"Benign sources tested:        "
    f"{len(benign)}"
)

print(
    f"Benign FP sources:            "
    f"{fp_sources}"
)

if benign:
    print(
        f"Benign source correctness:    "
        f"{(len(benign)-fp_sources) / len(benign) * 100:.2f}%"
    )

print()
print(
    "Saved:",
    summary_file,
)
PY


echo
echo "============================================================"
echo "EXPERIMENT 11 COMPLETE"
echo "============================================================"

echo "Results directory:"
echo "$OUTDIR"

