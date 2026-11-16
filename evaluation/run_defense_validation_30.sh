#!/usr/bin/env bash
set -euo pipefail

# Destructive lab tests: explicit permission and a complete original checkout
# are required. The GitHub publication snapshot is for review by default.
if [[ "${AI_IDS_ALLOW_LAB_TESTS:-}" != "YES" ]]; then
    echo "Refusing lab tests: set AI_IDS_ALLOW_LAB_TESTS=YES only in an authorized testbed." >&2
    exit 2
fi
AI_IDS_PROJECT_ROOT="${AI_IDS_PROJECT_ROOT:?Set AI_IDS_PROJECT_ROOT to the original full ai-ids checkout}"
AI_IDS_INFERENCE_URL="${AI_IDS_INFERENCE_URL:?Set AI_IDS_INFERENCE_URL to the authorized V4 service base URL}"
cd "$AI_IDS_PROJECT_ROOT"

NS="ids-defense-lab"
FW_NS="ai-ids"
FW_POD="ai-ids-firewall"
TARGET_POD="defense-target"
EVENTS="simple_ids/reports/live_v4_events.csv"
EXPECTED_SHA="4ff285c89a58f3defddc8b68084ef9e132b697463b158b537e2c1d2bc777a774"
MODEL="simple_ids/model/zeek_ids_final_candidate_v4.joblib"
SEED=20261102
WASHOUT=65
POLL_INTERVAL=0.5
BLOCK_POLLS=360
EXPIRY_POLLS=360

STAMP="$(date +%Y%m%d_%H%M%S)"
OUTDIR="${1:-simple_ids/reports/defense_validation/final_30_${STAMP}}"
mkdir -p "$OUTDIR/trials"

MASTER="$OUTDIR/defense_validation_trials.csv"
SCHEDULE="$OUTDIR/schedule.csv"
SUMMARY="$OUTDIR/final_summary.txt"

echo "$OUTDIR" > simple_ids/reports/defense_validation/LAST_CAMPAIGN_DIR.txt

sudo -v

epoch_now() {
    python3 - <<'PY'
import time
print(time.time())
PY
}

probe_http() {
    local pod="$1"
    local count="$2"
    local target_ip="$3"

    kubectl exec -i -n "$NS" "$pod" -c py -- \
        python3 - "$target_ip" "$count" <<'PY'
import sys, time, urllib.request
target = sys.argv[1]
count = int(sys.argv[2])
ok = 0
fail = 0
for _ in range(count):
    try:
        with urllib.request.urlopen(f"http://{target}:8088/", timeout=0.6) as r:
            if 200 <= r.status < 400:
                ok += 1
            else:
                fail += 1
    except Exception:
        fail += 1
    time.sleep(0.10)
print(ok, fail)
PY
}

flush_blocks() {
    kubectl exec -n "$FW_NS" "$FW_POD" -- \
        nft flush set inet ai_ids_defense blocked_ipv4 >/dev/null
}

reset_counters() {
    kubectl exec -n "$FW_NS" "$FW_POD" -- \
        nft reset counters table inet ai_ids_defense >/dev/null 2>&1 || true
}

drop_counters() {
    kubectl exec -n "$FW_NS" "$FW_POD" -- \
        nft list chain inet ai_ids_defense forward |
    awk '
      /ip saddr @blocked_ipv4/ && /counter packets/ {
        packets=0; bytes=0
        for (i=1;i<=NF;i++) {
          if ($i=="packets") packets=$(i+1)
          if ($i=="bytes") bytes=$(i+1)
        }
        print packets, bytes
        exit
      }'
}

source_is_blocked() {
    local ip="$1"
    kubectl exec -n "$FW_NS" "$FW_POD" -- \
        nft list set inet ai_ids_defense blocked_ipv4 2>/dev/null |
        grep -Fq "$ip"
}

restart_controller_clean() {
    sudo systemctl restart ai-ids-v4-controller.service
    for _ in $(seq 1 20); do
        if [[ "$(systemctl is-active ai-ids-v4-controller.service || true)" == "active" ]]; then
            sleep 3
            return 0
        fi
        sleep 1
    done
    systemctl status ai-ids-v4-controller.service --no-pager || true
    return 1
}

delete_trial_pods() {
    kubectl delete pod defense-val-attacker defense-val-benign defense-val-benign-only \
        -n "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true
}

create_attack_clients() {
cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: defense-val-attacker
  namespace: ids-defense-lab
  labels:
    experiment: defense-final
    role: attacker
spec:
  nodeName: athena
  restartPolicy: Never
  containers:
  - name: py
    image: python:3.13-alpine
    command: ["sh","-c","sleep 7200"]
  - name: net
    image: nicolaka/netshoot:latest
    command: ["sh","-c","sleep 7200"]
    securityContext:
      capabilities:
        add: ["NET_RAW"]
---
apiVersion: v1
kind: Pod
metadata:
  name: defense-val-benign
  namespace: ids-defense-lab
  labels:
    experiment: defense-final
    role: benign-control
spec:
  nodeName: athena
  restartPolicy: Never
  containers:
  - name: py
    image: python:3.13-alpine
    command: ["sh","-c","sleep 7200"]
YAML
    kubectl wait --for=condition=Ready pod/defense-val-attacker -n "$NS" --timeout=180s >/dev/null
    kubectl wait --for=condition=Ready pod/defense-val-benign -n "$NS" --timeout=180s >/dev/null
}

create_benign_only() {
cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: defense-val-benign-only
  namespace: ids-defense-lab
  labels:
    experiment: defense-final
    role: benign-only
spec:
  nodeName: athena
  restartPolicy: Never
  containers:
  - name: py
    image: python:3.13-alpine
    command: ["sh","-c","sleep 7200"]
YAML
    kubectl wait --for=condition=Ready pod/defense-val-benign-only -n "$NS" --timeout=180s >/dev/null
}

run_attack_workload() {
    local scenario="$1"
    local target="$2"
    local logfile="$3"

    case "$scenario" in
      tcp_recon)
        kubectl exec -i -n "$NS" defense-val-attacker -c py -- \
          python3 -u - "$target" >"$logfile" 2>&1 <<'PY'
import socket, sys, time
target=sys.argv[1]
print(f"WORKLOAD_START={time.time()}", flush=True)
for port in range(8000,8120):
    s=socket.socket()
    s.settimeout(0.20)
    try: s.connect_ex((target,port))
    except Exception: pass
    finally: s.close()
    time.sleep(0.25)
print(f"WORKLOAD_END={time.time()}", flush=True)
PY
        ;;
      slow_tcp_recon)
        kubectl exec -i -n "$NS" defense-val-attacker -c py -- \
          python3 -u - "$target" >"$logfile" 2>&1 <<'PY'
import socket, sys, time
target=sys.argv[1]
print(f"WORKLOAD_START={time.time()}", flush=True)
for port in range(8060,8120):
    s=socket.socket()
    s.settimeout(0.30)
    try: s.connect_ex((target,port))
    except Exception: pass
    finally: s.close()
    time.sleep(1.0)
print(f"WORKLOAD_END={time.time()}", flush=True)
PY
        ;;
      syn_heavy)
        kubectl exec -n "$NS" defense-val-attacker -c net -- \
          sh -lc "echo WORKLOAD_START=\$(date +%s.%N); nping --tcp --flags syn -p 8088 --rate 10 -c 400 '$target' || true; echo WORKLOAD_END=\$(date +%s.%N)" \
          >"$logfile" 2>&1
        ;;
      tcp_flood)
        kubectl exec -i -n "$NS" defense-val-attacker -c py -- \
          python3 -u - "$target" >"$logfile" 2>&1 <<'PY'
import socket, sys, time
target=sys.argv[1]
print(f"WORKLOAD_START={time.time()}", flush=True)
ok=fail=0
for _ in range(400):
    s=socket.socket()
    s.settimeout(0.30)
    try:
        rc=s.connect_ex((target,8088))
        if rc==0: ok+=1
        else: fail+=1
    except Exception: fail+=1
    finally: s.close()
    time.sleep(0.10)
print(f"WORKLOAD_END={time.time()} success={ok} failed={fail}", flush=True)
PY
        ;;
      udp_closed)
        kubectl exec -i -n "$NS" defense-val-attacker -c py -- \
          python3 -u - "$target" >"$logfile" 2>&1 <<'PY'
import socket, sys, time
target=sys.argv[1]
print(f"WORKLOAD_START={time.time()}", flush=True)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(4):
    for port in range(9100,9120):
        try: s.sendto(b"ids-defense-validation", (target,port))
        except Exception: pass
        time.sleep(0.50)
s.close()
print(f"WORKLOAD_END={time.time()}", flush=True)
PY
        ;;
      *)
        echo "Unknown attack scenario: $scenario" >&2
        return 1
        ;;
    esac
}

run_benign_workload() {
    local pod="$1"
    local target="$2"
    local logfile="$3"
    kubectl exec -i -n "$NS" "$pod" -c py -- \
      python3 -u - "$target" >"$logfile" 2>&1 <<'PY'
import sys, time, urllib.request
target=sys.argv[1]
print(f"WORKLOAD_START={time.time()}", flush=True)
ok=fail=0
for _ in range(30):
    try:
        with urllib.request.urlopen(f"http://{target}:8088/", timeout=1.0) as r:
            if 200 <= r.status < 400: ok+=1
            else: fail+=1
    except Exception:
        fail+=1
    time.sleep(1.0)
print(f"WORKLOAD_END={time.time()} success={ok} failed={fail}", flush=True)
PY
}

parse_events() {
    local src="$1"
    local start="$2"
    local end="$3"
    local outfile="$4"

    python3 - "$EVENTS" "$src" "$start" "$end" "$outfile" <<'PY'
import csv, sys
from pathlib import Path
path=Path(sys.argv[1]); src=sys.argv[2]
start=float(sys.argv[3]); end=float(sys.argv[4]); out=Path(sys.argv[5])
rows=[]
with path.open(newline="") as f:
    r=csv.DictReader(f); fields=r.fieldnames or []
    for row in r:
        try: t=float(row.get("processed_at") or 0)
        except Exception: continue
        if row.get("src_ip")==src and start-5 <= t <= end+20:
            rows.append(row)
with out.open("w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
att=[x for x in rows if (x.get("prediction") or "").upper()=="ATTACK"]
def yes(v): return str(v).lower() in {"1","true","yes"}
enf=[x for x in rows if yes(x.get("enforced",""))]
first_attack=float(att[0]["processed_at"]) if att else None
first_enf=float(enf[0]["processed_at"]) if enf else None
vals = {
 "event_rows": len(rows),
 "attack_windows": len(att),
 "enforced_rows": len(enf),
 "first_attack_processed_at": "" if first_attack is None else first_attack,
 "first_enforced_processed_at": "" if first_enf is None else first_enf,
 "traffic_to_first_attack_s": "" if first_attack is None else f"{first_attack-start:.3f}",
 "traffic_to_enforced_event_s": "" if first_enf is None else f"{first_enf-start:.3f}",
 "first_attack_to_enforcement_s": "" if first_attack is None or first_enf is None else f"{first_enf-first_attack:.3f}",
 "defense_latency_ms": "" if not enf else enf[0].get("defense_latency_ms",""),
 "defense_action": "" if not enf else enf[0].get("defense_action",""),
 "new_block": "" if not enf else enf[0].get("new_block",""),
}
for k,v in vals.items():
    print(f"{k}={v}")
PY
}

append_master_header() {
    if [[ ! -f "$MASTER" ]]; then
      cat > "$MASTER" <<'CSV'
trial_id,trial_type,scenario,rep,natural_expiry,target_ip,source_ip,benign_control_ip,baseline_source_ok,baseline_source_fail,baseline_benign_ok,baseline_benign_fail,block_observed,traffic_to_observed_block_s,event_rows,attack_windows,enforced_rows,traffic_to_first_attack_s,traffic_to_enforced_event_s,first_attack_to_enforcement_s,defense_latency_ms,defense_action,new_block,drop_packets_before,drop_packets_after,drop_packet_delta,drop_bytes_before,drop_bytes_after,drop_byte_delta,source_after_decision_ok,source_after_decision_fail,benign_during_ok,benign_during_fail,mitigation_success,recovery_mode,recovery_ok,recovery_fail,expiry_observed_s,false_block,trial_error
CSV
    fi
}

csv_append() {
    python3 - "$MASTER" "$@" <<'PY'
import csv, sys
path=sys.argv[1]
fields=[
"trial_id","trial_type","scenario","rep","natural_expiry","target_ip","source_ip","benign_control_ip",
"baseline_source_ok","baseline_source_fail","baseline_benign_ok","baseline_benign_fail",
"block_observed","traffic_to_observed_block_s","event_rows","attack_windows","enforced_rows",
"traffic_to_first_attack_s","traffic_to_enforced_event_s","first_attack_to_enforcement_s",
"defense_latency_ms","defense_action","new_block","drop_packets_before","drop_packets_after","drop_packet_delta",
"drop_bytes_before","drop_bytes_after","drop_byte_delta",
"source_after_decision_ok","source_after_decision_fail","benign_during_ok","benign_during_fail",
"mitigation_success","recovery_mode","recovery_ok","recovery_fail","expiry_observed_s","false_block","trial_error"
]
vals=sys.argv[2:]
row={k:(vals[i] if i < len(vals) else "") for i,k in enumerate(fields)}
with open(path,"a",newline="") as f:
    csv.DictWriter(f,fieldnames=fields).writerow(row)
PY
}

if [[ ! -f "$SCHEDULE" ]]; then
    python3 - "$SCHEDULE" "$SEED" <<'PY'
import csv, random, sys
out=sys.argv[1]; seed=int(sys.argv[2])
rows=[]
scenarios=[
 ("tcp_recon","TCP Reconnaissance"),
 ("slow_tcp_recon","Slow TCP Reconnaissance"),
 ("syn_heavy","SYN-Heavy Traffic"),
 ("tcp_flood","TCP Connection Flood"),
 ("udp_closed","Closed-Port UDP Reconnaissance"),
]
natural={("tcp_recon",1),("syn_heavy",1),("udp_closed",1)}
for key,label in scenarios:
    for rep in range(1,6):
        rows.append({
          "trial_id":f"A_{key}_{rep:02d}",
          "trial_type":"attack",
          "scenario":key,
          "scenario_label":label,
          "rep":rep,
          "natural_expiry":1 if (key,rep) in natural else 0,
        })
for rep in range(1,6):
    rows.append({
      "trial_id":f"B_benign_http_{rep:02d}",
      "trial_type":"benign",
      "scenario":"benign_http",
      "scenario_label":"Benign HTTP",
      "rep":rep,
      "natural_expiry":0,
    })
random.Random(seed).shuffle(rows)
with open(out,"w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator="\n"); w.writeheader(); w.writerows(rows)
PY
fi

append_master_header

echo "============================================================"
echo "FINAL DEFENSE VALIDATION - 30 TRIALS"
echo "============================================================"
echo "Output: $OUTDIR"
echo "Seed:   $SEED"

# preflight
systemctl is-active ai-ids-v4-controller.service >/dev/null
kubectl wait --for=condition=Ready pod/zeek-apollo -n default --timeout=30s >/dev/null
kubectl wait --for=condition=Ready pod/"$FW_POD" -n "$FW_NS" --timeout=30s >/dev/null
kubectl wait --for=condition=Ready pod/"$TARGET_POD" -n "$NS" --timeout=30s >/dev/null
TARGET_IP="$(kubectl get pod "$TARGET_POD" -n "$NS" -o jsonpath='{.status.podIP}')"
./tools/sync_v4_lab_firewall.sh --require-target >/dev/null
kubectl exec -n "$FW_NS" "$FW_POD" -- nft list set inet ai_ids_defense lab_target_ipv4 | grep -Fq "$TARGET_IP"
HEALTH="$(curl -fsS --max-time 8 "${AI_IDS_INFERENCE_URL%/}/health")"
grep -Fq "$EXPECTED_SHA" <<<"$HEALTH"
if [[ -f "$MODEL" ]]; then
    LOCAL_SHA="$(sha256sum "$MODEL" | awk '{print $1}')"
    [[ "$LOCAL_SHA" == "$EXPECTED_SHA" ]]
fi

mapfile -t TRIAL_LINES < <(tail -n +2 "$SCHEDULE")

for line in "${TRIAL_LINES[@]}"; do
    IFS=',' read -r TRIAL_ID TRIAL_TYPE SCENARIO SCENARIO_LABEL REP NATURAL <<<"$line"

    if [[ -f "$MASTER" ]] && awk -F, -v id="$TRIAL_ID" 'NR>1 && $1==id {found=1} END{exit !found}' "$MASTER"; then
        echo "SKIP completed $TRIAL_ID"
        continue
    fi

    echo
    echo "============================================================"
    echo "TRIAL $TRIAL_ID - $SCENARIO_LABEL"
    echo "============================================================"

    TDIR="$OUTDIR/trials/$TRIAL_ID"
    mkdir -p "$TDIR"
    delete_trial_pods
    flush_blocks
    reset_counters

    if [[ "$TRIAL_TYPE" == "attack" ]]; then
        create_attack_clients
        kubectl exec -n "$NS" defense-val-attacker -c net -- sh -lc 'command -v nping' >/dev/null
        SRC_IP="$(kubectl get pod defense-val-attacker -n "$NS" -o jsonpath='{.status.podIP}')"
        BENIGN_IP="$(kubectl get pod defense-val-benign -n "$NS" -o jsonpath='{.status.podIP}')"

        read -r BASE_OK BASE_FAIL <<<"$(probe_http defense-val-attacker 5 "$TARGET_IP")"
        read -r BEN_BASE_OK BEN_BASE_FAIL <<<"$(probe_http defense-val-benign 5 "$TARGET_IP")"

        if [[ "$BASE_OK" != "5" || "$BASE_FAIL" != "0" || "$BEN_BASE_OK" != "5" || "$BEN_BASE_FAIL" != "0" ]]; then
            printf 'baseline_failure source=%s/%s benign=%s/%s\n' "$BASE_OK" "$BASE_FAIL" "$BEN_BASE_OK" "$BEN_BASE_FAIL" > "$TDIR/ERROR.txt"
            echo "ABORT: baseline connectivity failed; trial was not added to master CSV"
            exit 3
        fi

        flush_blocks
        reset_counters
        restart_controller_clean

        START="$(epoch_now)"
        run_attack_workload "$SCENARIO" "$TARGET_IP" "$TDIR/workload.log" &
        JOB=$!

        BLOCK=0
        BLOCK_EPOCH=""
        for _ in $(seq 1 "$BLOCK_POLLS"); do
            if source_is_blocked "$SRC_IP"; then
                BLOCK=1
                BLOCK_EPOCH="$(epoch_now)"
                break
            fi
            sleep "$POLL_INTERVAL"
        done

        wait "$JOB" 2>/dev/null || true
        WORK_END="$(epoch_now)"
        sleep 5

        OBS_DELAY=""
        if [[ "$BLOCK" == "1" ]]; then
            OBS_DELAY="$(python3 - "$START" "$BLOCK_EPOCH" <<'PY'
import sys
print(f"{float(sys.argv[2])-float(sys.argv[1]):.3f}")
PY
)"
        fi

        read -r PACK_BEFORE BYTE_BEFORE <<<"$(drop_counters)"
        read -r POST_OK POST_FAIL <<<"$(probe_http defense-val-attacker 10 "$TARGET_IP")"
        read -r PACK_AFTER BYTE_AFTER <<<"$(drop_counters)"
        read -r PACK_DELTA BYTE_DELTA <<<"$(python3 - "$PACK_BEFORE" "$PACK_AFTER" "$BYTE_BEFORE" "$BYTE_AFTER" <<'PY'
import sys
pb,pa,bb,ba=[int(x or 0) for x in sys.argv[1:5]]
print(pa-pb, ba-bb)
PY
)"
        read -r BEN_DURING_OK BEN_DURING_FAIL <<<"$(probe_http defense-val-benign 10 "$TARGET_IP")"

        EVENT_KV="$TDIR/event_summary.txt"
        parse_events "$SRC_IP" "$START" "$(epoch_now)" "$TDIR/events.csv" | tee "$EVENT_KV" >/dev/null

        getv(){ awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/,"");print;exit}' "$EVENT_KV"; }
        EVENT_ROWS="$(getv event_rows)"
        ATTACK_WINDOWS="$(getv attack_windows)"
        ENFORCED_ROWS="$(getv enforced_rows)"
        T_FIRST="$(getv traffic_to_first_attack_s)"
        T_ENF="$(getv traffic_to_enforced_event_s)"
        A_TO_E="$(getv first_attack_to_enforcement_s)"
        DEF_MS="$(getv defense_latency_ms)"
        DEF_ACTION="$(getv defense_action)"
        NEW_BLOCK="$(getv new_block)"

        MITIGATION=0
        if [[ "$BLOCK" == "1" && "$POST_OK" == "0" && "$POST_FAIL" == "10" && "$BEN_DURING_OK" == "10" && "$PACK_DELTA" -ge 10 ]]; then
            MITIGATION=1
        fi

        REC_MODE="manual"
        REC_OK=""
        REC_FAIL=""
        EXPIRY_S=""

        if [[ "$NATURAL" == "1" && "$BLOCK" == "1" ]]; then
            REC_MODE="natural"
            EXP_START="$BLOCK_EPOCH"
            EXPIRED=0
            for _ in $(seq 1 "$EXPIRY_POLLS"); do
                SET_CHECK=""

                if ! SET_CHECK="$(kubectl exec                     -n "$FW_NS"                     "$FW_POD" --                     nft list set                     inet ai_ids_defense blocked_ipv4                     2>/dev/null)"
                then
                    echo "$(date -Is) WARN firewall set query failed; retrying"                         >> "$TDIR/expiry_poll_warnings.log"

                    sleep 1
                    continue
                fi

                if ! grep -Fq "$SRC_IP" <<< "$SET_CHECK"; then
                    EXPIRED=1
                    EXP_END="$(epoch_now)"
                    break
                fi

                sleep 1
            done
            if [[ "$EXPIRED" == "1" ]]; then
                EXPIRY_S="$(python3 - "$EXP_START" "$EXP_END" <<'PY'
import sys
print(f"{float(sys.argv[2])-float(sys.argv[1]):.3f}")
PY
)"
                read -r REC_OK REC_FAIL <<<"$(probe_http defense-val-attacker 5 "$TARGET_IP")"
            else
                REC_OK=0; REC_FAIL=5
            fi
        else
            flush_blocks
            sleep 2
            read -r REC_OK REC_FAIL <<<"$(probe_http defense-val-attacker 5 "$TARGET_IP")"
        fi

        csv_append "$TRIAL_ID" "$TRIAL_TYPE" "$SCENARIO" "$REP" "$NATURAL" "$TARGET_IP" "$SRC_IP" "$BENIGN_IP" \
          "$BASE_OK" "$BASE_FAIL" "$BEN_BASE_OK" "$BEN_BASE_FAIL" "$BLOCK" "$OBS_DELAY" "$EVENT_ROWS" "$ATTACK_WINDOWS" \
          "$ENFORCED_ROWS" "$T_FIRST" "$T_ENF" "$A_TO_E" "$DEF_MS" "$DEF_ACTION" "$NEW_BLOCK" "$PACK_BEFORE" \
          "$PACK_AFTER" "$PACK_DELTA" "$BYTE_BEFORE" "$BYTE_AFTER" "$BYTE_DELTA" "$POST_OK" "$POST_FAIL" "$BEN_DURING_OK" "$BEN_DURING_FAIL" "$MITIGATION" \
          "$REC_MODE" "$REC_OK" "$REC_FAIL" "$EXPIRY_S" "0" ""

        echo "block=$BLOCK attack_windows=$ATTACK_WINDOWS enforced=$ENFORCED_ROWS mitigation=$MITIGATION"
        echo "post attacker=${POST_OK}/10 benign=${BEN_DURING_OK}/10 drop_packets=$PACK_DELTA drop_bytes=$BYTE_DELTA recovery=${REC_OK}/5 mode=$REC_MODE"

    else
        create_benign_only
        SRC_IP="$(kubectl get pod defense-val-benign-only -n "$NS" -o jsonpath='{.status.podIP}')"

        read -r BASE_OK BASE_FAIL <<<"$(probe_http defense-val-benign-only 5 "$TARGET_IP")"
        if [[ "$BASE_OK" != "5" || "$BASE_FAIL" != "0" ]]; then
            printf 'baseline_failure source=%s/%s\n' "$BASE_OK" "$BASE_FAIL" > "$TDIR/ERROR.txt"
            echo "ABORT: benign baseline connectivity failed; trial was not added to master CSV"
            exit 4
        fi

        flush_blocks
        reset_counters
        restart_controller_clean

        START="$(epoch_now)"
        run_benign_workload defense-val-benign-only "$TARGET_IP" "$TDIR/workload.log" &
        JOB=$!

        FALSE_BLOCK=0
        for _ in $(seq 1 90); do
            if source_is_blocked "$SRC_IP"; then FALSE_BLOCK=1; break; fi
            if ! kill -0 "$JOB" 2>/dev/null; then break; fi
            sleep 0.5
        done
        wait "$JOB" 2>/dev/null || true
        sleep 12

        if source_is_blocked "$SRC_IP"; then FALSE_BLOCK=1; fi

        read -r POST_OK POST_FAIL <<<"$(probe_http defense-val-benign-only 10 "$TARGET_IP")"

        EVENT_KV="$TDIR/event_summary.txt"
        parse_events "$SRC_IP" "$START" "$(epoch_now)" "$TDIR/events.csv" | tee "$EVENT_KV" >/dev/null
        getv(){ awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/,"");print;exit}' "$EVENT_KV"; }
        EVENT_ROWS="$(getv event_rows)"
        ATTACK_WINDOWS="$(getv attack_windows)"
        ENFORCED_ROWS="$(getv enforced_rows)"
        T_FIRST="$(getv traffic_to_first_attack_s)"
        T_ENF="$(getv traffic_to_enforced_event_s)"
        A_TO_E="$(getv first_attack_to_enforcement_s)"
        DEF_MS="$(getv defense_latency_ms)"
        DEF_ACTION="$(getv defense_action)"
        NEW_BLOCK="$(getv new_block)"

        csv_append "$TRIAL_ID" "$TRIAL_TYPE" "$SCENARIO" "$REP" "$NATURAL" "$TARGET_IP" "$SRC_IP" "" \
          "$BASE_OK" "$BASE_FAIL" "" "" "$FALSE_BLOCK" "" "$EVENT_ROWS" "$ATTACK_WINDOWS" "$ENFORCED_ROWS" \
          "$T_FIRST" "$T_ENF" "$A_TO_E" "$DEF_MS" "$DEF_ACTION" "$NEW_BLOCK" "" "" "" "" "" "" "$POST_OK" "$POST_FAIL" \
          "" "" "" "" "" "" "" "$FALSE_BLOCK" ""

        echo "benign false_block=$FALSE_BLOCK attack_windows=$ATTACK_WINDOWS enforced=$ENFORCED_ROWS post_ok=$POST_OK/10"
        flush_blocks
    fi

    delete_trial_pods
    echo "Washout: ${WASHOUT}s"
    sleep "$WASHOUT"
done

python3 - "$MASTER" > "$SUMMARY" <<'PY'
import csv, statistics, sys
from pathlib import Path
rows=list(csv.DictReader(Path(sys.argv[1]).open()))
atk=[r for r in rows if r["trial_type"]=="attack"]
ben=[r for r in rows if r["trial_type"]=="benign"]
blocked=[r for r in atk if r["block_observed"]=="1"]
mit=[r for r in atk if r["mitigation_success"]=="1"]
false=[r for r in ben if r["false_block"]=="1"]
nat=[r for r in atk if r["recovery_mode"]=="natural"]
def nums(key, data):
    out=[]
    for r in data:
        try:
            if r[key]!="": out.append(float(r[key]))
        except: pass
    return out
print("FINAL DEFENSE VALIDATION SUMMARY")
print("="*72)
print(f"completed_trials={len(rows)}")
print(f"attack_trials={len(atk)}")
print(f"benign_trials={len(ben)}")
print(f"block_observed={len(blocked)}/{len(atk)}")
print(f"mitigation_success={len(mit)}/{len(atk)}")
ben_pred=sum((int(r["attack_windows"] or 0)>0) for r in ben)
print(f"benign_false_blocks={len(false)}/{len(ben)}")
print(f"benign_attack_prediction_trials={ben_pred}/{len(ben)}")
print(f"natural_expiry_trials={len(nat)}")
for k in ["traffic_to_first_attack_s","traffic_to_enforced_event_s","first_attack_to_enforcement_s","defense_latency_ms","traffic_to_observed_block_s"]:
    x=nums(k,atk)
    if x:
        print(f"{k}: n={len(x)} mean={statistics.mean(x):.3f} median={statistics.median(x):.3f}")
x=nums("drop_packet_delta",blocked)
if x:
    print(f"drop_packet_delta: n={len(x)} mean={statistics.mean(x):.2f} median={statistics.median(x):.2f}")
x=nums("drop_byte_delta",blocked)
if x:
    print(f"drop_byte_delta: n={len(x)} mean={statistics.mean(x):.2f} median={statistics.median(x):.2f}")
x=nums("expiry_observed_s",nat)
if x:
    print(f"expiry_observed_s: n={len(x)} mean={statistics.mean(x):.3f} median={statistics.median(x):.3f}")
print()
print("BY SCENARIO")
for s in sorted({r["scenario"] for r in atk}):
    q=[r for r in atk if r["scenario"]==s]
    b=sum(r["block_observed"]=="1" for r in q)
    m=sum(r["mitigation_success"]=="1" for r in q)
    print(f"{s}: block={b}/{len(q)} mitigation={m}/{len(q)}")
PY

cat "$SUMMARY"
echo
echo "Results: $MASTER"
echo "Summary: $SUMMARY"
echo "Output:  $OUTDIR"
