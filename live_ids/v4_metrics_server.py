import hashlib
import json
import os
import time
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path

import joblib
import pandas as pd

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)


# ============================================================
# FROZEN V4 MODEL
# ============================================================

MODEL_PATH = Path(os.environ.get(
    "AI_IDS_MODEL_PATH"
) or "/work/zeek_ids_final_candidate_v4.joblib"
)

EXPECTED_SHA256 = (
    "4ff285c89a58f3defddc8b68084ef9e132b697463b158b537e2c1d2bc777a774"
)


if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Missing V4 model: {MODEL_PATH}"
    )


actual_sha256 = hashlib.sha256(
    MODEL_PATH.read_bytes()
).hexdigest()


if actual_sha256 != EXPECTED_SHA256:
    raise RuntimeError(
        "Frozen V4 checksum mismatch.\n"
        f"Expected: {EXPECTED_SHA256}\n"
        f"Actual:   {actual_sha256}"
    )


artifact = joblib.load(
    MODEL_PATH
)

model = artifact["model"]

features = list(
    artifact["features"]
)

threshold = float(
    artifact["threshold"]
)


# Determine ATTACK class index.
classes = list(
    model.classes_
)

if 1 in classes:
    ATTACK_INDEX = classes.index(1)
else:
    ATTACK_INDEX = len(classes) - 1


# ============================================================
# PROMETHEUS METRICS
# ============================================================

IDS_UP = Gauge(
    "ai_ids_up",
    "Whether the frozen V4 inference service is running.",
)

WINDOWS_TOTAL = Counter(
    "ai_ids_windows_total",
    "Total 10-second source windows processed by V4.",
)

PREDICTIONS_TOTAL = Counter(
    "ai_ids_predictions_total",
    "Total V4 predictions by label.",
    ["label"],
)

ALERTS_TOTAL = Counter(
    "ai_ids_alerts_total",
    "Total first-hit defense alerts.",
)

BLOCKS_TOTAL = Counter(
    "ai_ids_blocks_total",
    "Total new temporary firewall blocks.",
)

BLOCKED_SOURCES = Gauge(
    "ai_ids_blocked_sources",
    "Current number of temporarily blocked sources.",
)

ATTACK_PROBABILITY = Gauge(
    "ai_ids_attack_probability",
    "Attack probability from the most recently scored window.",
)

INFERENCE_LATENCY = Histogram(
    "ai_ids_inference_latency_seconds",
    "Frozen V4 model inference latency.",
    buckets=(
        0.001,
        0.002,
        0.003,
        0.005,
        0.010,
        0.025,
        0.050,
        0.100,
        0.250,
        0.500,
        1.000,
    ),
)

DEFENSE_LATENCY = Histogram(
    "ai_ids_defense_latency_seconds",
    "Defense decision/enforcement latency.",
    buckets=(
        0.001,
        0.002,
        0.005,
        0.010,
        0.025,
        0.050,
        0.100,
        0.250,
        0.500,
        1.000,
        2.000,
        5.000,
    ),
)


IDS_UP.set(1)
BLOCKED_SOURCES.set(0)


# ============================================================
# V4 INFERENCE
# ============================================================

def predict(features_in):

    if not isinstance(
        features_in,
        dict,
    ):
        raise ValueError(
            "features must be a JSON object"
        )


    missing = [
        name
        for name in features
        if name not in features_in
    ]

    if missing:
        raise ValueError(
            "Missing V4 features: "
            + ", ".join(missing)
        )


    row = {
        name: features_in[name]
        for name in features
    }


    X = pd.DataFrame(
        [row]
    )

    X = (
        X[features]
        .apply(
            pd.to_numeric,
            errors="coerce",
        )
        .fillna(0)
    )


    start_ns = (
        time.perf_counter_ns()
    )


    probability = float(
        model.predict_proba(
            X
        )[0][ATTACK_INDEX]
    )


    end_ns = (
        time.perf_counter_ns()
    )


    latency_seconds = (
        end_ns - start_ns
    ) / 1_000_000_000


    is_attack = (
        probability
        >= threshold
    )


    label = (
        "attack"
        if is_attack
        else "benign"
    )


    WINDOWS_TOTAL.inc()

    PREDICTIONS_TOTAL.labels(
        label=label
    ).inc()

    ATTACK_PROBABILITY.set(
        probability
    )

    INFERENCE_LATENCY.observe(
        latency_seconds
    )


    return {
        "prediction":
            label,

        "attack_probability":
            probability,

        "threshold":
            threshold,

        "inference_latency_seconds":
            latency_seconds,

        "model":
            type(model).__name__,

        "model_sha256":
            actual_sha256,
    }


# ============================================================
# DEFENSE METRIC UPDATE
# ============================================================

def record_defense(
    event,
):

    action = str(
        event.get(
            "action",
            "ALLOW",
        )
    ).upper()


    if action not in {
        "ALLOW",
        "ALERT",
        "BLOCK",
    }:
        raise ValueError(
            "action must be "
            "ALLOW, ALERT, or BLOCK"
        )


    new_block = bool(
        event.get(
            "new_block",
            False,
        )
    )


    if action == "ALERT":
        ALERTS_TOTAL.inc()


    enforced = bool(
        event.get(
            "enforced",
            False,
        )
    )

    if new_block and enforced:
        BLOCKS_TOTAL.inc()


    if "blocked_sources" in event:

        blocked = int(
            event[
                "blocked_sources"
            ]
        )

        if blocked < 0:
            raise ValueError(
                "blocked_sources cannot "
                "be negative"
            )

        BLOCKED_SOURCES.set(
            blocked
        )


    if (
        "defense_latency_seconds"
        in event
        and event[
            "defense_latency_seconds"
        ] is not None
    ):

        latency = float(
            event[
                "defense_latency_seconds"
            ]
        )

        if latency < 0:
            raise ValueError(
                "defense latency cannot "
                "be negative"
            )

        DEFENSE_LATENCY.observe(
            latency
        )


# ============================================================
# HTTP
# ============================================================

class Handler(
    BaseHTTPRequestHandler
):

    def log_message(
        self,
        fmt,
        *args,
    ):
        return


    def send_json(
        self,
        status,
        payload,
    ):

        data = json.dumps(
            payload
        ).encode()

        self.send_response(
            status
        )

        self.send_header(
            "Content-Type",
            "application/json",
        )

        self.send_header(
            "Content-Length",
            str(len(data)),
        )

        self.end_headers()

        self.wfile.write(
            data
        )


    def read_json(
        self,
    ):

        length = int(
            self.headers.get(
                "Content-Length",
                "0",
            )
        )

        body = self.rfile.read(
            length
        )

        return json.loads(
            body.decode()
        )


    def do_GET(
        self,
    ):

        if self.path == "/health":

            self.send_json(
                200,
                {
                    "status": "ok",

                    "service":
                        "ai-ids-v4",

                    "model":
                        type(model).__name__,

                    "threshold":
                        threshold,

                    "features":
                        len(features),

                    "model_sha256":
                        actual_sha256,
                },
            )

            return


        if self.path == "/metrics":

            data = generate_latest()

            self.send_response(
                200
            )

            self.send_header(
                "Content-Type",
                CONTENT_TYPE_LATEST,
            )

            self.send_header(
                "Content-Length",
                str(len(data)),
            )

            self.end_headers()

            self.wfile.write(
                data
            )

            return


        self.send_json(
            404,
            {
                "error":
                    "not found"
            },
        )


    def do_POST(
        self,
    ):

        try:

            payload = self.read_json()


            if self.path == "/predict":

                result = predict(
                    payload[
                        "features"
                    ]
                )

                self.send_json(
                    200,
                    result,
                )

                return


            if self.path == "/defense":

                record_defense(
                    payload
                )

                self.send_json(
                    200,
                    {
                        "accepted": True
                    },
                )

                return


            self.send_json(
                404,
                {
                    "error":
                        "not found"
                },
            )


        except Exception as e:

            self.send_json(
                400,
                {
                    "error":
                        str(e)
                },
            )


def main():

    print(
        "=" * 72,
        flush=True,
    )

    print(
        "AI IDS FROZEN V4 INFERENCE + METRICS",
        flush=True,
    )

    print(
        "=" * 72,
        flush=True,
    )

    print(
        "Model:",
        MODEL_PATH,
        flush=True,
    )

    print(
        "SHA256:",
        actual_sha256,
        flush=True,
    )

    print(
        "Threshold:",
        threshold,
        flush=True,
    )

    print(
        "Features:",
        len(features),
        flush=True,
    )

    print(
        "Listening:",
        "0.0.0.0:9105",
        flush=True,
    )


    server = ThreadingHTTPServer(
        (
            "0.0.0.0",
            9105,
        ),
        Handler,
    )

    server.serve_forever()


if __name__ == "__main__":
    main()
