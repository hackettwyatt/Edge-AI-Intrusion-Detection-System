from collections import defaultdict, deque


class DefensePolicy:
    """
    Simple IDS response policy.

    ALLOW
        V4 probability < threshold.

    ALERT
        First attack-classified window.

    BLOCK
        Two attack-classified windows from the
        same source within 60 seconds, or the
        source is already inside its 5-minute
        temporary block period.

    new_block=True
        Only on the window that actually creates
        a new temporary block.
    """

    def __init__(
        self,
        threshold=0.50,
        hits_required=2,
        hit_window_seconds=60,
        block_seconds=300,
    ):
        self.threshold = threshold
        self.hits_required = hits_required
        self.hit_window_seconds = hit_window_seconds
        self.block_seconds = block_seconds

        self.attack_hits = defaultdict(deque)
        self.block_until = {}


    def process(
        self,
        src_ip,
        timestamp,
        attack_probability,
    ):
        src_ip = str(src_ip)
        now = float(timestamp)
        probability = float(
            attack_probability
        )

        # ====================================================
        # Existing block
        # ====================================================

        existing_until = self.block_until.get(
            src_ip
        )

        if existing_until is not None:

            if now < existing_until:

                return {
                    "action": "BLOCK",
                    "reason": "temporary block active",
                    "attack_probability": probability,
                    "hits": 0,
                    "new_block": False,
                    "block_until": existing_until,
                }

            # Block expired.
            del self.block_until[src_ip]

            self.attack_hits[
                src_ip
            ].clear()


        # ====================================================
        # Expire old attack hits
        # ====================================================

        hits = self.attack_hits[
            src_ip
        ]

        cutoff = (
            now
            - self.hit_window_seconds
        )

        while hits and hits[0] < cutoff:
            hits.popleft()


        # ====================================================
        # BENIGN
        # ====================================================

        if probability < self.threshold:

            return {
                "action": "ALLOW",
                "reason": "below attack threshold",
                "attack_probability": probability,
                "hits": len(hits),
                "new_block": False,
                "block_until": None,
            }


        # ====================================================
        # ATTACK
        # ====================================================

        hits.append(now)

        if len(hits) >= self.hits_required:

            until = (
                now
                + self.block_seconds
            )

            self.block_until[
                src_ip
            ] = until

            hits.clear()

            return {
                "action": "BLOCK",
                "reason": (
                    f"{self.hits_required} "
                    "attack windows within "
                    f"{self.hit_window_seconds}s"
                ),
                "attack_probability": probability,
                "hits": self.hits_required,
                "new_block": True,
                "block_until": until,
            }


        return {
            "action": "ALERT",
            "reason": "first attack window",
            "attack_probability": probability,
            "hits": len(hits),
            "new_block": False,
            "block_until": None,
        }
