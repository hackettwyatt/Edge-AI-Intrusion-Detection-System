from defense.defense_policy import (
    DefensePolicy,
)

from defense.firewall_enforcer import (
    FirewallEnforcer,
)


class DefenseController:
    """
    Combines detection-response policy with
    the nftables enforcement mechanism.
    """

    def __init__(
        self,
        threshold=0.50,
        hits_required=2,
        hit_window_seconds=60,
        block_seconds=300,
        enforce=True,
    ):
        self.policy = DefensePolicy(
            threshold=threshold,
            hits_required=hits_required,
            hit_window_seconds=hit_window_seconds,
            block_seconds=block_seconds,
        )

        self.enforcer = FirewallEnforcer(
            timeout_seconds=block_seconds
        )

        self.enforce = enforce


    def process(
        self,
        src_ip,
        timestamp,
        attack_probability,
    ):
        decision = self.policy.process(
            src_ip=src_ip,
            timestamp=timestamp,
            attack_probability=attack_probability,
        )

        decision["enforced"] = False

        # Critical safety rule:
        #
        # Only a NEW block decision modifies
        # the firewall.
        if (
            decision["action"] == "BLOCK"
            and decision["new_block"]
        ):

            if self.enforce:

                result = self.enforcer.block(
                    src_ip=src_ip,
                    timeout_seconds=(
                        self.policy.block_seconds
                    ),
                )

                decision["enforced"] = (
                    result["enforced"]
                )

        return decision
