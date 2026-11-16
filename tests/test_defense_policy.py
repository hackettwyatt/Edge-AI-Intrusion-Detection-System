"""Non-networking unit tests for the alert and enforcement safety policy."""

import os
import unittest
from unittest.mock import patch

from defense.defense_policy import DefensePolicy
from defense.firewall_enforcer import FirewallEnforcer


class DefensePolicyTests(unittest.TestCase):
    def test_two_hits_create_one_temporary_block(self):
        policy = DefensePolicy(
            threshold=0.5, hits_required=2,
            hit_window_seconds=60, block_seconds=300,
        )
        first = policy.process("192.0.2.15", 100.0, 0.9)
        second = policy.process("192.0.2.15", 110.0, 0.9)
        repeated = policy.process("192.0.2.15", 111.0, 0.9)
        self.assertEqual(first["action"], "ALERT")
        self.assertEqual(second["action"], "BLOCK")
        self.assertTrue(second["new_block"])
        self.assertEqual(repeated["action"], "BLOCK")
        self.assertFalse(repeated["new_block"])
        self.assertEqual(second["block_until"], 410.0)

    def test_benign_and_expired_hits(self):
        policy = DefensePolicy(threshold=0.5)
        self.assertEqual(
            policy.process("192.0.2.25", 10.0, 0.2)["action"],
            "ALLOW",
        )
        self.assertEqual(
            policy.process("192.0.2.25", 20.0, 0.7)["action"],
            "ALERT",
        )
        # The old first hit expires outside the 60-second hit window.
        self.assertEqual(
            policy.process("192.0.2.25", 100.0, 0.7)["action"],
            "ALERT",
        )

    def test_sources_do_not_share_hit_counters(self):
        policy = DefensePolicy()
        policy.process("192.0.2.1", 0, 0.99)
        self.assertEqual(
            policy.process("192.0.2.2", 1, 0.99)["action"],
            "ALERT",
        )

    def test_temporary_block_expires(self):
        policy = DefensePolicy(block_seconds=300)
        policy.process("192.0.2.30", 0, 0.99)
        policy.process("192.0.2.30", 1, 0.99)
        after_expiry = policy.process("192.0.2.30", 302, 0.99)
        self.assertEqual(after_expiry["action"], "ALERT")
        self.assertFalse(after_expiry["new_block"])


class FirewallValidationTests(unittest.TestCase):
    def test_requires_explicit_lab_cidr(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                FirewallEnforcer()._validate_ip("192.168.0.10")

    def test_rejects_outside_allowed_network(self):
        with patch.dict(
            os.environ, {"AI_IDS_ALLOWED_CIDR": "192.168.50.0/24"},
            clear=True,
        ):
            fw = FirewallEnforcer()
            self.assertEqual(
                fw._validate_ip("192.168.50.10"), "192.168.50.10"
            )
            with self.assertRaises(ValueError):
                fw._validate_ip("192.168.51.10")
            with self.assertRaises(ValueError):
                fw._validate_ip("224.0.0.1")


if __name__ == "__main__":
    unittest.main()
