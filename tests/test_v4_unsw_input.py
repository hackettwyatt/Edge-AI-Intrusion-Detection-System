"""Regression tests for the UWF-free V4 training input builder."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from model_pipeline import combine_v4_datasets as builder


class V4UnswTrainingInputTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.source = self.root / "unsw.csv"
        self.output = self.root / "export" / "combined_v4_binary_windows_10s.csv"

    def make_frame(self, datasets):
        rows = []
        for index, dataset in enumerate(datasets):
            row = {feature: index + 1 for feature in builder.FEATURES}
            row.update({
                "dataset": dataset,
                "src_ip": f"192.0.2.{index + 1}",
                "window_start": index * 3600,
                "label_binary": index % 2,
                "extra_metadata": "excluded from training input",
            })
            rows.append(row)
        return pd.DataFrame(rows)

    def run_builder(self, frame):
        frame.to_csv(self.source, index=False)
        with patch.object(builder, "UNSW", self.source), patch.object(
            builder, "OUT", self.output
        ):
            builder.main()

    def test_builds_training_input_from_unsw_only(self):
        frame = self.make_frame(["UNSW-NB15", "UNSW-NB15"])
        self.run_builder(frame)
        actual = pd.read_csv(self.output)
        expected_columns = builder.FEATURES + [
            "dataset", "src_ip", "window_start", "label_binary"
        ]
        pd.testing.assert_frame_equal(actual, frame[expected_columns])

    def test_rejects_non_unsw_rows(self):
        frame = self.make_frame(["UNSW-NB15", "UWF-ZeekData24"])
        with self.assertRaisesRegex(RuntimeError, "only UNSW-NB15"):
            self.run_builder(frame)
        self.assertFalse(self.output.exists())

    def test_reports_missing_feature(self):
        frame = self.make_frame(["UNSW-NB15"]).drop(
            columns=["connection_count"]
        )
        with self.assertRaisesRegex(RuntimeError, "connection_count"):
            self.run_builder(frame)


if __name__ == "__main__":
    unittest.main()
