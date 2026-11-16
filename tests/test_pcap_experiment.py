"""Independent experiment contracts: no production model loads or network access."""

from copy import deepcopy
import csv
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np

from pcap_experiment.common import sha256, write_json
from pcap_experiment.contract import FEATURE_NAMES, PROTOCOL_ENCODING, PROTOCOL_VERSION, SPECIFICATION
from pcap_experiment.dataset import eligible, feature_row, load_dataset, table_files
from pcap_experiment.evaluation import aggregate_groups, evaluate_views, metric_report, paired_comparison, split_indices
from pcap_experiment.models import make_models, positive_scores, training_weights


def metadata(index=0, capture="a", group=None, label=0, protocol="tcp", segments=1):
    return {"row_index": index, "flow_id": f"flow{index}", "capture": capture,
            "capture_group_id": "capture-"+capture, "connection_group_id": group or f"group{index}",
            "binary_label": label, "protocol": protocol, "behavior_flow": "tcp_other" if protocol == "tcp" else "udp",
            "behavior_group": "tcp_other" if protocol == "tcp" else "udp",
            "group_admitted_segment_count": segments, "feature_unknown_reasons": {}}


def feature_flow(protocol="tcp"):
    return {"features": {name: {"value": protocol if name == "transport_protocol" else 0,
                                "status": "ok", "reason": None} for name in FEATURE_NAMES}}


class ExperimentContractTests(unittest.TestCase):
    def test_exact_38_predictors_no_identity_or_target(self):
        self.assertEqual(len(FEATURE_NAMES), 38)
        self.assertEqual(len(set(FEATURE_NAMES)), 38)
        self.assertFalse(set(FEATURE_NAMES) & {"binary_label", "capture", "uid", "flow_id", "orig_ip", "orig_port"})

    def test_explicit_protocol_encoding(self):
        self.assertEqual(feature_row(feature_flow("tcp"))[0][1], 1)
        self.assertEqual(feature_row(feature_flow("udp"))[0][1], 0)

    def test_unknown_remains_none_with_reason(self):
        flow = feature_flow(); name = "forward_iat_min_seconds"
        flow["features"][name] = {"value": None, "status": "unavailable", "reason": "fewer_than_two_packets_in_direction"}
        row, unknown = feature_row(flow)
        self.assertIsNone(row[FEATURE_NAMES.index(name)])
        self.assertEqual(unknown[name], "fewer_than_two_packets_in_direction")

    def test_unknown_without_reason_rejected(self):
        flow = feature_flow(); flow["features"]["forward_iat_min_seconds"] = {"value": None, "status": "unavailable", "reason": None}
        with self.assertRaises(ValueError): feature_row(flow)

    def test_invented_zero_in_unknown_rejected(self):
        flow = feature_flow(); flow["features"]["forward_iat_min_seconds"] = {"value": 0, "status": "unavailable", "reason": "unknown"}
        with self.assertRaises(ValueError): feature_row(flow)

    def test_predictor_injection_and_missing_column_rejected(self):
        for extra in (True, False):
            flow = feature_flow()
            if extra: flow["features"]["label"] = {"value": 1}
            else: del flow["features"][FEATURE_NAMES[0]]
            with self.assertRaises(ValueError): feature_row(flow)

    def test_unknown_protocol_rejected(self):
        with self.assertRaises(ValueError): feature_row(feature_flow("icmp"))

    def test_nonfinite_value_rejected(self):
        flow = feature_flow(); flow["features"][FEATURE_NAMES[0]]["value"] = float("inf")
        with self.assertRaises(ValueError): feature_row(flow)

    def test_metadata_cannot_change_predictors(self):
        flow = feature_flow(); expected = feature_row(flow)
        flow.update(binary_label=1, uid="injected", capture="evaluation", forward_endpoint={"ipv4": "1.2.3.4"})
        self.assertEqual(feature_row(flow), expected)

    def test_quarantined_or_unmatched_is_not_eligible(self):
        for status in ("counter_mismatch", "quarantined_partial_checksum", "ambiguous", "contradictory", "not_found"):
            self.assertFalse(eligible({"status": status, "binary_label": None}))

    def test_false_admission_fails_closed(self):
        for value in ({"status": "counter_mismatch", "binary_label": 1},
                      {"status": "admitted_unique", "binary_label": None},
                      {"status": "admitted_unique", "binary_label": 0, "admitted_reference_ids": []}):
            with self.assertRaises(ValueError): eligible(value)

    def test_unverified_admitted_reference_fails(self):
        with self.assertRaises(ValueError):
            eligible({"status": "admitted_unique", "binary_label": 1, "admitted_reference_ids": ["r"],
                      "reference_validation_states": {"r": "counter_mismatch"}})

    def test_verified_reference_admitted(self):
        self.assertTrue(eligible({"status": "admitted_sibling_segment", "binary_label": 1,
                                 "admitted_reference_ids": ["r"], "reference_validation_states": {"r": "verified"}}))


class PartitionAndGroupTests(unittest.TestCase):
    def test_complete_capture_partitions(self):
        rows = [metadata(0, "a"), metadata(1, "b"), metadata(2, "b")]
        train, test = split_indices(rows, {"train": ["a"], "test": "b"})
        self.assertEqual(train.tolist(), [0]); self.assertEqual(test.tolist(), [1, 2])

    def test_connection_leak_rejected(self):
        with self.assertRaisesRegex(ValueError, "connection_group_id"):
            split_indices([metadata(0, "a", "same"), metadata(1, "b", "same")], {"train": ["a"], "test": "b"})

    def test_capture_hash_leak_rejected(self):
        rows = [metadata(0, "a"), metadata(1, "b")]; rows[1]["capture_group_id"] = rows[0]["capture_group_id"]
        with self.assertRaisesRegex(ValueError, "capture_group_id"): split_indices(rows, {"train": ["a"], "test": "b"})

    def test_capture_name_overlap_rejected(self):
        with self.assertRaises(ValueError): split_indices([metadata()], {"train": ["a"], "test": "a"})

    def test_weight_total_equal_per_group(self):
        rows = [metadata(0, group="long"), metadata(1, group="long"), metadata(2, group="short")]
        weights = training_weights(rows)
        self.assertAlmostEqual(weights[0]+weights[1], weights[2]); self.assertAlmostEqual(weights.mean(), 1)

    def test_group_mean_not_max_or_packet_weight(self):
        rows = [metadata(0, group="g", segments=2), metadata(1, group="g", segments=2)]
        result = aggregate_groups(rows, [.1, .8])
        self.assertAlmostEqual(result[0]["probability_malicious"], .45)
        self.assertEqual(result[0]["prediction"], 0); self.assertEqual(len(result), 1)

    def test_group_contradiction_rejected(self):
        rows = [metadata(0, group="g", segments=2), metadata(1, group="g", label=1, segments=2)]
        with self.assertRaises(ValueError): aggregate_groups(rows, [.1, .8])

    def test_group_duplicate_and_partial_rejected(self):
        row = metadata(0, group="g", segments=2)
        with self.assertRaises(ValueError): aggregate_groups([row], [.1])
        with self.assertRaises(ValueError): aggregate_groups([row, row], [.1, .8])

    def test_group_slice_does_not_aggregate_partial_groups(self):
        rows = [metadata(0, group="g", segments=2), metadata(1, group="g", segments=2)]
        rows[0]["behavior_flow"] = "tcp_pure_syn"
        views, _ = evaluate_views(rows, [.1, .8])
        self.assertEqual(views["flow"]["tcp_pure_syn"]["n"], 1)
        self.assertEqual(views["group"]["tcp_pure_syn"]["n"], 0)
        self.assertEqual(views["group"]["tcp_other"]["n"], 1)

    def test_constant_probability_remains_identical_across_segment_counts(self):
        rows = []
        for group, count in enumerate([1, 2, 3, 7, 137, 147]):
            start = len(rows)
            rows.extend(metadata(start+i, group=f"constant{group}", segments=count) for i in range(count))
        probability = 0.44730275783217
        result = aggregate_groups(rows, [probability]*len(rows))
        self.assertTrue(all(r["probability_malicious"] == probability for r in result))

    def test_dummy_group_average_precision_is_prevalence(self):
        rows = []
        for group, count in enumerate([1, 3, 137, 147]):
            start = len(rows)
            rows.extend(metadata(start+i, group=f"constant{group}", label=int(group == 2), segments=count) for i in range(count))
        views, _ = evaluate_views(rows, [0.44730275783217]*len(rows))
        self.assertEqual(views["group"]["all"]["pr_auc_average_precision"], .25)


class MetricTests(unittest.TestCase):
    def test_confusion_matrix_and_threshold(self):
        r = metric_report([0, 0, 1, 1], [.1, .6, .2, .5])
        self.assertEqual(r["confusion_matrix_true_rows_predicted_columns_B_M"], [[1, 1], [1, 1]])
        for k in ("precision_malicious", "recall_malicious", "f1_malicious", "false_positive_rate", "balanced_accuracy"):
            self.assertEqual(r[k], .5)

    def test_average_precision_definition(self):
        self.assertEqual(metric_report([0, 1, 0, 1], [.1, .8, .4, .9])["pr_auc_average_precision"], 1)

    def test_benign_only_metrics(self):
        r = metric_report([0, 0], [.6, .2])
        self.assertEqual(r["false_positive_rate"], .5); self.assertEqual(r["precision_malicious"], 0)
        for k in ("recall_malicious", "f1_malicious", "balanced_accuracy", "pr_auc_average_precision"): self.assertIsNone(r[k])

    def test_no_predicted_malicious_precision_not_invented(self):
        r = metric_report([0, 1], [.1, .2])
        self.assertIsNone(r["precision_malicious"]); self.assertEqual(r["recall_malicious"], 0); self.assertEqual(r["f1_malicious"], 0)

    def test_empty_slice_is_explicit(self):
        r = metric_report([], [])
        self.assertEqual(r["n"], 0); self.assertIsNone(r["false_positive_rate"])

    def test_invalid_probability_rejected(self):
        for p in ([np.nan], [1.01], [-.01]):
            with self.assertRaises(ValueError): metric_report([1], p)

    def test_paired_comparison(self):
        r = paired_comparison([0, 1, 0, 1], [.1, .9, .9, .1], [.1, .1, .1, .1])
        self.assertEqual([r[k] for k in ("both_correct", "rf_only_correct", "baseline_only_correct", "both_wrong")], [1, 1, 1, 1])


class ModelAndTableTests(unittest.TestCase):
    def test_fixed_rule_ignores_labels_and_udp_missing_flags(self):
        X = np.zeros((3, 38)); X[:, 1] = [1, 1, 0]
        X[0, FEATURE_NAMES.index("forward_tcp_syn_count")] = 1
        X[1, FEATURE_NAMES.index("forward_tcp_syn_count")] = 1
        X[1, FEATURE_NAMES.index("reverse_tcp_ack_count")] = 1
        X[2, [i for i, name in enumerate(FEATURE_NAMES) if "_tcp_" in name]] = np.nan
        for labels in ([0, 0, 0], [1, 1, 1]):
            models = make_models()
            for name, expected in (("tcp_rule", [1, 1, 0]), ("syn_no_ack_rule", [1, 0, 0])):
                model = models[name].fit(X, labels)
                np.testing.assert_array_equal(positive_scores(model, X), expected)

    def test_syn_rule_rejects_missing_tcp_flags(self):
        X = np.zeros((1, 38)); X[:, 1] = 1; X[0, FEATURE_NAMES.index("forward_tcp_syn_count")] = np.nan
        model = make_models()["syn_no_ack_rule"].fit(X, [0])
        with self.assertRaises(ValueError): positive_scores(model, X)

    def test_rf_native_nan_seed_and_38_features(self):
        X = np.arange(760, dtype=float).reshape(20, 38); X[:, 1] = [0, 1]*10; X[::2, 4] = np.nan
        y = np.array([0]*10+[1]*10)
        first = make_models()["random_forest"].fit(X, y)
        second = make_models()["random_forest"].fit(X, y)
        self.assertEqual(first.n_features_in_, 38)
        np.testing.assert_array_equal(positive_scores(first, X), positive_scores(second, X))
        self.assertEqual(len(first.steps), 1)
        self.assertEqual(first.named_steps["classifier"].get_params()["max_depth"], 8)

    def test_dummy_uses_only_weighted_training_prior(self):
        X = np.zeros((3, 38))
        model = make_models()["dummy"].fit(X, [0, 1, 1], classifier__sample_weight=[2, 1, 1])
        np.testing.assert_array_equal(positive_scores(model, X), [.5, .5, .5])

    def test_single_class_probability_helper(self):
        X = np.zeros((2, 38))
        model = make_models()["dummy"].fit(X, [0, 0])
        np.testing.assert_array_equal(positive_scores(model, X), [0, 0])

    def test_locally_created_model_serialization_roundtrip(self):
        import joblib
        X = np.zeros((2, 38)); X[1, 1] = 1
        original = make_models()["tcp_rule"].fit(X, [0, 1])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"own-model.joblib"
            joblib.dump(original, path)
            restored = joblib.load(path)
            np.testing.assert_array_equal(positive_scores(original, X), positive_scores(restored, X))

    def make_table(self, directory):
        row, unknown = feature_row(feature_flow()); row[4] = None
        m = metadata(); m["feature_unknown_reasons"] = {FEATURE_NAMES[4]: "no_packets_in_direction"}
        table_files(directory, [row], [m])
        manifest = {"predictors": list(FEATURE_NAMES), "predictor_count": 38, "rows": 1,
                    "protocol_encoding": PROTOCOL_ENCODING, "protocol_encoding_version": PROTOCOL_VERSION,
                    "files_sha256": {name: sha256(directory/name) for name in ("features.csv", "targets.csv", "metadata.jsonl")}}
        write_json(directory/"manifest.json", manifest)

    def test_csv_roundtrip_keeps_missing_and_separates_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); self.make_table(directory)
            X, y, _, _ = load_dataset(directory)
            self.assertEqual(X.shape, (1, 38)); self.assertTrue(np.isnan(X[0, 4])); self.assertEqual(y.tolist(), [0])

    def test_dataset_bytes_are_repeatable(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            self.make_table(Path(a)); self.make_table(Path(b))
            self.assertEqual((Path(a)/"manifest.json").read_bytes(), (Path(b)/"manifest.json").read_bytes())

    def test_tampered_feature_file_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); self.make_table(directory)
            with (directory/"features.csv").open("a") as f: f.write("tampered\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"): load_dataset(directory)

    def test_new_run_cannot_overwrite_previous_artifacts(self):
        from pcap_experiment.run import run_experiment
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileExistsError): run_experiment(Path(temp))

    def test_prespecified_folds_and_threshold(self):
        self.assertEqual([r["test"] for r in SPECIFICATION["splits"]], ["torii", "hakai", "hue"])
        self.assertEqual(SPECIFICATION["threshold"], .5)


if __name__ == "__main__":
    unittest.main()
