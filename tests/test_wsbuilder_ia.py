import sys
import types
import unittest
from unittest.mock import patch

from sniff4hound.wsbuilder_ia import (
    WsbuilderIAScorer,
    sanitize_features,
    score_snapshot,
    snapshot_features,
)


class _Predictor:
    def predict(self, vector):
        self.vector = vector
        return [72.5], [1.0], [70.5], [74.5]


class WsbuilderIAAdapterTests(unittest.TestCase):
    def test_is_disabled_by_default_and_does_not_import_wsbuilder_ia(self):
        with patch.dict(sys.modules, {"wsbuilder": None}):
            result = score_snapshot({"soc_summary": {"risk_score": 91}})
        self.assertEqual(result["status"], "disabled")
        self.assertIsNone(result["score"])

    def test_snapshot_extraction_ignores_sensitive_rows_and_caps_features(self):
        snapshot = {
            "soc_summary": {"risk_score": 88, "sampled_packets": 4, "top_host": "10.0.0.1"},
            "findings": [{"evidence": "secret", "value": 999}],
            "payload_patterns": [{"example": "token", "value": 100}],
        }
        features = snapshot_features(snapshot)
        self.assertEqual(features, {"risk_score": 88.0, "sampled_packets": 4.0})
        self.assertNotIn("secret", repr(features))

    def test_explicit_features_are_bounded_and_non_numeric_values_are_dropped(self):
        features = sanitize_features({"risk_score": 5000, "packets": float("inf"), "ip": 7, "title": "private"})
        self.assertEqual(features, {"risk_score": 5000.0})

    def test_prefitted_predictor_is_used_only_when_enabled_and_result_is_bounded(self):
        module = types.ModuleType("wsbuilder")
        module.NeuralNetwork = object
        module.Predictor = _Predictor
        module.evaluate_errors = lambda *args, **kwargs: None
        with patch.dict(sys.modules, {"wsbuilder": module}):
            result = WsbuilderIAScorer(enabled=True, model=_Predictor()).score(
                features={"risk_score": 10, "packets": 2}
            )
        self.assertEqual(result.status, "scored")
        self.assertEqual(result.score, 72.5)
        self.assertEqual(result.source, "model")

    def test_error_evaluation_is_opt_in_and_kept_as_numeric_metrics(self):
        class Summary:
            mean_absolute_error = 2.5
            root_mean_squared_error = 2.5
            within_permissible_error = True

        module = types.ModuleType("wsbuilder")
        module.NeuralNetwork = object
        module.Predictor = _Predictor
        module.evaluate_errors = lambda *args, **kwargs: Summary()
        with patch.dict(sys.modules, {"wsbuilder": module}):
            result = WsbuilderIAScorer(enabled=True, model=_Predictor()).score(
                features={"risk_score": 10}, expected=70, permissible_error=5
            )
        self.assertEqual(result.error_metrics["mean_absolute_error"], 2.5)
        self.assertTrue(result.error_metrics["within_permissible_error"])

    def test_model_failure_falls_back_to_existing_risk_score_without_payload(self):
        class Broken:
            def predict(self, _vector):
                raise RuntimeError("boom")

        module = types.ModuleType("wsbuilder")
        module.NeuralNetwork = object
        module.Predictor = object
        module.evaluate_errors = lambda *args, **kwargs: None
        with patch.dict(sys.modules, {"wsbuilder": module}):
            result = WsbuilderIAScorer(enabled=True, model=Broken()).score(
                {"soc_summary": {"risk_score": 77}, "payloads": [{"response_plain": "secret"}]}
            )
        self.assertEqual(result.status, "fallback")
        self.assertEqual(result.score, 77.0)
        self.assertNotIn("secret", repr(result.as_dict()))


if __name__ == "__main__":
    unittest.main()
