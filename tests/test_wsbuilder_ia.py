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

    def test_excluded_containers_aliases_and_plurals_never_reach_the_model(self):
        canary = 314159
        for container in ("payload", "payloads", "host", "hosts", "ips", "evidence", "findings", "top_hosts", "raw"):
            with self.subTest(container=container):
                self.assertEqual(snapshot_features({container: {"value": canary, "packets": canary}}), {})
        nested = {"soc_summary": {"risk_score": 5, "payloads": {"value": canary}, "inner": {"packets": canary}}}
        self.assertEqual(snapshot_features(nested), {"risk_score": 5.0})
        self.assertEqual(sanitize_features({"payloads_count": canary, "host_count": canary, "packets": 3}), {"packets": 3.0})

        class Spy:
            calls = []

            def predict(self, vector):
                self.calls.append(list(vector))
                return [50.0]

        module = types.ModuleType("wsbuilder")
        module.NeuralNetwork = object
        module.evaluate_errors = lambda *args, **kwargs: None
        spy = Spy()
        with patch.dict(sys.modules, {"wsbuilder": module}):
            WsbuilderIAScorer(enabled=True, model=spy).score({"payloads": {"value": canary}, "summary": {"packets": 2}})
        self.assertEqual(spy.calls, [[2.0]])
        self.assertNotIn(float(canary), spy.calls[0])

    def test_valid_aggregates_are_deterministic_bounded_and_top_level_wins(self):
        snapshot = {"packets": 1, "summary": {"packets": 9, "flows": 2}, "totals": {f"count_{i:02d}": i for i in range(40)}}
        first = snapshot_features(snapshot)
        self.assertEqual(first, snapshot_features(dict(reversed(list(snapshot.items())))))
        self.assertEqual(len(first), 32)
        self.assertEqual(first["packets"], 1.0)
        self.assertEqual(first["flows"], 2.0)

    def test_disabled_scorer_never_inspects_adversarial_input(self):
        class Hostile(dict):
            def __iter__(self):
                raise AssertionError("OFF must not read the input")

        for value in (10**400, float("nan"), float("inf"), object()):
            with self.subTest(value=repr(value)[:20]):
                result = WsbuilderIAScorer(enabled=False).score(features={"packets": value})
                self.assertEqual((result.status, result.feature_count), ("disabled", 0))
        with patch.dict(sys.modules, {"wsbuilder": None}):
            self.assertEqual(WsbuilderIAScorer(enabled=False).score(Hostile()).status, "disabled")

    def test_enabled_scorer_drops_unrepresentable_values_without_raising(self):
        self.assertEqual(sanitize_features({"packets": 10**400, "flows": float("nan"), "rows": 4}), {"rows": 4.0})
        self.assertEqual(snapshot_features({"summary": {"packets": 10**400}}), {})

        class Hostile(dict):
            def __iter__(self):
                raise RuntimeError("hostile mapping")

        result = WsbuilderIAScorer(enabled=True, model=_Predictor()).score(Hostile(a=1))
        self.assertEqual(result.status, "unavailable")
        self.assertIsNone(result.score)
        result = WsbuilderIAScorer(enabled=True).score(features={"risk_score": 10**400})
        self.assertEqual(result.status, "unavailable")

    def test_off_never_calls_predict_and_on_calls_it_once(self):
        class Spy:
            def __init__(self):
                self.calls = 0

            def predict(self, _vector):
                self.calls += 1
                return [0.5]

        module = types.ModuleType("wsbuilder")
        module.NeuralNetwork = object
        module.evaluate_errors = lambda *args, **kwargs: None
        spy = Spy()
        with patch.dict(sys.modules, {"wsbuilder": module}):
            self.assertEqual(WsbuilderIAScorer(enabled=False, model=spy).score(features={"packets": 1}).status, "disabled")
            self.assertEqual(spy.calls, 0)
            result = WsbuilderIAScorer(enabled=True, model=spy).score(features={"packets": 1})
        self.assertEqual((spy.calls, result.status, result.score), (1, "scored", 50.0))


if __name__ == "__main__":
    unittest.main()
