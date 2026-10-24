"""Optional, bounded adapter for the small ``wsbuilder`` IA primitives.

This module deliberately sits outside the capture path.  It consumes an
already-built snapshot (or an explicit feature mapping), never trains a
model, and never retains or returns packet payloads.  A missing dependency,
disabled model, malformed input, or model failure is reported as a safe
non-score instead of becoming a capture failure.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from numbers import Real
from typing import Any, Mapping


MAX_FEATURES = 32
MAX_FEATURE_VALUE = 1_000_000.0
SCORE_MIN = 0.0
SCORE_MAX = 100.0

# These are deliberately aggregate/shape fields.  In particular, names that
# could contain network identity, text, or payload material are not accepted.
_SAFE_KEY_PARTS = frozenset(
    {
        "available_packets",
        "count",
        "cycles_requested",
        "direction_unknown_rows",
        "findings_total",
        "flows",
        "high_findings",
        "info_findings",
        "local_rows",
        "low_findings",
        "medium_findings",
        "noisy_payloads",
        "packets",
        "private_rows",
        "processed",
        "protocols",
        "protocols_seen",
        "public_rows",
        "risk_score",
        "rows",
        "sampled_flows",
        "sampled_packets",
        "sampled_payloads",
        "sampled_tags",
        "structured_payloads",
        "tags",
        "total",
        "unknown_rows",
        "value",
    }
)
_SENSITIVE_KEY_PARTS = frozenset(
    {
        "address",
        "evidence",
        "example",
        "host",
        "ip",
        "label",
        "note",
        "payload",
        "question",
        "recommendation",
        "text",
        "title",
    }
)


@dataclass(frozen=True)
class ScoreResult:
    """Serializable outcome of one isolated score attempt."""

    score: float | None
    status: str
    source: str
    feature_count: int
    model: str | None = None
    reason: str | None = None
    error_metrics: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result = {
            "score": self.score,
            "status": self.status,
            "source": self.source,
            "feature_count": self.feature_count,
            "model": self.model,
        }
        if self.reason:
            result["reason"] = self.reason
        if self.error_metrics is not None:
            result["error_metrics"] = dict(self.error_metrics)
        return result


def _safe_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, Real):
        return None
    try:
        number = float(value)
    except (ArithmeticError, TypeError, ValueError):
        # float(10**400) raises OverflowError; a value that cannot be
        # represented is dropped rather than clamped to a guessed bound.
        return None
    if not math.isfinite(number):
        return None
    return max(-MAX_FEATURE_VALUE, min(MAX_FEATURE_VALUE, number))


# Snapshot containers whose aggregate leaves may cross the boundary.  This is
# a positive schema: any other mapping (``payloads``, ``hosts``, aliases or
# unknown nesting) is never traversed, whatever its leaves are called.
_SNAPSHOT_CONTAINERS = frozenset({"soc_summary", "summary", "pipeline", "stats", "counts", "totals"})


def _key_parts(key: str) -> set[str]:
    parts = {part for part in key.lower().replace("-", "_").split("_") if part}
    # Plurals and simple suffixed forms (payloads, hosts, ips) are the same
    # sensitive concept as their singular token.
    return parts | {part[:-1] for part in parts if part.endswith("s") and len(part) > 2}


def _key_sensitive(key: str) -> bool:
    return bool(_key_parts(key) & _SENSITIVE_KEY_PARTS)


def _key_allowed(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if _key_sensitive(normalized):
        return False
    parts = {part for part in normalized.split("_") if part}
    return normalized in _SAFE_KEY_PARTS or bool(parts & _SAFE_KEY_PARTS)


def sanitize_features(features: Mapping[str, Any] | None, *, limit: int = MAX_FEATURES) -> dict[str, float]:
    """Keep only bounded numeric features; return a fresh, deterministic map."""

    if not isinstance(features, Mapping):
        return {}
    limit = max(1, min(int(limit), MAX_FEATURES))
    sanitized: dict[str, float] = {}
    for raw_key in sorted(features, key=lambda value: str(value)):
        key = str(raw_key).strip()
        if not key or not _key_allowed(key):
            continue
        number = _safe_number(features[raw_key])
        if number is not None:
            sanitized[key] = number
        if len(sanitized) >= limit:
            break
    return sanitized


def snapshot_features(snapshot: Mapping[str, Any] | None, *, limit: int = MAX_FEATURES) -> dict[str, float]:
    """Extract aggregate numeric leaves from an explicit container schema.

    Only top-level allowed leaves and the leaves of the containers named in
    ``_SNAPSHOT_CONTAINERS`` (one level deep) are read.  Lists of rows and any
    other mapping are ignored: callers can aggregate them upstream and pass
    the resulting feature map explicitly.  A top-level leaf wins over a
    container leaf of the same name; containers are read in sorted order.
    """

    if not isinstance(snapshot, Mapping):
        return {}
    limit = max(1, min(int(limit), MAX_FEATURES))
    found: dict[str, float] = {}

    def take(value: Mapping[str, Any]) -> None:
        for raw_key in sorted(value, key=lambda item: str(item)):
            if len(found) >= limit:
                return
            key = str(raw_key).strip()
            if not key or key in found or not _key_allowed(key):
                continue
            number = _safe_number(value[raw_key])
            if number is not None:
                found[key] = number

    take(snapshot)
    for raw_key in sorted(snapshot, key=lambda item: str(item)):
        child = snapshot[raw_key]
        if str(raw_key).strip().lower() in _SNAPSHOT_CONTAINERS and isinstance(child, Mapping):
            take(child)
    return found


def _load_api() -> tuple[Any, Any, Any]:
    """Import optional IA symbols only when scoring is explicitly requested."""

    # The installed wsbuilder API exposes NeuralNetwork/evaluate_errors; model
    # instances are accepted by duck typing and there is no Predictor class.
    from wsbuilder import NeuralNetwork, evaluate_errors

    return NeuralNetwork, None, evaluate_errors


def _bounded_score(value: Any) -> float:
    number = _safe_number(value)
    if number is None:
        raise ValueError("model returned a non-finite score")
    return round(max(SCORE_MIN, min(SCORE_MAX, number)), 4)


class WsbuilderIAScorer:
    """Score precomputed features with an explicitly supplied, fitted model.

    ``enabled`` defaults to ``False``.  ``model`` must be fitted by the caller;
    this adapter never calls ``fit`` or starts background work.  ``fallback``
    uses an existing aggregate ``risk_score`` only when a model cannot score.
    """

    def __init__(self, *, enabled: bool = False, model: Any = None, fallback: bool = True):
        self.enabled = bool(enabled)
        self.model = model
        self.fallback = bool(fallback)

    def score(
        self,
        snapshot: Mapping[str, Any] | None = None,
        *,
        features: Mapping[str, Any] | None = None,
        expected: Any = None,
        permissible_error: float | None = None,
    ) -> ScoreResult:
        if not self.enabled:
            # OFF never inspects its input, so no input can make it fail.
            return ScoreResult(None, "disabled", "none", 0, reason="model disabled by default")
        try:
            safe_features = sanitize_features(features) if features is not None else snapshot_features(snapshot)
        except Exception as exc:  # adversarial mappings must not reach the caller
            return ScoreResult(None, "unavailable", "none", 0, reason=f"invalid input: {type(exc).__name__}")
        fallback_score = safe_features.get("risk_score")

        if self.model is None:
            return self._fallback(safe_features, fallback_score, "no fitted model")

        try:
            _load_api()
            prediction = self._predict(list(safe_features.values()))
            score = _bounded_score(prediction)
            metrics = self._metrics(expected, score, permissible_error)
            return ScoreResult(score, "scored", "model", len(safe_features), type(self.model).__name__, error_metrics=metrics)
        except Exception as exc:  # optional integration must not affect capture
            return self._fallback(safe_features, fallback_score, f"model unavailable: {type(exc).__name__}")

    def _predict(self, vector: list[float]) -> Any:
        if not vector:
            raise ValueError("no safe features")
        prediction = self.model.predict(vector)
        if isinstance(prediction, (list, tuple)):
            if not prediction:
                raise ValueError("model returned no prediction")
            prediction = prediction[0]
        if isinstance(prediction, (list, tuple)):
            if not prediction:
                raise ValueError("model returned no prediction")
            prediction = prediction[0]
        # Neural-network classification commonly returns a probability in
        # [0, 1], while Predictor returns the target scale.  Normalize only
        # the unambiguously probability-shaped case.
        number = _safe_number(prediction)
        if number is not None and 0.0 <= number <= 1.0:
            return number * SCORE_MAX
        return prediction

    def _metrics(self, expected: Any, score: float, permissible_error: float | None) -> Mapping[str, Any] | None:
        if expected is None:
            return None
        _, _, evaluate_errors = _load_api()
        summary = evaluate_errors([float(expected)], [score], permissible_error=permissible_error)
        return {name: getattr(summary, name) for name in ("mean_absolute_error", "root_mean_squared_error", "within_permissible_error")}

    def _fallback(self, safe_features: Mapping[str, float], value: float | None, reason: str) -> ScoreResult:
        if self.fallback and value is not None:
            return ScoreResult(_bounded_score(value), "fallback", "snapshot", len(safe_features), reason=reason)
        return ScoreResult(None, "unavailable", "none", len(safe_features), reason=reason)


def score_snapshot(snapshot: Mapping[str, Any] | None, *, enabled: bool = False, model: Any = None) -> dict[str, Any]:
    """Small functional entry point for callers that do not need a scorer object."""

    return WsbuilderIAScorer(enabled=enabled, model=model).score(snapshot).as_dict()


__all__ = ["ScoreResult", "WsbuilderIAScorer", "sanitize_features", "snapshot_features", "score_snapshot"]
