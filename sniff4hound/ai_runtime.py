"""Small, local and observable aggregate-risk engine.

The engine is intentionally deterministic and never receives packet rows.  It
only consumes numeric aggregates produced by ``analytics_snapshot``.  This
keeps the AI setting useful out of the box while leaving a clear seam for a
future model provider without making network calls or blocking capture.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import threading
from typing import Any, Mapping


MODEL_ID = "sniff4hound-aggregate-risk-v1"
PROVIDER = "Local aggregate engine"
MODEL_STATUS = "ready"
HISTORY_LIMIT = 24


def _number(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return max(0.0, number)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AggregateAiRuntime:
    """Thread-safe state and deterministic analysis for aggregate metrics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: deque[dict[str, Any]] = deque(maxlen=HISTORY_LIMIT)
        self._total_runs = 0
        self._total_findings = 0
        self._last: dict[str, Any] | None = None

    @property
    def model_status(self) -> str:
        return MODEL_STATUS

    def analyze(self, snapshot: Mapping[str, Any] | None) -> dict[str, Any]:
        snapshot = snapshot if isinstance(snapshot, Mapping) else {}
        summary = snapshot.get("summary") if isinstance(snapshot.get("summary"), Mapping) else {}
        packets = _number(summary.get("ports"))
        targets = _number(summary.get("targets"))
        open_ports = _number(summary.get("open_ports"))
        banners = _number(summary.get("banners"))
        tags = _number(summary.get("tags"))
        hosts = _number(summary.get("unique_hosts"))
        protocols = len(snapshot.get("ports_by_proto") or []) if isinstance(snapshot.get("ports_by_proto"), list) else 0
        risky_ports = len(snapshot.get("risk_ports") or []) if isinstance(snapshot.get("risk_ports"), list) else 0

        features = {
            "packets": int(packets),
            "targets": int(targets),
            "open_ports": int(open_ports),
            "banners": int(banners),
            "tags": int(tags),
            "unique_hosts": int(hosts),
            "protocols": protocols,
            "risky_ports": risky_ports,
        }
        exposure = min(35.0, open_ports * 3.5)
        risky = min(35.0, risky_ports * 9.0)
        breadth = min(20.0, protocols * 4.0 + min(8.0, hosts / 10.0))
        activity = min(10.0, (packets / max(targets, 1.0)) / 20.0)
        score = round(min(100.0, exposure + risky + breadth + activity), 1)

        findings: list[dict[str, str]] = []
        if risky_ports:
            findings.append({
                "severity": "high" if risky_ports >= 3 else "medium",
                "title": "Puertos de interés observados",
                "detail": f"{risky_ports} servicios coinciden con el conjunto de puertos de riesgo.",
            })
        if open_ports >= 5:
            findings.append({
                "severity": "medium",
                "title": "Superficie expuesta amplia",
                "detail": f"Se observaron {int(open_ports)} puertos abiertos en el periodo analizado.",
            })
        if protocols >= 4:
            findings.append({
                "severity": "low",
                "title": "Diversidad de protocolos",
                "detail": f"La actividad incluye {protocols} protocolos agregados.",
            })
        if not findings:
            findings.append({
                "severity": "info",
                "title": "Sin señales destacadas",
                "detail": "El agregado disponible no contiene señales que superen los umbrales actuales.",
            })

        result = {
            "id": self._total_runs + 1,
            "generated_at": _now(),
            "score": score,
            "label": "alto" if score >= 70 else "medio" if score >= 35 else "bajo",
            "confidence": round(min(0.99, 0.45 + min(0.5, (packets + targets) / 1000.0)), 2),
            "features": features,
            "findings": findings,
            "engine": PROVIDER,
            "model": MODEL_ID,
            "source": "aggregate_metrics",
        }
        with self._lock:
            self._total_runs += 1
            self._total_findings += len(findings)
            self._last = result
            self._runs.append(result)
        return result

    def status(self, *, enabled: bool) -> dict[str, Any]:
        with self._lock:
            last = dict(self._last) if self._last else None
            history = [dict(item) for item in reversed(self._runs)]
            return {
                "provider": PROVIDER,
                "model": MODEL_ID,
                "model_status": MODEL_STATUS,
                "enabled": bool(enabled),
                "total_runs": self._total_runs,
                "total_findings": self._total_findings,
                "last_run": last,
                "history": history,
            }


__all__ = ["AggregateAiRuntime", "MODEL_ID", "MODEL_STATUS", "PROVIDER"]
