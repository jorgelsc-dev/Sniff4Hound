"""The real `RuntimeController` - owns the active capture engine
(`Sniffer` or `HoneypotEngine`) and switches between them.

Lives in its own module so the privileged capture process
(`capture_service.py`) can use it directly, unchanged, exactly as
`sniff4hound.app` used to when everything ran in one process. The web
process talks to this over IPC via `app.RuntimeControllerClient` instead.
"""

from __future__ import annotations

import json
import threading

from .settings import RUNTIME_MODE
from .utils import utc_now


ENGINE_NAMES = ("sniffer", "honeypot")


def normalize_runtime_mode(value: str) -> str:
    mode = str(value or "").strip().lower()
    if mode not in {"sniffer", "honeypot"}:
        return "sniffer"
    return mode


def normalize_interface_selection(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw_items = [raw]
    elif isinstance(raw, (list, tuple, set)):
        raw_items = list(raw)
    else:
        raw_items = [raw]

    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        normalized.append(value)
        seen.add(value)
    return normalized


def configured_runtime_mode() -> str:
    return normalize_runtime_mode(RUNTIME_MODE)


def read_stored_sniffer_interfaces(store) -> list[str]:
    stored = str(store.get_runtime_config("sniffer_interfaces", "") or "").strip()
    if stored:
        try:
            parsed = json.loads(stored)
        except Exception:
            parsed = [item for item in stored.split(",")]
        normalized = normalize_interface_selection(parsed)
        if normalized or stored in {"[]", ""}:
            return normalized

    legacy = str(store.get_runtime_config("sniffer_interface", "") or "").strip()
    return normalize_interface_selection(legacy)


class RuntimeController:
    def __init__(self, *, store, sniffer, honeypot, hub, capture_auto_start: bool):
        self._store = store
        self._sniffer = sniffer
        self._honeypot = honeypot
        self._hub = hub
        self._capture_auto_start = bool(capture_auto_start)
        self._lock = threading.RLock()
        self.mode = configured_runtime_mode()
        self._store.set_runtime_config("runtime_mode", self.mode)
        try:
            self._sniffer.set_interfaces(read_stored_sniffer_interfaces(self._store))
        except ValueError:
            self._store.set_runtime_config("sniffer_interfaces", "[]")
            self._store.set_runtime_config("sniffer_interface", "")

    def current_engine(self):
        return self._engine(self.mode)

    def _engine(self, name: str):
        return self._honeypot if normalize_runtime_mode(name) == "honeypot" else self._sniffer

    def _engine_snapshot(self, name: str) -> dict:
        normalized = normalize_runtime_mode(name)
        engine = self._engine(normalized)
        if normalized == "honeypot":
            try:
                return engine.snapshot(include_listeners=False)
            except TypeError:
                return engine.snapshot()
        return engine.snapshot()

    def _is_running(self, name: str) -> bool:
        try:
            return bool(self._engine_snapshot(name).get("running"))
        except Exception:
            return False

    def snapshot(self):
        sniffer = self._engine_snapshot("sniffer")
        honeypot = self._engine_snapshot("honeypot")
        running = [name for name in ENGINE_NAMES if (sniffer if name == "sniffer" else honeypot).get("running")]
        return {
            # `mode` is which engine the single-engine controls act on when no
            # engine is named, and which one `active` describes. It is no
            # longer a claim that the other engine is stopped - both can run
            # at once, so read `running_engines` for that.
            "mode": self.mode,
            "supported_modes": list(ENGINE_NAMES),
            "auto_start": bool(self._capture_auto_start),
            "active": honeypot if self.mode == "honeypot" else sniffer,
            "sniffer": sniffer,
            "honeypot": honeypot,
            "running_engines": running,
            "concurrent": len(running) > 1,
        }

    def _broadcast_snapshot(self, snapshot: dict):
        self._hub.broadcast(
            {
                "type": "runtime_mode",
                "runtime": snapshot,
                "generated_at": utc_now(),
            }
        )

    def start(self, engine=None):
        """Start one engine, or the focused one when none is named.

        Engines are independent: starting the honeypot no longer stops the
        sniffer. Both write into the same store - the honeypot under its
        `honeypot:<port>` pseudo-interfaces - so running them together is a
        supported combination, not a conflict.
        """
        with self._lock:
            for name in self._resolve_engines(engine):
                self._engine(name).start()
            snapshot = self.snapshot()
        self._broadcast_snapshot(snapshot)
        return snapshot

    def stop(self, engine=None):
        with self._lock:
            for name in self._resolve_engines(engine):
                self._engine(name).stop()
            snapshot = self.snapshot()
        self._broadcast_snapshot(snapshot)
        return snapshot

    def set_engines(self, selection):
        """Bring the running set to exactly what the caller asked for.

        Accepts {"sniffer": True, "honeypot": False} or a list of the engines
        that should be running. Any of the four combinations is valid,
        including none at all.
        """
        if isinstance(selection, dict):
            wanted = {name: bool(selection.get(name)) for name in ENGINE_NAMES if name in selection}
        else:
            names = {normalize_runtime_mode(item) for item in (selection or [])}
            wanted = {name: name in names for name in ENGINE_NAMES}
        with self._lock:
            for name, should_run in wanted.items():
                if should_run and not self._is_running(name):
                    self._engine(name).start()
                elif not should_run and self._is_running(name):
                    self._engine(name).stop()
            snapshot = self.snapshot()
        self._broadcast_snapshot(snapshot)
        return snapshot

    def _resolve_engines(self, engine) -> tuple:
        """Which engines a start/stop call refers to.

        None keeps the historic behaviour (act on the focused mode) so every
        existing caller and stored automation keeps working unchanged;
        "all"/"both" acts on both.
        """
        if engine is None or engine == "":
            return (self.mode,)
        if isinstance(engine, (list, tuple, set)):
            return tuple(dict.fromkeys(normalize_runtime_mode(item) for item in engine))
        name = str(engine).strip().lower()
        if name in ("all", "both", "*"):
            return ENGINE_NAMES
        return (normalize_runtime_mode(name),)

    def set_mode(self, mode: str):
        normalized = normalize_runtime_mode(mode)
        with self._lock:
            if normalized == self.mode:
                if self._capture_auto_start and not self._engine_snapshot(self.mode).get("running"):
                    self.current_engine().start()
                self._store.set_runtime_config("runtime_mode", self.mode)
                snapshot = self.snapshot()
            else:
                # Deliberately does not stop the engine being switched away
                # from: `mode` selects which engine the unqualified controls
                # act on, and both may run at once. Use stop("sniffer") /
                # set_engines() to actually stop one.
                self.mode = normalized
                self._store.set_runtime_config("runtime_mode", self.mode)
                if self._capture_auto_start:
                    self.current_engine().start()
                snapshot = self.snapshot()
        self._broadcast_snapshot(snapshot)
        return snapshot

    def set_sniffer_interfaces(self, interfaces=None):
        selected = normalize_interface_selection(interfaces)
        with self._lock:
            previous_interfaces = tuple(self._sniffer.snapshot().get("selected_interfaces") or ())
            was_running = bool(self._sniffer.snapshot().get("running"))
            self._sniffer.set_interfaces(selected)
            self._store.set_runtime_config("sniffer_interfaces", json.dumps(selected))
            self._store.set_runtime_config("sniffer_interface", selected[0] if len(selected) == 1 else "")
            if self.mode == "sniffer" and was_running and tuple(selected) != previous_interfaces:
                self._sniffer.restart()
            snapshot = self.snapshot()
            self._hub.broadcast(
                {
                    "type": "runtime_mode",
                    "runtime": snapshot,
                    "generated_at": utc_now(),
                }
            )
            return snapshot

    def set_sniffer_interface(self, interface: str = ""):
        selected = str(interface or "").strip()
        return self.set_sniffer_interfaces([selected] if selected else [])

    def list_honeypot_listeners(self):
        """Listener management is independent of which engine is currently
        active - you can create or toggle a honeypot listener while the
        Sniffer is the active mode; it just won't have a live thread until
        honeypot mode is started."""
        return self._honeypot.store.list_honeypot_listeners()

    def create_honeypot_listener(self, proto: str, port, label: str = ""):
        with self._lock:
            snapshot = self._honeypot.create_listener(proto, port, label)
        self._broadcast_snapshot(self.snapshot())
        return snapshot

    def set_honeypot_listener_enabled(self, listener_id: str, enabled: bool):
        with self._lock:
            snapshot = self._honeypot.set_listener_enabled(listener_id, bool(enabled))
        self._broadcast_snapshot(self.snapshot())
        return snapshot
