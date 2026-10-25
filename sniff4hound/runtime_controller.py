"""The real `RuntimeController` - owns the active capture engine
(`Sniffer` or `HoneypotEngine`) and switches between them.

Lives in its own module so the privileged capture process
(`capture_service.py`) can use it directly, unchanged, exactly as
`sniff4hound.app` used to when everything ran in one process. The web
process talks to this over IPC via `app.RuntimeControllerClient` instead.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time

from .settings import RUNTIME_MODE
from .utils import coerce_bool, utc_now


ENGINE_NAMES = ("sniffer", "honeypot")

# How long an interface change watches the restarted sniffer before calling it
# applied. Sniffer.start() returns once its workers are spawned; a worker that
# cannot open its interface fails a moment later on its own thread, so an
# immediate snapshot would still read "running". Bounded and short: the
# controller lock is held meanwhile.
def _configured_interface_verify_seconds() -> float:
    try:
        value = float(os.environ.get("SNIFF4HOUND_INTERFACE_VERIFY_SECONDS", "0.5"))
    except (TypeError, ValueError):
        return 0.5
    # Never let a malformed override fail import or hold the controller lock
    # indefinitely. Zero disables the observation window, not state checks.
    return min(5.0, max(0.0, value)) if math.isfinite(value) else 0.5


INTERFACE_VERIFY_SECONDS = _configured_interface_verify_seconds()
INTERFACE_VERIFY_POLL_SECONDS = 0.05


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
        self._interface_update = None
        self._interface_verify_seconds = INTERFACE_VERIFY_SECONDS
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

    def reset_packet_pipeline(self):
        # Counters live on the sniffer (capture process); reset there and hand
        # back the fresh pipeline snapshot.
        return self._sniffer.reset_pipeline_counters()

    def snapshot(self):
        sniffer = self._engine_snapshot("sniffer")
        if self._interface_update is not None:
            sniffer = {**sniffer, "interface_update": dict(self._interface_update)}
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

    def broadcast_state(self) -> dict:
        """Push the current runtime snapshot to every client, e.g. after a
        mutation finished too late for its caller to see the answer."""
        snapshot = self.snapshot()
        self._broadcast_snapshot(snapshot)
        return snapshot

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
            wanted = {
                name: coerce_bool(selection.get(name), f"engines.{name}")
                for name in ENGINE_NAMES
                if name in selection
            }
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

    @staticmethod
    def _sniffer_failure(snapshot: dict) -> str:
        """Why a sniffer snapshot does not count as capturing, or ""."""
        # Optional promiscuous-mode warnings and old receive errors do not
        # mean bind failed. New sniffers report startup failures separately.
        errors = snapshot.get("startup_errors", snapshot.get("errors")) or {}
        if errors:
            return "; ".join(f"{name}: {message}" for name, message in sorted(errors.items()))
        if not snapshot.get("running"):
            return "sniffer is not running"
        if snapshot.get("active_threads", 1) < 1:
            return "sniffer has no live capture worker"
        state = snapshot.get("capture_state")
        if state is not None and state != "running":
            return f"sniffer capture is {state}"
        return ""

    def _restart_sniffer_verified(self):
        """Restart the sniffer and watch it for a short, bounded window.

        Raises RuntimeError when it is not capturing at any point in the
        window, including worker failures that surface after start()."""
        self._sniffer.restart()
        deadline = time.monotonic() + self._interface_verify_seconds
        while True:
            snapshot = self._sniffer.snapshot()
            failure = self._sniffer_failure(snapshot)
            if failure:
                raise RuntimeError(f"sniffer interface restart failed: {failure}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if "ready_interfaces" in snapshot and (
                    not snapshot["ready_interfaces"]
                    or set(snapshot.get("interfaces") or ()) != set(snapshot["ready_interfaces"])
                ):
                    raise RuntimeError("sniffer interface startup did not finish before the deadline")
                return
            time.sleep(min(INTERFACE_VERIFY_POLL_SECONDS, remaining))

    def set_sniffer_interfaces(self, interfaces=None):
        selected = normalize_interface_selection(interfaces)
        with self._lock:
            before = self._sniffer.snapshot()
            previous_interfaces = tuple(before.get("selected_interfaces") or ())
            was_running = bool(before.get("running"))
            self._sniffer.set_interfaces(selected)
            changed = tuple(selected) != previous_interfaces
            if was_running and changed:
                try:
                    self._restart_sniffer_verified()
                except Exception as exc:
                    # Put back what was capturing before the attempt, and the
                    # capture itself: a failed change must not leave the
                    # operator with a stopped sniffer and a selection that
                    # looks as if nothing happened.
                    update = {
                        "status": "rolled_back",
                        "requested_interfaces": selected,
                        "previous_interfaces": list(previous_interfaces),
                        "restored_interfaces": [],
                        "error": str(exc),
                        "rollback_error": "",
                    }
                    try:
                        self._sniffer.set_interfaces(list(previous_interfaces))
                        update["restored_interfaces"] = list(previous_interfaces)
                        self._restart_sniffer_verified()
                    except Exception as rollback_exc:  # noqa: BLE001 - reported below
                        update["status"] = "rollback_failed"
                        update["rollback_error"] = str(rollback_exc)
                    self._interface_update = update
                    self._broadcast_snapshot(self.snapshot())
                    raise
            self._store.set_runtime_config("sniffer_interfaces", json.dumps(selected))
            self._store.set_runtime_config("sniffer_interface", selected[0] if len(selected) == 1 else "")
            # An identical retry must not erase an earlier restart failure.
            if changed or self._interface_update is None:
                self._interface_update = {
                    "status": "applied" if was_running else "saved",
                    "requested_interfaces": selected, "error": "",
                }
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

    def honeypot_listener_page(self, **query):
        page = self._honeypot.store.honeypot_listener_page(**query)
        page["items"] = [{**row, **self._honeypot._listener_view(row)} for row in page["items"]]
        return page

    def set_dashboard_port(self, port):
        self._sniffer.dashboard_port = int(port)
        return {"port": int(port)}

    def list_honeypot_listeners(self):
        """Listener management is independent of which engine is currently
        active - you can create or toggle a honeypot listener while the
        Sniffer is the active mode; it just won't have a live thread until
        honeypot mode is started.

        Each row carries the engine's own view of it too (`running`, and
        `can_enable`, which says whether the port policy lets it be turned on)
        - the same shape the toggle's snapshot returns, so the table does not
        change what it knows about a listener after the first click."""
        return [
            {**row, **self._honeypot._listener_view(row)}
            for row in self._honeypot.store.list_honeypot_listeners()
        ]

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
