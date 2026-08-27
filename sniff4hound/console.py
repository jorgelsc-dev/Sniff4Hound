"""The interactive `sniff4hound>` console: command registry, tab completion
and handlers.

Split out of `manage.py` (which is about process startup, not about being a
shell) once the command set outgrew a chain of `if command == ...` branches.

Every command is declared once, as a `ConsoleCommandSpec`. The help text, the
`/help <command>` detail, the alias table and the tab completion are all
derived from that single declaration, so a new command cannot end up
executable but undocumented, or documented but not completable.

Completion is positional: `spec.completions` holds one entry per argument
slot, and each entry is either a literal tuple (`("sniffer", "honeypot")`) or
a `"@provider"` string resolved at keypress time against the live runtime -
so `/monitor off <TAB>` offers monitor ids that actually exist right now, and
`/interfaces <TAB>` offers the interfaces this machine actually has.

Handlers receive a `ConsoleContext` rather than loose arguments so adding a
command never means threading another parameter through the call chain.
"""

from __future__ import annotations

import shlex
import webbrowser

try:
    import readline
except ImportError:  # pragma: no cover - platform dependent
    readline = None
from dataclasses import dataclass
from typing import Any, Callable

from .process_control import request_process_shutdown


@dataclass
class ConsoleContext:
    """Everything a command handler is allowed to touch."""

    host: str
    port: int
    runtime: Any
    hub: Any
    append_chat_message: Callable[..., dict]
    store: Any = None


@dataclass(frozen=True)
class ConsoleCommandSpec:
    command: str
    help_text: str
    aliases: tuple[str, ...] = ()
    # One entry per positional argument. Each entry is either a tuple of
    # literals or a "@provider" key resolved through _COMPLETION_PROVIDERS.
    completions: tuple = ()
    usage: str = ""
    details: str = ""

    def usage_line(self) -> str:
        return self.usage or self.command


# --------------------------------------------------------------------------
# Command table
# --------------------------------------------------------------------------

CONSOLE_COMMAND_SPECS = (
    ConsoleCommandSpec(
        "/help",
        "Show this help, or detail for one command",
        usage="/help [command]",
        completions=("@command",),
    ),
    ConsoleCommandSpec(
        "/status",
        "Show runtime and WebSocket status",
        aliases=("/stats",),
    ),
    ConsoleCommandSpec(
        "/mode",
        "Switch mode: sniffer | honeypot",
        usage="/mode sniffer|honeypot",
        completions=(("sniffer", "honeypot"),),
    ),
    ConsoleCommandSpec("/start", "Start the active engine", aliases=("/run",)),
    ConsoleCommandSpec("/stop", "Stop the active engine"),
    ConsoleCommandSpec(
        "/restart",
        "Stop and start the active engine",
        details="Equivalent to /stop followed by /start, without changing the mode.",
    ),
    ConsoleCommandSpec(
        "/interfaces",
        "List capture interfaces, or select which ones to capture on",
        aliases=("/iface",),
        usage="/interfaces [name ...]",
        completions=("@interface", "@interface", "@interface"),
        details=(
            "With no arguments, lists every interface the capture process can see and\n"
            "marks the selected ones. With one or more names, replaces the selection.\n"
            "Use /interfaces all to capture on every visible interface."
        ),
    ),
    ConsoleCommandSpec(
        "/monitors",
        "List detection monitors, optionally filtered",
        usage="/monitors [search] [--limit N]",
        details="Shows id, severity and enabled state. Matching is a substring of id or name.",
    ),
    ConsoleCommandSpec(
        "/monitor",
        "Show or toggle one monitor",
        usage="/monitor show|on|off <monitor-id>",
        completions=(("show", "on", "off"), "@monitor_id"),
    ),
    ConsoleCommandSpec(
        "/listeners",
        "List honeypot listeners and their state",
        details="Listeners are only actually bound while the honeypot engine is the active mode.",
    ),
    ConsoleCommandSpec(
        "/listener",
        "Enable or disable one honeypot listener",
        usage="/listener on|off <proto/port>",
        completions=(("on", "off"), "@listener"),
    ),
    ConsoleCommandSpec(
        "/top",
        "Rank the busiest talkers in the capture",
        usage="/top ips|ports|protocols|domains [N]",
        completions=(("ips", "ports", "protocols", "domains"),),
    ),
    ConsoleCommandSpec(
        "/alerts",
        "Show the most recent monitor hits",
        usage="/alerts [N]",
    ),
    ConsoleCommandSpec(
        "/packets",
        "Show the most recent captured packets",
        usage="/packets [N]",
    ),
    ConsoleCommandSpec(
        "/intel",
        "Show what is known about one IP address",
        aliases=("/lookup",),
        usage="/intel <ip>",
        completions=("@ip",),
    ),
    ConsoleCommandSpec(
        "/clear",
        "Delete stored capture data for a scope",
        usage="/clear monitors|honeypot|all|everything [--yes]",
        completions=(("monitors", "honeypot", "all", "everything"),),
        details=(
            "monitors/honeypot/all clear detection history (packets, tags, payloads).\n"
            "everything also wipes flows, domains, paths and sessions, then vacuums\n"
            "the database file. Monitor and listener definitions are never touched.\n"
            "Destructive and irreversible: needs --yes to actually run."
        ),
    ),
    ConsoleCommandSpec(
        "/config",
        "Show the effective runtime configuration",
        details="Retention, capture and access-log settings as they are actually in effect.",
    ),
    ConsoleCommandSpec(
        "/chat",
        "Show the operator chat transcript",
        usage="/chat [N]",
        details=(
            "Plain text typed at this prompt is posted to the chat; messages sent from\n"
            "the dashboard are echoed here as they arrive. This shows the backlog."
        ),
    ),
    ConsoleCommandSpec("/token", "Show the current security code"),
    ConsoleCommandSpec("/url", "Show the current dashboard URL"),
    ConsoleCommandSpec("/clients", "List connected WebSocket clients"),
    ConsoleCommandSpec(
        "/broadcast",
        "Broadcast an operator note",
        aliases=("/say",),
        usage="/broadcast <text>",
    ),
    ConsoleCommandSpec("/open", "Open the dashboard in the browser"),
    ConsoleCommandSpec("/version", "Show the Sniff4Hound version"),
    ConsoleCommandSpec("/quit", "Stop Sniff4Hound", aliases=("/exit",)),
)

CONSOLE_COMMAND_ALIASES = {
    alias: spec.command
    for spec in CONSOLE_COMMAND_SPECS
    for alias in spec.aliases
}
CONSOLE_COMMANDS_BY_NAME = {spec.command: spec for spec in CONSOLE_COMMAND_SPECS}
CONSOLE_COMPLETION_TOKENS = tuple(
    sorted({spec.command for spec in CONSOLE_COMMAND_SPECS} | set(CONSOLE_COMMAND_ALIASES))
)


def resolve_console_command(command: str) -> str:
    normalized = str(command or "").strip().lower()
    return CONSOLE_COMMAND_ALIASES.get(normalized, normalized)


# --------------------------------------------------------------------------
# Completion
# --------------------------------------------------------------------------

# readline's completer is a bare global callback with no room for context, so
# the live runtime is parked here when the console starts and read back by the
# "@provider" completions below.
_ACTIVE_CONTEXT: ConsoleContext | None = None


def set_active_console_context(context: ConsoleContext | None) -> None:
    global _ACTIVE_CONTEXT
    _ACTIVE_CONTEXT = context


def _provider_command() -> list[str]:
    return list(CONSOLE_COMPLETION_TOKENS)


def _provider_interface() -> list[str]:
    context = _ACTIVE_CONTEXT
    if context is None:
        return []
    try:
        snapshot = context.runtime.snapshot() or {}
        active = snapshot.get("active") or {}
        names = list(active.get("available_interfaces") or [])
    except Exception:
        return []
    return ["all", *[str(name) for name in names if name]]


def _provider_monitor_id() -> list[str]:
    context = _ACTIVE_CONTEXT
    if context is None or context.store is None:
        return []
    try:
        # Only the enabled/disabled builtins an operator plausibly toggles by
        # hand: the bundled catalog holds ~30k ids and completing all of them
        # would hang the terminal on every Tab.
        rows = context.store.list_monitors()
    except Exception:
        return []
    return [str(row.get("id")) for row in rows[:400] if row.get("id")]


def _provider_listener() -> list[str]:
    context = _ACTIVE_CONTEXT
    if context is None:
        return []
    try:
        rows = context.runtime.list_honeypot_listeners() or []
    except Exception:
        return []
    return [str(row.get("id")) for row in rows if row.get("id")]


def _provider_ip() -> list[str]:
    """The busiest addresses in the capture - the ones an operator is
    plausibly about to look up. Not the full endpoint catalog: that call
    takes a route list, and completing every address ever seen would be
    unusable anyway."""
    context = _ACTIVE_CONTEXT
    if context is None or context.store is None:
        return []
    try:
        rows = context.store.top_ips(limit=50) or []
    except Exception:
        return []
    values = []
    for row in rows:
        ip = str(row.get("ip") or row.get("value") or row.get("address") or "").strip()
        if ip:
            values.append(ip)
    return values


_COMPLETION_PROVIDERS = {
    "@command": _provider_command,
    "@interface": _provider_interface,
    "@monitor_id": _provider_monitor_id,
    "@listener": _provider_listener,
    "@ip": _provider_ip,
}


def _candidates_for_slot(spec: ConsoleCommandSpec, index: int) -> list[str]:
    """Every value valid in argument slot `index` of `spec`."""
    if not spec.completions:
        return []
    if index >= len(spec.completions):
        # A trailing "@provider" slot repeats, so `/interfaces eth0 <TAB>`
        # keeps offering interfaces for the second and third name too.
        last = spec.completions[-1]
        if not (isinstance(last, str) and last.startswith("@")):
            return []
        entry = last
    else:
        entry = spec.completions[index]
    if isinstance(entry, str) and entry.startswith("@"):
        provider = _COMPLETION_PROVIDERS.get(entry)
        if provider is None:
            return []
        try:
            return list(provider())
        except Exception:
            return []
    return list(entry or ())


def build_console_completion_candidates(buffer: str, text: str, begidx: int) -> list[str]:
    current = str(text or "").strip().lower()
    if begidx == 0:
        if current and not current.startswith("/"):
            return []
        return [token for token in CONSOLE_COMPLETION_TOKENS if token.startswith(current)]

    tokens = str(buffer[:begidx] or "").split()
    if not tokens:
        return []

    spec = CONSOLE_COMMANDS_BY_NAME.get(resolve_console_command(tokens[0]))
    if spec is None:
        return []
    # tokens[0] is the command itself, so the slot being completed is the
    # number of arguments already typed.
    slot = max(0, len(tokens) - 1)
    candidates = _candidates_for_slot(spec, slot)
    seen = set()
    ordered = []
    for candidate in candidates:
        value = str(candidate)
        if value.lower().startswith(current) and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered



def _console_readline_completer(text: str, state: int) -> str | None:
    if readline is None:
        return None
    buffer = readline.get_line_buffer()
    matches = build_console_completion_candidates(buffer, text, readline.get_begidx())
    if state < len(matches):
        return matches[state]
    return None


def configure_console_autocomplete() -> bool:
    """Bind Tab to the completer. Returns whether it actually took effect."""
    if readline is None:
        return False
    try:
        bind_command = "bind ^I rl_complete" if "libedit" in str(readline.__doc__ or "").lower() else "tab: complete"
        readline.parse_and_bind(bind_command)
        # Default delims include "/" and "-", which would split "/monitor" and
        # "builtin-port-scan" mid-token and make command and id completion
        # useless. Only whitespace separates arguments here.
        readline.set_completer_delims(" \t\n")
        readline.set_completer(_console_readline_completer)
        return True
    except Exception:
        return False

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def _say(message: str) -> None:
    print(f"[console] {message}")


def _rows(lines: list[str]) -> None:
    print("\n".join(lines))


def _as_int(value, default: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _truncate(value, width: int) -> str:
    text = str(value if value is not None else "")
    return text if len(text) <= width else text[: width - 1] + "…"


def format_runtime_status(runtime, client_count: int) -> str:
    snapshot = runtime.snapshot()
    mode = str(snapshot.get("mode") or "sniffer")
    active = snapshot.get("active") or {}
    running = "yes" if active.get("running") else "no"
    packets = active.get("packets_seen") or active.get("packets") or 0
    return (
        f"[status] mode={mode} running={running} "
        f"packets={packets} ws_clients={client_count}"
    )


def print_console_help(command: str = "") -> None:
    target = resolve_console_command(command)
    if target:
        spec = CONSOLE_COMMANDS_BY_NAME.get(target)
        if spec is None:
            _say(f"Unknown command: {command}. Type /help.")
            return
        lines = [f"[console] {spec.usage_line()}", f"  {spec.help_text}"]
        if spec.aliases:
            lines.append(f"  aliases: {', '.join(spec.aliases)}")
        for slot, entry in enumerate(spec.completions or (), start=1):
            values = _candidates_for_slot(spec, slot - 1)
            if values:
                lines.append(f"  arg {slot}: {', '.join(str(v) for v in values[:12])}")
        if spec.details:
            lines.extend(f"  {line}" for line in spec.details.splitlines())
        _rows(lines)
        return

    lines = ["[console] Commands:"]
    for spec in CONSOLE_COMMAND_SPECS:
        lines.append(f"  {spec.usage_line():<34}{spec.help_text}")
        if spec.aliases:
            lines.append(f"  {'aliases:':<34}{', '.join(spec.aliases)}")
    lines.append(f"  {'<text>':<34}Save and broadcast an operator note")
    lines.append("")
    lines.append("  Tab completes commands and their arguments. /help <command> for detail.")
    _rows(lines)


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------

def _cmd_help(context: ConsoleContext, args: list[str]) -> None:
    print_console_help(args[0] if args else "")


def _cmd_status(context: ConsoleContext, args: list[str]) -> None:
    print(format_runtime_status(context.runtime, len(context.hub.list_clients())))


def _cmd_mode(context: ConsoleContext, args: list[str]) -> None:
    target_mode = str(args[0] if args else "").strip().lower()
    if target_mode not in {"sniffer", "honeypot"}:
        _say("Usage: /mode sniffer|honeypot")
        return
    snapshot = context.runtime.set_mode(target_mode)
    _say(f"Runtime mode set to {snapshot.get('mode')}")


def _cmd_start(context: ConsoleContext, args: list[str]) -> None:
    active = (context.runtime.start() or {}).get("active") or {}
    _say(f"Active engine started (running={bool(active.get('running'))})")


def _cmd_stop(context: ConsoleContext, args: list[str]) -> None:
    active = (context.runtime.stop() or {}).get("active") or {}
    _say(f"Active engine stopped (running={bool(active.get('running'))})")


def _cmd_restart(context: ConsoleContext, args: list[str]) -> None:
    context.runtime.stop()
    active = (context.runtime.start() or {}).get("active") or {}
    _say(f"Active engine restarted (running={bool(active.get('running'))})")


def _cmd_interfaces(context: ConsoleContext, args: list[str]) -> None:
    if args:
        names = [] if [a.lower() for a in args] == ["all"] else [str(a) for a in args]
        context.runtime.set_sniffer_interfaces(names)
        _say(f"Capture interfaces set to {', '.join(names) if names else 'all visible'}")
        return
    snapshot = context.runtime.snapshot() or {}
    active = snapshot.get("active") or {}
    available = list(active.get("available_interfaces") or [])
    selected = set(active.get("selected_interfaces") or [])
    if not available:
        _say("No interfaces reported by the capture process.")
        return
    lines = [f"[console] Interfaces ({len(available)}):"]
    for name in available:
        lines.append(f"  {'*' if name in selected else ' '} {name}")
    lines.append("  (* = selected; an empty selection means every visible interface)")
    _rows(lines)


def _cmd_monitors(context: ConsoleContext, args: list[str]) -> None:
    if context.store is None:
        _say("Monitor catalog unavailable in this process.")
        return
    limit = 25
    terms = []
    index = 0
    while index < len(args):
        if args[index] == "--limit" and index + 1 < len(args):
            limit = _as_int(args[index + 1], 25)
            index += 2
            continue
        terms.append(args[index])
        index += 1
    needle = " ".join(terms).strip().lower()
    rows = context.store.list_monitors() or []
    if needle:
        rows = [
            row for row in rows
            if needle in str(row.get("id") or "").lower() or needle in str(row.get("name") or "").lower()
        ]
    if not rows:
        _say(f"No monitors match {needle!r}." if needle else "No monitors defined.")
        return
    lines = [f"[console] Monitors: {len(rows)} match, showing {min(limit, len(rows))}"]
    for row in rows[:limit]:
        action = row.get("action") or {}
        severity = str(action.get("severity") or "-")
        state = "on " if row.get("enabled") else "off"
        lines.append(f"  [{state}] {_truncate(row.get('id'), 44):<44} {severity:<8} {_truncate(row.get('name'), 40)}")
    if len(rows) > limit:
        lines.append(f"  ... {len(rows) - limit} more (use --limit N, or narrow the search)")
    _rows(lines)


def _cmd_monitor(context: ConsoleContext, args: list[str]) -> None:
    if context.store is None:
        _say("Monitor catalog unavailable in this process.")
        return
    action = str(args[0] if args else "").strip().lower()
    monitor_id = str(args[1] if len(args) > 1 else "").strip()
    if action not in {"show", "on", "off"} or not monitor_id:
        _say("Usage: /monitor show|on|off <monitor-id>")
        return
    monitor = context.store.get_monitor(monitor_id)
    if not monitor:
        _say(f"No such monitor: {monitor_id}")
        return
    if action == "show":
        lines = [f"[console] {monitor.get('id')}"]
        lines.append(f"  name:     {monitor.get('name')}")
        lines.append(f"  enabled:  {bool(monitor.get('enabled'))}")
        lines.append(f"  severity: {(monitor.get('action') or {}).get('severity', '-')}")
        lines.append(f"  mode:     {monitor.get('mode')}")
        lines.append(f"  source:   {monitor.get('source')}")
        description = str(monitor.get("description") or "").strip()
        if description:
            lines.append(f"  detail:   {_truncate(description, 200)}")
        _rows(lines)
        return
    enabled = action == "on"
    context.store.set_monitor_enabled(monitor_id, enabled)
    _say(f"Monitor {monitor_id} {'enabled' if enabled else 'disabled'}")


def _cmd_listeners(context: ConsoleContext, args: list[str]) -> None:
    rows = context.runtime.list_honeypot_listeners() or []
    if not rows:
        _say("No honeypot listeners defined.")
        return
    lines = [f"[console] Honeypot listeners ({len(rows)}):"]
    for row in rows:
        state = "on " if row.get("enabled") else "off"
        running = "running" if row.get("running") else "idle"
        lines.append(f"  [{state}] {str(row.get('id')):<12} {running:<8} {row.get('label') or ''}")
    _rows(lines)


def _cmd_listener(context: ConsoleContext, args: list[str]) -> None:
    action = str(args[0] if args else "").strip().lower()
    listener_id = str(args[1] if len(args) > 1 else "").strip()
    if action not in {"on", "off"} or not listener_id:
        _say("Usage: /listener on|off <proto/port>")
        return
    enabled = action == "on"
    try:
        context.runtime.set_honeypot_listener_enabled(listener_id, enabled)
    except Exception as exc:
        _say(f"Could not update {listener_id}: {exc}")
        return
    _say(f"Listener {listener_id} {'enabled' if enabled else 'disabled'}")


def _cmd_top(context: ConsoleContext, args: list[str]) -> None:
    if context.store is None:
        _say("Capture store unavailable in this process.")
        return
    what = str(args[0] if args else "").strip().lower()
    limit = _as_int(args[1] if len(args) > 1 else "", 10)
    getters = {
        "ips": lambda: context.store.top_ips(limit=limit),
        "ports": lambda: context.store.top_ports(limit=limit),
        "protocols": lambda: context.store.top_protocols(limit=limit),
        "domains": lambda: context.store.list_domains(limit=limit),
    }
    if what not in getters:
        _say("Usage: /top ips|ports|protocols|domains [N]")
        return
    rows = getters[what]() or []
    if not rows:
        _say(f"No {what} recorded yet.")
        return
    lines = [f"[console] Top {what} ({len(rows)}):"]
    for row in rows:
        if not isinstance(row, dict):
            lines.append(f"  {row}")
            continue
        label = row.get("ip") or row.get("port") or row.get("proto") or row.get("name") or row.get("value") or "-"
        count = row.get("count") or row.get("hits") or row.get("hit_count") or row.get("packets") or 0
        lines.append(f"  {str(label):<42} {count}")
    _rows(lines)


def _cmd_alerts(context: ConsoleContext, args: list[str]) -> None:
    if context.store is None:
        _say("Capture store unavailable in this process.")
        return
    limit = _as_int(args[0] if args else "", 20)
    rows = context.store.list_recent_alerts(limit=limit) or []
    if not rows:
        _say("No monitor hits recorded yet.")
        return
    lines = [f"[console] Recent alerts ({len(rows)}):"]
    for row in rows:
        lines.append(
            f"  {_truncate(row.get('created_at'), 19):<19} "
            f"{str(row.get('severity') or '-'):<8} "
            f"{_truncate(row.get('label') or row.get('key'), 30):<30} "
            f"{_truncate(row.get('value') or row.get('detail'), 50)}"
        )
    _rows(lines)


def _cmd_packets(context: ConsoleContext, args: list[str]) -> None:
    if context.store is None:
        _say("Capture store unavailable in this process.")
        return
    limit = _as_int(args[0] if args else "", 20)
    rows = context.store.list_packets(limit=limit) or []
    if not rows:
        _say("No packets stored yet.")
        return
    lines = [f"[console] Recent packets ({len(rows)}):"]
    for row in rows:
        src = f"{row.get('src_ip') or '-'}:{row.get('src_port') or 0}"
        dst = f"{row.get('dst_ip') or '-'}:{row.get('dst_port') or 0}"
        lines.append(
            f"  {_truncate(row.get('created_at'), 19):<19} "
            f"{str(row.get('proto') or '-'):<8} {src:<24} -> {dst:<24} "
            f"{row.get('length') or 0}B"
        )
    _rows(lines)


def _cmd_intel(context: ConsoleContext, args: list[str]) -> None:
    if context.store is None:
        _say("Capture store unavailable in this process.")
        return
    ip = str(args[0] if args else "").strip()
    if not ip:
        _say("Usage: /intel <ip>")
        return
    try:
        intel = context.store.ip_intel(ip) or {}
    except Exception as exc:
        _say(f"Lookup failed for {ip}: {exc}")
        return
    if not intel:
        _say(f"Nothing recorded for {ip}.")
        return
    lines = [f"[console] Intel for {ip}:"]
    for key, value in intel.items():
        if isinstance(value, (list, tuple)):
            if not value:
                continue
            lines.append(f"  {key}: {len(value)} entr{'y' if len(value) == 1 else 'ies'}")
            for item in list(value)[:5]:
                lines.append(f"    - {_truncate(item, 90)}")
        elif isinstance(value, dict):
            if value:
                lines.append(f"  {key}: {_truncate(value, 90)}")
        elif value not in ("", None):
            lines.append(f"  {key}: {_truncate(value, 90)}")
    _rows(lines)


def _cmd_clear(context: ConsoleContext, args: list[str]) -> None:
    if context.store is None:
        _say("Capture store unavailable in this process.")
        return
    scope = str(args[0] if args else "").strip().lower()
    confirmed = any(str(a).lower() in ("--yes", "-y") for a in args[1:])
    if scope not in {"monitors", "honeypot", "all", "everything"}:
        _say("Usage: /clear monitors|honeypot|all|everything [--yes]")
        return
    if not confirmed:
        # Irreversible, and the console has no undo - make the operator say
        # so explicitly rather than losing a capture to a stray Tab+Enter.
        extra = " including flows, domains, paths and sessions" if scope == "everything" else ""
        _say(f"This permanently deletes stored {scope} data{extra}. Re-run: /clear {scope} --yes")
        return
    try:
        if scope == "everything":
            result = context.store.purge_capture_data() or {}
        else:
            # The store calls the sniffer half "sniffer"; the dashboard (and
            # therefore this command, for consistency) calls it "monitors".
            result = context.store.clear_detections("sniffer" if scope == "monitors" else scope) or {}
    except Exception as exc:
        _say(f"Clear failed: {exc}")
        return
    detail = ", ".join(f"{key}={value}" for key, value in result.items()) or "done"
    _say(f"Cleared {scope}: {detail}")


def _cmd_config(context: ConsoleContext, args: list[str]) -> None:
    from . import settings

    keys = (
        "HOST", "PORT", "DB_PATH", "REQUIRE_AUTH",
        "CAPTURE_AUTO_START", "CAPTURE_PROMISCUOUS", "CAPTURE_EXCLUDE_SELF",
        "RETENTION_DAYS", "RETENTION_ALERT_DAYS", "RETENTION_MAX_PACKETS",
        "API_MAX_LIMIT", "ACCESS_LOG_ENABLED", "ACCESS_LOG_COLOR",
    )
    lines = ["[console] Effective configuration:"]
    for key in keys:
        if hasattr(settings, key):
            lines.append(f"  {key:<24}{getattr(settings, key)}")
    _rows(lines)


def _cmd_chat(context: ConsoleContext, args: list[str]) -> None:
    from .app import _CHAT_MESSAGES

    limit = _as_int(args[0] if args else "", 20)
    rows = list(_CHAT_MESSAGES)[-limit:]
    if not rows:
        _say("No chat messages yet. Type plain text at this prompt to post one.")
        return
    lines = [f"[console] Chat ({len(rows)} of {len(_CHAT_MESSAGES)}):"]
    for row in rows:
        lines.append(
            f"  {_truncate(row.get('created_at'), 19):<19} "
            f"{str(row.get('author') or '-'):<10} {row.get('content')}"
        )
    _rows(lines)


def _cmd_token(context: ConsoleContext, args: list[str]) -> None:
    from .auth import get_security_code

    _say(f"Security code: {get_security_code()}")


def _cmd_url(context: ConsoleContext, args: list[str]) -> None:
    _say(f"Dashboard: http://{context.host}:{context.port}/")


def _cmd_clients(context: ConsoleContext, args: list[str]) -> None:
    clients = context.hub.list_clients()
    if not clients:
        _say("No WebSocket clients connected.")
        return
    lines = [f"[console] WebSocket clients: {len(clients)}"]
    for client in clients:
        lines.append(
            f"  - id={client.get('id')} addr={client.get('addr')} "
            f"connected_at={client.get('connected_at')}"
        )
    _rows(lines)


def _cmd_broadcast(context: ConsoleContext, args: list[str]) -> None:
    message_text = " ".join(args).strip()
    if not message_text:
        _say("Usage: /broadcast <text>")
        return
    message = context.append_chat_message(
        message_text,
        author="operator",
        kind="broadcast",
        meta={"source": "terminal"},
        broadcast=True,
    )
    _say(f"Broadcast sent: {message.get('content')}")


def _cmd_open(context: ConsoleContext, args: list[str]) -> None:
    url = f"http://{context.host}:{context.port}/"
    opened = webbrowser.open(url)
    _say(f"Browser {'opened' if opened else 'not opened'}: {url}")


def _cmd_version(context: ConsoleContext, args: list[str]) -> None:
    from . import __version__

    _say(f"Sniff4Hound {__version__}")


def _cmd_quit(context: ConsoleContext, args: list[str]) -> None:
    if request_process_shutdown():
        _say("Stopping Sniff4Hound...")
    else:
        _say("Shutdown already in progress.")


CONSOLE_HANDLERS = {
    "/help": _cmd_help,
    "/status": _cmd_status,
    "/mode": _cmd_mode,
    "/start": _cmd_start,
    "/stop": _cmd_stop,
    "/restart": _cmd_restart,
    "/interfaces": _cmd_interfaces,
    "/monitors": _cmd_monitors,
    "/monitor": _cmd_monitor,
    "/listeners": _cmd_listeners,
    "/listener": _cmd_listener,
    "/top": _cmd_top,
    "/alerts": _cmd_alerts,
    "/packets": _cmd_packets,
    "/intel": _cmd_intel,
    "/clear": _cmd_clear,
    "/config": _cmd_config,
    "/chat": _cmd_chat,
    "/token": _cmd_token,
    "/url": _cmd_url,
    "/clients": _cmd_clients,
    "/broadcast": _cmd_broadcast,
    "/open": _cmd_open,
    "/version": _cmd_version,
    "/quit": _cmd_quit,
}


def handle_console_line(raw_line: str, context: ConsoleContext) -> None:
    line = str(raw_line or "").strip()
    if not line:
        return

    if not line.startswith("/"):
        message = context.append_chat_message(
            line,
            author="operator",
            kind="note",
            meta={"source": "terminal"},
            broadcast=True,
        )
        if message:
            print(f"[note] {message['content']}")
        return

    try:
        parts = shlex.split(line)
    except ValueError as exc:
        _say(f"Invalid command: {exc}")
        return
    if not parts:
        return

    command = resolve_console_command(parts[0])
    handler = CONSOLE_HANDLERS.get(command)
    if handler is None:
        _say(f"Unknown command: {command}. Type /help.")
        return
    try:
        handler(context, parts[1:])
    except Exception as exc:
        # A failing command must never kill the console thread and leave the
        # operator with a live server and no shell.
        _say(f"{command} failed: {exc}")
