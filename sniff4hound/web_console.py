"""Safe command execution for the dashboard operations console.

This is deliberately not a system shell.  Only registered Sniff4Hound
operations are accepted, so a browser session can control the sensor without
turning the HTTP API into arbitrary process execution.
"""

from __future__ import annotations

import shlex


COMMAND_HELP = (
    "/status                         estado de los motores y clientes",
    "/start [sniffer|honeypot|all]   iniciar uno o ambos motores",
    "/stop [sniffer|honeypot|all]    detener uno o ambos motores",
    "/restart [sniffer|honeypot]     reiniciar un motor",
    "/mode sniffer|honeypot          cambiar el motor enfocado",
    "/interfaces [all|nombre ...]    consultar o elegir interfaces",
    "/alerts [N]                     alertas recientes",
    "/packets [N]                    paquetes recientes",
    "/top ips|ports|protocols [N]    principales entidades",
    "/intel <IP>                     resumen de una dirección",
    "/monitors [texto]               buscar monitores",
    "/listeners                      listeners del honeypot",
    "/clients                        clientes WebSocket",
    "/help                           mostrar esta ayuda",
)


def _positive_int(value, default=10, maximum=50):
    try:
        return max(1, min(maximum, int(value)))
    except (TypeError, ValueError):
        return default


def _engine(value, *, allow_all=True):
    name = str(value or "").strip().lower()
    allowed = {"sniffer", "honeypot"} | ({"all", "both"} if allow_all else set())
    if name not in allowed:
        expected = "sniffer, honeypot o all" if allow_all else "sniffer o honeypot"
        raise ValueError(f"Motor inválido; usa {expected}.")
    return "all" if name == "both" else name


def _runtime_status(snapshot, clients):
    sniffer = snapshot.get("sniffer") or {}
    honeypot = snapshot.get("honeypot") or {}
    return "\n".join((
        f"Modo enfocado: {snapshot.get('mode') or 'sniffer'}",
        f"Sniffer: {'activo' if sniffer.get('running') else 'detenido'} · {int(sniffer.get('packets_seen') or 0)} paquetes",
        f"Honeypot: {'activo' if honeypot.get('running') else 'detenido'} · {int(honeypot.get('packets_seen') or 0)} eventos",
        f"Clientes WebSocket: {len(clients)}",
    ))


def execute_dashboard_command(raw_command, *, runtime, store, hub) -> dict:
    command_text = str(raw_command or "").strip()
    if not command_text.startswith("/"):
        raise ValueError("Los comandos deben comenzar con /. Usa /help para ver opciones.")
    if len(command_text) > 500:
        raise ValueError("El comando es demasiado largo.")
    try:
        parts = shlex.split(command_text)
    except ValueError as exc:
        raise ValueError(f"Comando inválido: {exc}") from exc
    command = str(parts[0] if parts else "").lower()
    args = parts[1:]

    if command in {"/help", "/?"}:
        output = "Comandos disponibles:\n" + "\n".join(COMMAND_HELP)
    elif command in {"/status", "/stats"}:
        output = _runtime_status(runtime.snapshot(), hub.list_clients())
    elif command in {"/start", "/stop"}:
        snapshot = runtime.start(_engine(args[0]) if args else None) if command == "/start" else runtime.stop(_engine(args[0]) if args else None)
        output = _runtime_status(snapshot, hub.list_clients())
    elif command == "/restart":
        target = _engine(args[0], allow_all=False) if args else str((runtime.snapshot() or {}).get("mode") or "sniffer")
        runtime.stop(target)
        output = _runtime_status(runtime.start(target), hub.list_clients())
    elif command == "/mode":
        if not args:
            raise ValueError("Uso: /mode sniffer|honeypot")
        output = _runtime_status(runtime.set_mode(_engine(args[0], allow_all=False)), hub.list_clients())
    elif command in {"/interfaces", "/iface"}:
        if args:
            names = [] if len(args) == 1 and args[0].lower() == "all" else args
            snapshot = runtime.set_sniffer_interfaces(names)
            output = f"Interfaces seleccionadas: {', '.join(names) if names else 'todas las visibles'}\n" + _runtime_status(snapshot, hub.list_clients())
        else:
            active = (runtime.snapshot() or {}).get("sniffer") or {}
            available = list(active.get("available_interfaces") or [])
            selected = set(active.get("selected_interfaces") or [])
            output = "Interfaces:\n" + "\n".join(f"{'●' if name in selected else '○'} {name}" for name in available)
    elif command == "/alerts":
        rows = store.list_recent_alerts(limit=_positive_int(args[0] if args else None, 10)) or []
        output = "No hay alertas recientes." if not rows else "Alertas recientes:\n" + "\n".join(
            f"{row.get('created_at') or '-'} · {row.get('severity') or '-'} · {row.get('src_ip') or '?'} → {row.get('dst_ip') or '?'} · {row.get('label') or row.get('detail') or '-'}"
            for row in rows
        )
    elif command == "/packets":
        rows = store.list_packets(limit=_positive_int(args[0] if args else None, 10)) or []
        output = "No hay paquetes almacenados." if not rows else "Paquetes recientes:\n" + "\n".join(
            f"#{row.get('id')} · {row.get('proto') or 'unknown'} · {row.get('src_ip') or '?'}:{row.get('src_port') or 0} → {row.get('dst_ip') or '?'}:{row.get('dst_port') or 0}"
            for row in rows
        )
    elif command == "/top":
        category = str(args[0] if args else "").lower()
        limit = _positive_int(args[1] if len(args) > 1 else None, 10)
        getters = {"ips": store.top_ips, "ports": store.top_ports, "protocols": store.top_protocols}
        if category not in getters:
            raise ValueError("Uso: /top ips|ports|protocols [N]")
        rows = getters[category](limit=limit) or []
        output = f"Top {category}:\n" + "\n".join(
            f"{row.get('ip') or row.get('port') or row.get('proto') or row.get('label') or '-'} · {row.get('count') or row.get('hits') or row.get('hit_count') or row.get('value') or 0}"
            for row in rows
        )
    elif command in {"/intel", "/lookup"}:
        if not args:
            raise ValueError("Uso: /intel <IP>")
        intel = store.ip_intel(args[0]) or {}
        summary = intel.get("summary") or {}
        output = "\n".join((
            f"Inteligencia para {args[0]}",
            f"Paquetes: {summary.get('packets') or 0} · Flujos: {summary.get('flows') or 0}",
            f"Dominios: {len((intel.get('domains') or {}).get('domains') or [])}",
            f"Servicios: {len(((intel.get('host') or {}).get('transport') or {}).get('services') or [])}",
        ))
    elif command == "/monitors":
        needle = " ".join(args).lower()
        rows = store.list_monitors() or []
        if needle:
            rows = [row for row in rows if needle in str(row.get("id") or "").lower() or needle in str(row.get("name") or "").lower()]
        rows = rows[:25]
        output = "No hay coincidencias." if not rows else "Monitores:\n" + "\n".join(
            f"{'●' if row.get('enabled') else '○'} {row.get('id')} · {row.get('name') or '-'}" for row in rows
        )
    elif command == "/listeners":
        rows = runtime.list_honeypot_listeners() or []
        output = "No hay listeners configurados." if not rows else "Listeners:\n" + "\n".join(
            f"{'●' if row.get('enabled') else '○'} {row.get('id')} · {'activo' if row.get('running') else 'detenido'} · {row.get('label') or '-'}"
            for row in rows
        )
    elif command == "/clients":
        rows = hub.list_clients()
        output = "No hay clientes WebSocket." if not rows else "Clientes WebSocket:\n" + "\n".join(
            f"#{row.get('id')} · {row.get('addr') or '-'} · {row.get('connected_at') or '-'}" for row in rows
        )
    elif command in {"/clear", "/quit", "/exit", "/open", "/token"}:
        raise ValueError("Ese comando está bloqueado en el navegador por seguridad; ejecútalo en la terminal local.")
    else:
        raise ValueError(f"Comando desconocido: {command}. Usa /help.")

    return {"ok": True, "command": command_text, "output": str(output)[:12000]}
