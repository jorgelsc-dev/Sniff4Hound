# Consola interactiva

Al arrancar, Sniff4Hound abre un prompt `sniff4hound>` en la misma terminal.
**Tab** completa tanto los comandos como sus argumentos: `/mode <TAB>` ofrece
`sniffer` y `honeypot`, `/interfaces <TAB>` ofrece las interfaces que esta
maquina tiene de verdad, y `/monitor off <TAB>` ofrece ids de monitores que
existen ahora mismo. `/help <comando>` muestra el detalle de uno solo.

Cualquier linea que no empiece por `/` se publica en el chat de operador y
llega al dashboard; lo que se escriba desde el dashboard se muestra aqui con
el prefijo `[chat]`. `/chat` muestra el historial.

## Comandos

| Comando | Alias | Descripcion |
| --- | --- | --- |
| `/help [command]` | - | Show this help, or detail for one command |
| `/status` | `/stats` | Show runtime and WebSocket status |
| `/mode sniffer\|honeypot` | - | Switch mode: sniffer \| honeypot |
| `/start` | `/run` | Start the active engine |
| `/stop` | - | Stop the active engine |
| `/restart` | - | Stop and start the active engine |
| `/interfaces [name ...]` | `/iface` | List capture interfaces, or select which ones to capture on |
| `/monitors [search] [--limit N]` | - | List detection monitors, optionally filtered |
| `/monitor show\|on\|off <monitor-id>` | - | Show or toggle one monitor |
| `/listeners` | - | List honeypot listeners and their state |
| `/listener on\|off <proto/port>` | - | Enable or disable one honeypot listener |
| `/top ips\|ports\|protocols\|domains [N]` | - | Rank the busiest talkers in the capture |
| `/alerts [N]` | - | Show the most recent monitor hits |
| `/packets [N]` | - | Show the most recent captured packets |
| `/intel <ip>` | `/lookup` | Show what is known about one IP address |
| `/clear monitors\|honeypot\|all\|everything [--yes]` | - | Delete stored capture data for a scope |
| `/config` | - | Show the effective runtime configuration |
| `/chat [N]` | - | Show the operator chat transcript |
| `/token` | - | Show the current security code |
| `/url` | - | Show the current dashboard URL |
| `/clients` | - | List connected WebSocket clients |
| `/broadcast <text>` | `/say` | Broadcast an operator note |
| `/open` | - | Open the dashboard in the browser |
| `/version` | - | Show the Sniff4Hound version |
| `/quit` | `/exit` | Stop Sniff4Hound |

## Notas

**`/restart`** — Equivalent to /stop followed by /start, without changing the mode.

**`/interfaces`** — With no arguments, lists every interface the capture process can see and marks the selected ones. With one or more names, replaces the selection. Use /interfaces all to capture on every visible interface.

**`/monitors`** — Shows id, severity and enabled state. Matching is a substring of id or name.

**`/listeners`** — Listeners are only actually bound while the honeypot engine is the active mode.

**`/clear`** — monitors/honeypot/all clear detection history (packets, tags, payloads). everything also wipes flows, domains, paths and sessions, then vacuums the database file. Monitor and listener definitions are never touched. Destructive and irreversible: needs --yes to actually run.

**`/config`** — Retention, capture and access-log settings as they are actually in effect.

**`/chat`** — Plain text typed at this prompt is posted to the chat; messages sent from the dashboard are echoed here as they arrive. This shows the backlog.

El completado de `/monitor` se limita a los primeros 400 monitores: el
catalogo empaquetado tiene ~30.000 entradas y ofrecerlas todas colgaria la
terminal en cada Tab. Para encontrar un id concreto, usa `/monitors <texto>`.
