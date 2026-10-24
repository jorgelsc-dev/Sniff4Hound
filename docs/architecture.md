# Arquitectura

## Mapa de modulos

<div class="cards">
<div class="card"><strong>manage.py</strong><br>Arranque, puerto, token y relanzado con privilegios.</div>
<div class="card"><strong>app.py</strong><br>SPA, API, WebSocket y controlador de runtime.</div>
<div class="card"><strong>sniffer.py</strong><br>Captura raw y parseo de trafico.</div>
<div class="card"><strong>honeypot.py</strong><br>Listeners emulados y respuestas activas.</div>
<div class="card"><strong>store.py</strong><br>SQLite, snapshots y limites de retencion.</div>
<div class="card"><strong>auth.py</strong><br>Token de sesion y JWT HS256.</div>
</div>

## Procesos y privilegios

El modo local predeterminado (`sniff4hound`, también usado por el runtime de
escritorio) requiere root desde el arranque. Ejecuta servidor web, base de datos,
sniffer y honeypot en un solo proceso Python con captura embebida; no hay una
separación de privilegios entre la API y los motores en este modo.

Electron y su renderer conservan el usuario y la sesión gráfica del operador.
El escritorio solicita autorización mediante el agente nativo de Polkit
(`pkexec`) para iniciar el runtime Python como root. Los motores empiezan en
pausa. Cerrar su pipe de vida detiene únicamente el runtime iniciado por esa
instancia. Conectar un sensor remoto no inicia un runtime local ni solicita
privilegios locales.

`SNIFF4HOUND_CAPTURE_EMBEDDED=0` separa el servidor y el hijo de captura mediante
IPC, pero el comando combinado sigue ejecutando ambos como root. Para un
despliegue con web sin privilegios se usa `sniff4hound-web`, que nunca se eleva y
requiere un `sniff4hound-capture` iniciado aparte y configurado por IPC.

Consulta el [arranque y despliegue](getting-started.md), la
[referencia del runtime](reference/runtime.md) y el
[modelo de escritorio](https://github.com/jorgelsc-dev/Sniff4Hound/blob/main/desktop/README.md).

## Flujo interno

<div class="diagram">
<div class="diagram-title">Ruta de ejecucion</div>
<div class="diagram-stack">
<div class="diagram-row">
<div class="diagram-step">manage.py</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-step">app.py</div>
<div class="diagram-note">Selecciona host, puerto y modo inicial.</div>
</div>
<div class="diagram-row">
<div class="diagram-step">app.py</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-step">RuntimeController</div>
<div class="diagram-note">Activa `sniffer` o `honeypot` y publica snapshots por WebSocket.</div>
</div>
<div class="diagram-row">
<div class="diagram-step">Engine</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-step">SniffStore</div>
<div class="diagram-note">Guarda sesiones, flows, packets, payloads, tags y config persistida.</div>
</div>
</div>
</div>

## Puntos clave

- `RuntimeController` cambia de modo y conserva el estado en `runtime_config`.
- `WebSocketHub` emite `packet`, `stats_update`, `runtime_mode` y mensajes de chat.
- `SniffStore` usa SQLite con WAL y recorta tablas activas para limitar crecimiento.
- La UI publica la API local y la documentacion de runtime desde el mismo proceso.

## Ruta de lectura

1. [Empezar](getting-started.md)
2. [Ayuda](help/index.md)
3. [Referencia](reference/index.md)
