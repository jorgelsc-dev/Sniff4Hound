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
