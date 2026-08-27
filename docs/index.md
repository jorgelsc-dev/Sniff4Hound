<div class="hero">
<img class="hero-mark" src="assets/logo.png" alt="Sniff4Hound">
<div class="hero-copy">
<div class="hero-kicker">Neon packet telemetry</div>

<h1>Sniff4Hound</h1>

<p>Captura y analisis de trafico en Python nativo con SQLite, auth por token y WebSocket en vivo.</p>

<div class="hero-actions">
<a class="link" href="getting-started.md"><span>Empezar</span><strong>Instalacion y arranque</strong></a>
<a class="link" href="architecture.md"><span>Arquitectura</span><strong>Flujo interno y runtime</strong></a>
<a class="link" href="reference/index.md"><span>Referencia</span><strong>Runtime, auth y API</strong></a>
</div>
</div>
</div>

<div class="meta-grid">
<div class="meta"><span>Sitio publico</span><strong>porthound.jorgelsc.dev</strong></div>
<div class="meta"><span>Docs runtime</span><strong>/docs</strong></div>
<div class="meta"><span>Base de datos</span><strong>Sniff4Hound.db</strong></div>
<div class="meta"><span>Modo por defecto</span><strong>sniffer</strong></div>
</div>

## Lo esencial

<div class="cards">
<div class="card"><strong>Captura nativa</strong><br>Socket raw, parseo local y control de interfaces.</div>
<div class="card"><strong>Persistencia</strong><br>SQLite con snapshots de sesiones, flows y runtime.</div>
<div class="card"><strong>API y WebSocket</strong><br>Dashboard, metricas y broadcast en tiempo real.</div>
<div class="card"><strong>Documentacion MkDocs</strong><br>Sitio publico en <a href="https://porthound.jorgelsc.dev/"><code>porthound.jorgelsc.dev</code></a>.</div>
</div>

## Mapa de plataforma

<div class="diagram">
<div class="diagram-title">Flujo principal</div>
<div class="diagram-track">
<div class="diagram-node">Operador</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-node">Token</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-node">Dashboard</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-node">Runtime</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-node">SQLite + WS</div>
</div>
<div class="diagram-rows" style="margin-top: 1rem;">
<div class="diagram-row">
<div class="diagram-step">Sniffer</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-step">Flows, packets, tags</div>
<div class="diagram-note">Captura Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP e ICMPv6.</div>
</div>
<div class="diagram-row">
<div class="diagram-step">Honeypot</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-step">Banners y respuestas</div>
<div class="diagram-note">Escucha puertos comunes y registra la actividad activa en la misma base.</div>
</div>
</div>
</div>

## Ruta recomendada

1. Empieza por [Empezar](getting-started.md).
2. Revisa [Arquitectura](architecture.md) para entender el flujo.
3. Usa [Referencia](reference/index.md) si necesitas rutas, variables o esquema.
4. Si trabajas en la UI, valida tambien `frontend/` y el runtime `/docs`.
