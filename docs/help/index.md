# Ayuda

Esta seccion agrupa guias practicas para usar `Sniff4Hound` en escenarios reales, con foco en decisiones de operacion y en la diferencia entre captura pasiva y honeypot activo.

## Que encontraras aqui

<div class="cards">
<div class="card"><strong>Modos</strong><br>Cuando usar `sniffer` o `honeypot` y como cambiar entre ellos.</div>
<div class="card"><strong>Runtime</strong><br>Variables, arranque y control del proceso principal.</div>
<div class="card"><strong>Auth</strong><br>Token de sesion, JWT y cabeceras soportadas.</div>
<div class="card"><strong>API</strong><br>Rutas utiles para dashboard, mapas, catalogos y WebSocket.</div>
</div>

## Ruta recomendada

1. Lee [Modos](modes.md) si estas decidiendo como ejecutar el runtime.
2. Revisa [Runtime](../reference/runtime.md) para ver variables y acciones soportadas.
3. Consulta [Auth](../reference/auth.md) antes de automatizar peticiones.
4. Usa [API](../reference/api.md) si necesitas rutas concretas.

## Criterio rapido

- usa `sniffer` cuando necesitas captura pasiva y analisis de trafico;
- usa `honeypot` cuando quieres responder activamente en puertos conocidos;
- manten `SNIFF4HOUND_REQUIRE_AUTH=1` salvo entornos de laboratorio;
- consulta `/api/endpoints/` cuando no recuerdes el nombre exacto de una ruta.
