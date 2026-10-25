# Resolución de la auditoría #284

Seguimiento de los [17 cards públicos de la auditoría](https://github.com/jorgelsc-dev/Sniff4Hound/issues/284).
La revisión parte de `main` en `db9a7e8`; no se han usado bases de datos ni
sesiones de captura del operador.

## Equipo y revisión

- Agente Backend: recuperación SSE, jobs interrumpidos, cambio de interfaces,
  búsqueda literal de dominios y limpieza de IPC (#279–#283).
- Agente Packaging/CI: dependencia instalable, documentación estricta, lockfile
  y verificación de releases (#267, #268, #270, #271).
- Agente Docs/QA: certificados, referencia de configuración y revisión
  independiente de escritorio (#269, #272–#278).
- Coordinador: integración, revisión cruzada, regresión de reconexión del
  frontend, evidencias en los cards y seguimiento de CI/merge.

Se reutilizaron cambios que estaban preparados en ramas locales, preservando
su autoría y DCO, y se sometieron de nuevo a revisión y pruebas. No se considera
que un card esté verificado solo porque su código esté fusionado.

## Evidencia de reconexión SSE

La prueba `an SSE slow-consumer close obtains a fresh ticket and resumes feed data`
ejecuta `appStore.openDataFeed` con el transporte real `RealtimeChannel` y un
EventSource simulado. Recibe `event: close` con código `1013`, comprueba que el
canal anterior se cierra, obtiene un ticket diferente tras el backoff, recibe
datos en el canal nuevo y rechaza mensajes tardíos del anterior.

Comando: `cd desktop/frontend && node --test tests/feed-lifecycle.test.js`.
Resultado durante la integración: **18/18 pruebas correctas**.
Esta prueba es determinista; no equivale a una sesión remota de 30 minutos.

## Instalación, documentación y releases

La [PR #286](https://github.com/jorgelsc-dev/Sniff4Hound/pull/286) se fusionó
en `main` como `8db7c31` tras revisión cruzada y todos sus checks verdes.
El [run manual de empaquetado](https://github.com/jorgelsc-dev/Sniff4Hound/actions/runs/40145759199)
verificó el `.deb`, imports del runtime extraído, **223 pruebas frontend** y
**1.343 pruebas backend** (314 + 339 + 228 + 462), con Python 3.12 y wsbuilder
1.3.0. La publicación fue omitida correctamente por ejecutarse en rama auxiliar.
La publicación real en `main` se comprueba por separado.

La [PR #287](https://github.com/jorgelsc-dev/Sniff4Hound/pull/287) contiene los
arreglos backend. Validación independiente del coordinador en Python 3.12 y
wsbuilder 1.3.0:

- Jobs, realtime SSE y regresiones FA/QA: **58 pruebas correctas**, 147,625 s.
- Captura e IPC sobre el parche final: **54 pruebas correctas**, 69,299 s.
- Registro de shards: **59 módulos cubiertos**.

El control de dependencias conserva un riesgo anterior: la alerta pública
[GHSA-ch52-4w7c-c8xp](https://github.com/advisories/GHSA-ch52-4w7c-c8xp), sin
versión corregida publicada según GitHub a 2026-10-25 UTC. Su alcance concreto
y seguimiento se registran en el [card #288](https://github.com/jorgelsc-dev/Sniff4Hound/issues/288);
normalizar el registry no corrige esa alerta.

## Límites

Los tres avisos privados enlazados desde el índice se gestionan por separado.
Este informe no publica sus detalles ni afirma que estén resueltos.
Las comprobaciones con mocks o inspección de código se distinguen de las
comprobaciones ejecutadas en Electron y del resultado real de GitHub Actions.
