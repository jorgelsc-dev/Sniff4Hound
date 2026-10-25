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

## Límites

Los tres avisos privados enlazados desde el índice se gestionan por separado.
Este informe no publica sus detalles ni afirma que estén resueltos.
Las comprobaciones con mocks o inspección de código se distinguen de las
comprobaciones ejecutadas en Electron y del resultado real de GitHub Actions.
