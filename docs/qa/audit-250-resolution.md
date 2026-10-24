# Auditoría #250 — resolución y verificación

PR: https://github.com/jorgelsc-dev/Sniff4Hound/pull/266  
Índice: https://github.com/jorgelsc-dev/Sniff4Hound/issues/250  
Fecha: 2026-10-24

## Alcance

Resolución de los quince cards #251–#265 e integración de siete commits
locales anteriores, mediante una rama auxiliar y una PR con destino main.
No se modifica ni reinicia la sesión del operador para las pruebas.

## Matriz de regresión

| Cards | Contrato de aceptación | Verificación |
| --- | --- | --- |
| #251 | Una lectura vencida no queda fuera de supervisión; reemplazos de workers acotados; cierre seguro | jobs, storage y pruebas de timeout |
| #252 | Solo booleano JSON true confirma borrado; tipos inválidos no mutan datos | API de historial con stores temporales |
| #253 | Cambio de interfaces aplica al sniffer activo con cualquier foco; fallo visible | runtime con motores simulados |
| #254 | Reconexión implícita revalida cooldown bajo lock; startup explícito conserva presupuesto | IPC concurrente y generación |
| #255 | Respuestas, errores, finally y feeds obsoletos no repintan otro contexto | Protocols con promesas controlables |
| #256 | Pausa congela tablas/fecha; reanudar refresca contexto vigente | Dominios/Rutas, feed y fallback |
| #257 | 503 no bloquea el panel; reintento y reconexión recuperan estado confirmado | panel IA con red simulada |
| #258 | Trap de foco excluye paneles ocultos, inert y controles deshabilitados | DOM simulado y navegador |
| #259 | Preferencia guardada no equivale a modelo/inferencia; sin aristas ficticias | panel, grafo y documentación |
| #260 | Solo rutas exactas del DTO agregado alcanzan el modelo | canarios sintéticos de nesting/alias |
| #261 | OFF no inspecciona entradas; conversiones inválidas no propagan | límites numéricos y objetos adversos |
| #262 | CDP OFF/ON/valor inválido evalúan el arranque sin variables indefinidas | smoke VM de Electron y no-undef |
| #263 | Fallo de READY/mDNS/QUIC limpia el intento propio y permite reintentar/remoto | main/preload/splash simulados |
| #264 | Tooltips nombrados, etiquetas consistentes y referencias ARIA válidas | Lighthouse y teclado |
| #265 | Landing describe privilegios reales del modo local y separado | revisión documental + lint/build |

## Estado de validación

Ejecutada el 2026-10-24 sobre la rama `fix/audit-250-all-findings`, con las
dependencias de #247, #248 y #249 (undici, fast-uri, Electron 42.11.16)
integradas en la misma PR.

| Comando | Resultado |
| --- | --- |
| `SNIFF4HOUND_DATA_DIR=<tmp> .venv/bin/python -m unittest discover -t . -s tests -q` | 1352 tests OK (2 skipped) |
| `.venv/bin/python -m unittest tests.test_wsbuilder_ia tests.test_ai_activation tests.test_documented_routes -q` | 21 tests OK |
| `.venv/bin/python scripts/check_test_shards.py` | 59 módulos cubiertos |
| `cd desktop/frontend && npm test` | lint + 194 tests OK |
| `cd desktop/frontend && npm run build` | OK |
| `cd desktop && frontend/node_modules/.bin/eslint --config eslint.config.cjs main.js preload.js lib/ splash.js --max-warnings=0` | OK |
| `cd desktop/frontend && node --test tests/desktop-*.test.js` | 62 tests OK |
| `cd landing && npm test && npm run build` | OK |
| `cd desktop && npm ci` (lockfile combinado) | OK; electron 42.11.16, undici 6.29.1, fast-uri 3.1.9 |
| `git diff --check` | OK |

### E2E en Electron 42 (sin root)

Electron 42.11.16 bajo `xvfb-run`, `SNIFF4HOUND_DESKTOP_ELEVATE=0` y CDP
en loopback, conectado por el formulario remoto a un `sniff4hound-web` real
(TLS, datos temporales) con un servicio de captura sustituto sin privilegios:

- Splash: puente `sniff4houndDesktop` presente, sin errores de consola.
- `GET /api/settings/ai` → `{"enabled": false, "model_status": "not_configured"}`.
- #259: con la preferencia ON el nodo muestra "Permitida · sin modelo";
  las dos aristas IA son `planificado`, discontinuas y nunca activas.
- #257: con el backend caído, el panel queda "Estado desconocido" con
  Reintentar y alerta `role=alert`; al volver el backend la reconexión
  recarga el panel y rehabilita el interruptor sin desmontar la vista.

### Riesgo restante

- No se ejecutó un arranque con runtime root (Polkit) ni captura real; el
  E2E de fallo mDNS/QUIC de #263 sigue cubierto por la simulación VM.
- Lighthouse de #264 no se repitió dentro de Electron; la cobertura es por
  AST de plantilla y pruebas de foco.
- Electron 42 es un salto de versión mayor: se verificó arranque, splash,
  conexión remota y Settings, no el empaquetado del instalador.

## Límite explícito de IA

Esta entrega no incorpora un modelo entrenado ni un proveedor externo.
El permiso ON/OFF es persistente, pero la UI debe indicar que no existe
modelo operativo. El adaptador se mantiene aislado de captura y solo acepta
agregados autorizados; un fallback determinista no es una predicción IA.

## Proceso de cierre

Los cards se reclaman y enlazan a la PR durante implementación. Tras pasar
las regresiones y la revisión, se registran comandos/resultados en los
mismos cards. Solo se cierran cuando la PR verificada entra en main.

