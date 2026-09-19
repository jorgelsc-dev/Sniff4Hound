# Sniff4Hound - Informe FAQA / Revision QA

**Fecha:** 2026-09-19

**Version observada:** `0.54.0` (`pyproject.toml`, `sniff4hound/__init__.py`, `desktop/package.json` y Electron `User-Agent`)

**Instancia viva revisada:** Electron por CDP en `127.0.0.1:9223`, target `Sniff4Hound`, backend local en `http://127.0.0.1:45671/?code=...&desktop=1`

**Alcance:** revision estatica del repo, pruebas automatizadas backend/frontend, build frontend, recorrido interactivo de la ventana Electron ya corriendo por CDP (menus, pestañas, busqueda, detalles y mapas), capturas de pantalla y verificacion HTTP de rutas SPA/deep links.

**Nota de seguridad:** no se documenta el codigo de sesion observado.

**Ampliacion Blue Team:** 2026-09-19. Este documento es una auditoria y una especificacion de mejoras; las correcciones propuestas no estan implementadas. Solo se modifica este informe. Los resultados del pase inicial se conservan, separados de las pruebas nuevas.

**Guia de lectura:** hallazgos verificables en seccion 1; evidencia y limites en 2; plan tecnico detallado en 6; experiencia Blue Team en 7; arquitectura/rendimiento en 8; entregas y criterios de salida en 9; reproducciones en 10; referencias en 11. Las prioridades P0/P1/P2 de la ampliacion son orden de trabajo, no equivalen a una clasificacion CVSS.

> Convencion de severidad: **Critical** (explotable / caida fuerte), **High** (riesgo serio o bloqueo de release), **Medium** (defecto funcional o seguridad defensiva), **Low** (mantenibilidad/limpieza), **Info** (contexto o recomendacion).

---

## 0. Resumen ejecutivo

La app Electron esta accesible y operativa. El Dashboard monta correctamente y muestra telemetria real: `1415` paquetes almacenados, `37` hosts unicos, `10` protocolos, `1394` respuestas; Sniffer y Honeypot aparecen detenidos en la instancia viva.

La revision actual no puede considerarse "aprobada limpia": hay fallos abiertos en deep links, pruebas y orden del repo. El problema mas visible para usuario es que varias rutas nuevas del router de Vue devuelven `404` si se abren directo o se refrescan desde Electron/backend: `/ai/overview`, `/ai/neural-network`, `/dashboard/overview`, `/dashboard/node-map` y `/dashboard/live-map`.

**Conclusion de la revision profunda:** la prioridad Blue Team es corregir la integridad de la investigacion y la visibilidad antes de ampliar funciones visuales. Se reproducen mezcla de IPs distintas, evidencia retenida que desaparece del investigador, alertas fuera del periodo seleccionado y exportaciones de alertas que ignoran el host buscado. Dos textos de configuracion contradicen decisiones de descarte del motor. Settings carga un catalogo de monitores de 42,9 MB por WebSocket. Estos problemas pesan mas que el desorden de carpetas o una renovacion estetica.

La base permite evolucionar: hay evidencia por monitor, limites y metadatos en varias APIs, SQL parametrizado, proteccion CSV, control de origen/autenticacion, retencion diferenciada y fallback de WebSocket a HTTP. La propuesta es conservarlos y hacer consistente su contrato en toda la app.

Tambien hay deuda clara de QA: `npm test` falla en el test unitario bajo Node 24 por una importacion ESM sin extension; la suite backend con `.venv` corre casi completa, pero termina con 2 fallos (`935 passed, 2 skipped, 2 failed`). Uno de esos fallos confirma que el test que debia proteger `SPA_ROUTES` esta obsoleto y no cubre todas las rutas actuales.

El "reguero" existe pero es recuperable: hay artefactos generados (`dist/`, `QA/`, `build/`, `__pycache__`, `.pytest_cache`, `sniff4hound.egg-info`) presentes en el arbol local; varios estan ignorados por git, pero ensucian el workspace y confunden la revision. Ademas `FAQA.md` anterior hablaba de `v0.59.0`, mientras el codigo y Electron reportan `0.54.0`.

---

## 1. Hallazgos abiertos

### 1.1 Medium - Rutas SPA nuevas devuelven 404 en carga directa

**Estado:** abierto.

**Evidencia dinamica contra la app viva (`127.0.0.1:45671`):**

```text
200 /
200 /ai
404 /ai/overview
404 /ai/neural-network
404 /dashboard/overview
404 /dashboard/node-map
404 /dashboard/live-map
200 /chat
200 /investigate
200 /sniffer
200 /soc
200 /protocols
200 /honeypot
200 /monitors
200 /domains
200 /paths
200 /ips
200 /settings
```

**Causa probable:** `frontend/src/router/index.js` ya tiene rutas anidadas/nuevas, pero `sniff4hound/app.py::SPA_ROUTES` no incluye `/ai/overview`, `/ai/neural-network`, `/dashboard/overview`, `/dashboard/node-map` ni `/dashboard/live-map`.

**Impacto:** navegar desde la SPA puede funcionar, pero refrescar, abrir un marcador o pegar un link directo devuelve `404 Not Found`.

**Recomendacion:** agregar esas rutas a `SPA_ROUTES` y mejorar la prueba `test_every_vue_router_path_is_in_spa_routes` para parsear el router de forma robusta o mantener una lista exportable compartida.

### 1.2 Medium - Prueba de regresion de rutas SPA esta obsoleta

**Estado:** abierto.

**Evidencia:** `.venv/bin/python -m pytest tests/ -q` fallo en `SmokeTests.test_every_vue_router_path_is_in_spa_routes`. El parser regex del test no detecta bien rutas con objetos multilinea/meta y ni siquiera encuentra `/chat`, aunque la ruta existe en `frontend/src/router/index.js`.

**Impacto:** el test que deberia prevenir 404 de deep links no esta protegiendo el caso actual. El hallazgo 1.1 paso a produccion/local precisamente por esa grieta.

**Recomendacion:** reemplazar el parser regex por una fuente de verdad mas simple: por ejemplo, mover rutas SPA estaticas a un JSON/JS exportable, generar `SPA_ROUTES` desde ahi, o parsear el router con una herramienta AST en vez de regex.

### 1.3 Medium - `npm test` falla bajo Node 24

**Estado:** abierto.

**Evidencia:** `cd frontend && npm test` ejecuta lint correctamente, pero `npm run test:unit` falla con:

```text
Error [ERR_MODULE_NOT_FOUND]: Cannot find module
frontend/src/utils/runtimeEnv imported from frontend/src/router/index.js
```

**Causa probable:** `router/index.js` importa `../utils/runtimeEnv` sin extension. Vite lo resuelve; Node ESM del runner unitario no.

**Impacto:** CI/local QA queda rojo aunque `npm run build` si compila.

**Recomendacion:** cambiar el import a `../utils/runtimeEnv.js` o ajustar el runner/loader para resolver igual que Vite. Preferible usar extension explicita en imports locales si los tests corren directo en Node.

### 1.4 Low - Suite backend depende de usar el entorno correcto

**Estado:** abierto/documental.

**Evidencia:** `python -m pytest tests/ -q` con Python global fallo durante collection por `ModuleNotFoundError: No module named 'wsbuilder'`. Con `.venv/bin/python`, la suite si arranca y llega al final.

**Resultado con `.venv`:**

```text
2 failed, 935 passed, 2 skipped, 316 subtests passed
```

**Recomendacion:** documentar en `README.md`/`FAQA.md` que QA local debe correr con `.venv/bin/python -m pytest ...` o despues de `python -m pip install -e .`. Si CI usa otro comando, alinearlo.

### 1.5 Low - Fallo intermitente de limpieza de temporales en tests

**Estado:** abierto/observado.

**Evidencia:** `TestTrainingAndAiAlertModes.test_training_plus_ai_mode_leaves_the_catalog_in_charge` fallo en `tearDown`:

```text
OSError: [Errno 39] Directory not empty: '/tmp/...'
```

Este fallo ya aparecia mencionado como transitorio en el FAQA viejo, pero sigue ocurriendo.

**Recomendacion:** revisar hilos/timers/handles que quedan vivos en ese test o hacer que el teardown espere/cierre explicitamente writers antes de `TemporaryDirectory.cleanup()`.

### 1.6 Low - Versiones/documentacion desalineadas

**Estado:** abierto.

**Evidencia:** el FAQA anterior documentaba `v0.59.0`; el codigo actual declara `0.54.0` en `pyproject.toml`, `sniff4hound/__init__.py` y `desktop/package.json`. El frontend declara `1.0.0`, distinto del backend/desktop.

**Recomendacion:** definir una sola fuente de version para backend, desktop y reportes de QA, o documentar explicitamente por que el frontend usa version independiente.

### 1.7 Low - Documentacion historica con afirmaciones stale

**Estado:** abierto.

**Evidencia:** `ARCHITECTURE.md` todavia dice que el token se persiste en `localStorage`, mientras `README.md` y el codigo actual indican token en memoria y limpieza de storage legado. `CHANGELOG.md` tambien conserva entradas historicas sobre localStorage.

**Recomendacion:** actualizar `ARCHITECTURE.md` para no contradecir el modelo de auth actual. En `CHANGELOG.md` puede quedarse como historia, pero conviene evitar que parezca comportamiento actual.

### 1.8 Info/Seguridad - CDP Electron siempre abierto

**Estado:** aceptado explicitamente por el operador en `AGENTS.md`; no es un defecto pendiente.

**Evidencia:** `desktop/main.js` abre `remote-debugging-port` por defecto en `9223` y `remote-allow-origins=*`, salvo que `SNIFF4HOUND_DESKTOP_DEBUG_PORT=0/false/off/no`.

**Impacto:** cualquier proceso local puede controlar la ventana Electron por CDP. Es util para QA/automatizacion, pero es una superficie fuerte para una herramienta que controla un backend privilegiado.

**Recomendacion:** respetar el default solicitado y mantener documentada la opcion de desactivarlo por lanzamiento. Esta auditoria no propone revertir esa decision.

### 1.9 Info - Desorden local de artefactos generados

**Estado:** abierto/local.

**Evidencia:** hay artefactos presentes en el arbol local:

```text
dist/sniff4hound_0.64.0_amd64.deb
dist/sniff4hound_latest.deb
dist/desktop/Sniff4Hound-0.54.0-amd64.deb
dist/desktop/Sniff4Hound-0.54.0-x86_64.AppImage
dist/desktop/builder-debug.yml
dist/desktop/builder-effective-config.yaml
QA/
build/
__pycache__/
sniff4hound.egg-info/
.pytest_cache/
```

Muchos estan ignorados por `.gitignore`, pero el workspace se vuelve dificil de leer y puede confundir revisiones manuales.

**Recomendacion:** documentar un flujo de limpieza para artefactos de build/QA/caches. Ojo: `scripts/clean_artifacts.sh` hoy solo limpia artefactos runtime sensibles (`*.db`, logs, certificados honeypot/service) y deliberadamente no toca `dist/`, `QA/`, `build/`, `__pycache__`, `.pytest_cache` ni `sniff4hound.egg-info`.

### 1.10 Low - Pase visual actual no cubre todas las rutas reales ni el puerto Electron

**Estado:** abierto.

**Evidencia:** `scripts/qa_visual_pass.js` declara manualmente solo rutas top-level (`/`, `/sniffer`, `/honeypot`, `/soc`, `/ai`, etc.) y omite `/ai/overview`, `/ai/neural-network`, `/dashboard/overview`, `/dashboard/node-map` y `/dashboard/live-map`. Tambien busca CDP en `127.0.0.1:9222`, mientras la app Electron documentada y viva esta en `9223`.

**Impacto:** el pase visual puede salir verde aunque deep links reales fallen en carga directa, que es exactamente lo que ocurre con las rutas anidadas.

**Recomendacion:** generar la lista desde `frontend/src/router/index.js` o una fuente compartida, incluir rutas anidadas y hacer configurable el puerto CDP (`QA_CDP_PORT`, default `9223` para Electron o `9222` para Chromium headless segun modo).

### 1.11 Low - `openExternal` de Electron no valida esquema

**Estado:** abierto/hardening.

**Evidencia:** `desktop/preload.js` expone `openExternal(url)` al renderer y `desktop/main.js` llama `shell.openExternal(url)` sin allowlist de protocolo. Tambien `setWindowOpenHandler` envia cualquier URL externa a `shell.openExternal`.

**Impacto:** con contenido renderer comprometido o un link malicioso servido por el backend, la app podria intentar abrir esquemas no deseados. El riesgo practico baja porque la ventana renderiza la SPA propia y `nodeIntegration` esta desactivado, pero el bridge deberia ser defensivo.

**Recomendacion:** permitir solo `http:` y `https:`, y opcionalmente `mailto:` si se necesita. Rechazar `file:`, `javascript:`, `data:` y esquemas arbitrarios antes de llamar `shell.openExternal`.

---

### 1.12 Medium - Resumen limita incorrectamente el contador de protocolos a ocho

**Estado:** reproducido en la interfaz y confirmado en codigo.

**Pasos:** abrir Dashboard principal con periodo ALL y observar 10 protocolos; abrir Dashboard > Resumen con ALL: muestra 8, aunque conserva los mismos 1415 paquetes y 37 hosts.

**Causa:** `frontend/src/views/DashboardView.vue:299` calcula el indicador con `this.protocolSeries.length`; esa serie usa `.slice(0, 8)` en la linea 316. El limite de un grafico se convierte en un total incorrecto.

**Recomendacion:** calcular el total desde la lista completa o el resumen del backend. Reservar el recorte para la visualizacion del top de protocolos.

### 1.13 Medium - Mapa etiqueta paquetes como servicios activos

**Estado:** reproducido en Mercator y Globe; confirmado en codigo.

**Pasos:** Dashboard > Mapa en Vivo muestra `Active services: 1415`, igual al total de paquetes retenidos.

**Causa:** `frontend/src/components/MapPanel.vue:393` presenta `summary.total_open_ports` como servicios. `sniff4hound/store.py:4818` llena ese campo contando filas de `packets` con `state = 'open'`, sin contar servicios distintos ni comprobar actividad actual.

**Impacto:** el operador puede interpretar miles de paquetes como miles de servicios expuestos.

**Recomendacion:** renombrar el indicador para describir paquetes retenidos o calcular servicios distintos con una definicion explicita de host, transporte, puerto y ventana temporal.

### 1.14 Low - Orden anunciado de alertas IA no coincide con las filas

**Estado:** reproducido.

**Pasos:** Dashboard > Resumen anuncia "mas recientes primero", pero las primeras filas observadas son de 12:34:49, 12:34:50, 12:34:47 y 12:34:48, con scores descendentes 68, 66, 65.9 y 65.8.

**Causa:** `frontend/src/views/DashboardView.vue:36` anuncia orden temporal; la asignacion de filas en la linea 657 conserva el orden del API. `sniff4hound/packet_ai.py:121` ordena por score descendente.

**Recomendacion:** mostrar "mayor puntuacion primero" o aplicar orden cronologico real; ofrecer un selector claro si ambos modos son utiles.

### 1.15 Low - Listas blancas muestran entradas duplicadas

**Estado:** duplicados observados; no se comprobo su mecanismo de creacion.

**Pasos:** Settings > Lists > IP Whitelist muestra ocho entradas, incluyendo dos pares con la misma IP y tipo `exact`. Un par tiene etiquetas distintas y otro presenta la misma etiqueta vacia.

**Impacto:** introduce ambiguedad al editar o desactivar una entrada que sigue existiendo en otra fila.

**Recomendacion:** comprobar unicidad por lista/tipo/valor normalizado y definir como combinar etiquetas. Revisar duplicados existentes antes de cualquier migracion; no se borraron datos en esta auditoria.

### 1.16 Low - Idioma y estados iniciales poco consistentes

**Estado:** observado en el recorrido.

Dashboard principal y Chat usan español; Settings, SOC y tablas usan mayormente ingles. Settings mezcla pestañas inglesas con IA y Arquitectura en español. Protocols abre por defecto `Unknown` con cero filas aunque DNS tiene 898 y HTTP 217.

Al entrar por primera vez en Monitors aparecieron contadores cero y "No monitor has matched" antes de cargar 30122 monitores y sus coincidencias. Al esperar la respuesta, la vista se completo; no se confirma un fallo de carga permanente.

**Recomendacion:** unificar idioma, elegir un protocolo con trafico al abrir el atlas y distinguir carga inicial de ausencia confirmada de datos mediante skeleton/estado de carga.

### Hallazgos de la ampliacion profunda (1.17-1.29)

Se conservan los identificadores para que cada correccion y prueba pueda referenciar un hallazgo. **UI** significa reproducido en Electron; **aislado** significa ejecutado con datos temporales; **estatico** significa confirmado en codigo, sin forzar el fallo sobre la sesion del operador.

#### 1.17 High / P0 - El periodo del Dashboard no filtra las alertas IA

**Evidencia UI:** a las 13:24 locales, seleccionar 15M en Resumen deja paquetes/tags/hosts en cero, pero mantiene 200 filas IA de las 12:34. ALL vuelve a 1415 paquetes sin cambiar esas filas. Se restauro ALL.

**Causa:** `DashboardView.vue::load()` solicita `/api/ai/packets/?threshold=50` sin periodo; `app.py::ai_packets/_ai_snapshot` y `store.py::list_ai_packets` tampoco admiten `since`.

**Impacto:** evidencia de otra ventana se presenta junto a una evaluacion temporal distinta. Puede provocar priorizacion incorrecta y conclusiones imposibles de reproducir.

**Correccion:** propagar el contexto temporal por HTTP y feed IA, filtrar en SQL antes de seleccionar/muestrear y devolver el intervalo efectivo. Si la IA requiere una cohorte de referencia externa a la ventana, separar explicitamente filas investigadas de cohorte de comparacion. Cohorte insuficiente debe producir ese estado, no rellenarse silenciosamente con historia.

**Aceptacion:** con paquetes recientes y antiguos, 15M excluye los antiguos en todos los paneles; ALL los incluye; HTTP y WS producen el mismo conjunto. Probar cambio rapido de ventana con respuestas en orden inverso.

#### 1.18 High / P0 - Investigar una IP mezcla otras IPs y menciones textuales

**Evidencia aislada:** una BD con solo `10.0.0.10` devuelve un paquete y un flujo al investigar `10.0.0.1`. Una IP presente unicamente en `summary` tambien aparece como un paquete del host.

**Causa:** `store.py::ip_intel()` usa `list_packets(search=ip)` y `list_flows(search=ip)`. La busqueda es parcial (`LIKE`), e incluye campos de texto. Los filtros de payloads/tags tambien buscan subcadenas en `flow_key`.

**Impacto:** atribucion de actividad a un activo que no participo en la comunicacion.

**Correccion:** filtro de entidad exacta `src_ip = ? OR dst_ip = ?`, normalizacion IPv4/IPv6 y joins por `packet_id`/flujo estructurado. Mantener busqueda libre como otro modo, sin usarla para resolver identidad. No corregir mediante regex sobre `flow_key`.

**Aceptacion:** separar `.1`, `.10`, `.100`; incluir sentidos origen/destino; rechazar IP invalida; probar IPv6 equivalente, IP mencionada en payload y filas sin IP. Todas las tablas y exports del investigador deben mantener el mismo host objetivo.

#### 1.19 High / P0 - Evidencia de un host se pierde del resultado por limitar antes de filtrar

**Evidencia aislada:** un host tiene un payload y el investigador lo muestra. Tras insertar 255 payloads ajenos, el investigador muestra cero payloads para el host, aunque SQL confirma que el original sigue retenido.

**Causa:** `store.py::ip_intel()` primero obtiene los ultimos 250 payloads y 400 tags globales; despues filtra por IP en Python. Los resumenes usan longitudes de muestras como si fueran totales.

**Correccion:** aplicar entidad y periodo en SQL antes de `LIMIT`; contar sobre el mismo predicado; paginar cada tipo de evidencia. Exponer `returned`, `total_available`, `truncated` y cursor. Mostrar "250 de N" en lugar de un total ambiguo.

**Aceptacion:** la evidencia del host permanece accesible aunque existan miles de eventos recientes ajenos. Verificar payloads, tags, flujos, ambos sentidos y paginacion sin duplicar/omitir filas.

#### 1.20 High / P0 - Los controles de conservacion describen un comportamiento diferente al motor

**Evidencia UI/codigo/tests:** `SettingsView.vue` promete que desactivar "Store only detected traffic" conserva todo. Sin embargo, `Sniffer._store_packet()` sigue persistiendo solo `detection_muted or is_alert or training_sample`; `test_filter_disabled_does_not_persist_clean_traffic` confirma el descarte. `BlacklistPanel.vue` dice que whitelist mantiene paquetes visibles, pero `_store_packet()` retorna antes de persistir cuando `_whitelisted()` coincide.

**Impacto:** el operador puede creer que conserva evidencia completa o que solo silencia alertas cuando realmente excluye paquetes del historial.

**Correccion inmediata:** alinear rotulos, ayuda y confirmacion con el comportamiento real. Correccion funcional recomendada: separar `detection_enabled`, `persistence_policy` y `notification_policy`; no inferir las tres de un booleano. Definir "silenciar deteccion, conservar metadatos", "ignorar y no almacenar" y "retener evidencia" como decisiones distintas, con contadores de descarte y motivo.

**Migracion:** preservar el comportamiento existente de cada instalacion; no activar conservacion completa por sorpresa. Presentar explicitamente el modo migrado. Revisar tambien la promesa de muestreo 1 paquete/s de IA frente a `training_capture_enabled`; su tasa real no se midio en esta auditoria.

**Aceptacion:** matriz de pruebas por catalogo activado/desactivado, whitelist, exclusiones, entrenamiento, raw retention, anomalías y alerta IA. Cada fila debe fijar deteccion, persistencia, bytes, aprendizaje y notificacion esperados. Verificar el texto UI contra esa matriz.

#### 1.21 High / P0 - Exportar alertas desde un investigador ignora el objetivo

**Evidencia estatica/aislada:** `InvestigateView.vue::exportParams` envia `search: target`. `export.py::build_export` no pasa `search` a `_alert_rows`. Una solicitud de alerts con `search=203.0.113.250` devuelve una alerta de `192.0.2.1` a `192.0.2.2` en el fixture.

**Impacto:** un fichero que el analista espera asociado al host puede contener alertas de toda la muestra. Riesgo de atribucion y de compartir evidencia ajena al caso.

**Correccion:** contrato explicito de exportacion (`entity_type`, `entity_value`, tiempo, severidad, protocolo), soportado por cada dataset. Aplicar filtros antes de agrupar/limitar. Rechazar filtros no soportados en lugar de ignorarlos. Vista previa con alcance y cantidad antes de descargar.

**Aceptacion:** datos de dos hosts; exportar el primero solo incluye su evidencia. Verificar CSV/JSON, variantes dominio e IP, filtros combinados y paridad con la tabla investigada.

#### 1.22 Medium / P1 - Agregaciones de exportacion pueden parecer completas siendo parciales

**Evidencia estatica/aislada:** `_alert_rows` pagina alertas crudas antes de agrupar. Dos eventos se convierten en una fila con `count=1, limit=2`; ese count no permite saber si se consumio toda la pagina de eventos. `build_export` no devuelve `total_available`, `next_cursor` ni `truncated`. `_alert_index` enriquece endpoints solo con 2000 alertas, y ante cualquier excepcion devuelve un indice vacio.

**Impacto:** counts y first/last seen de una regla son parciales por pagina; un fallo de enriquecimiento puede parecer ausencia de alertas; CSV omite incluso los metadatos del JSON.

**Correccion:** decidir entre export de eventos y export de agregados. Para agregados, agrupar el conjunto filtrado y despues paginar por clave estable; para eventos, mantener ids y contar eventos consumidos. Añadir estado de completitud/enriquecimiento y manifest para CSV. Una excepcion de lectura debe marcar resultado parcial o fallar la exportacion.

**Aceptacion:** grupo dividido entre paginas, >2000 alertas y fallo del enriquecimiento. Totales/fechas consistentes; cursor avanza correctamente incluso si muchas filas crudas colapsan en un agregado.

#### 1.23 Medium / P1 - Settings transfiere todo el catalogo aunque se abra Capture

**Evidencia UI/CDP:** dos entradas observadas en Settings; en la segunda se recibieron 45.005.382 bytes de payload WebSocket en unos seis segundos. Un `get_result` de `/api/monitors/` tuvo **42.926.707 bytes y 30122 filas**. `/api/honeypot/listeners/` tuvo **2.060.571 bytes y 10134 filas**. Son bytes de mensajes decodificados observados por CDP, no trafico comprimido de red ni benchmark p95.

**Causa:** `SettingsView.vue::load()` llama `listMonitors()` al montar; la API devuelve definiciones completas. Paginacion visual de tablas no evita transferir/deserializar el catalogo.

**Correccion:** endpoints de resumen y listado paginado (50-100 filas), filtro/sort en servidor, detalle de regla bajo demanda, carga por pestaña y cache por revision del catalogo. Mantener un endpoint separado para exportacion completa. Compartir caché con Monitors; no reconstruir definiciones de reglas para cada contador.

**Aceptacion propuesta:** abrir Capture no solicita el catalogo completo. Con 30k reglas, primer listado <=1 MB de JSON y p95 <=1 s en hardware de referencia acordado. Medir CPU, heap, tiempo de parse/render y bytes; son metas, no resultados ya alcanzados.

#### 1.24 Medium / P1 - El worker de entrenamiento no tiene cierre propio

**Evidencia estatica:** `sniffer.py::_run_ai_training_worker` usa `while True` y `queue.get()` sin sentinel; `_enqueue_ai_training` crea un daemon sin conservar handle. `Sniffer.stop()` espera hilos de captura, no este worker. `SniffStore.close()` cierra SQLite sin coordinarlo. La cola llena descarta ejemplos silenciosamente.

**Impacto:** posibles escrituras contra store cerrado, hilos retenidos en pruebas/reinicios y falta de visibilidad sobre muestras perdidas. Es un candidato para investigar el teardown 1.5; no esta demostrada la causalidad de aquel fallo.

**Correccion:** handle propio, evento/sentinel de cierre, politica explicita de drenar o cancelar pendientes, `task_done`, cierre idempotente y `join` acotado antes del store. Separar pausa de captura de cierre definitivo. Contadores queued/processed/dropped/failed. Aplicar coordinacion equivalente al torneo, sin esperar bajo locks que necesite el worker.

**Aceptacion:** iniciar/procesar/detener/cerrar repetidamente sin nuevos hilos vivos ni escrituras tardias; cola llena visible; cierre con trabajo en curso; ausencia de deadlock; repetir la prueba de teardown de forma aislada.

#### 1.25 Medium / P1 - Las metricas IA no permiten juzgar deteccion operacional

**Evidencia:** `ai_learning.py::model_effectiveness` calcula acierto sobre ejemplos de entrenamiento. En UI se observo "Efectividad 83% (500/601)" con 500 benignos y 101 maliciosos: coincide con el acierto de una prediccion siempre benigna (83,2%). Esto no prueba que el modelo actual prediga siempre benigno; muestra por que accuracy sola es insuficiente.

`run_tournament_round` usa holdout estratificado si hay >=6 ejemplos por clase; con menos reutiliza entrenamiento. La UI del torneo afirma de forma general que el acierto es sobre entrenamiento, lo que no describe ambos modos. El holdout aleatorio por ejemplo tampoco garantiza separacion por flujo/sesion. `_store_packet()` añade etiquetas automaticas `auto:training` derivadas de severidad de reglas; no son confirmaciones humanas de ataque.

**Correccion:** devolver y mostrar `evaluation_mode`, procedencia de etiquetas, tamaños/clases y revision del dataset; renombrar "Efectividad" a "Acierto en entrenamiento" donde corresponda. Matriz de confusion, precision/recall de maliciosos, balanced accuracy, tasa de falsos positivos y comparacion con baseline. Separar validacion temporal/por flujo del entrenamiento y de la seleccion de arquitectura; no usar el conjunto de seleccion repetidamente como test final.

**Aceptacion:** dataset 500/101 siempre benigno debe mostrar recall malicioso 0 y balanced accuracy 50%, sin señal visual de validacion satisfactoria. Holdout/resustitucion rotulados correctamente; ninguna etiqueta automatica aparece como verificacion humana. La IA debe complementar reglas hasta demostrar rendimiento independiente.

#### 1.26 Low / P2 - El enlace de exclusiones abre otra pestaña

**Evidencia UI:** IA > "Ir a Configuracion -> Exclusiones" abre `/settings` con Capture seleccionado. En `SettingsView.vue`, `VALID_TABS` tampoco incluye `exclusions`, aunque existe la pestaña.

**Correccion:** link `/settings?section=exclusions`, incluir esa clave en validacion y sincronizar pestaña/URL. Usar una definicion comun de pestañas para evitar drift.

**Aceptacion:** enlace desde IA, carga directa, atras/adelante y pestaña seleccionada coinciden; section desconocida cae en Capture sin error.

#### 1.27 Medium / P1 - Dashboard puede aplicar respuestas de un contexto anterior

**Evidencia estatica; carrera no forzada en la app viva:** `DashboardView.vue::load()` aplica resultados sin contador de secuencia ni comparar ventana solicitada con la actual. Investigate y SOC ya contienen protecciones de secuencia aprovechables. El fallback HTTP de `appStore.js::httpFetchWithMeta` tampoco fija un timeout propio.

**Correccion:** incrementar revision de consulta y aceptar solo la mas reciente; cancelar peticiones obsoletas cuando sea posible; no borrar evidencia vigente durante refrescos de fondo. Incorporar timeout/cancelacion explicitos en lecturas HTTP y preservar error/frescura por panel. No reintentar escrituras automaticamente.

**Aceptacion:** respuesta de ALL llega despues de 15M y no la reemplaza; navegar fuera durante carga no altera el nuevo contexto; error parcial mantiene datos previos marcados como desactualizados, no ceros.

#### 1.28 Low / P2 - Controles de filtrado demasiado pequeños para uso continuado

**Evidencia UI/CSS:** botones include/exclude de tabla miden 16x16 CSS px, con gap de 2 px en `components/ui/EntityTablePanel.vue`. Aparecen en hover o focus-within. En Sniffer a 1536x835 la tabla mide 2615 px; hay scroll interno, sin overflow global. En Settings a 390x844 no hubo overflow global, pero solo Capture/Honeypot caben enteros en la tira de pestañas.

**Correccion:** area interactiva de al menos 24x24 con separacion adecuada, foco visible, menu de acciones por fila/celda y columnas predeterminadas por tarea. Tabla detallada sigue disponible. En viewport estrecho: selector de seccion reconocible y prioridad de lectura. WCAG 2.2 contempla excepciones de espaciado; no se afirma conformidad o incumplimiento global sin auditoria completa.

**Aceptacion:** teclado completo, zoom 200%, contraste medido, foco no oculto; inspeccion 1280x800, 1536x835 y 390x844. Ninguna accion depende solo de color/hover. Ver referencia W3C en seccion 11.

#### 1.29 Medium / P1 - Investigacion por dominio depende de texto libre, no de identidad DNS/HTTP/TLS

**Evidencia estatica/aislada:** `InvestigateView.vue::loadDomain` combina consultas `search=dominio` a packets/banners/tags con el catalogo. `_packet_filter` no consulta las columnas `domain`/`http_host`. El fixture con una fila cuyo `domain=needle.example`, sin ese nombre en el resumen, devuelve un paquete por SQL exacto y cero por `list_packets(search=...)`.

**Impacto:** evidencia estructurada existente puede omitirse; coincidencias incidentales de texto pueden incluirse. No se infiere cobertura completa de un dominio a partir del resumen visible.

**Correccion:** endpoint de investigacion por dominio normalizado, con modos exacto/subdominios explicitos, fuentes DNS query, HTTP Host y TLS SNI separadas y enlaces a packet/flow ids. Normalizar mayusculas, punto final, puerto HTTP y representacion IDNA; no aplicar regex libre al buscar una entidad exacta. Compartir paginacion/tiempo del investigador IP.

**Aceptacion:** dominio solo en campo estructurado, nombres parecidos, subdominio, punto final, Host con puerto y evidencia sin payload retenido. Ninguna fila ajena por mera mencion textual salvo modo de busqueda libre seleccionado.

## 2. Validacion ejecutada

### 2.1 Electron/CDP

- `GET http://127.0.0.1:9223/json/version`: OK, Electron `38.8.6`, app `sniff4hound-desktop/0.54.0`.
- `GET http://127.0.0.1:9223/json/list`: OK, target `Sniff4Hound`.
- Lectura DOM por WebSocket CDP: OK, Dashboard montado con datos reales.

### 2.2 Backend

- `python -m pytest tests/ -q`: fallo por entorno global sin `wsbuilder`.
- `.venv/bin/python -m pytest tests/ -q`: ejecuta suite completa y termina con `2 failed, 935 passed, 2 skipped, 316 subtests passed`.

### 2.3 Frontend

- `cd frontend && npm run build`: OK.
- `cd frontend && npm test`: falla en `npm run test:unit` por resolucion ESM de `../utils/runtimeEnv`.
- `npm run lint` dentro de `npm test`: no reporto errores antes del fallo unitario.

### 2.4 Deep links SPA

Se probaron rutas principales con `curl` contra el backend Electron vivo. Las rutas top-level principales responden `200`; las rutas nuevas anidadas de IA/Dashboard responden `404` y deben entrar a `SPA_ROUTES`.

### 2.5 Recorrido interactivo sobre la ventana Electron existente

Realizado el 2026-09-19, aproximadamente 13:16-13:22 America/Sao_Paulo. Conexion al target existente en CDP 9223; se accionaron controles DOM de la propia ventana, sin abrir otra instancia. Las capturas se inspeccionaron para Dashboard, nodos, red neuronal y mapas Mercator/Globe. Otros pantallazos se capturaron como evidencia auxiliar sin afirmar inspeccion visual completa de cada uno.

| Modulo | Accion y resultado observado |
| --- | --- |
| Dashboard principal | Datos cargados: 1415 paquetes, 37 hosts, 10 protocolos. |
| Dashboard Resumen / alertas IA | Abierto desde menu; 200 registros y 184 analizados. Detectados contador y orden incorrectos (1.12, 1.14). |
| Mapa de nodos | Abierto con el enlace NODOS; grafo visible con hosts y conexiones. |
| Mapa en Vivo | Cambio mediante botones de Mercator a Globe y vuelta; ambas proyecciones dibujan hosts/conexiones. Hallazgo 1.13. |
| Chat | Seleccion de Estado general y envio de `/status`; respuesta confirma ambos motores detenidos y un cliente WebSocket. Se añadieron dos mensajes al historial (comando y respuesta). |
| Settings | Abiertas Capture, Honeypot, Detection, Lists, Exclusions, Notifications, IA y Arquitectura; sin guardar cambios. |
| Arquitectura | Click en nodo Trafico / conexiones abre su descripcion. |
| IA Resumen | Galeria y configuracion cargadas: 184 analizados de 200, 601 ejemplos retenidos, revision 1284. No se etiquetaron paquetes. |
| Red neuronal | Grafico 8 -> 4 -> 1 y comparacion de modelos visibles. Click sobre L1 no produjo texto adicional en la lectura realizada; detalle de neurona no validado. |
| SOC | Tras cargar: 1415 paquetes, 9 findings, riesgo 76 y cuatro pasadas. No se modifico la profundidad. |
| Investigador | Click en Investigate IP desde tabla de IPs abre evidencia del host: 250 paquetes, 100 flujos y 173 payloads en el resultado cargado. |
| Monitors | Carga 30122 definiciones (18499 habilitadas); expandir Port scan / reconnaissance muestra un paquete, estadisticas y tabla. |
| Protocols | Seleccion de tarjeta DNS navega a `/protocols/dns` y carga tablas (500 filas en la muestra); atlas indica 898 paquetes DNS retenidos. |
| Sniffer | Busqueda `HTTP`: 152 de 600 filas cargadas. Texto inexistente: 0. Limpiar: 600. Expand JSON view abre el JSON de una fila. |
| Honeypot | Estado vacio coherente con motor detenido: 0 hits, 10134 listeners configurados. No se abrieron listeners. |
| Domains / Paths | Tablas cargadas con 312 dominios y 43 paths. |
| IPs | Tabla con 37 hosts y enlace funcional al investigador. |

Durante las ventanas de observacion CDP no se recogieron excepciones `Runtime.exceptionThrown` ni respuestas HTTP >=400. Esto no cubre mensajes de consola completos, fallos de transporte, ni solicitudes anteriores a cada conexion. Los 404 de carga directa siguen documentados por separado; la navegacion interna SPA funciona.

**Limites:** no se iniciaron capturas/honeypot, no se borraron datos ni se guardaron ajustes, no se reentreno/importo el modelo y no se enviaron notificaciones externas. No se verificaron todos los botones, todas las familias de protocolos ni todos los flujos de escritura. Esta es cobertura interactiva por modulo, no una certificacion exhaustiva de cada funcion. Las pruebas automatizadas de 2.2/2.3 pertenecen al pase anterior y no se repitieron en este recorrido.

**Evidencia local temporal:** `/tmp/s4h-dashboard.png`, `/tmp/s4h-nodes.png`, `/tmp/s4h-investigate.png`, `/tmp/s4h-ai.png`, `/tmp/s4h-rnn.png`, `/tmp/s4h-architecture.png`, `/tmp/s4h-architecture-detail.png`, `/tmp/s4h-sniffer.png`, `/tmp/s4h-alerts.png`, `/tmp/s4h-live-map.png`, `/tmp/s4h-globe.png`, `/tmp/s4h-dns.png`, `/tmp/s4h-monitor-detail.png`, `/tmp/s4h-chat.png`. Contienen datos de la sesion; no se incorporaron al repositorio. El script temporal `/tmp/s4h-live-review.cjs` permite adjuntarse al target y capturar resultados.

---

## 3. Recomendaciones priorizadas

1. **Corregir deep links antes de release:** agregar rutas faltantes a `SPA_ROUTES` y verificar con `curl`/test que todas responden `200`.
2. **Rehacer el test de rutas SPA:** no depender de regex fragil sobre objetos JS; usar AST, lista compartida o generacion automatica.
3. **Arreglar `npm test`:** usar extension `.js` en `frontend/src/router/index.js` o adaptar el runner Node.
4. **Cerrar el fallo de teardown temporal:** identificar hilos/handles vivos en `TestTrainingAndAiAlertModes`.
5. **Alinear versiones:** backend, desktop, artefactos `dist` y FAQA no deben hablar de versiones distintas sin explicacion.
6. **Limpiar workspace antes de QA:** crear/usar un flujo claro de limpieza para `dist/`, `build/`, `QA/`, caches y bytecode; el script actual solo cubre artefactos runtime sensibles.
7. **Actualizar docs stale:** especialmente `ARCHITECTURE.md` sobre auth/localStorage.
8. **Mantener documentado CDP 9223:** el operador ya acepta su apertura por defecto; conservar su opcion de desactivacion.
9. **Actualizar scripts QA visuales:** `scripts/qa_visual_pass.js` debe cubrir rutas anidadas y puerto Electron; `scripts/qa_ui_cdp.js` parece apuntar a UI vieja y deberia marcarse legacy o reescribirse.
10. **Endurecer Electron bridge:** allowlist de esquemas antes de `shell.openExternal`.
11. **Corregir metricas visibles:** contador completo de protocolos y significado de Active services (1.12 y 1.13).
12. **Ordenar la experiencia de operacion:** alinear orden de alertas y rotulos, revisar duplicados en listas, unificar idioma y evitar estados vacios durante carga (1.14-1.16).

---

## 4. Cobertura por modulo revisado

- **Backend API/runtime (`sniff4hound/app.py`, `runtime_controller.py`, `manage.py`, `capture_service.py`):** auth guards, origin guard, tickets WebSocket, rutas SPA, endpoints mutantes y arranque/cierre. Hallazgo principal: rutas SPA incompletas.
- **Persistencia (`store.py`, `export.py`, `access_log.py`):** retencion raw, listados IA, purga por IP, exports y logs. No se encontro una inyeccion SQL directa en los puntos revisados; se observaron queries parametrizadas en las rutas sensibles revisadas.
- **Captura/deteccion (`sniffer.py`, `honeypot.py`, `monitors.py`, `rulesets.py`, `regex_safety.py`, `anomaly.py`, `packet_ai.py`, `ai_learning.py`):** cache de monitores, whitelist/exclusion, entrenamiento IA, throttling y retencion. Riesgo pendiente: fallo intermitente de teardown apunta a hilos/handles vivos en pruebas de entrenamiento/IA.
- **Frontend SPA (`frontend/src/router`, `state`, `views`, `components`):** router, auth en memoria, WS GET fallback, vistas principales y componentes grandes. Hallazgo principal: imports ESM sin extension rompen `npm test`; router y backend no comparten fuente de verdad.
- **Desktop Electron (`desktop/main.js`, `preload.js`):** launcher backend, conexion remota, CDP, navegacion y bridge. Riesgos: CDP abierto por diseno, sandbox desactivado por empaquetado, `openExternal` sin allowlist.
- **Scripts/QA/packaging (`scripts/*.sh`, `scripts/*.js`, `scripts/*.py`):** build Debian, postinst/postrm, QA CDP, limpieza local. Riesgos: scripts QA desfasados/incompletos y limpieza de build/caches no cubierta por `clean_artifacts.sh`.
- **Docs/config/versionado (`README.md`, `ARCHITECTURE.md`, `FAQA.md`, package metadata):** inconsistencias de version y docs stale sobre almacenamiento del token.

---

## 5. Estado final

**No aprobado limpio.** La aplicacion corre y el build frontend compila, pero hay defectos abiertos que afectan navegacion directa, confiabilidad de tests y orden del repo. El foco recomendado es primero arreglar `SPA_ROUTES` + prueba de regresion, luego dejar `npm test` verde y limpiar/normalizar artefactos y versiones antes de generar otro paquete.

**Actualizacion de prioridad tras la revision profunda:** corregir primero 1.17-1.21 (periodo, entidad, completitud, politica de conservacion y exportacion). Deep links y tests son parte de esa primera entrega. Los artefactos ignorados en disco son una cuestion organizativa, no un bloqueo por si mismos. No hay evidencia suficiente para declarar la app lista como consola SOC de produccion ni para afirmar cobertura completa de deteccion.

## 6. Plan tecnico de correccion

### 6.1 Contrato de evidencia y consultas (P0)

Aplicar primero a investigador IP, investigador dominio, alertas y exportaciones. Evitar implementar un nuevo lenguaje de consultas antes de resolver filtros estructurados.

Contrato propuesto, todavia no existente:

```json
{
  "query": {
    "entity_type": "ip",
    "entity_value": "192.0.2.10",
    "from": "2026-09-19T12:00:00Z",
    "to": "2026-09-19T13:00:00Z",
    "sensor_id": "local",
    "sort": ["created_at:desc", "id:desc"]
  },
  "meta": {
    "snapshot_id": "opaque-snapshot-id",
    "generated_at": "2026-09-19T13:00:01Z",
    "returned": 50,
    "total_available": 834,
    "truncated": true,
    "next_cursor": "opaque-cursor",
    "coverage": "retained-evidence",
    "partial": false
  },
  "rows": []
}
```

- Definir intervalo UTC semiabierto `[from, to)`; resolver una ventana relativa una vez por investigacion. Todos los paneles y export comparten ese corte.
- Validar filtros/sort en backend con allowlist; valores siempre parametrizados. No interpolar nombres de columna recibidos libremente.
- Identidad exacta y texto libre son predicados distintos. La IP canonica debe conservar tambien el valor observado si se necesita trazabilidad.
- Aplicar WHERE antes de limites y contar con el mismo WHERE. Cursor estable por timestamp/id; fijar snapshot o limite superior de id para evitar desplazamientos durante ingesta.
- `total_available` significa filas retenidas que cumplen la consulta, nunca cantidad recibida en una pagina. Para estimaciones costosas, declararlas como estimacion.
- Distinguir conteos de paquetes, flujos, servicios inferidos, hosts, detecciones y grupos de detecciones. Un servicio inferido no implica puerto confirmado abierto.
- Documentar las unidades y alcance: periodo, acumulado de flujo, sesion actual del sensor o muestra. Mostrarlo junto al numero.
- Añadir al export un manifest con consulta normalizada, version de app/esquema/reglas, corte temporal, completitud, hash SHA-256 de archivos y zona horaria. Un hash ayuda a verificar integridad, pero no garantiza por si mismo cadena de custodia.

Archivos iniciales: `store.py::ip_intel`, `_packet_filter`, filtros payload/tags/flows; `app.py::ip_intel`, `ai_packets`, `_export_response`; `InvestigateView.vue`, `DashboardView.vue`, `IocExportMenu.vue`, `appStore.js`. Mantener compatibilidad de los endpoints actuales mientras migran los consumidores.

### 6.2 Visibilidad, retencion y reglas (P0/P1)

Definir una tabla de comportamiento antes de cambiar `_store_packet`. Propuesta de semantica, sujeta a migracion explicita:

| Decision | Analizar | Conservar | Alertar | Uso |
| --- | --- | --- | --- | --- |
| Normal | Reglas/anomalias activas | Segun politica | Segun severidad | Operacion habitual |
| Silenciar deteccion | No | Metadatos segun politica | No | Ruido conocido, aun investigable |
| Excluir captura/almacenamiento | No | No | No | Exclusiones deliberadas y visibles |
| Suprimir notificacion | Si | Evidencia | Sin popup; evento disponible | Reducir interrupciones |
| Muestreo de fondo | Si, segun presupuesto | Muestra con tasa/procedencia | Segun resultado | Contexto para hunting/IA |

El comportamiento actual no coincide necesariamente con esta tabla. No cambiarlo sin tests y migracion. La pantalla debe mostrar cantidad y motivo de paquetes omitidos; una vista vacia no equivale a red limpia.

Para reglas: version/fuente/licencia, fecha, severidad, evidencia concreta que produjo el match, costo de ejecucion, ejemplos positivos y negativos. Separar firmas especificas, indicadores genericos y comportamiento. Los 30k monitores son volumen de catalogo, no medida demostrada de cobertura.

Añadir perfiles de operacion conservadores (laboratorio, endpoint local, sensor de red) como configuraciones revisables. Correlacion y supresion con tiempo de expiracion, razon y auditoria; conservar el evento original. Evitar escalar automaticamente toda coincidencia generica a incidente critico.

`_direction_for()` compara contra IPs locales del sensor; un SPAN/TAP puede observar terceros y producir `unknown`. El SOC vivo mostro 1415 direction gaps. No es prueba de parser roto: faltan contexto de sensor y definicion de direccion. Proponer redes internas configurables y clasificaciones separadas: direccion respecto al sensor, limites de red y rol cliente/servidor, cada una con fuente/confianza.

### 6.3 Navegacion, pruebas y duplicados (P0/P1)

| Hallazgo | Trabajo concreto | Verificacion |
| --- | --- | --- |
| 1.1 / 1.2 | Inventario compartido de rutas estaticas; añadir cinco rutas faltantes. Si se usa fallback SPA, limitarlo a navegacion HTML conocida, nunca ocultar 404 API/assets. Reemplazar regex fragil por lectura estructurada de rutas. | Carga directa, refresh y trailing slash; API/asset inexistente sigue 404; rutas dinamicas como `/protocols/dns`. |
| 1.3 | Extension `.js` en import local; revisar imports ejecutados directamente por Node. Registrar version soportada de Node/Python y usar lockfiles. | `npm test` y build, en entorno documentado. |
| 1.4 / 1.5 | Entorno de QA reproducible y cierre ordenado de workers. No ocultar fallos con reintentos indiscriminados o `ignore_errors=True`. | Suite completa mas repeticion focalizada del teardown despues del cambio. |
| 1.6 / 1.7 | Fuente unica de version o politica explicita de componentes; docs de auth actualizadas. Conservar changelog como historia. | Comparar metadata, UI, User-Agent y paquete generado. |
| 1.10 | QA CDP configurable a 9223; inventario de rutas derivado del router; registrar app/version/viewport y errores. | Ejecucion sobre build concreto; fixtures separadas de sesion real. |
| 1.12 / 1.13 | Contadores desde consulta completa; servicios con semantica definida. | Dataset >8 protocolos; 100 paquetes del mismo servicio no son 100 servicios. |
| 1.14 / 1.26 | Orden temporal/score explicito; pestaña en query string. | Navegacion atras/adelante y orden visible verificable. |
| 1.15 | Unicidad `(category, match_type, normalized_value)` por tipo de lista; operacion idempotente y conflicto de etiquetas visible. | Crear dos veces no duplica; concurrencia; regex no se normaliza como dominio; migracion genera reporte antes de fusionar. |

### 6.4 Seguridad defensiva y evidencia hostil (P1)

El contenido capturado puede contener credenciales, HTML malicioso, comandos o enlaces de phishing. La consola debe tratarlo como datos incluso cuando procede del propio backend.

- Mantener renderizado como texto, limites de payload y acciones explicitas para abrir URLs. No se encontraron usos de `v-html`/`innerHTML` en el barrido de frontend realizado; esto no equivale a una prueba completa de ausencia de XSS.
- `desktop/main.js`: centralizar validacion de `openExternal`; permitir protocolos justificados, rechazar esquemas arbitrarios y validar sender del IPC. Pruebas con URL valida, malformada y `file:`, `data:`, `javascript:`.
- Evaluar restaurar sandbox de renderer arreglando empaquetado/plataforma; documentar excepciones reales. Mantener `contextIsolation`, bridge minimo y navegacion restringida. La guia oficial de Electron es la referencia, no el comentario de que el costo es "modesto".
- CDP 9223 permanece aceptado por el operador. No cambiar el default por esta auditoria; conservar opt-out y evitar distribuir secretos en capturas/logs.
- Distinguir producto local de despliegue compartido. Para acceso multiusuario, diseñar roles viewer/analyst/admin, identidad de operador y autorizacion por accion. La autenticacion existente no demuestra ese modelo de autorizacion.
- Auditoria de cambios: actor, accion, objeto, revision previa/nueva, momento, resultado y correlation id. Evitar registrar tokens/payload sensible completo. Los access logs HTTP no reemplazan historial de decisiones analiticas.
- Mantener limites de regex, importacion/modelo, payload y peticiones. Revisar presupuestos CPU/memoria antes de ofrecer arquitecturas neuronales sin limites operacionales.
- Exportar muestras sensibles con alcance visible y redaccion opcional. Conservar original controlado y export redactado como artefactos distintos, con manifest que explique la transformacion.

### 6.5 Aprendizaje y ciclo de vida (P1)

No confundir revisar un paquete, enseñarle al modelo y cerrar una alerta. `save_packet_review` escribe tags; `save_ai_feedback` escribe el estado del modelo. Son mecanismos independientes hoy. Mostrar claramente si una decision tambien entrena y ofrecer una politica explicita de precedencia para etiquetas manuales frente a automaticas.

La procedencia debe acompañar al ejemplo: manual, derivado de regla, importado; actor, motivo, revision y confianza. No entrenar/validar con una copia del mismo flujo en particiones distintas. Conservar un conjunto de evaluacion final que no participe en seleccion de arquitectura.

Implementar jobs con estados queued/running/cancelling/completed/failed, progreso basado en trabajo real y limites de CPU/memoria/tiempo. Reportar motivo de parada, version de pesos y rollback. El entrenamiento usa Python y threads sujetos al GIL; mas hilos no implican mas throughput. Medir interferencia con captura antes de decidir procesos separados o librerias numericas.

Las decisiones operativas de bloqueo/contencion requieren evidencia y confirmacion contextual; no automatizarlas solo por score LOF o acierto del entrenamiento.

## 7. Experiencia Blue Team propuesta

### 7.1 Flujo principal de trabajo

La primera pantalla debe permitir decidir que atender, por que y con que evidencia. Propuesta de navegacion principal:

| Area | Trabajo del analista | Contenido principal |
| --- | --- | --- |
| Operaciones | Ver salud y pendientes | Estado sensor, ingesta/perdidas, cola de alertas, ultima evidencia, degradaciones |
| Investigar | Pivotar desde entidad/evento | Consulta estructurada, cronologia, flujos, DNS/HTTP/TLS, bytes y evidencia asociada |
| Casos | Registrar y entregar decisiones | Estado, propietario, notas, evidencias fijadas, tareas, conclusion, export |
| Detecciones | Reducir ruido y explicar matches | Reglas, excepciones temporales, cobertura evaluada, versiones y pruebas |
| Activos | Entender contexto | IPs observadas, nombres, roles inferidos, propietario/criticidad cuando se conozcan |
| Configuracion | Operar sensor y producto | Interfaces, retencion, listeners, permisos, integraciones y diagnostico |

Mapas, red neuronal y Chat quedan accesibles como vistas especializadas. La topologia ayuda a investigar, pero no sustituye una cola de trabajo ordenada. Se puede reutilizar buena parte del SOC actual; evitar duplicar tres dashboards con contadores distintos.

Flujo objetivo: alerta -> evidencia exacta -> pivote a host/flujo/dominio conservando tiempo -> decision con motivo -> caso/tarea -> export reproducible. Un operador debe volver a la misma fila, filtros y scroll al regresar.

### 7.2 Triage y casos: extension propuesta, no funcionalidad validada

No se encontro un modelo explicito de casos, asignacion o ciclo de cierre en las rutas/tablas revisadas. Añadirlo progresivamente:

- Estado de alerta: nueva, en revision, escalada, resuelta; resolucion y razon separadas (actividad esperada, falso positivo, incidente confirmado, evidencia insuficiente).
- Agrupacion por regla, entidad y ventana; mostrar eventos originales, primer/ultimo evento y count. Dedupe no debe borrar evidencia.
- Priorizacion explicable: severidad de regla, criticidad del activo si existe, recurrencia, correlaciones y confianza. No reemplazar estos campos por un score opaco.
- Caso local inicialmente: titulo, estado, notas con timestamps y referencias de evidencia. Incorporar identidad/asignacion cuando haya multiusuario real, sin prometer concurrencia que SQLite/UI aun no gestionen.
- Evidencia fijada: vinculo al evento mas una copia/manifest conservable si retencion puede eliminarlo. Definir espacio y expiracion de casos; no dejar evidencias fijadas crecer sin control.
- Historial de decisiones append-only; correccion por nueva entrada, no sobrescritura invisible. Separar dato observado, inferencia y nota humana.
- Persistir investigaciones guardadas con consulta y corte temporal; enlaces reproducibles sin tokens en URL.

### 7.3 Tablas y detalle de evidencia

Conservar los componentes actuales, pero reducir la carga visual inicial. Para una cola: tiempo, severidad, regla, origen, destino, count, estado y accion principal. El resto en un panel lateral de detalle con pestañas Evidencia, Flujo, Contexto e Historial.

Filtros compartidos visibles: tiempo, sensor, IP exacta/CIDR, dominio, protocolo, puerto, regla, severidad y estado. Chips removibles, limpiar todo y consultas guardadas. Indicar expresamente "buscar en filas cargadas" cuando el filtro sea local; ofrecer "buscar en toda la evidencia retenida" con consulta backend. No presentar cero resultados de una muestra como inexistencia global.

Congelar la seleccion durante actualizacion en vivo; mostrar contador de nuevos eventos y boton para incorporarlos. Evitar reordenar la fila bajo el cursor. Columnas, densidad y sort persistidos por vista con opcion de restablecer. UTC/local seleccionable, zona visible y timestamps exportados en UTC.

Bytes/hex y texto deben alinearse con el paquete exacto; señalar truncamiento, bytes disponibles, ausencia por politica y procedencia. Añadir comparacion solicitud/respuesta donde el parser permita relacionarlas; no inventar reconstruccion de sesion TCP/TLS que no exista.

### 7.4 Estilo visual y ergonomia

- Mantener identidad Sniff4Hound, pero usar superficies neutras y acentos semanticos consistentes. Reservar rojo/ambar para severidad/estado, y cian para seleccion/accion.
- Reducir tarjetas gigantes, texto introductorio repetitivo y encabezados altos en vistas operativas. Priorizar filas escaneables y detalle bajo demanda.
- Adoptar español consistente o selector de idioma con catalogo centralizado; formato uniforme de fechas/numeros. Conservar terminos de protocolo estandar.
- Barra de salud persistente: conectado, backend/sensor, motores deseados/reales, ultimo dato, errores y backlog. "WS online" no significa captura activa ni evidencia reciente.
- Estados distintos para cargando, vacio real, error, parcial y desactualizado. Los ceros iniciales no deben parecer resultados definitivos.
- Iconos conocidos con nombre accesible; acciones destructivas separadas de navegacion. Tamaños de hit-area, foco visible y soporte teclado revisados en componentes compartidos.
- Respetar reduced-motion; graficos no deben competir con lectura. Ofrecer vista tabular de mapas/red neuronal. No basar informacion solo en color.
- Pantalla estrecha: lista priorizada y panel de detalle, filtros en drawer y selector claro de seccion. El escritorio sigue siendo el objetivo principal; 390px sirve como prueba de robustez, no como promesa de paridad movil.

### 7.5 Integraciones y cobertura

Antes de integrar un SIEM externo, estabilizar el esquema de eventos y exports. Proponer JSONL/stream con event id, sensor id, schema version, timestamps, rule id/version, entidades, evidencia y politica de redaccion. Reintentos idempotentes y backlog observable; nunca bloquear captura por entrega remota.

Mapeo ATT&CK solo donde la regla y la evidencia justifiquen una tecnica; permitir multiples tecnicas o ninguna. Mantener version de la taxonomia y separar cobertura teorica de cobertura validada por replay. Importar formatos de reglas exige documentar operadores soportados/no soportados; no afirmar compatibilidad completa por aceptar un archivo.

Agregar replay offline de capturas controladas para evaluar detecciones sin escuchar la red real. Registrar esperados, observados, falsos positivos, falsos negativos y costo; elegir herramientas/librerias de parsing tras una evaluacion acotada, sin reescribir el motor entero como condicion para mejorar el producto.

## 8. Arquitectura, rendimiento y orden

### 8.1 Refactor incremental

Medido en esta revision: `store.py` 5797 lineas; `app.py` 3977; `sniffer.py` 2708; `appStore.js` 2078; `SettingsView.vue` 2021; `MapPanel.vue` 1855. El tamaño es un indicador de concentracion de responsabilidades, no un defecto por si solo.

Extraer por dominio cuando se toque el codigo correspondiente, manteniendo fachadas y contratos:

1. Consultas/evidencia: predicados comunes, paginacion, snapshots y export.
2. Catalogos/configuracion: monitores, listas, listeners y migraciones.
3. IA: ejemplos, jobs, modelo, evaluacion y ciclo de vida.
4. API: routers/handlers agrupados, validacion/auth transversal y serializacion consistente.
5. Frontend: cliente HTTP/WS, estado de sesion, consulta, notificaciones y preferencias como responsabilidades separadas.
6. Mapas: fuente de datos, proyeccion y controles, sin mezclar conteos de paquetes/servicios.

No crear microservicios por cantidad de lineas. Primero hacer explicitos ownership, cierre y contratos; despues medir si una separacion de proceso mejora captura/analitica.

### 8.2 Presupuestos de rendimiento propuestos

Estas son metas para acordar y medir, no cifras logradas:

| Operacion | Objetivo inicial | Metodo |
| --- | --- | --- |
| Cambio de vista con datos cacheados | Feedback visual <=100 ms | Performance trace y marcas UI |
| Consulta paginada local caliente | p95 <=500 ms; render estable <=1 s | 30 repeticiones con dataset/hardware documentados |
| Listado de 30k reglas | <=100 filas y <=1 MB por pagina | Bytes JSON, heap y latencia |
| Ingesta bajo carga | Cero perdida no contabilizada | Comparar fixture enviado/capturado/descartado/persistido |
| Refresco en vivo | Sin solapamiento de consultas equivalentes | Instrumentar in-flight y revision de contexto |
| Entrenamiento | Presupuesto configurable y parada observable | CPU/RSS, backlog y latencia de ingesta concurrente |
| Cierre | Sin workers ni escrituras posteriores | Enumeracion de threads/procesos y fixture temporal |

Datasets de prueba sugeridos: 2k, 50k y 200k paquetes, 30k reglas y 10k listeners, con distribuciones de entidades realistas y payloads acotados. No generar estas cargas sobre la sesion del operador. Separar cold/warm cache y versiones del build.

Usar `EXPLAIN QUERY PLAN` antes de añadir indices; los indices src/dst/created_at ya existen. Medir joins y consultas con OR; no añadir indices redundantes sin comprobar write amplification. Evitar materializar BLOBs en listados. Mantener WAL/retencion y verificar recuperacion en entorno aislado.

### 8.3 Observabilidad del sensor

Mostrar paquetes recibidos, descartados por kernel/socket cuando sea medible, errores de parseo, descartados por politica, escritos, bytes raw retenidos, backlog de persistencia/IA y ultima escritura. Si una metrica no existe, mostrar no disponible en vez de cero.

Añadir timings por parse/deteccion/store/consulta, regla/version lenta, tamaño de DB/WAL y estado de retencion. La configuracion por defecto del codigo declara 7 dias generales, 30 dias de alertas y tope de 200000 paquetes; la UI debe mostrar valores efectivos de cada despliegue y prioridad del tope de filas.

Health endpoint basico (proceso vivo) separado de readiness (DB/acceso/sensor listos). Logs estructurados con correlation id y contexto acotado; contadores persistentes/sesion diferenciados. Un boton de diagnostico exporta informacion redacted y nunca codigo de sesion.

### 8.4 Workspace y entrega

`dist/`, `build/`, caches y metadata editable son normales en desarrollo. La mejora es hacerlos reproducibles y distinguibles de codigo fuente, no borrarlos indiscriminadamente.

- Mantener documentacion activa coherente; conservar informes antiguos como historicos fechados si hace falta.
- Artefactos de release en directorio por version/plataforma, con manifest de commit, dependencias, checksums y resultados QA. `latest` debe resolver a un build identificable.
- Separar limpieza de caches/build de limpieza de datos sensibles. Añadir dry-run y lista de rutas; nunca borrar DB o capturas desde un comando de limpieza de build.
- Guardar screenshots/logs QA fuera de git cuando contienen telemetria. Evidencia sintetica apta para repo puede ir en fixtures.
- Revisar si vistas legacy (Ports/Banners/Targets) siguen siendo accesibles/reutilizadas antes de eliminarlas. Retirar rutas/imports/docs juntos, con pruebas de compatibilidad.
- CI: backend, lint/unit, build, humo Electron empaquetado y pase UI contra fixture. Fallo de una etapa no se compensa con build verde.
- No regenerar lockfiles ni cambiar dependencias/versiones durante una auditoria documental sin necesidad. No se realizo un inventario CVE/SBOM completo ni se afirma ausencia de vulnerabilidades de dependencias.

## 9. Backlog y criterios de salida

| Entrega | Prioridad | Resultado comprobable | Dependencias |
| --- | --- | --- | --- |
| A: evidencia fiable | P0 | Entidades exactas; filtros temporales consistentes; evidencia paginada; export con mismo alcance; semantica de descarte explicita | Hallazgos 1.17-1.21 y 1.29 |
| B: base verificable | P0/P1 | Deep links y tests verdes; cierre coordinado; contadores/orden correctos | 1.1-1.5, 1.12-1.14, 1.24 |
| C: operacion fluida | P1 | Catalogos paginados/cacheados; errores/frescura visibles; sin respuestas obsoletas | 1.22, 1.23, 1.27 y contratos de A |
| D: triage util | P1 | Cola, agrupacion, decision/razon, consultas guardadas, caso local y export reproducible | A-C |
| E: deteccion medible | P1 | Replay, procedencia de labels, confusion matrix, holdout correcto, presupuesto IA | 1.20, 1.25 y telemetria |
| F: pulido/integracion | P2 | Idioma, accesibilidad, navegacion, integracion versionada y entrega reproducible | A-E |

No se asignan fechas artificiales sin conocer equipo, hardware y alcance de despliegue. Dimensionar A por cambios de contrato y migraciones, C por volumen real y D por necesidad local/multiusuario.

**Puerta de salida para una version de uso Blue Team local:** cero P0 abiertos; tests nuevos de identidad/tiempo/export/persistencia pasan; QA completo del build identificado; warnings de evidencia parcial visibles; no se pierde evidencia silenciosamente por limites; captura/retencion y cierre verificados en fixture; manual de operacion alineado con UI.

**Para despliegue compartido:** añadir identidad/autorizacion, concurrencia de decisiones, audit log, proteccion de exports, backup/restore y estrategia de actualizacion. No asumir que una version local cumple esos requisitos.

**Pruebas de usuario propuestas:** con evidencia sintetica, pedir a un analista localizar una alerta, justificarla con dos eventos, pivotar a host, registrar decision y exportar el caso. Medir tiempo, errores de atribucion, pasos repetidos y dudas de alcance. Comparar contra el mismo ejercicio antes/despues; una interfaz moderna debe reducir errores y esfuerzo, no solo cambiar colores.

## 10. Evidencia nueva y reproduccion

### 10.1 Pruebas ejecutadas en la ampliacion

```text
.venv/bin/python -m pytest tests/test_soc_qa.py tests/test_packet_ai.py tests/test_auth_hardening.py tests/test_api_hardening.py tests/test_packet_review.py -q
81 passed, 9 subtests passed in 38.06s

.venv/bin/python -m pytest tests/test_monitors.py::TestSnifferGatedPersistence tests/test_detection_scopes.py -q
44 passed in 90.42s
```

Son 125 pruebas seleccionadas aprobadas; no invalidan los dos fallos de la suite completa anterior. En particular, las pruebas actuales de persistencia pasan porque validan el comportamiento del motor que contradice los textos UI. No se repitio build ni toda la suite en esta ampliacion documental.

Pruebas temporales adicionales: `/tmp/s4h-deep-probes.py`, ejecutado con `.venv` y `PYTHONPATH` del repo. Crea/cierra una SQLite temporal, sin conectarse a la DB viva. Resultados confirmados: prefijo de IP mezclado; IP solo textual incluida; payload retenido omitido tras ruido; whitelist duplicada; dominio estructurado no encontrado por busqueda textual; alcance de export alerts ignorado; count agregado distinto de eventos consumidos.

La prueba de export usa un store simulado para aislar serializacion/filtrado; no es una descarga real del historial del operador. La omision de filtros se confirma tambien leyendo el camino UI -> API -> export.

### 10.2 Reproductor minimo durable para identidad IP

Ejecutar desde el repo con el entorno de pruebas instalado. No debe apuntar a una DB del operador. Se recomienda convertirlo en un test de regresion al corregir 1.18:

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from sniff4hound.store import SniffStore

with TemporaryDirectory(prefix="s4h-regression-") as directory:
    store = SniffStore(Path(directory) / "test.db")
    try:
        store.register_packet({
            "src_ip": "10.0.0.10", "dst_ip": "192.0.2.9",
            "src_port": 52000, "dst_port": 80, "proto": "tcp",
        })
        result = store.ip_intel("10.0.0.1")
        # Falla en el codigo auditado: devuelve 1.
        assert result["summary"]["packets"] == 0
    finally:
        store.close()
```

Para 1.19: insertar un paquete del host con `payload_text`/`banner_text`, consultar `ip_intel`, insertar 255 paquetes con payload de otro host, volver a consultar y contrastar `COUNT(*) FROM payloads WHERE packet_id = ?`. El contador del investigador cae de 1 a 0; el de almacenamiento permanece en 1.

Para 1.21: fixture de `list_recent_alerts` con IP A; llamar `build_export(..., "alerts", search=IP_B)`. Esperado cero, observado una fila agregada de A. Al corregir, ampliar al handler real y UI para evitar que el filtro vuelva a perderse en otra capa.

### 10.3 Evidencia UI y limites adicionales

Se utilizo el mismo target Electron CDP 9223. Se probaron 15M/ALL en Resumen y se restauro ALL; enlace IA -> Exclusiones reprodujo seleccion Capture. Medicion de frames WebSocket registro solo tamaños/tipo/path/numero de filas, sin publicar contenido del catalogo ni credenciales.

Capturas adicionales locales: `/tmp/s4h-deep-settings.png`, `/tmp/s4h-settings-1280.png`, `/tmp/s4h-settings-390.png`. Se inspecciono la captura estrecha; emulacion de viewport retirada al terminar cada captura. No se concluye soporte movil completo a partir de una pantalla.

No se hicieron pruebas de saturacion de red, intrusiones, envios externos, arranque de listeners, purgas, importacion de modelos ni modificaciones de listas en la sesion real. Las carreras HTTP, fallos de transporte, multiusuario, recuperacion ante corte electrico y rendimiento bajo carga quedan pendientes de fixture dedicado. No se promete haber probado cada combinacion de reglas/protocolos.

## 11. Referencias y criterio de diseño

Las siguientes fuentes primarias orientan las propuestas; no prueban que la aplicacion ya las cumpla:

- [NIST SP 800-61 Rev. 3, abril de 2025](https://csrc.nist.gov/pubs/sp/800/61/r3/final): sitúa la respuesta a incidentes dentro de la gestion de riesgo. La propuesta de casos/evidencia/decisiones es una adaptacion de producto, no una certificacion NIST.
- [Electron: seguridad](https://github.com/electron/electron/blob/main/docs/tutorial/security.md) y [sandbox de procesos](https://www.electronjs.org/docs/latest/tutorial/sandbox): referencias para renderer, bridge y empaquetado. [API shell](https://www.electronjs.org/docs/latest/api/shell) documenta la apertura de recursos en aplicaciones del sistema.
- [W3C WCAG 2.2, tamaño minimo del objetivo](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html): referencia de 24x24 CSS px con excepciones, incluyendo espaciado. [WCAG 2.2](https://www.w3.org/TR/WCAG22/) orienta la evaluacion de teclado, foco, contraste y zoom.

Las metas de rendimiento, arquitectura propuesta y orden de entregas son juicio tecnico de esta auditoria basado en el codigo y las mediciones locales, no requisitos normativos de esas fuentes.
