# Sniff4Hound - Informe FAQA / Revision QA

**Fecha:** 2026-09-19 (revision: 2026-09-27)

**Version observada:** `0.54.0` (`pyproject.toml`, `sniff4hound/__init__.py`, `desktop/package.json` y Electron `User-Agent`)

**Instancia viva revisada (2026-09-19):** Electron por CDP en `127.0.0.1:9223`, target `Sniff4Hound`, backend local en `http://127.0.0.1:45671/?code=...&desktop=1`

**Revision 2026-09-27:** revision estatica del repo tras PR #124-#128 (commits `b00345f` a `d473508`). Sin instancia Electron viva: CDP es opt-in y no hay sesion activa. Se ejecutaron suite backend (`1043 passed, 1 failed`) y frontend (`36 passed, 0 failed`) en entorno limpio. Se inspeccionaron estaticamente los cambios de cada PR y su relacion con hallazgos previos.

**Alcance (pase inicial):** revision estatica del repo, pruebas automatizadas backend/frontend, build frontend, recorrido interactivo de la ventana Electron ya corriendo por CDP (menus, pestañas, busqueda, detalles y mapas), capturas de pantalla y verificacion HTTP de rutas SPA/deep links.

**Nota de seguridad:** no se documenta el codigo de sesion observado.

**Ampliacion Blue Team:** 2026-09-19. Este documento es una auditoria y una especificacion de mejoras; las correcciones propuestas no estan implementadas salvo que se indique lo contrario. Los resultados del pase inicial se conservan, separados de las pruebas nuevas.

**Guia de lectura:** hallazgos verificables en seccion 1; evidencia y limites en 2; plan tecnico detallado en 6; experiencia Blue Team en 7; arquitectura/rendimiento en 8; entregas y criterios de salida en 9; reproducciones en 10; referencias en 11. Las prioridades P0/P1/P2 de la ampliacion son orden de trabajo, no equivalen a una clasificacion CVSS. Hallazgos marcados **[RESUELTO]** fueron cerrados en PRs posteriores al 2026-09-19.

> Convencion de severidad: **Critical** (explotable / caida fuerte), **High** (riesgo serio o bloqueo de release), **Medium** (defecto funcional o seguridad defensiva), **Low** (mantenibilidad/limpieza), **Info** (contexto o recomendacion).

---

## 0. Resumen ejecutivo

La app Electron esta accesible y operativa. El Dashboard monta correctamente y muestra telemetria real: `1415` paquetes almacenados, `37` hosts unicos, `10` protocolos, `1394` respuestas; Sniffer y Honeypot aparecen detenidos en la instancia viva (datos de la sesion 2026-09-19; no se midio una sesion nueva el 2026-09-27 por no haber instancia activa).

La revision inicial no pudo considerarse "aprobada limpia". El problema mas visible era que varias rutas del router de Vue devolvian `404` en carga directa. **Ese problema fue resuelto** en los cinco PRs que siguieron (#124-#128): el router migro a `createWebHashHistory` —eliminando por completo la dependencia de rutas backend para la navegacion SPA— y la suite frontend paso de 0 tests corriendo a 36/36. CDP paso de opt-out a opt-in. `openExternal` recibio allowlist de protocolos. El contador de protocolos y el etiquetado del mapa se corrigieron. El script QA CDP se actualizo al puerto y rutas reales.

**Conclusion de la revision profunda (vigente):** la prioridad Blue Team sigue siendo corregir la integridad de la investigacion y la visibilidad. Se reproducen mezcla de IPs distintas, evidencia retenida que desaparece del investigador, alertas fuera del periodo seleccionado y exportaciones de alertas que ignoran el host buscado. Dos textos de configuracion contradicen decisiones de descarte del motor. Settings carga un catalogo de monitores de 42,9 MB por WebSocket. Estos problemas (1.17-1.29) siguen abiertos.

La base permite evolucionar: hay evidencia por monitor, limites y metadatos en varias APIs, SQL parametrizado, proteccion CSV, control de origen/autenticacion, retencion diferenciada y fallback de WebSocket a HTTP. La propuesta es conservarlos y hacer consistente su contrato en toda la app.

**Estado de suites al 2026-09-27:** backend `1043 passed, 1 failed (intermitente), 2 skipped, 316 subtests passed`; frontend `36 passed, 0 failed`. El unico fallo backend (`test_purge_no_longer_runs_a_whole_file_vacuum`) pasa en aislamiento; es sensible al orden de ejecucion de la suite completa. La version sigue en `0.54.0` en todos los componentes.

**Novedad funcional:** se incorporo el flujo de streaming movil por QR (PR #125, corregido en #128): servidor TLS local, emparejamiento en dos pasos con aprobacion del operador, redaccion de payloads y revocacion dirigida por sesion. El fix #124 corrige que una interfaz silenciosa acumule errores de socket y abandone la captura prematuramente. El fix #122 elimina los "falsos vacios" en carga inicial (skeleton loaders, `loading: true` por defecto).

---

## 1. Hallazgos abiertos

> **Actualizacion 2026-09-27:** los hallazgos marcados **[RESUELTO]** o **[COMPORTAMIENTO CAMBIADO]** fueron cerrados en PRs #113-#128. Los marcados **[PARCIALMENTE RESUELTO]** tienen avance pero requieren trabajo adicional. El resto permanece abierto. Se agregan hallazgos nuevos en la seccion 1.30-1.33.

### 1.1 Medium - Rutas SPA nuevas devuelven 404 en carga directa — **[RESUELTO #126]**

**Estado:** resuelto. Migrado a `createWebHashHistory` en `desktop/frontend/src/router/index.js`. El fragmento hash nunca llega al servidor, por lo que el backend ya no necesita una lista de rutas SPA para responder `200`. El catch-all `/:pathMatch(.*)*` ahora redirige a `/` dentro del router en lugar de depender de `SPA_ROUTES` en el backend. La prueba `test_every_vue_router_path_is_in_spa_routes` fue eliminada (ver 1.2).

**Evidencia dinamica contra la app viva (`127.0.0.1:45671`, 2026-09-19):**

```text
404 /ai/overview
404 /ai/neural-network
404 /dashboard/overview
404 /dashboard/node-map
404 /dashboard/live-map
```

**Causa resuelta:** `createWebHashHistory` hace que la ruta viva en el fragmento `#/ai/overview`; el servidor solo recibe `GET /` y sirve el `index.html` de siempre. La eliminacion de `SPA_ROUTES` del flujo es consecuencia directa del cambio de historial, no un parche adicional.

### 1.2 Medium - Prueba de regresion de rutas SPA esta obsoleta — **[RESUELTO #126]**

**Estado:** resuelto. La prueba `test_every_vue_router_path_is_in_spa_routes` fue eliminada del repo. Dado que el router ahora usa hash history y el backend ya no mantiene una lista de rutas SPA, la prueba deja de tener objeto. La regresion de deep links queda prevenida por el propio mecanismo de hash routing: no hay lista que mantener sincronizada.

**Evidencia:** `grep -rn "test_every_vue_router_path_is_in_spa_routes" tests/` no encuentra ningun resultado en el arbol actual.

### 1.3 Medium - `npm test` falla bajo Node 24 — **[RESUELTO #126]**

**Estado:** resuelto. `desktop/frontend/src/router/index.js` ahora importa `../utils/runtimeEnv.js` con extension explicita. Ademas el runner de tests usa `node:test` nativo (no vitest/jest), por lo que la resolucion de modulos sigue las reglas ESM de Node.

**Resultado actual:** `npm test` (dentro de `desktop/frontend/`) ejecuta lint + 36 tests unitarios, todos pasando, sin errores. El runner cubre `jobs.test.js`, `list-actions.test.js`, `loading-states.test.js`, `navigation.test.js` y `soc-qa.test.js`.

### 1.4 Low - Suite backend depende de usar el entorno correcto

**Estado:** abierto/documental (no cambio en codigo).

**Evidencia:** `python -m pytest tests/ -q` con Python global falla durante collection por `ModuleNotFoundError: No module named 'wsbuilder'`. Con el entorno correcto (venv que incluya wsbuilder y sniff4hound instalado con `pip install -e .`), la suite arranca y llega al final.

**Resultado con entorno correcto (2026-09-27):**

```text
1 failed, 1043 passed, 2 skipped, 316 subtests passed
```

(El fallo es `test_purge_no_longer_runs_a_whole_file_vacuum`, intermitente; pasa en aislamiento.)

**Recomendacion:** documentar en `README.md`/`FAQA.md` que QA local requiere instalar el paquete en modo desarrollo antes de correr pytest. Si CI usa otro comando, alinearlo.

### 1.5 Low - Fallo intermitente de limpieza de temporales en tests

**Estado:** abierto/observado. No se observo en la ejecucion del 2026-09-27, pero sigue sin correccion explicita.

**Evidencia (2026-09-19):** `TestTrainingAndAiAlertModes.test_training_plus_ai_mode_leaves_the_catalog_in_charge` fallo en `tearDown`:

```text
OSError: [Errno 39] Directory not empty: '/tmp/...'
```

**Nota 2026-09-27:** el test pasa en aislamiento y no aparecio como fallo en la ejecucion completa de esta fecha. La intermitencia dificulta su reproduccion y correccion. El worker de entrenamiento (1.24) sigue siendo el candidato principal como causa.

**Recomendacion:** revisar hilos/timers/handles que quedan vivos en ese test o hacer que el teardown espere/cierre explicitamente writers antes de `TemporaryDirectory.cleanup()`. Ver 1.24.

### 1.6 Low - Versiones/documentacion desalineadas

**Estado:** parcialmente resuelto. La inconsistencia de version original era: FAQA documentaba `v0.59.0`, el frontend `desktop/frontend/package.json` declaraba `1.0.0` mientras backend y desktop declaraban `0.54.0`. Al 2026-09-27, el frontend ya declara `0.54.0` al igual que backend y desktop: las tres versiones estan alineadas.

**Pendiente:** el FAQA anterior usaba `v0.59.0` (numero superior al real), lo que sugeria que la version del paquete no se actualiza consistentemente con cada release. No hay evidencia de un bump de version entre la primera revision y esta.

**Recomendacion:** documentar el flujo de bump de version (quien actualiza, cuando y en que archivos) para que no vuelvan a desalinearse entre componentes ni con los informes QA.

### 1.7 Low - Documentacion historica con afirmaciones stale

**Estado:** abierto.

**Evidencia:** `ARCHITECTURE.md` todavia dice que el token se persiste en `localStorage`, mientras `README.md` y el codigo actual indican token en memoria y limpieza de storage legado. `CHANGELOG.md` tambien conserva entradas historicas sobre localStorage.

**Recomendacion:** actualizar `ARCHITECTURE.md` para no contradecir el modelo de auth actual. En `CHANGELOG.md` puede quedarse como historia, pero conviene evitar que parezca comportamiento actual.

### 1.8 Info/Seguridad - CDP Electron siempre abierto — **[COMPORTAMIENTO CAMBIADO #113]**

**Estado:** resuelto como riesgo. CDP es ahora **opt-in**: esta cerrado por defecto y solo se abre si el operador define `SNIFF4HOUND_DESKTOP_DEBUG_PORT=<puerto>` antes de arrancar la app.

**Cambio:** en PR #113 (`128c239`) el valor por defecto paso de puerto `9223` (requeria `=0/false/off/no` para desactivar) a `0` (requiere un numero de puerto explicito para activar). `AGENTS.md` actualizo la descripcion a "opt-in, off by default".

**Impacto residual:** con CDP activado, cualquier proceso local puede controlar la ventana Electron por CDP. Sigue siendo un factor a considerar en despliegues multiusuario. La opcion de activarlo es deliberada y util para QA/automatizacion.

**Nota:** la instancia del 2026-09-27 no tiene CDP abierto (no hay sesion activa ni variable de entorno); la verificacion de esta revision es estatica.

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

### 1.10 Low - Pase visual actual no cubre todas las rutas reales ni el puerto Electron — **[RESUELTO #126]**

**Estado:** resuelto. `scripts/qa_visual_pass.js` fue actualizado: usa `9223` por defecto (con `QA_CDP_PORT` para sobreescribir), incluye las rutas anidadas `/ai/overview`, `/ai/neural-network`, `/dashboard/overview`, `/dashboard/node-map` y `/dashboard/live-map`, y el propio comentario en el archivo cita explicitamente el hallazgo 1.10 como razon del cambio.

**Nota:** dado que CDP es ahora opt-in, el script QA requiere que el operador arranque Electron con `SNIFF4HOUND_DESKTOP_DEBUG_PORT=9223` para que el pase visual funcione. La configuracion es la esperada para un entorno QA deliberado.

### 1.11 Low - `openExternal` de Electron no valida esquema — **[RESUELTO #126]**

**Estado:** resuelto. `desktop/main.js` define `ALLOWED_EXTERNAL_PROTOCOLS = new Set(["http:", "https:", "mailto:"])` y la funcion `isAllowedExternalUrl(url)` valida el esquema antes de cada llamada a `shell.openExternal`. Los handlers `setWindowOpenHandler` y `preload.js::openExternal` pasan por la misma validacion. Esquemas como `file:`, `javascript:` y `data:` son rechazados.

### 1.12 Medium - Resumen limita incorrectamente el contador de protocolos a ocho — **[RESUELTO #126]**

**Estado:** resuelto. `DashboardView.vue` separa ahora `protocolSeries` (chart, `.slice(0, 8)`) de `protocolCount` (tarjeta de estadistica, `ports_by_proto.length` sin recorte). El comentario en `protocolSeries` cita explicitamente el hallazgo 1.12. El total mostrado en la tarjeta refleja ahora el numero real de protocolos observados, independientemente de cuantos dibuje el grafico.

### 1.13 Medium - Mapa etiqueta paquetes como servicios activos — **[PARCIALMENTE RESUELTO #126]**

**Estado:** parcialmente resuelto. La tarjeta de metrica en el mapa renombra el indicador a "Open-port packets" con un comentario que describe exactamente la limitacion (cuenta filas con `state='open'`, no servicios distintos). Sin embargo, el encabezado de tabla que sigue al mismo dato aun dice `Active services` (`MapPanel.vue:410`).

**Impacto residual:** el encabezado de tabla sigue siendo semanticamente incorrecto. El contexto del metric card ahora es correcto y ayuda al operador a entender el numero. Queda pendiente unificar el encabezado de tabla al mismo vocabulario ("Open-port packets" o "Paquetes con puerto abierto").

**Recomendacion:** cambiar `<th>Active services</th>` a un encabezado coherente con la definicion documentada. Una vez alineado el vocabulario, documentar en la seccion de observabilidad (8.3) la distincion entre paquetes, flujos y servicios inferidos.

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

**Estado:** parcialmente resuelto (estados de carga); idioma y protocolo por defecto pendientes.

**Parte resuelta (#122):** el "falso vacio" en carga inicial fue corregido. `MonitorsView.vue` ahora inicializa `loading: true` y muestra un skeleton loader mientras la respuesta no llega (`v-else-if="loading"` con `v-skeleton-loader`). El comentario en el codigo cita explicitamente finding 1.16. El `loading-states.test.js` añadido en #122 cubre esta regresion en todas las vistas afectadas.

**Sigue abierto:**
- Dashboard principal y Chat usan español; Settings, SOC y tablas usan mayormente ingles. Settings mezcla pestañas inglesas con IA y Arquitectura en español.
- Protocols abre por defecto `Unknown` con cero filas aunque DNS tiene 898 y HTTP 217.

**Recomendacion:** elegir un protocolo con trafico al abrir el atlas; unificar idioma en toda la UI o añadir selector de idioma con catalogo centralizado.

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

### Nuevos hallazgos incorporados en la revision 2026-09-27 (1.30-1.33)

#### 1.30 Low - Encabezado de tabla del mapa sigue diciendo "Active services"

**Evidencia estatica:** `MapPanel.vue:410` tiene `<th>Active services</th>` como encabezado de la columna que muestra `total_open_ports` (paquetes con `state='open'`). La tarjeta de metrica sobre la tabla fue corregida a "Open-port packets" en #126, pero el `<th>` no se actualizo. Ver 1.13.

**Impacto:** inconsistencia semantica menor; el operador puede interpretar el encabezado de tabla como la definicion correcta cuando la tarjeta dice algo distinto.

**Recomendacion:** cambiar `<th>Active services</th>` a `<th>Open-port packets</th>` o al vocabulario acordado.

#### 1.31 Low - Suite backend muestra variacion de recuento entre ejecuciones

**Evidencia:** dos ejecuciones completas en la misma maquina y misma revision dieron `1043 passed, 1 failed` y `1046 passed, 0 failed`. La diferencia de 3 tests y el fallo intermitente en `test_purge_no_longer_runs_a_whole_file_vacuum` sugieren sensibilidad al orden de ejecucion o a estado compartido entre tests.

**Impacto:** un resultado "rojo" no es concluyente si el mismo test pasa en aislamiento. Dificulta la revision de CI y la deteccion de regresiones reales.

**Recomendacion:** identificar si los tests afectados comparten fixtures de BD/filesystem, y aislarlos o serializar su ejecucion. Registrar el recuento exacto en cada run de CI con el hash del commit como referencia.

#### 1.32 Info - Nueva superficie de red: servidor TLS de streaming movil

**Evidencia:** PR #125 introduce `MobileStreamService` que abre un servidor HTTP/HTTPS independiente en un puerto configurable (default `45679`). El servidor escucha en la interfaz seleccionada, no solo en loopback. Usa un certificado TLS autofirmado gestionado por `sniff4hound/tls.py`. El codigo QR apunta a `https://<ip-local>:<puerto>/mobile/pair/<pairing_id>`.

**Consideraciones:**
- El certificado autofirmado requiere que el movil instale la CA del servidor o ignore advertencias TLS; el flujo actual presenta la CA para descarga en `/publicca`.
- El servidor solo esta activo cuando el operador lo arranca explicitamente; no hay autoarranque.
- Los eventos transmitidos al movil estan redactados (`_public_event` omite `value`).
- La aprobacion del operador es requerida antes de emitir el codigo de seis digitos.
- La vinculacion IP del codigo impide que otro dispositivo lo use aunque obtenga el enlace.

**Pendiente de auditoria completa:** validar que el servidor rechaza requests sin token valido desde la red, que la CA exportable no se comparte inadvertidamente, y que el servidor no queda en estado activo tras un cierre anormal del backend principal.

#### 1.33 Low - `test_every_vue_router_path_is_in_spa_routes` eliminado sin test de reemplazo documentado

**Evidencia:** el test fue eliminado al migrar a hash routing (1.2 resuelto). La regresion de deep links queda prevenida por el mecanismo de hash, que es correcto. Sin embargo, no hay un test que verifique que el router usa `createWebHashHistory` (y no `createWebHistory` que volveria a introducir la dependencia de backend). `navigation.test.js` cubre nav-links y busqueda pero no el tipo de historial del router.

**Impacto:** bajo. Un cambio accidental de `createWebHashHistory` a `createWebHistory` volveria a introducir 404 en deep links sin ningun test que lo detecte.

**Recomendacion:** agregar una asercion en `navigation.test.js` (o un nuevo test) que importe el router y verifique que su modo de historial es hash/memory (no HTML5 pushState).

## 2. Validacion ejecutada

### 2.1 Electron/CDP

- `GET http://127.0.0.1:9223/json/version`: OK, Electron `38.8.6`, app `sniff4hound-desktop/0.54.0`.
- `GET http://127.0.0.1:9223/json/list`: OK, target `Sniff4Hound`.
- Lectura DOM por WebSocket CDP: OK, Dashboard montado con datos reales.

### 2.2 Backend

- `python -m pytest tests/ -q`: fallo por entorno global sin `wsbuilder`.
- `.venv/bin/python -m pytest tests/ -q`: ejecuta suite completa y termina con `2 failed, 935 passed, 2 skipped, 316 subtests passed`. (Estado al 2026-09-19; ver 2.6 para resultado actualizado.)

### 2.3 Frontend (2026-09-19)

- `cd frontend && npm run build`: OK.
- `cd frontend && npm test`: falla en `npm run test:unit` por resolucion ESM de `../utils/runtimeEnv`.
- `npm run lint` dentro de `npm test`: no reporto errores antes del fallo unitario. (Estado al 2026-09-19; ver 2.7 para resultado actualizado.)

### 2.4 Deep links SPA (2026-09-19)

Se probaron rutas principales con `curl` contra el backend Electron vivo. Las rutas top-level principales responden `200`; las rutas nuevas anidadas de IA/Dashboard responden `404` y deben entrar a `SPA_ROUTES`. (Resuelto por hash routing; ver 1.1.)

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

### 2.6 Suite backend (2026-09-27)

Ejecutada con Python del venv que incluye `wsbuilder` y `sniff4hound` instalado en modo desarrollo.

```
# ejecucion 1:
1 failed, 1043 passed, 2 skipped, 316 subtests passed in 916s
# FAILED tests/test_store_recovery.py::PurgeDoesNotWedgeOtherConnectionsTests::test_purge_no_longer_runs_a_whole_file_vacuum
# (pasa en aislamiento: 1 passed in 7.86s)

# ejecucion 2 (mismo commit, misma maquina):
1046 passed, 2 skipped, 316 subtests passed in 943s
```

El fallo es intermitente y sensible al orden de ejecucion (ver 1.31). La variacion de 1043 a 1046 tests pasantes entre ejecuciones esta bajo investigacion; la mas probable causa es que 3 tests dependen de estado externo o compiten con otros tests en escritura de disco. Sin el fallo, la suite esta limpia.

Mejora respecto a 2026-09-19: `2 failed, 935 passed` → `0-1 failed (intermitente), 1043-1046 passed`. Se añadieron aproximadamente 111 tests (netos).

### 2.7 Suite frontend (2026-09-27)

Ejecutada con `npm test` desde `desktop/frontend/`:

```
✔ 36 tests pass (lint + 5 archivos de test unitario)
ℹ tests 36 | pass 36 | fail 0 | duration_ms ~2500
```

Archivos de test: `jobs.test.js`, `list-actions.test.js`, `loading-states.test.js`, `navigation.test.js`, `soc-qa.test.js`. El fallo ESM de import `runtimeEnv` (1.3) esta resuelto.

Mejora respecto a 2026-09-19: `0 tests pasando (fallo de import en carga)` → `36 tests pasando`.

### 2.8 Revision estatica de PRs #124-#128 (2026-09-27)

Sin instancia Electron activa (CDP opt-in desactivado). Se verificaron estaticamente:

| PR | Cambio principal | Verificacion |
| --- | --- | --- |
| #124 | `consecutive_socket_errors` se reinicia en timeout de socket | `sniffer.py:1161` + test `test_a_quiet_interface_does_not_accumulate_towards_giving_up` |
| #125 | `MobileStreamService`: servidor TLS, pairings, SSE, eventos redactados | `mobile_stream.py` + `tests/test_mobile_stream.py` (103 tests iniciales) |
| #126 | Hash routing, ESM fix, openExternal allowlist, contadores, UX | Cambios en `router/index.js`, `main.js`, `DashboardView.vue`, `MapPanel.vue` |
| #127 | UX MapPanel, ProtocolsView, NeuralNetworkView, AiHubView | Cambios visuales; no rompen logica de datos |
| #128 | Aprobacion en dos pasos, redaccion de `value`, revoke dirigido | `mobile_stream.py` + `tests/test_mobile_stream.py` (209 tests ampliados) |

---

## 3. Recomendaciones priorizadas

> **Actualizacion 2026-09-27:** los items 1, 2, 3, 8, 9 y 10 fueron resueltos en PRs #113-#128. El item 11 fue parcialmente resuelto (1.12 cerrado; 1.13 encabezado de tabla pendiente). La lista se actualiza a continuacion con el estado actual.

**Resueltos (#113-#128):**

1. ~~Corregir deep links: agregar rutas faltantes a `SPA_ROUTES`~~ → **resuelto** por migrar a `createWebHashHistory` (#126).
2. ~~Rehacer el test de rutas SPA~~ → **resuelto** por eliminar el test obsoleto (#126).
3. ~~Arreglar `npm test`~~ → **resuelto** con `.js` en imports y 36 tests pasando (#126).
8. ~~Documentar CDP 9223~~ → **resuelto** como opt-in (#113); AGENTS.md actualizado.
9. ~~Actualizar scripts QA visuales~~ → **resuelto** en `qa_visual_pass.js` (#126).
10. ~~Endurecer Electron bridge~~ → **resuelto** con `ALLOWED_EXTERNAL_PROTOCOLS` (#126).
11. ~~Corregir metricas visibles (1.12)~~ → **resuelto** (#126); encabezado de tabla 1.13 pendiente.

**Pendientes (en orden de prioridad):**

1. **[P0] Corregir encabezado "Active services" en tabla del mapa** (1.13/1.30): cambiar `<th>Active services</th>` a vocabulario coherente con la tarjeta de metrica.
2. **[P0] Entidades exactas en investigador IP y dominio** (1.17-1.19, 1.29): filtros por campo estructurado, limites aplicados despues de predicado, paginacion con `total_available`.
3. **[P0] Periodo del Dashboard debe filtrar alertas IA** (1.17): propagar contexto temporal al endpoint `/api/ai/packets/`.
4. **[P0] Exportacion de alertas con alcance correcto** (1.21): `build_export` debe pasar `search`/entidad a `_alert_rows`.
5. **[P0] Alinear textos UI con comportamiento real del motor** (1.20): rotulos de conservation y whitelist deben describir lo que el codigo hace.
6. **[P1] Corregir el fallo intermitente de teardown / suite** (1.5, 1.31): aislar tests que compiten por recursos de BD/filesystem.
7. **[P1] Catalogo de monitores paginado en Settings** (1.23): evitar transferir 42 MB por apertura de pestaña.
8. **[P1] Coordinacion del worker de entrenamiento** (1.24): sentinel de cierre, join acotado, contadores.
9. **[P1] Metricas de IA operacionalmente significativas** (1.25): confusion matrix, recall de maliciosos, baseline.
10. **[P1] Prevenir respuestas de contexto anterior en Dashboard** (1.27): numero de revision de consulta, cancelar peticiones obsoletas.
11. **[P2] Actualizar docs stale** (1.7): `ARCHITECTURE.md` sobre auth/localStorage.
12. **[P2] Cerrar hallazgos de UX** (1.14-1.16, 1.26, 1.28): orden de alertas, duplicados en listas, idioma, link de exclusiones, areas de interaccion.
13. **[P2] Auditar nueva superficie movil** (1.32): revisar que el servidor rechaza requests sin token, gestion de CA exportable y cierre limpio.
14. **[P2] Agregar test de tipo de historial del router** (1.33): asegurar que hash history no se revierte accidentalmente.

---

## 4. Cobertura por modulo revisado

- **Backend API/runtime (`sniff4hound/app.py`, `runtime_controller.py`, `manage.py`, `capture_service.py`):** auth guards, origin guard, tickets WebSocket, rutas SPA, endpoints mutantes y arranque/cierre. *(2026-09-27)* Nueva superficie: `mobile_stream.py` (MobileStreamService, 9 nuevos endpoints `/api/mobile-stream/*`). Hallazgos de SPA resueltos por hash routing.
- **Persistencia (`store.py`, `export.py`, `access_log.py`):** retencion raw, listados IA, purga por IP, exports y logs. *(2026-09-27)* Purge cambiado a VACUUM incremental en lugar de VACUUM completo (#120). No se encontro inyeccion SQL directa; queries parametrizadas en rutas sensibles. Hallazgos 1.17-1.22 siguen abiertos.
- **Captura/deteccion (`sniffer.py`, `honeypot.py`, `monitors.py`, `rulesets.py`, `regex_safety.py`, `anomaly.py`, `packet_ai.py`, `ai_learning.py`):** cache de monitores, whitelist/exclusion, entrenamiento IA, throttling y retencion. *(2026-09-27)* Fix #124 para quiet interfaces. Fallo intermitente de teardown (1.5) y coordinacion del worker de entrenamiento (1.24) siguen abiertos.
- **Frontend SPA (`desktop/frontend/src/router`, `state`, `views`, `components`):** router migrado a `createWebHashHistory`, auth en memoria, WS GET fallback, vistas principales y componentes. *(2026-09-27)* Import ESM resuelto; 36 tests pasando. Nuevas vistas: `SettingsView.vue` con seccion de streaming movil. Hallazgos de evidencia/investigador (1.17-1.29) siguen abiertos.
- **Desktop Electron (`desktop/main.js`, `preload.js`):** launcher backend, conexion remota, CDP opt-in, navegacion y bridge. *(2026-09-27)* CDP ahora opt-in (#113). `openExternal` con allowlist de protocolos (#126). Sandbox desactivado por empaquetado: pendiente de evaluacion; no se agrego a esta revision.
- **Streaming movil (`sniff4hound/mobile_stream.py`, `sniff4hound/tls.py`):** *(nuevo 2026-09-27)* Servidor TLS independiente, pairings en dos pasos, SSE, redaccion de payloads, revocacion dirigida. Auditoria de superficie de red en 1.32 pendiente.
- **Scripts/QA/packaging (`scripts/*.sh`, `scripts/*.js`, `scripts/*.py`):** build Debian, postinst/postrm, QA CDP, limpieza local. *(2026-09-27)* `qa_visual_pass.js` actualizado a rutas y puerto correctos (#126). Limpieza de build/caches sigue sin cubrir `clean_artifacts.sh`.
- **Docs/config/versionado (`README.md`, `ARCHITECTURE.md`, `FAQA.md`, package metadata):** *(2026-09-27)* Version `0.54.0` consistente en todos los componentes. `ARCHITECTURE.md` con nota stale sobre localStorage sigue pendiente (1.7).

---

## 5. Estado final

**Estado al 2026-09-19 (historico):** No aprobado limpio. Deep links rotos, `npm test` roto, suite backend con 2 fallos.

**Estado al 2026-09-27:** Mejora significativa en infraestructura de QA y seguridad del bridge Electron. Los problemas de navegacion, tests y bridge quedan resueltos. La app corre con las rutas correctas, la suite frontend pasa limpia (36/36) y la backend pasa con variacion intermitente (1043-1046 passed, 0-1 failed en distintas ejecuciones).

Los P0 de integridad de datos (hallazgos 1.17-1.21, 1.29) siguen abiertos. No hay evidencia suficiente para declarar la app lista como consola SOC de produccion: la mezcla de entidades en el investigador, el filtrado temporal incompleto de alertas IA y la exportacion que ignora el objetivo son defectos que afectan directamente la confiabilidad de la evidencia presentada al analista.

**Puerta de salida recomendada para uso Blue Team local:** cerrar los P0 de seccion 3, ejecutar suite completa con 0 fallos deterministas, QA interactivo del build identificado (con CDP opt-in activado deliberadamente), y actualizar este documento con los resultados.

**Nueva funcionalidad a auditar:** el servidor de streaming movil (1.32) representa una nueva superficie de red que requiere revision de acceso, gestion de CA y cierre limpio antes de usarse en un entorno con trafico real.

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

> **Actualizacion 2026-09-27:** columna de estado añadida.

| Hallazgo | Trabajo concreto | Estado (2026-09-27) | Verificacion |
| --- | --- | --- | --- |
| 1.1 / 1.2 | Inventario compartido de rutas estaticas; añadir cinco rutas faltantes. Si se usa fallback SPA, limitarlo a navegacion HTML conocida. Reemplazar regex fragil. | **RESUELTO** por hash routing | Hash siempre sirve `/` al servidor; test obsoleto eliminado. |
| 1.3 | Extension `.js` en import local; revisar imports en Node. | **RESUELTO** | `npm test` 36/36; `runtimeEnv.js` con extension. |
| 1.4 / 1.5 | Entorno de QA reproducible y cierre ordenado de workers. | **PARCIAL** (1.4 doc; 1.5 sin fix) | Suite limpia en un run, fallo intermitente en otro; ver 1.31. |
| 1.6 / 1.7 | Fuente unica de version; docs de auth actualizadas. | **PENDIENTE** | Version `0.54.0` consistente pero `ARCHITECTURE.md` stale. |
| 1.10 | QA CDP configurable a 9223; inventario de rutas correcto. | **RESUELTO** | `qa_visual_pass.js` actualizado. |
| 1.12 / 1.13 | Contadores desde consulta completa; servicios con semantica definida. | **1.12 RESUELTO; 1.13 PARCIAL** | `<th>Active services</th>` sigue en tabla. |
| 1.14 / 1.26 | Orden temporal/score explicito; pestaña en query string. | **PENDIENTE** | Sin cambio. |
| 1.15 | Unicidad por lista/tipo/valor normalizado; conflicto de etiquetas visible. | **PENDIENTE** | Sin cambio. |
| 1.30 | Cambiar `<th>Active services</th>` a vocabulario coherente. | **PENDIENTE (nuevo)** | `MapPanel.vue:410`. |
| 1.31 | Identificar tests con estado compartido; aislar o serializar. | **PENDIENTE (nuevo)** | Run reproducible sin variacion de recuento. |
| 1.33 | Agregar test que verifique que el router usa hash history. | **PENDIENTE (nuevo)** | `navigation.test.js` o nuevo test. |

### 6.4 Seguridad defensiva y evidencia hostil (P1)

El contenido capturado puede contener credenciales, HTML malicioso, comandos o enlaces de phishing. La consola debe tratarlo como datos incluso cuando procede del propio backend.

- Mantener renderizado como texto, limites de payload y acciones explicitas para abrir URLs. No se encontraron usos de `v-html`/`innerHTML` en el barrido de frontend realizado; esto no equivale a una prueba completa de ausencia de XSS.
- `desktop/main.js`: *(2026-09-27)* `ALLOWED_EXTERNAL_PROTOCOLS` y `isAllowedExternalUrl` ya implementados (#126); `openExternal` resuelto. Pendiente: validacion de sender del IPC y sandbox de renderer.
- Evaluar restaurar sandbox de renderer arreglando empaquetado/plataforma; documentar excepciones reales. Mantener `contextIsolation`, bridge minimo y navegacion restringida. La guia oficial de Electron es la referencia, no el comentario de que el costo es "modesto".
- CDP: *(2026-09-27)* ahora opt-in; el riesgo de apertura inadvertida queda eliminado. Evitar distribuir secretos en capturas/logs si se activa para QA.
- *(Nuevo 2026-09-27)* **Superficie movil** (1.32): validar que el servidor de streaming rechaza requests sin token, que la CA exportable no se expone fuera del flujo de emparejamiento, y que el servidor cierra limpiamente al parar el backend principal. El servidor escucha en la interfaz de red, no en loopback; cualquier dispositivo en la misma red puede alcanzar el endpoint de emparejamiento antes de que el operador lo apruebe.
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

> **Actualizacion 2026-09-27:** entrega B cerrada en gran parte por PRs #113-#128. Columna de estado añadida.

| Entrega | Prioridad | Resultado comprobable | Estado (2026-09-27) | Dependencias |
| --- | --- | --- | --- | --- |
| A: evidencia fiable | P0 | Entidades exactas; filtros temporales consistentes; evidencia paginada; export con mismo alcance; semantica de descarte explicita | **Pendiente** | Hallazgos 1.17-1.21 y 1.29 |
| B: base verificable | P0/P1 | Deep links y tests verdes; cierre coordinado; contadores/orden correctos | **Mayormente cerrado** (1.1-1.3, 1.8, 1.10-1.12 resueltos; 1.5/1.13 parciales) | 1.1-1.5, 1.12-1.14, 1.24 |
| C: operacion fluida | P1 | Catalogos paginados/cacheados; errores/frescura visibles; sin respuestas obsoletas | **Pendiente** | 1.22, 1.23, 1.27 y contratos de A |
| D: triage util | P1 | Cola, agrupacion, decision/razon, consultas guardadas, caso local y export reproducible | **Pendiente** | A-C |
| E: deteccion medible | P1 | Replay, procedencia de labels, confusion matrix, holdout correcto, presupuesto IA | **Pendiente** | 1.20, 1.25 y telemetria |
| F: pulido/integracion | P2 | Idioma, accesibilidad, navegacion, integracion versionada y entrega reproducible | **Pendiente** | A-E |
| G: streaming movil | P2 | Servidor rechaza requests sin token; CA no expuesta innecesariamente; cierre limpio | **Nuevo / sin auditar** | 1.32 |

No se asignan fechas artificiales sin conocer equipo, hardware y alcance de despliegue. Dimensionar A por cambios de contrato y migraciones, C por volumen real y D por necesidad local/multiusuario.

**Puerta de salida para una version de uso Blue Team local:** cero P0 abiertos; tests nuevos de identidad/tiempo/export/persistencia pasan; QA completo del build identificado (con `SNIFF4HOUND_DESKTOP_DEBUG_PORT=9223` deliberado); warnings de evidencia parcial visibles; no se pierde evidencia silenciosamente por limites; captura/retencion y cierre verificados en fixture; manual de operacion alineado con UI.

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

### 10.4 Validacion estatica de PRs #124-#128 (revision 2026-09-27)

Sin instancia Electron activa (CDP opt-in desactivado). Revision estatica del diff y de los tests introducidos por cada PR.

**#124 - Quiet interface error counter**
- `sniff4hound/sniffer.py:1161`: `consecutive_socket_errors = 0` en el bloque `except socket.timeout`.
- Test nuevo: `tests/test_comprehensive.py::test_a_quiet_interface_does_not_accumulate_towards_giving_up` (interleaves 3 errores con timeouts contra limite 2; pasa).

**#125 + #128 - QR mobile stream**
- `sniff4hound/mobile_stream.py`: `PAIRING_APPROVAL_TTL_SECONDS = 300`, `PAIRING_TTL_SECONDS = 60`. `open_pairing` solo registra el intent; `approve_pairing` emite el codigo. `_public_event` omite `value` con comentario explicito. `_notify_all(..., token=session.token)` en `revoke_session`.
- `_public_event` verificado: construye `public_tags` con solo `key` y `severity`; ningun `value` sale del servidor.
- `revoke_session`: llama `_notify_all(event, token=session.token)`; la sesion revocada sigue recibiendo su propio evento (excepcion explícita en `_notify_all`).
- `tests/test_mobile_stream.py`: ampliado de 103 a 209 tests tras #128. Cubre aprobacion, vinculacion por IP, redaccion, revoke dirigido y TTL.

**#126 - Hash routing + UX + security**
- `desktop/frontend/src/router/index.js:1`: import de `createWebHashHistory`; usado en `createRouter`.
- `desktop/frontend/src/router/index.js:2`: import `runtimeEnv.js` con `.js` explicito.
- `desktop/main.js:78`: `ALLOWED_EXTERNAL_PROTOCOLS = new Set(["http:", "https:", "mailto:"])`.
- `desktop/frontend/src/views/DashboardView.vue:334`: `protocolCount` usa `ports_by_proto.length` sin recorte.
- `desktop/frontend/src/components/MapPanel.vue:398`: tarjeta renombrada a "Open-port packets"; `<th>Active services</th>` sin cambio (1.30 pendiente).
- `scripts/qa_visual_pass.js`: puerto `9223`, rutas anidadas añadidas.
- Suite frontend: `npm test` 36/36.

**#127 - UX tightening**
- Cambios visuales en MapPanel, ProtocolsView, NeuralNetworkView, AiHubView. Sin impacto en logica de datos ni contratos de API.

**Suite backend post-#128:**
```
# Run 1:
1 failed (intermitente), 1043 passed, 2 skipped, 316 subtests passed in 916s
# FAILED: test_store_recovery.py::PurgeDoesNotWedgeOtherConnectionsTests::test_purge_no_longer_runs_a_whole_file_vacuum
# (pasa en aislamiento en 7.86s)

# Run 2:
1046 passed, 2 skipped, 316 subtests passed in 943s
```

Hallazgos previos 1.18, 1.19 y 1.21 no se re-ejecutaron con el reproductor minimo de 10.2 en esta revision; siguen sin correccion y el reproductor sigue siendo valido.

## 11. Referencias y criterio de diseño

Las siguientes fuentes primarias orientan las propuestas; no prueban que la aplicacion ya las cumpla:

- [NIST SP 800-61 Rev. 3, abril de 2025](https://csrc.nist.gov/pubs/sp/800/61/r3/final): sitúa la respuesta a incidentes dentro de la gestion de riesgo. La propuesta de casos/evidencia/decisiones es una adaptacion de producto, no una certificacion NIST.
- [Electron: seguridad](https://github.com/electron/electron/blob/main/docs/tutorial/security.md) y [sandbox de procesos](https://www.electronjs.org/docs/latest/tutorial/sandbox): referencias para renderer, bridge y empaquetado. [API shell](https://www.electronjs.org/docs/latest/api/shell) documenta la apertura de recursos en aplicaciones del sistema.
- [W3C WCAG 2.2, tamaño minimo del objetivo](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html): referencia de 24x24 CSS px con excepciones, incluyendo espaciado. [WCAG 2.2](https://www.w3.org/TR/WCAG22/) orienta la evaluacion de teclado, foco, contraste y zoom.

Las metas de rendimiento, arquitectura propuesta y orden de entregas son juicio tecnico de esta auditoria basado en el codigo y las mediciones locales, no requisitos normativos de esas fuentes.
