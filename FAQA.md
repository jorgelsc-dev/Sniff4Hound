# Sniff4Hound — Informe de QA / Auditoría de Seguridad (FAQA)

**Rol:** Auditoría realizada asumiendo el rol de QA Lead / analista SOC especializado en sniffers, honeypots y motores de IA de detección.
**Alcance:** Backend (`sniff4hound/*.py`), frontend (`frontend/src/**`), y una pasada de QA en vivo contra una instancia real en ejecución (`v0.51.0`, `http://127.0.0.1:45678`) navegando las 14 vistas principales con DevTools Protocol, capturando errores de consola, excepciones no controladas y respuestas HTTP con error.
**Método:** Lectura estática dirigida por 4 auditorías paralelas (auth/IPC, almacenamiento/API, sniffer/honeypot/IA, frontend) más una pasada dinámica en vivo. Todos los hallazgos citan archivo y línea aproximada; nada se reporta sin haber leído el código real.
**Fecha:** 2026-09-12.

> Convención de severidad: **Critical** (explotable remotamente / crash del sensor) · **High** (bypass de un límite de seguridad importante con impacto real) · **Medium** (gap de defensa en profundidad o riesgo de diseño) · **Low** (mejora menor) · **Info** (nota o mitigación ya confirmada).

---

## 0. Resumen ejecutivo

- **No se encontró bypass de autenticación, inyección SQL, ni XSS explotable.** El diseño de JWT, comparaciones en tiempo constante, rate limiting, parametrización SQL, saneo del access log y el escaping por defecto de Vue están todos correctamente implementados y se confirmaron leyendo el código, no asumidos.
- El hallazgo más serio es **Critical: ReDoS remoto** en la evaluación de regex de reglas/monitores/whitelist contra el payload capturado — un solo paquete crafteado puede colgar el hilo de captura si existe una regla con backtracking catastrófico.
- El segundo hallazgo relevante es **High: `create_honeypot_listener` no valida contra una lista de puertos sensibles** antes de pedirle al proceso privilegiado (root) que haga bind — la única validación es rango 1-65535 + protocolo.
- La pasada en vivo (14 vistas, instancia real con ~38k paquetes / ~189k tags capturados) **no arrojó ninguna excepción de consola, advertencia ni respuesta HTTP con error** durante la navegación normal — buena señal de estabilidad del frontend actual.
- El resto son hallazgos Medium/Low de higiene defensiva (retención de credenciales capturadas sin redacción, el código de seguridad viajando en query string de WebSocket, límites de concurrencia por listener del honeypot).

---

## 1. Hallazgos CRITICAL

### 1.1 ReDoS remoto vía regex de reglas/monitores/whitelist evaluada sobre payload capturado
**Dónde:** `sniff4hound/rulesets.py:23-31` (compilación de patrones), `sniff4hound/monitors.py` (evaluación de `payload_regex`/`ip_regex`/`port_regex`/`protocol_regex`, p.ej. líneas 590-643 y 2914-2944), `sniff4hound/sniffer.py:929-968` (regex de whitelist).

**Problema:** cualquier patrón definido por el operador en una regla, monitor o entrada de whitelist se compila con `re.compile()` normal, sin límite de longitud, sin timeout y sin protección contra backtracking catastrófico (tipo `(a+)+b`). Estos patrones se ejecutan sobre `packet_text`, que se construye directamente de los bytes del paquete capturado — es decir, **contenido 100% controlado por quien está en la red**, no por el operador.

**Escenario de fallo concreto:** el operador crea (o importa) un monitor/regla con un patrón de IOC escrito a mano de forma ingenua (muy común en reglas de detección reales, p.ej. patrones de log parsing copiados de otra herramienta). Un atacante en el segmento de red envía un único paquete diseñado para maximizar el backtracking de ese patrón. `evaluate_packet`/`classify_packet` corre de forma síncrona dentro de `_store_packet`, en el mismo hilo de captura — el hilo se cuelga indefinidamente procesando ese paquete, deteniendo la detección (y potencialmente la captura) del resto del tráfico. Es un DoS remoto de un solo paquete contra el sensor de seguridad mismo.

**Recomendación:**
- Añadir un límite duro de longitud al texto evaluado antes de aplicar regex (ya existe `PAYLOAD_TEXT_MAX_CHARS` para almacenamiento — reutilizar el mismo límite para evaluación).
- Evaluar los patrones de reglas/monitores en un hilo o proceso con timeout (p.ej. `regex` module con `timeout=`, o un watchdog que aborte tras N ms).
- Como mitigación más simple: validar patrones al guardarlos (rechazar patrones con cuantificadores anidados obviamente peligrosos), aunque esto no cubre todos los casos — el timeout en tiempo de evaluación es la defensa robusta.

---

## 2. Hallazgos HIGH

### 2.1 `create_honeypot_listener` permite bind arbitrario sin lista de puertos sensibles
**Dónde:** `sniff4hound/store.py:1029` (`create_honeypot_listener`, validación de `proto`/`port`) → cruza el límite de IPC hacia `sniff4hound/capture_service.py` (proceso privilegiado/root).

**Problema:** la única validación es `proto in {tcp, udp}` y `1 <= port <= 65535`. No hay denylist de puertos ya usados por servicios reales del sistema (22, 53, 111, etc.) ni de rangos reservados. Como esta llamada se ejecuta como root en el proceso de captura, cualquier compromiso del proceso web sin privilegios (o un token robado) permite que el proceso privilegiado haga `bind()`/`listen()` en cualquier puerto — incluyendo DoS contra un servicio real que ya esté escuchando ahí, o exponer un listener honeypot no autenticado en un puerto que el operador no pretendía.

**Escenario de fallo:** un atacante con el token de sesión (o vía CSRF, ver 3.3) llama a `create_honeypot_listener` con `port=22` o el puerto de un servicio interno sensible, causando disrupción o un listener inesperado.

**Recomendación:** aplicar una denylist configurable (por defecto: denegar <1024 salvo whitelist explícita de puertos honeypot conocidos) **dentro de `capture_service.py`/el módulo honeypot**, independiente de lo que pida la capa web — el proceso privilegiado no debe confiar ciegamente en el rango que le pide el proceso no privilegiado.

### 2.2 Import de modelo de IA: validación de forma pero no de tipo/magnitud de los valores
**Dónde:** `sniff4hound/ai_learning.py:270-299` (`_validate_imported_model`).

**Problema:** se valida que las dimensiones (`len(row)`, ancho de capas ocultas dentro de `[MIN_HIDDEN_NEURONS, MAX_HIDDEN_NEURONS]`) sean correctas, pero **nunca se valida el tipo ni el rango numérico de los pesos/bias individuales**. Un JSON con forma válida pero `w=[["x","y"]]` pasa la validación y solo revienta más tarde, sin try/except, la primera vez que se usa el modelo para puntuar (`learning_snapshot`) — que ocurre en cada visita al dashboard de IA.

**Escenario de fallo:** un operador importa un archivo de modelo compartido por otra persona (o descargado), o uno corrupto por error de copia — la vista de IA completa deja de funcionar con una excepción no controlada, sin mensaje de error claro sobre la causa real.

**Recomendación:** en `_validate_imported_model`, verificar explícitamente que cada elemento de `w`/`b` sea `int`/`float` (rechazando strings, `None`, listas anidadas incorrectas) y opcionalmente acotar magnitud (p.ej. rechazar valores con `abs(v) > 1e6` como señal de corrupción), devolviendo un `ValueError` claro en vez de dejar que falle en el primer forward pass.

### 2.3 Responders UDP del honeypot (DNS/NTP/SIP/SNMP) sin rate limiting ni verificación de origen
**Dónde:** `sniff4hound/honeypot.py`, `_udp_response_for` (líneas ~1894-1916).

**Problema:** los responders DNS, NTP, SIP OPTIONS y SNMP GetResponse contestan a la dirección de origen del paquete UDP recibido sin ningún rate limiting por IP de origen. Estos son protocolos UDP clásicos usados en ataques de amplificación/reflexión (origen falsificado = víctima). El factor de amplificación aquí es modesto (respuestas de tamaño fijo, no zone transfers ni SNMP GetBulk), pero si la instancia es alcanzable desde redes donde el spoofing de origen es posible, puede usarse como uno más de muchos reflectores en un ataque distribuido.

**Recomendación:** añadir rate limiting por IP de origen (ventana deslizante, similar al `AuthRateLimiter` ya existente para HTTP/WS) a los listeners UDP del honeypot, y documentar explícitamente en el README/docs que exponer estos listeners a Internet sin control adicional no es recomendado.

---

## 3. Hallazgos MEDIUM

### 3.1 Sin política de redacción/retención para credenciales capturadas en crudo
**Dónde:** `sniff4hound/store.py` (esquema `packets`/`payloads`, `payload_text`/`banner_text` almacenados verbatim); exportable en bulk vía `/api/export/*` (`app.py:667-670`).

**Problema:** la retención está acotada por tiempo/filas (`RETENTION_DAYS`, `RETENTION_MAX_PACKETS`), pero nada redacta secretos (una cabecera `Authorization`, una contraseña en texto plano capturada por el honeypot) antes de guardarlos. Cualquiera con acceso al API/dashboard puede exportar ese contenido en bulk.

**Recomendación:** documentar esto explícitamente como riesgo conocido (mínimo), y evaluar reglas de redacción a nivel de campo para patrones comunes de credenciales (Basic Auth, `password=`, JWT) antes de persistir o al menos antes de exportar.

### 3.2 Código de seguridad viaja en query string del WebSocket
**Dónde:** `frontend/src/state/appStore.js:1537, 1636, 1731, 1744` (`feedUrl()`/`wsUrl()`, `?security_code=<token>`).

**Problema:** los navegadores no permiten headers custom en el handshake WS, así que el token va en la URL. Si la app llega a correr alguna vez detrás de un reverse proxy (para acceso remoto), ese código queda en los logs de acceso del proxy en texto plano, a diferencia de las llamadas HTTP normales que sí usan headers.

**Recomendación:** intercambiar un ticket de un solo uso y corta duración (emitido vía el canal HTTP ya autenticado) en vez del código de seguridad de larga vida para el handshake WS.

### 3.3 Sin verificación CORS/CSRF explícita confirmada en las rutas que cambian estado
**Dónde:** `sniff4hound/app.py:3035` (`_apply_api_auth_guards`); no se encontró manejo de `Access-Control-Allow-Origin` en el código revisado, solo `Access-Control-Expose-Headers`.

**Problema:** el guard de auth acepta bearer token vía header (correcto), pero no hay una verificación explícita de origen encontrada en el código para las rutas que cambian estado (`/api/data/clear/`, `/api/console/execute`, `/api/app/shutdown`). Mientras el frontend no guarde el token en una cookie (no se encontró que lo haga — usa `localStorage` + header), el riesgo práctico de CSRF cross-origin es bajo, pero no hay una comprobación de origen server-side que lo confirme de forma robusta.

**Recomendación:** añadir una verificación explícita de `Origin`/`Referer` en el servidor para las rutas destructivas, como defensa en profundidad independiente de dónde viva el token.

### 3.4 Código de seguridad en `localStorage` en texto plano
**Dónde:** `frontend/src/state/appStore.js:189, 913, 1200-1207` (clave `sniff4hound.securityCode`).

**Problema:** si alguna vez se introdujera un XSS (hoy no se encontró ninguno — ver sección "Confirmado correcto"), cualquier script en el mismo origen podría leer `localStorage` y exfiltrar el código, obteniendo acceso completo a la API/WS.

**Recomendación:** dado que hoy no hay vector de XSS conocido, esto es defensa en profundidad, no una vulnerabilidad activa. Si se desea reducir superficie, considerar `sessionStorage` (se pierde al cerrar pestaña) como alternativa, aceptando el trade-off de UX.

### 3.5 `readStartupAuthTokenFromUrl` adopta silenciosamente un token de un link no verificado
**Dónde:** `frontend/src/state/appStore.js:119-146`.

**Problema:** acepta el código desde cualquiera de los parámetros `code`, `security_code`, `access_token`, `token`, `auth` y lo persiste antes de limpiar la URL. Un link de phishing con apariencia de "link de arranque" de Sniff4Hound podría hacer que la app adopte un token atacante-provisto en `localStorage` sin ninguna confirmación.

**Recomendación:** bajo riesgo (requiere que el operador reciba y haga clic en un link malicioso deliberadamente parecido al real), pero documentar el comportamiento; considerar pedir confirmación visual antes de persistir un token que llega por URL.

### 3.6 Sin límite de concurrencia por listener del honeypot
**Dónde:** `sniff4hound/honeypot.py`, `_listen` (línea ~1238): cada conexión TCP aceptada genera un `threading.Thread` sin límite.

**Problema:** no hay semáforo ni límite de conexiones concurrentes por puerto. Un flood de conexiones lentas/inactivas (estilo slowlorís, abrir sockets sin enviar datos) puede generar hilos sin límite y agotar memoria/hilos del host, a pesar de que sí existen buenos límites por-conexión (`MAX_PACKET_SIZE=4096`, `MAX_HTTP_REQUEST_SIZE=16384`, `READ_TIMEOUT_SECONDS=6`).

**Recomendación:** añadir un límite máximo de conexiones concurrentes por listener (semáforo o pool de hilos acotado), rechazando/cerrando conexiones adicionales educadamente.

### 3.7 Correctness latente en el backprop manual (sin bug activo encontrado)
**Dónde:** `sniff4hound/ai_learning.py` (`_backprop_step`, línea ~134; `features()`, líneas 40-49).

**Nota:** el delta de la capa oculta divide por una constante fija `/3` sin normalización atada al tamaño de batch o escala de features; `features()` divide por `len(data)` sin guard en varios puntos, aunque todos los call-sites revisados sí protegen contra `data` vacío antes de llamar. No es un bug activo hoy, pero es matemática hecha a mano sin aserciones de dimensión (a diferencia de NumPy, listas de Python no fallan ruidosamente ante un broadcast incorrecto) — una futura edición a `_forward_full`/`_backprop_step` que desalinee formas produciría gradientes silenciosamente incorrectos en vez de un error visible.

**Recomendación:** añadir aserciones de dimensión explícitas (`assert len(row) == expected`) en los puntos internos de multiplicación, no solo en la validación de import.

### 3.8 Evasión de detección: el umbral mínimo de cohorte del LOF es fijo y conocido
**Dónde:** `sniff4hound/packet_ai.py:14-16` (`MIN_COHORT=20`, piso 5, techo 200).

**Nota:** cualquier grupo `(proto, source, partial)` con menos miembros que el mínimo configurado nunca se puntúa — queda como `insufficient_data`. Esto ya está documentado en los docstrings del propio código ("Scores describe the current cohort, not attack probabilities"), pero vale la pena resaltarlo como **limitación conocida y explotable**: tráfico low-and-slow por debajo del umbral configurado evade completamente la capa de detección de anomalías no supervisada.

**Recomendación:** ninguna acción de código requerida — es una limitación inherente al diseño LOF de ventana pequeña. Sí recomendable: mostrar esto más explícitamente en la UI de IA (ya se documenta en el código; falta resaltarlo en el texto visible al operador) para que la expectativa de cobertura sea correcta.

### 3.9 Falta `Referrer-Policy` explícita + orden de limpieza del código en URL
**Dónde:** `frontend/index.html:14-18` (fonts de Google cargadas sin meta de referrer); `appStore.js` limpia el código de la URL con `history.replaceState` *después* del mount, no antes de la primera petición de subrecurso.

**Problema:** en teoría, si una petición a `fonts.googleapis.com`/`fonts.gstatic.com` se dispara antes de que se limpie el `?code=...` de la URL, el `Referer` podría llevar el código completo a un tercero. Los navegadores modernos con `strict-origin-when-cross-origin` por defecto ya mitigan esto (solo mandan el origen, no el path+query), así que es defensa en profundidad, no una fuga confirmada.

**Recomendación:** añadir `<meta name="referrer" content="strict-origin-when-cross-origin">` explícito (no depender solo del default del navegador) y mover la limpieza de la URL antes de que se disparen peticiones de subrecursos externos.

---

## 4. Hallazgos LOW

### 4.1 Sin límite de longitud en los campos del access log
**Dónde:** `sniff4hound/access_log.py:125-148` (`_sanitize_field`).

**Nota:** se sanea bien contra inyección de líneas falsas y secuencias de escape ANSI (CR/LF/ESC → escapados), pero no hay tope de longitud. Un flood de requests con paths/headers muy largos puede inflar rápidamente el log/consola.

**Recomendación:** truncar cada campo saneado a un máximo razonable (p.ej. 512 caracteres) antes de imprimir.

### 4.2 `manage.py`: la limpieza de socket IPC obsoleto no está sincronizada contra un tercer proceso concurrente
**Dónde:** `sniff4hound/manage.py`, `_clear_stale_capture_socket` (líneas ~393-420).

**Nota:** el fix ya documentado en el código cubre el caso de una única nueva instancia contra un hijo previo que no cerró limpio. Si dos instancias de `sniff4hound` arrancan simultáneamente (p.ej. desde cron/systemd back-to-back), ambas pueden interlacear `unlink()`+`bind()` sobre el mismo path. Baja probabilidad práctica en una herramienta de un solo operador local.

**Recomendación:** si alguna vez se soporta ejecución multi-instancia, añadir un lock file adicional para coordinar el arranque.

---

## 5. Confirmado correcto (mitigaciones ya presentes — no tocar sin razón)

Listado explícitamente para que quede registro de qué se verificó y funciona, no solo de lo que falta:

- **JWT bien construido**: `secrets.compare_digest` para verificación de firma (auth.py:174), `iss`/`aud` fijos, `alg` verificado estrictamente contra `HS256` (sin vector de confusión de algoritmo "none"), `kid` ata la firma a secreto+versión (rotar el secreto invalida todos los tokens emitidos), `exp`/`nbf` con skew acotado, `JWT_MAX_TTL_SECONDS` acota la vida máxima del token, lista de revocación por `jti` en memoria.
- **Comparaciones en tiempo constante** en verificación de sesión (`auth.py:253`) y de token IPC (`ipc.py:52-55`).
- **Rate limiting compartido** entre HTTP y WebSocket (`AuthRateLimiter`, auth.py:308-437), con backoff exponencial y tabla de clientes acotada.
- **Secretos nunca en argv**: ni el token IPC ni el secreto JWT viajan como argumento de proceso (visibles en `/proc/pid/cmdline`); se pasan por archivo 0600.
- **Permisos de archivo consistentemente estrictos**: secreto JWT 0600 (creación atómica `O_CREAT|O_EXCL`), token IPC 0600, socket IPC 0600.
- **El proceso web se niega a correr como root** (`manage.py`, `_running_as_root`), acotando el radio de impacto de cualquier bug en la capa no privilegiada.
- **`/api/console/execute` no es una shell**: vocabulario cerrado de comandos vía `shlex.split`, sin `subprocess`/`eval`/`os.system` alcanzable desde input de usuario.
- **Límites de DoS ya presentes**: `MAX_FRAME_BYTES` en IPC, `API_MAX_LIMIT` en paginación, `PAYLOAD_TEXT_MAX_CHARS` en almacenamiento.
- **SQL parametrizado de forma consistente** en todo `store.py` — ningún valor de usuario se interpola directamente en una query; los pocos lugares con f-strings solo arman la *forma* de la cláusula (nombres de tabla/columna hardcodeados o validados contra un allowlist), nunca valores.
- **CSV/export protegido contra formula injection tanto en backend (`export.py:320-326`) como en frontend (`exporters.js:18-26`)** — doble capa, ambas correctas.
- **Access log saneado contra inyección de líneas falsas y secuencias de escape ANSI** (`access_log.py:_sanitize_field`), con redacción de query params sensibles.
- **Operación de purga/trim atómica**: el lock se mantiene durante todo el bloque multi-statement, sin ventana de estado a medio borrar.
- **Parsers de paquetes robustos**: todos los parsers (Ethernet/VLAN/LLC/ARP/IPv4/IPv6/TCP/UDP/DNS/TLS-SNI) verifican longitud antes de indexar; cada paquete se procesa dentro de su propio `try/except`, así que un paquete malformado se marca "unparseable" en vez de tumbar el hilo de captura o el proceso.
- **Honeypot no ejecuta nada controlado por el atacante**: no hay `eval`/`exec`/shell-out disparado por datos de red; el único `subprocess.run` es un comando fijo de `openssl` para bootstrap de certificados, sin argumentos controlados por el atacante.
- **Frontend: cero `v-html`/`innerHTML`/`eval` en todo `src/`** — cada campo controlado por el atacante (payload, banner, dominio, path HTTP, mensaje de chat) se renderiza vía interpolación `{{ }}` de Vue, que escapa HTML por defecto. Esta es la mitigación más importante para una herramienta cuyo propósito es mostrar bytes no confiables, y está aplicada de forma consistente.
- **`router-link :to` siempre como objeto**, nunca string crudo — un dominio/IP capturado no puede convertirse en una URI `javascript:`.
- **Modelo de IA**: export/import separa correctamente arquitectura+pesos de los ejemplos etiquetados; `is_current_model_shape` migra con gracia un modelo de formato anterior sin crashear (fix ya aplicado esta sesión).

---

## 6. Pasada de QA en vivo (instancia real, v0.51.0)

Conectado a la instancia real en ejecución (`http://127.0.0.1:45678`) y navegadas las 14 vistas principales (Dashboard, Chat, Sniffer, Honeypot, Protocols, Domains, Paths, IPs, Monitors, Radar, SOC, Investigate, IA, Settings) vía Chrome DevTools Protocol, capturando:
- Excepciones de JavaScript no controladas.
- `console.error`/`console.warn`.
- Respuestas HTTP `>= 400` de cualquier llamada a `/api/*`.

**Resultado: cero hallazgos.** Ninguna vista produjo un error de consola, una excepción, ni una respuesta HTTP fallida durante la navegación normal, con datos reales en producción (≈38,007 paquetes, ≈189,239 tags, 30 hosts únicos, 8 familias de protocolo, 10,134 listeners de honeypot configurados). Esto es una señal fuerte de estabilidad del frontend actual contra el volumen real de datos del operador.

*(No se exploraron flujos que cambian estado — iniciar/detener motores, borrar datos — para no alterar el estado real de la instancia en vivo del operador durante la auditoría.)*

---

## 7. Recomendaciones priorizadas (resumen accionable)

1. **[Critical]** Acotar longitud + añadir timeout a la evaluación de regex de reglas/monitores/whitelist sobre payload capturado (§1.1).
2. **[High]** Denylist de puertos sensibles para `create_honeypot_listener`, validada dentro del proceso privilegiado (§2.1).
3. **[High]** Validar tipo/magnitud de pesos al importar un modelo de IA, no solo la forma (§2.2).
4. **[High]** Rate limiting por IP en los responders UDP del honeypot (DNS/NTP/SIP/SNMP) (§2.3).
5. **[Medium]** Documentar (y evaluar redacción de) credenciales capturadas en crudo antes de exportar (§3.1).
6. **[Medium]** Límite de concurrencia por listener del honeypot para prevenir agotamiento de hilos (§3.6).
7. **[Medium]** Ticket de un solo uso para el handshake WS en vez del código de seguridad de larga vida (§3.2).
8. **[Low]** Tope de longitud en campos del access log ya saneados (§4.1).

Todo lo demás auditado y **confirmado correcto** — ver sección 5 antes de "arreglar" algo que ya está bien implementado.
