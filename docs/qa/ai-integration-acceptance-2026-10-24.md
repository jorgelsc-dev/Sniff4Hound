# QA independiente: integración IA

Fecha: 2026-10-24  
Rama: `agents/qa-independent-integration-sniff4hound`  
Alcance: Settings, contratos backend, seguridad, rendimiento, accesibilidad y tests.

## Veredicto

**No apto para integrar IA todavía.** El checkout auditado no contiene una integración IA activa: la IA histórica fue retirada en los commits `09d92be`/`1366bd7`, y no hay un toggle, proveedor, adaptador, configuración persistida ni ruta IA actual que probar. Esto es un bloqueo de integración, no una aprobación implícita por ausencia de código.

## Hallazgos

### F-IA-01 — blocker — superficie IA inexistente

Evidencia:

- [SettingsView.vue](../../desktop/frontend/src/views/SettingsView.vue:5) solo expone Sniffer/Honeypot en Runtime; no existe control IA ni sección de proveedor.
- [app.py](../../sniff4hound/app.py:653) documenta rutas de captura, exclusiones, pipeline, chat y SOC, pero ninguna ruta de activación/configuración IA.
- [app.py](../../sniff4hound/app.py:2436) implementa chat/notas y comandos del operador, no inferencia ni envío a un proveedor externo.
- El historial `09d92be` elimina `ai_learning.py`, `packet_ai.py`, las vistas IA y sus tests; el estado actual no reintroduce un contrato equivalente.

Aceptación: debe existir un contrato documentado y probado de configuración/estado IA, conectado a Settings y al runtime, antes de evaluar comportamiento positivo.

### F-IA-02 — high — no hay garantía de default OFF ni reversibilidad

No hay una clave persistida ni una ruta GET/POST que permita demostrar que IA empieza desactivada, que el cambio es reversible o que reiniciar conserva la elección. El toggle de Settings existente controla únicamente motores de captura ([SettingsView.vue](../../desktop/frontend/src/views/SettingsView.vue:12)).

Aceptación: instalación limpia devuelve `enabled=false`; OFF no crea jobs ni llamadas de proveedor; ON/OFF repetido es idempotente; el estado se lee después de reinicio y un fallo al guardar no deja el UI mintiendo.

### F-IA-03 — high — contrato de privacidad y secretos no definido

La configuración documentada mantiene retención de bytes crudos por defecto ([runtime.md](../../docs/reference/runtime.md:22)) y la API ya expone investigación con payloads a clientes autenticados ([app.py](../../sniff4hound/app.py:660)). No existe una frontera explícita que redija payloads, credenciales, tokens, cookies, claves o secretos antes del adaptador IA, ni una política de logs/respuestas para errores del proveedor.

Aceptación: el adaptador recibe un DTO mínimo redactado; tests con canarios de secreto prueban que no aparecen en request, logs, chat, jobs, errores ni respuestas; las credenciales solo se leen desde configuración segura y nunca se devuelven.

### F-IA-04 — high — riesgo de bloqueo de captura sin contrato de aislamiento

El runtime separa operaciones de captura por IPC y transforma fallos del servicio en `503` visibles ([app.py](../../sniff4hound/app.py:3503)), pero no hay diseño ni prueba que demuestre que una llamada IA lenta, caída o saturación no bloquea captura. Tampoco hay límites de cola, timeout, cancelación, backpressure o presupuesto de CPU/memoria IA.

Aceptación: IA usa worker/job aislado con timeout y límites; la captura sigue procesando durante latencia/fallo del proveedor; apagar IA cancela trabajos; métricas muestran cola, errores, latencia y descartes sin payload.

### F-IA-05 — medium — errores visibles y accesibilidad pendientes

El frontend sí tiene patrones existentes de error, carga y teclado (por ejemplo, el grafo de Settings), y sus tests actuales cubren accesibilidad general. Sin embargo, no existe un control IA que pueda auditarse: faltan nombre accesible, estado `aria-checked`/`aria-pressed`, foco, operación por teclado, feedback de guardado, error visible y estado de proveedor.

Aceptación: control operable con Tab/Space/Enter, foco visible y nombre/estado anunciables; estados loading/success/error son visibles y no dependen solo de color; error de backend conserva el valor confirmado y ofrece reintento.

## Validaciones ejecutadas

- `python scripts/check_test_shards.py` — OK: 57 módulos cubiertos.
- `npm ci` en `desktop/frontend` — OK; auditoría npm: 0 vulnerabilidades.
- `npm test` en `desktop/frontend` — OK: 149 tests, 0 fallos.
- `npm run build` en `desktop/frontend` — OK: Vite 8.3.5, build de producción completado.
- `python -m unittest discover -t . -s tests -q` — iniciado; la ejecución es muy lenta y no finalizó durante la ventana inicial de QA.
- `pytest tests/ -q` con Python del sistema — bloqueado en colección por `ModuleNotFoundError: wsbuilder`; se repitió la instalación editable en `/tmp/sniff4hound-qa-venv` y se dejó una ejecución unittest con esa dependencia.

## Criterios de aceptación para el próximo cambio

1. Default OFF verificable en instalación limpia y sin tráfico externo al proveedor.
2. Toggle reversible, persistente, idempotente y con rollback visual ante error.
3. Captura no bloqueada por latencia, error, cancelación o saturación IA.
4. Payloads y secretos redactados antes de salir del proceso; ningún secreto en logs, chat, jobs o errores.
5. Errores del backend/proveedor visibles, accionables y con estado confirmado correcto.
6. Control y estados IA accesibles por teclado y lector de pantalla.
7. Tests de contrato backend, aislamiento de captura, redacción, Settings/a11y y métricas de rendimiento; registrar el nuevo módulo en [.github/test-shards.json](../../.github/test-shards.json:2).

## Recomendaciones

- Acordar primero el DTO y la máquina de estados (`disabled`, `starting`, `ready`, `running`, `degraded`, `error`) antes de conectar UI.
- Mantener el adaptador IA detrás de una interfaz inyectable y un fake determinista para tests; no hacer llamadas de red desde captura.
- Añadir pruebas de canario de secretos y un test de concurrencia que mantenga captura activa mientras el proveedor duerme/falla.
- No reutilizar `/api/chat/messages` como canal IA sin separar notas del operador, prompt, respuesta y auditoría; su contrato actual solo guarda texto y lo difunde por WebSocket.

## Seguimiento del hallazgo

Se intentó crear el issue en `jorgelsc-dev/Sniff4Hound` con el contenido de F-IA-01..05; GitHub respondió `403 Resource not accessible by integration`. Por eso este documento contiene el registro completo requerido (owner, severidad, evidencia, aceptación, estado y validación) para que el responsable lo copie al issue tracker cuando tenga permisos.

Owner: `@agents/qa-independent-integration-sniff4hound`  
Severity: `blocker` — no hay superficie IA activa verificable.  
PR/commit: pendiente de este informe.  
Status: `new`.
