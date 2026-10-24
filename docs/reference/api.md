# API y WS

La superficie publica se expone desde el mismo proceso que sirve la UI. Para ver el catalogo completo y actualizado usa `GET /api/endpoints/`.

## Rutas mas usadas

| Ruta | Uso |
| --- | --- |
| `GET /docs` | Documentacion de runtime servida por la app. |
| `GET /docs.json` | Payload JSON de esa documentacion. |
| `GET /api/dashboard/` | Snapshot para la UI principal. |
| `GET /api/charts/analytics` | Datos para graficas. |
| `GET /api/map/scan` | Vista de red y mapa de trafico. |
| `POST /api/echo` | Eco de depuracion para probar POST y serializacion. |
| `GET /protocols/` | Protocolos observados. |
| `GET /targets/` | Sesiones de captura. |
| `GET|DELETE /ports/` | Paquetes capturados. |
| `GET|DELETE /banners/` | Respuestas registradas. |
| `GET /tags/` | Etiquetas de paquetes. |
| `GET /api/ip/domains/` | Dominios asociados a una IP. |
| `GET /api/history/dns/` | Historial DNS: dominio, tipo de registro, respuesta, contadores, TTL, clientes y resolvers. Filtros `search`, `type`, `rcode`, `domain`, `ip`, `since`. |
| `GET /api/history/arp/` | Asociaciones IP-MAC vistas por ARP. Filtros `search`, `ip`, `mac`, `since`. |
| `GET /api/history/arp/devices/` | Dispositivos ARP: una fila por MAC con todas las IP que reclamo. |
| `GET /api/history/arp/events/` | Cambios ARP: `new_device`, `mac_new_ip`, `ip_mac_changed`, `mac_mismatch`. Filtros `kind`, `search`, `ip`, `mac`, `since`. |
| `GET|POST /api/history/config` | Ajustes del historial (activar DNS/ARP, dias de retencion, topes de filas) y recuentos. |
| `POST /api/history/clear` | Borra el historial (`scope`: `dns`, `arp` o `all`). Sin `confirm: true` solo informa cuantas filas borraria. |
| `GET /api/ip/ttl-path/` | Estimacion de saltos para una IP. |
| `GET /api/ip/intel/` | Perfil combinado de una IP. |
| `GET|POST /api/catalog/file/banner-rules` | Archivo de reglas de banners. |
| `GET|POST /api/catalog/file/banner-requests` | Archivo de firmas de banners. |
| `GET|POST /api/catalog/file/ip-presets` | Archivo de presets de captura. |
| `GET|POST|PUT|DELETE /api/catalog/banner-rules/` | CRUD de reglas. |
| `GET|POST|PUT|DELETE /api/catalog/banner-requests/` | CRUD de firmas. |
| `GET|POST|PUT|DELETE /api/catalog/ip-presets/` | CRUD de presets. |
| `GET /api/monitors/stats` | Resumen ligero del catálogo de monitores: `total`, `enabled`, `builtin` y `custom`. |
| `GET /api/monitors/?limit=&offset=&q=&enabled=` | Página de monitores sin los cuerpos completos de coincidencia; el servidor filtra y limita el resultado. |
| `GET /api/monitors/?id=` | Detalle completo de un monitor, incluido `match` y `action`, bajo demanda. |
| `GET /api/honeypot/listeners/?limit=&offset=&q=&enabled=` | Página de listeners con estadísticas agregadas. |
| `GET|POST /api/ws/*` | Acciones sobre clientes WebSocket. |
| `GET /api/export/` | Datasets, formatos y columnas de export disponibles. |
| `GET /api/export/{alerts,endpoints,flows,domains}` | Export de indicadores en `csv` o `json`. |
| `WS /ws/` | Canal en vivo del dashboard. |

## Export de indicadores

`GET /api/export/<dataset>?format=csv|json` devuelve filas planas con forma de
IOC, reutilizando los mismos listados que consume la UI. Acepta ademas
`since`, `limit`, `offset`, `search`, `severity` y `proto`, y responde con
`Content-Disposition: attachment`.

| Dataset | Columnas |
| --- | --- |
| `alerts` | `rule_id`, `rule`, `severity`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`, `domain`, `interface`, `direction`, `detail`, `hit_count`, `first_seen`, `last_seen` |
| `endpoints` | `ip`, `private`, `hit_count`, `alert_count`, `max_severity`, `rules`, `first_seen`, `last_seen` |
| `flows` | `flow_key`, `proto`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `packet_count`, `byte_count`, `state`, `scan_state`, `banner_text`, `tags`, `first_seen`, `last_seen` |
| `domains` | `domain`, `source`, `ip`, `port`, `proto`, `hit_count`, `first_seen`, `last_seen` |

Las vistas SOC e Investigate ofrecen el mismo export desde el boton "Export"
de su cabecera.

### Catálogos de Settings

Settings no descarga el catálogo completo al abrirse. Capture y las demás
secciones usan páginas pequeñas; Detection solicita el resumen de monitores y
solo carga 25 filas al entrar, con búsqueda, filtro y paginación en servidor.
Al abrir o editar una regla concreta se solicita su detalle mediante
`GET /api/monitors/?id=...`. El catálogo completo no forma parte de estas
rutas: los clientes que necesiten exportarlo deben usar una ruta de exportación
específica.

## Flujo de autenticacion

La mayoria de las rutas de API requieren token de sesion o JWT. Usa `GET /api/auth/session` para comprobar si la peticion esta autenticada.

Un `401` se registra en el log de seguridad con la IP de origen y cuenta contra
un limitador por IP; superado el umbral la API responde `429` con `Retry-After`
(ver `reference/auth.md`).

## Clientes en vivo

- `GET /api/ws/clients`
- `POST /api/ws/broadcast`
- `POST /api/ws/ping`
- `POST /api/ws/close`
- `GET /api/chat/messages`
- `POST /api/chat/messages`
- `POST /api/chat/clear`
- `POST /api/console/execute`: ejecuta comandos operativos registrados de
  Sniff4Hound (`/status`, `/start`, `/stop`, `/alerts`, `/packets`, `/top`,
  `/intel`, etc.). No ejecuta comandos arbitrarios del sistema; las acciones
  destructivas, el cierre y la lectura del token están bloqueados en web.

`GET /api/intel/ips/` incluye `device_type`, `device_confidence` y
`device_evidence`, inferidos pasivamente a partir de los metadatos capturados.

## Notas utiles

- `GET /api/hello` devuelve version y modo activo.
- `GET /api/soc/analysis/` resume la triage SOC sobre datos recientes.
- `GET /api/settings/ai` devuelve la activación persistente de IA (`{"enabled": false}` por defecto).
- `POST /api/settings/ai` guarda `{"enabled": true|false}` con un booleano JSON estricto; solo persiste la intención y todavía no conecta un modelo al camino de captura.
- Las respuestas de ambas operaciones tienen exactamente la forma `{"enabled": boolean}`. Un cuerpo POST con campos extra, un valor no booleano o JSON no válido responde `400` y no cambia el valor guardado.
- La integración opcional de `wsbuilder.ia` consume únicamente métricas agregadas precomputadas mediante un modelo explícitamente inyectado; permanece desactivada por defecto, no hace llamadas de red y descarta claves/filas que puedan contener identidad, texto o payload. Consulta [la nota de arquitectura de IA](ai.md) antes de conectar un proveedor.
- el runtime emite eventos `packet`, `stats_update`, `runtime_mode` y mensajes de chat por WebSocket.
