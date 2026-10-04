# Persistencia SQLite

Sniff4Hound usa SQLite como unico almacenamiento local. La base por defecto es `Sniff4Hound.db`, pero puedes moverla con `SNIFF4HOUND_DB_PATH`.

## Tablas principales

- `sessions`: sesiones de captura y contadores globales.
- `flows`: conversaciones agregadas por clave estable.
- `packets`: paquetes individuales, previews redactados y metadatos de captura.
- `payloads`: respuestas registradas por el honeypot.
- `tags`: etiquetas y metadatos de analisis.
- `rulesets`: catalogo de reglas editables.
- `runtime_config`: estado persistido del runtime.

## Comportamiento de la base

- SQLite se abre con `WAL`.
- Se activa `foreign_keys`.
- El timeout de espera es de `5000 ms`.
- El `text_factory` normaliza texto binario para que la API no rompa al serializar.
- `raw_packet` y `payload_hex` se retienen por defecto (el analisis forense
  los necesita). `SNIFF4HOUND_STORE_RAW_PACKET` fija el valor inicial de la
  retencion; el interruptor guardado en `runtime_config` manda despues.
- `packets` solo guarda trafico que efectivamente alerto (Monitors o un
  detector de anomalia) - ver
  `Sniffer._store_packet`. Un paquete evaluado y limpio se procesa para su
  veredicto y se descarta; nunca llega a `INSERT`. La excepcion es
  trafico muteado/whitelisteado/excluido: no se evalua (nada que levantar
  por diseno) pero igual se guarda sin tags, para no perder visibilidad de
  lo que se esta excluyendo.

## Limites de retencion

La retencion es principalmente *temporal*. Los topes por numero de filas
siguen existiendo, pero solo como freno ante picos de trafico.

### Politica temporal (la principal)

- `SNIFF4HOUND_RETENTION_DAYS` (por defecto `7`): borra los paquetes con
  `created_at` anterior a esa ventana, y los `flows` cuyo `last_seen` quedo
  fuera de ella.
- `SNIFF4HOUND_RETENTION_ALERT_DAYS` (por defecto `30`): los paquetes con
  una etiqueta de severidad `high` o `critical` sobreviven mas tiempo que el
  resto - son los que un analista viene a buscar dias despues del hecho. El
  corte efectivo es `max(RETENTION_DAYS, RETENTION_ALERT_DAYS)`, asi que
  bajarlo por debajo de la ventana general no acorta la retencion de
  alertas.
- `tags` y `payloads` no se podan por fecha: se borran en cascada cuando
  desaparece el paquete del que dependen.
- Con `SNIFF4HOUND_RETENTION_DAYS=0` no hay barrido temporal y solo quedan
  los topes de filas de abajo.
- El barrido es `SniffStore.enforce_retention()`, invocado de forma
  oportunista por el hilo de captura a traves de `trim_oversized_tables()`,
  que se autolimita a un paso cada
  `SNIFF4HOUND_RETENTION_INTERVAL_SECONDS` (por defecto `60`, minimo `5`).
  Cada barrido devuelve ademas hasta 256 paginas libres al archivo.

La politica anterior era un tope puro de filas (`2000` paquetes / `4000`
etiquetas) recortado FIFO por `id`. En una captura real eso daba unos 99
segundos de historial, demasiado poco para investigar una alerta despues
del hecho, y expulsaba justo las filas que valia la pena conservar: el
volumen de `info`/`low` desalojaba a las `high`/`critical`.

### Topes de filas (freno ante picos)

Se aplican despues del barrido temporal y recortan FIFO por `id` ascendente.
Solo actuan si un pico de trafico hace crecer una tabla entre dos barridos
consecutivos; en operacion normal no llegan a dispararse.

Derivados de `SNIFF4HOUND_RETENTION_MAX_PACKETS` (por defecto `200000`,
minimo `1000`), de modo que subir la retencion los sube a todos juntos:

- `PACKET_TABLE_LIMIT`: `RETENTION_MAX_PACKETS`
- `PAYLOAD_TABLE_LIMIT`: `RETENTION_MAX_PACKETS`
- `FLOW_TABLE_LIMIT`: `RETENTION_MAX_PACKETS`
- `TAG_TABLE_LIMIT`: `RETENTION_MAX_PACKETS * 2`

Fijos, independientes de esa variable:

- `DOMAIN_TABLE_LIMIT`: `50000`
- `PATH_TABLE_LIMIT`: `50000`
- `SESSION_TABLE_LIMIT`: `20000` - se escribe una fila de `sessions` por
  paquete almacenado, asi que sin tope propio la tabla crece con la captura.

## Cuando tocar esto

Modifica la persistencia solo si cambias el esquema de `SniffStore`, la forma de calcular snapshots o la retencion de datos visibles en dashboard.
