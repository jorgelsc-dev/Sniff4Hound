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
- `raw_packet` y `payload_hex` se retienen por defecto (el clasificador de
  IA y el analisis forense los necesitan). Se puede desactivar con el
  interruptor "Bytes crudos" del Dashboard (o `POST /api/ai/config` con
  `{"raw_retention_enabled": false}`, flag `runtime_config`, sin
  reiniciar); `SNIFF4HOUND_STORE_RAW_PACKET` solo fija el valor inicial de
  una base que nunca uso ese interruptor.
- `packets` solo guarda trafico que efectivamente alerto (Monitors, un
  detector de anomalia o, en modo "solo IA", el clasificador) - ver
  `Sniffer._store_packet`. Un paquete evaluado y limpio se procesa para su
  veredicto y se descarta; nunca llega a `INSERT`. La excepcion es
  trafico muteado/whitelisteado/excluido: no se evalua (nada que levantar
  por diseno) pero igual se guarda sin tags, para no perder visibilidad de
  lo que se esta excluyendo.

## Limites de retencion

Las tablas activas se podan para evitar crecimiento infinito:

- `PACKET_TABLE_LIMIT`: `2000`
- `PAYLOAD_TABLE_LIMIT`: `2000`
- `FLOW_TABLE_LIMIT`: `2000`
- `TAG_TABLE_LIMIT`: `4000`

## Cuando tocar esto

Modifica la persistencia solo si cambias el esquema de `SniffStore`, la forma de calcular snapshots o la retencion de datos visibles en dashboard.
