# Persistencia SQLite

Sniff4Hound usa SQLite como unico almacenamiento local. La base por defecto es `Sniff4Hound.db`, pero puedes moverla con `SNIFF4HOUND_DB_PATH`.

## Tablas principales

- `sessions`: sesiones de captura y contadores globales.
- `flows`: conversaciones agregadas por clave estable.
- `packets`: paquetes individuales y payload bruto.
- `payloads`: respuestas registradas por el honeypot.
- `tags`: etiquetas y metadatos de analisis.
- `rulesets`: catalogo de reglas editables.
- `runtime_config`: estado persistido del runtime.

## Comportamiento de la base

- SQLite se abre con `WAL`.
- Se activa `foreign_keys`.
- El timeout de espera es de `5000 ms`.
- El `text_factory` normaliza texto binario para que la API no rompa al serializar.

## Limites de retencion

Las tablas activas se podan para evitar crecimiento infinito:

- `PACKET_TABLE_LIMIT`: `2000`
- `PAYLOAD_TABLE_LIMIT`: `2000`
- `FLOW_TABLE_LIMIT`: `2000`
- `TAG_TABLE_LIMIT`: `4000`

## Cuando tocar esto

Modifica la persistencia solo si cambias el esquema de `SniffStore`, la forma de calcular snapshots o la retencion de datos visibles en dashboard.
