# Quick Reference

Resumen corto del runtime real de `Sniff4Hound`.

## Instalar

```bash
python -m pip install sniff4hound
```

## Arrancar

```bash
sniff4hound
SNIFF4HOUND_CAPTURE_AUTO_START=0 sniff4hound
SNIFF4HOUND_RUNTIME_MODE=honeypot sniff4hound
SNIFF4HOUND_CAPTURE_INTERFACES="eth0,wlan0" sniff4hound
```

## Auth

- El launcher imprime un token de sesion de 8 caracteres.
- `GET /api/auth/session` indica si la API exige auth y si la sesion ya es valida.
- Se acepta `Authorization: Bearer <token>`, `X-Access-Token` o `?access_token=` en `WS /ws/`.

Generar un JWT:

```bash
python3 - <<'PY'
from sniff4hound.auth import generate_token
print(generate_token(user="operator", scope="full"))
PY
```

## Runtime API

Leer estado:

```bash
curl -H "Authorization: Bearer TOKEN" \
  http://127.0.0.1:45678/api/runtime/
```

Cambiar modo:

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"honeypot"}'
```

Arrancar o parar el motor activo:

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"start"}'

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"stop"}'
```

Seleccionar interfaces:

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interfaces":["eth0","wlan0"]}'
```

## URLs utiles

- Dashboard: `http://127.0.0.1:45678/`
- Docs runtime: `http://127.0.0.1:45678/docs`
- Endpoint catalog: `http://127.0.0.1:45678/api/endpoints/`
- Dashboard snapshot: `http://127.0.0.1:45678/api/dashboard/`
- WebSocket: `ws://127.0.0.1:45678/ws/?access_token=TOKEN`

## Variables utiles

```bash
SNIFF4HOUND_HOST=127.0.0.1
SNIFF4HOUND_PORT=45678
SNIFF4HOUND_DATA_DIR=~/.local/share/sniff4hound
SNIFF4HOUND_DB_PATH=/ruta/absoluta/Sniff4Hound.db   # relativa => bajo SNIFF4HOUND_DATA_DIR
SNIFF4HOUND_RUNTIME_MODE=sniffer
SNIFF4HOUND_CAPTURE_AUTO_START=1
SNIFF4HOUND_CAPTURE_INTERFACES=eth0,wlan0
SNIFF4HOUND_PROMISCUOUS=1
SNIFF4HOUND_REQUIRE_AUTH=1
SNIFF4HOUND_JWT_TTL=3600
SNIFF4HOUND_JWT_MAX_TTL=86400
SNIFF4HOUND_AUTH_FAILURE_THRESHOLD=10
SNIFF4HOUND_AUTH_FAILURE_WINDOW_SECONDS=60
```

No definas `SNIFF4HOUND_JWT_SECRET` con un valor de ejemplo. Si no lo defines,
Sniff4Hound genera un secreto aleatorio por instalacion y lo guarda con
permisos `0600` en `SNIFF4HOUND_DATA_DIR/jwt_secret`. Solo fijalo a mano si
necesitas compartir la firma entre varias instancias, y entonces usa un valor
realmente aleatorio (`openssl rand -hex 32`). Cambiarlo invalida todos los
tokens emitidos anteriormente.

## Export de indicadores (IOC)

```bash
curl -H "X-Security-Code: TOKEN" \
  "http://127.0.0.1:45678/api/export/alerts?format=csv&since=24h" -o alerts.csv
curl -H "X-Security-Code: TOKEN" \
  "http://127.0.0.1:45678/api/export/endpoints?format=json&since=7d"
```

Datasets: `alerts`, `endpoints`, `flows`, `domains`. Formatos: `csv`, `json`.
`GET /api/export/` lista datasets, formatos y columnas.

## Logger helper

`sniff4hound.logger` es un helper de libreria, no una configuracion automatica del runtime.

```python
from sniff4hound.logger import get_logger

logger = get_logger("demo", log_file="events.ndjson")
logger.info("runtime event", extra={"extra_fields": {"mode": "sniffer"}})
```

## Tests

```bash
python -m unittest discover -t . -s tests -q
pytest tests/ -q
```

## Frontend

```bash
cd frontend
npm ci
npm run dev
npm run lint
npm run build
```
