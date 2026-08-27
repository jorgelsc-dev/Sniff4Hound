# Ejemplos

Ejemplos cortos contra el runtime actual de `Sniff4Hound`.

## 1. Arrancar sin autoarranque de captura

```bash
SNIFF4HOUND_CAPTURE_AUTO_START=0 sniff4hound
```

Sirve para abrir la UI, validar auth y cambiar de modo sin intentar captura raw al iniciar.

## 2. Generar un JWT para scripts

```bash
python3 - <<'PY'
from sniff4hound.auth import generate_token

print(generate_token(user="analyst", scope="read:all"))
PY
```

## 3. Validar la sesion HTTP

```bash
TOKEN="tu_token_o_jwt"

curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:45678/api/auth/session
```

## 4. Leer el snapshot principal

```bash
TOKEN="tu_token_o_jwt"

curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:45678/api/dashboard/
```

## 5. Cambiar a modo honeypot

```bash
TOKEN="tu_token_o_jwt"

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"honeypot"}'
```

## 6. Arrancar o parar el motor activo

```bash
TOKEN="tu_token_o_jwt"

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"start"}'

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"stop"}'
```

## 7. Seleccionar interfaces para el sniffer

```bash
TOKEN="tu_token_o_jwt"

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interfaces":["eth0","wlan0"]}'
```

## 8. Consultar paquetes TCP

```bash
TOKEN="tu_token_o_jwt"

curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:45678/ports/tcp/?limit=50"
```

## 9. Consumir el WebSocket

### JavaScript

```javascript
const token = "tu_token_o_jwt";
const ws = new WebSocket(`ws://127.0.0.1:45678/ws/?access_token=${encodeURIComponent(token)}`);

ws.onmessage = (event) => {
  const payload = JSON.parse(event.data);
  console.log(payload.type, payload);
};

ws.onopen = () => {
  ws.send(JSON.stringify({ action: "runtime_snapshot" }));
  ws.send(JSON.stringify({ action: "scan_map_snapshot", limit: 100 }));
};
```

### Python

```python
import asyncio
import json
from websockets import connect


async def main():
    token = "tu_token_o_jwt"
    uri = f"ws://127.0.0.1:45678/ws/?access_token={token}"
    async with connect(uri) as ws:
        await ws.send(json.dumps({"action": "runtime_snapshot"}))
        while True:
            message = await ws.recv()
            print(message)


asyncio.run(main())
```

## 10. Usar `SniffStore` desde Python

```python
from sniff4hound.store import SniffStore

store = SniffStore("Sniff4Hound.db")
try:
    print(store.summary_counts())
    print(store.dashboard_snapshot())
finally:
    store.close()
```

## 11. Usar el logger NDJSON como helper

```python
from sniff4hound.logger import get_logger

logger = get_logger("demo", log_file="events.ndjson")
logger.info("capture started", extra={"extra_fields": {"mode": "sniffer"}})
```

## 12. Desarrollo de frontend

```bash
cd frontend
npm ci
npm run dev
```

En desarrollo, la SPA infiere `http://<host>:45678` cuando corres Vite en `5173` o puertos de dev similares.
