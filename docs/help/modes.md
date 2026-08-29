# Modos de ejecucion

Sniff4Hound trabaja con dos modos principales. Ambos comparten la misma base SQLite, la misma UI y la misma capa de autenticacion; cambia solo el motor activo.

| Modo | Uso | Que hace |
| --- | --- | --- |
| `sniffer` | Captura pasiva | Abre sockets raw, parsea paquetes y registra flows, tags y contadores. |
| `honeypot` | Respuesta activa | Escucha el set curado de puertos habilitados, ofrece 10k+ listeners activables, emite banners y guarda actividad emulada. |

## Cambiar de modo

### Variable de entorno

```bash
SNIFF4HOUND_RUNTIME_MODE=honeypot sniff4hound
```

### API local

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"honeypot"}'
```

## Arranque y parada

El endpoint `POST /api/runtime/` acepta estos payloads utiles:

- `{"action":"start"}`
- `{"action":"stop"}`
- `{"mode":"sniffer"}`
- `{"mode":"honeypot","interfaces":["eth0","wlan0"]}`
- `{"interfaces":["eth0"]}`

Si no quieres que el runtime arranque solo al iniciar, desactiva `SNIFF4HOUND_CAPTURE_AUTO_START`.

## Recomendacion practica

- usa `sniffer` para observacion real y analisis forense;
- usa `honeypot` para simulacion, deception o pruebas controladas;
- si cambias interfaces mientras `sniffer` esta corriendo, el runtime las persiste en `runtime_config`.
