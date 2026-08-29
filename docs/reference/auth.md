# Auth

Sniff4Hound usa un token de sesion corto para la UI y JWT HS256 para integraciones o pruebas automatizadas.

## Token de sesion

- se genera al arrancar;
- tiene 8 caracteres alfanumericos;
- se imprime en la terminal cuando inicia `sniff4hound`;
- el enlace de arranque usa `/?code=<token>` para que la UI lo guarde
  automaticamente.

Cabeceras aceptadas:

- `Authorization: Bearer <token>`
- `X-Security-Code: <token>`
- `X-Access-Token: <token>`
- `?security_code=<token>`, `?access_token=<token>`, `?token=<token>` o `?auth=<token>` solo para el handshake WebSocket

La UI conserva el codigo en `localStorage` como `sniff4hound.securityCode`.
Cuando el banner del siguiente arranque trae un codigo nuevo, abrir ese enlace
lo reemplaza.

Si `SNIFF4HOUND_REQUIRE_AUTH=0`, la app permite acceso anonimo cuando no se envia token.

## JWT

`sniff4hound.auth.generate_token()` crea JWT firmados con HS256.

### Secreto de firma

**No existe ningun secreto por defecto en el codigo.** Un literal fijo en el
repositorio (y por tanto en el paquete `.deb`) permitiria a cualquiera firmar
un token valido para cualquier instalacion que no hubiese definido la variable,
sin conocer el security code: un bypass completo de la autenticacion.

Resolucion del secreto, en orden:

1. `SNIFF4HOUND_JWT_SECRET` si esta definido;
2. el contenido de `SNIFF4HOUND_DATA_DIR/jwt_secret`, generado la primera vez
   con `secrets.token_hex(32)` y persistido con permisos `0600`
   (`SNIFF4HOUND_JWT_SECRET_FILE` permite moverlo);
3. si no se puede escribir ese fichero, un secreto efimero en memoria,
   distinto en cada arranque.

La clave con la que se firma se *deriva* del secreto y de `JWT_KEY_VERSION`
(`auth._derive_signing_key`), y su identificador (`kid`) viaja en la cabecera
del token. Rotar el secreto o subir la version invalida de golpe todos los
tokens emitidos.

### Claims y validacion

`generate_token()` emite `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`, `user` y
`scope`. `decode_jwt()` valida, en este orden: `alg`, `kid`, la firma, `iss`,
`aud`, `exp`, `nbf` (con 60 s de tolerancia de reloj) y la lista de `jti`
revocados en memoria (`auth.revoke_jwt_id()`).

Variables:

- `SNIFF4HOUND_JWT_SECRET`: clave de firma (opcional, ver arriba)
- `SNIFF4HOUND_JWT_SECRET_FILE`: ruta del secreto persistido
- `SNIFF4HOUND_JWT_TTL`: tiempo de vida por defecto en segundos
- `SNIFF4HOUND_JWT_MAX_TTL`: techo para el `expires_in` que pida el llamante

Ejemplo:

```bash
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:45678/api/auth/session
```

## Rate limiting y auditoria

Cada intento rechazado se escribe en el log de la consola como una linea
`SECURITY AUTH-FAIL` con metodo, ruta, IP de origen, motivo y lockout aplicado,
y se cuenta contra `auth.AuthRateLimiter`: ventana deslizante por IP de origen
con backoff incremental. Superado el umbral, la API responde `429` con
`Retry-After` y el handshake `WS /ws/` se cierra con `4401`.

El limitador es compartido por la API, el WebSocket y `GET /api/auth/session`,
de modo que no se puede esquivar cambiando de transporte.

Variables:

- `SNIFF4HOUND_AUTH_RATE_LIMIT`: `0` lo desactiva (por defecto `1`)
- `SNIFF4HOUND_AUTH_FAILURE_WINDOW_SECONDS` (60)
- `SNIFF4HOUND_AUTH_FAILURE_THRESHOLD` (10)
- `SNIFF4HOUND_AUTH_LOCKOUT_BASE_SECONDS` (5)
- `SNIFF4HOUND_AUTH_LOCKOUT_MAX_SECONDS` (300)

Las credenciales nunca llegan al log: `access_log.redact_query()` sustituye por
`REDACTED` el valor de `code`, `security_code`, `access_token`, `token` y
`auth` en la query string (y en el `Referer`) antes de imprimir la linea.

## Flujo de validacion

1. `extract_token_from_header()` limpia la cabecera `Authorization`.
2. `verify_token()` compara el token de sesion o valida el JWT.
3. `authenticate_request()` devuelve el estado de autentificacion para HTTP y WebSocket.
4. `app._guard_request_auth()` aplica el limitador y registra el fallo antes de responder.
5. La query string solo se usa para autenticar el handshake de `WS /ws/`, no para desbloquear peticiones HTTP normales.
