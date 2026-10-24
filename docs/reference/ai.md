# Integración opcional de IA

La activación de IA tiene dos responsabilidades separadas:

1. `GET|POST /api/settings/ai` persiste la intención del operador. `enabled`
   es un booleano JSON estricto, el valor inicial es `false` y un POST inválido
   responde `400` sin modificar el estado. Ambas respuestas incluyen
   `model_status`, hoy siempre `not_configured`: ningún consumidor del
   runtime carga un modelo, así que `enabled=true` es solo un permiso guardado
   y la interfaz lo presenta como "preferencia guardada · sin modelo", sin
   aristas activas hacia el almacenamiento.
2. `sniff4hound.wsbuilder_ia.WsbuilderIAScorer` es un adaptador aislado para
   puntuar métricas agregadas. No entrena modelos, no inicia workers ni hace
   llamadas de red; el modelo debe ser proporcionado explícitamente por el
   llamador.

## Frontera de datos

El adaptador acepta como máximo 32 valores numéricos finitos y acota cada uno
al rango `[-1_000_000, 1_000_000]`; un número no representable (por ejemplo
un entero mayor que el rango de `float`) se descarta. Solo atraviesan la
frontera nombres de campos agregados permitidos, como `packets`, `flows`,
`tags` o `risk_score`, del nivel superior o de los contenedores
`soc_summary`, `summary`, `pipeline`, `stats`, `counts` y `totals` (un solo
nivel). Cualquier otro contenedor, alias o anidamiento se ignora; las listas
de filas no se recorren y las claves asociadas a direcciones, hosts, texto,
evidencia, preguntas o payloads se descartan también en plural (`payloads`,
`hosts`, `ips`). Una hoja del nivel superior tiene prioridad sobre la misma
clave dentro de un contenedor. El resultado solo
contiene el puntaje acotado, estado, origen, conteo de features y métricas
numéricas opcionales.

Por diseño, activar el ajuste no equivale a enviar tráfico o datos a un
proveedor. Una futura conexión externa debe introducir un proveedor separado,
con límites de tiempo/cola y una política de secretos y redacción propia;
`/api/settings/ai` no debe reutilizarse como canal de prompts o respuestas.

## Contrato de error

El fallo de importación, modelo o evaluación se convierte en un resultado
`unavailable` o en un `fallback` sobre `risk_score` cuando existe; un
`fallback` es un valor determinista existente, no una predicción. Nunca se
propaga al camino de captura. `enabled=false` devuelve `disabled` sin
inspeccionar la entrada ni importar `wsbuilder`, lo que mantiene opcional la
dependencia de IA; una entrada adversaria con `enabled=true` devuelve
`unavailable`.
