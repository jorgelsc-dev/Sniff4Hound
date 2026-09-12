# Revisión funcional y QA SOC — 2026-09-05

Base: `origin/main` en `baf6fdf`. Rama: `improve/soc-qa-hardening`.

## Método y alcance

Inspección de la instancia local 0.40.0 en el puerto 45670, navegación por las vistas principales, revisión de contratos HTTP/WebSocket, almacenamiento, exportaciones y pruebas automatizadas. La instancia inicial tenía cero paquetes y ambos motores detenidos. Los escenarios con evidencia se validan en una base temporal con tráfico sintético; no se mezclan fixtures con datos operativos.

## Hallazgos y criterios de aceptación

| ID | Prioridad | Error / necesidad | Criterio de aceptación |
| --- | --- | --- | --- |
| SOC-01 | Alta | Con cero paquetes se generan hallazgos de cobertura y se recomienda observación suficiente con riesgo 0. | Estado explícito de evidencia insuficiente, riesgo no evaluado y ninguna conclusión de seguridad sin paquetes. |
| SOC-02 | Alta | SOC ignora `since` en HTTP y WebSocket; la selección temporal no reconfigura la vista. Además, los feeds comunes comparan ventanas relativas directamente con fechas SQL. | Un único corte temporal aplicado a paquetes, payloads, tags, flujos y contexto; cambio de ventana verificable. |
| SOC-03 | Alta | Exportar flujos informa una ventana que realmente no filtra. | Excluir flujos sin actividad desde el corte e indicar que sus contadores son acumulados. |
| SOC-04 | Alta | CSV permite fórmulas en banners y otros textos controlados por tráfico remoto. | Neutralizar prefijos de fórmulas en CSV del servidor y tablas; JSON conserva evidencia original. |
| SOC-05 | Media | SOC no identifica límite de muestra, cobertura ni método del riesgo/confianza. | Mostrar tamaño disponible, límite, truncamiento, corte y naturaleza heurística; exportar el snapshot completo para relevo. |
| SOC-06 | Media | Cambiar profundidad reabre el stream aunque el analista lo haya pausado. | Cambios con pausa hacen una sola consulta, mantienen la pausa y descartan respuestas anteriores. |
| SOC-07 | Alta | Eventos tardíos de WebSockets reemplazados pueden reconectar o entregar evidencia del filtro anterior. | Ignorar mensajes, errores y cierres de sockets obsoletos o cerrados por el consumidor. |
| SOC-08 | Alta | Investigate admite carreras entre objetivos; el arranque de dominio puede ser sustituido por Top host. | Solo el objetivo vigente aplica resultados; enlaces de dominio preservados; cambio de tipo limpia evidencia anterior. |
| SOC-09 | Media | SOC infiere tráfico local a partir de cualquier JSON y declara ausencia de honeypot sin comprobarlo. | Descripciones basadas en el dato observado, sin atribuir localidad, benignidad ni ausencia no medidas. |
| SOC-10 | Media | Tablas SOC normalizan severidad crítica como informativa. | Crítica precede a alta y usa color de máxima prioridad. |
| SOC-11 | Baja | Reconfigurar logger descarta handlers sin cerrarlos. | Cerrar recursos anteriores sin duplicar salida. |
| SOC-12 | Media | Frontend solo ejecuta lint; faltan regresiones de comportamiento. | Incorporar pruebas de CSV, streams y flujos SOC/Investigate que fallen ante los defectos originales. |

| SOC-13 | Alta | Con datos sintéticos, las tablas Top Hosts, Top Conversations y Top Ports quedan vacías porque el template referencia nombres inexistentes. | Mostrar las filas reales y permitir el salto al host; verificar bindings en regresión y navegador. |
| SOC-14 | Media | SOC atribuye ambos puertos de una conversación a cada host, mezclando servicios remotos con puertos efímeros del otro extremo. | Cada host muestra únicamente sus propios puertos observados. |

## Criterios operativos

El análisis es una ayuda heurística sobre evidencia retenida, no una certificación de ausencia de intrusión. Las reglas, exclusiones y muestreo condicionan visibilidad. Los hallazgos de exposición requieren validar propiedad y contexto del servicio. El snapshot exportado debe conservar fecha UTC, ventana, parámetros y evidencia para el relevo de turno.

## Validación

Pendiente de completar tras implementar y verificar los cambios.
