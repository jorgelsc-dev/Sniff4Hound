# Gobernanza, autoria y proteccion

Esta pagina resume como se protege la autoria, la trazabilidad y la identidad publica de `Sniff4Hound`.

## Estado oficial del proyecto

- Autor y mantenedor principal: `JorgelSC Dev`
- Repositorio canonico: `https://github.com/jorgelsc-dev/Sniff4Hound`
- Sitio oficial: `https://porthound.jorgelsc.dev`
- Comando oficial: `sniff4hound`

## Licencia y autoria

- El codigo fuente del repositorio usa licencia `MIT`, salvo que un archivo diga otra cosa.
- El copyright principal del proyecto figura en [`LICENSE`](https://github.com/jorgelsc-dev/Sniff4Hound/blob/main/LICENSE) y [`NOTICE`](https://github.com/jorgelsc-dev/Sniff4Hound/blob/main/NOTICE).
- La historia de Git y los metadatos de commit son parte de la trazabilidad de autoria y no deben alterarse a la ligera.

## Marca e identidad

La licencia del codigo no concede derechos de marca.

Eso significa que, salvo permiso expreso del mantenedor:

- el nombre `Sniff4Hound` no debe reutilizarse de forma que sugiera respaldo oficial;
- los logos e iconos publicos del proyecto no deben usarse para confundir origen o autoria;
- el dominio oficial y la presentacion publica del proyecto quedan reservados a su canal oficial.

## Reglas de contribucion con proteccion de procedencia

Toda contribucion deberia cumplir esto:

- ser trabajo propio o material que el autor puede relicenciar legalmente;
- conservar avisos de copyright, atribucion y licencia;
- no copiar codigo, texto o assets desde fuentes incompatibles o privadas;
- revelar uso de IA, fragmentos adaptados o dependencias de terceros cuando aplique;
- no incluir secretos, payloads capturados, datos personales ni contenido no redistribuible.

## Controles tecnicos del repositorio

El repositorio incluye estas defensas operativas:

- `CODEOWNERS`: asigna revision del repositorio al mantenedor.
- plantilla de PR: obliga a declarar autoria, atribucion y uso de IA/material de terceros.
- workflow `contribution-guard`: verifica `Signed-off-by:` en commits humanos y revisa la declaracion de procedencia del PR.
- `SECURITY.md`: fija reglas de manejo responsable para datos sensibles y reportes.

## Recomendaciones para GitHub branch protection

Para `main`, se recomienda activar en GitHub:

1. `Require a pull request before merging`
2. `Require approvals`
3. `Require review from Code Owners`
4. `Require conversation resolution before merging`
5. `Require status checks to pass before merging`
6. incluir `CI`, `dependency-review`, `CodeQL` y `contribution-guard`
7. bloquear force-push y branch deletion
8. limitar bypass administrativo a lo estrictamente necesario
9. activar secret scanning, push protection y alerts de dependencias

## Alcance

Estas medidas mejoran trazabilidad, defensa de autoria e higiene operativa del repositorio. No sustituyen asesoria legal formal en una jurisdiccion concreta.
