# Laboratorio VBox aislado para Sniff4Hound

Dos VMs Alpine Linux (imagen cloud oficial, ~180 MB, 512 MB RAM / 1 vCPU cada una)
conectadas solo entre si por la red hostonly `vboxnet0` (`192.168.56.0/24`), que
tambien es la interfaz por la que el host puede capturar el trafico con
Sniff4Hound. Ninguna VM tiene acceso a Internet ni a la LAN real.

## Requisitos

- VirtualBox + `VBoxManage` (ya presentes en este equipo).
- `qemu-img` (convierte el cloud image qcow2 a vdi).
- Python con `pycdlib` para generar los ISOs NoCloud: `python -m pip install pycdlib`.

## Pasos

1. Descargar el cloud image oficial de Alpine y su checksum en
   `.lab-vbox/alpine.qcow2` / `.lab-vbox/alpine.sha512` (no versionado; ver
   [`.gitignore`](../../.gitignore)). Usar siempre la URL de
   `https://dl-cdn.alpinelinux.org/alpine/` y el `.sha512` publicado junto al
   artefacto.
2. `python scripts/vbox_lab/prepare.py` — verifica el SHA-512, genera la
   clave SSH `id_ed25519`, convierte el disco a `.vdi` por VM y arma los ISOs
   `cidata` (cloud-init NoCloud) con IP estatica, la clave publica y el
   servicio `traffic.py` instalado en `/opt/s4h-lab`.
3. `scripts/vbox_lab/create_vms.sh` — asegura `vboxnet0` en `192.168.56.1/24`,
   registra `s4h-lab-a` (`192.168.56.10`) y `s4h-lab-b` (`192.168.56.20`) con
   NIC1 hostonly, adjunta disco + seed ISO y arranca ambas en modo headless.
4. Capturar con Sniff4Hound en la interfaz `vboxnet0` del host.
5. Generar trafico de prueba por SSH (clave en `.lab-vbox/id_ed25519`,
   usuario `alpine`, root deshabilitado):

   ```bash
   ssh -i .lab-vbox/id_ed25519 alpine@192.168.56.10 \
       python3 /opt/s4h-lab/traffic.py traffic --peer 192.168.56.20 --rounds 60
   ```

   Cada VM ya corre `traffic.py serve` como servicio OpenRC (`local.d`), que
   expone HTTP (`:8080`, rutas `/health` y `/bytes`) y eco UDP (`:9999`) solo
   para las IPs de las dos VMs del lab.
6. `scripts/vbox_lab/destroy_vms.sh` — apaga y desregistra ambas VMs (borra
   sus discos y seeds; conserva el qcow2 base y la clave SSH para volver a
   ejecutar `prepare.py` sin re-descargar la imagen).

## Notas de seguridad

- `prepare.py` aborta si el SHA-512 del qcow2 no coincide con el esperado.
- La red es hostonly, no NAT ni bridged: las VMs no pueden salir a Internet
  ni tocar la red real del host.
- `traffic.py` solo habla con las dos IPs fijas del lab (`PEERS`); rechaza
  cualquier otro destino.
