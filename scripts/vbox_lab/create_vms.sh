#!/usr/bin/env bash
# Create and start the two isolated Alpine VMs on the hostonly network vboxnet0.
# Run after scripts/vbox_lab/prepare.py has generated the disks and seed ISOs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="$ROOT/.lab-vbox"
HOSTONLY_IF="vboxnet0"
HOSTONLY_IP="192.168.56.1"
HOSTONLY_MASK="255.255.255.0"

if ! VBoxManage list hostonlyifs | grep -q "^Name:\s*${HOSTONLY_IF}\$"; then
    VBoxManage hostonlyif create
    HOSTONLY_IF="$(VBoxManage list hostonlyifs | awk '/^Name:/{print $2; exit}')"
fi
VBoxManage hostonlyif ipconfig "$HOSTONLY_IF" --ip "$HOSTONLY_IP" --netmask "$HOSTONLY_MASK"

for suffix_mac in "a 08:00:27:54:10:0a" "b 08:00:27:54:10:0b"; do
    suffix="${suffix_mac%% *}"
    mac="${suffix_mac#* }"
    name="s4h-lab-${suffix}"
    disk="$LAB/${name}.vdi"
    seed="$LAB/${name}-seed.iso"
    mac_novbox="${mac//:/}"

    if VBoxManage list vms | grep -q "\"${name}\""; then
        echo "${name}: already registered, skipping create" >&2
        continue
    fi

    VBoxManage createvm --name "$name" --ostype Linux_64 --register --basefolder "$LAB"
    VBoxManage modifyvm "$name" \
        --memory 512 --cpus 1 --vram 16 \
        --nic1 hostonly --hostonlyadapter1 "$HOSTONLY_IF" --macaddress1 "$mac_novbox" \
        --audio-driver none --usb off --usbehci off --nic2 none \
        --boot1 disk --boot2 none --boot3 none --boot4 none
    VBoxManage storagectl "$name" --name SATA --add sata --controller IntelAHCI
    VBoxManage storageattach "$name" --storagectl SATA --port 0 --device 0 --type hdd --medium "$disk"
    VBoxManage storagectl "$name" --name IDE --add ide
    VBoxManage storageattach "$name" --storagectl IDE --port 0 --device 0 --type dvddrive --medium "$seed"
    VBoxManage startvm "$name" --type headless
    echo "${name}: created and started" >&2
done
