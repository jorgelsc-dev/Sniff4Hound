#!/usr/bin/env bash
# Power off and delete the two lab VMs (disks + seed ISOs included). Leaves the
# downloaded alpine.qcow2/alpine.sha512 and the SSH keypair in .lab-vbox alone.
set -euo pipefail

for suffix in a b; do
    name="s4h-lab-${suffix}"
    if VBoxManage list vms | grep -q "\"${name}\""; then
        VBoxManage controlvm "$name" poweroff 2>/dev/null || true
        VBoxManage unregistervm "$name" --delete
        echo "${name}: removed" >&2
    else
        echo "${name}: not registered, skipping" >&2
    fi
done
