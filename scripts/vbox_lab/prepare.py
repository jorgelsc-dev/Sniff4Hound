#!/usr/bin/env python3
"""Prepare private disks and NoCloud seeds; run with the pycdlib environment."""
import hashlib
import io
import json
from pathlib import Path
import subprocess

import pycdlib

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / '.lab-vbox'
LAB.mkdir(mode=0o700, exist_ok=True)
expected = (LAB / 'alpine.sha512').read_text().split()[0]
with (LAB / 'alpine.qcow2').open('rb') as stream:
    actual = hashlib.file_digest(stream, 'sha512').hexdigest()
if actual != expected:
    raise SystemExit('Image SHA-512 mismatch; refusing to prepare VMs')
print('Official Alpine SHA-512 verified', flush=True)
key = LAB / 'id_ed25519'
if not key.exists():
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'sniff4hound-isolated-lab', '-f', str(key)], check=True)
public_key = key.with_suffix('.pub').read_text().strip()
traffic = (Path(__file__).parent / 'traffic.py').read_text()
for suffix, address, mac in [('a', '192.168.56.10', '08:00:27:54:10:0a'), ('b', '192.168.56.20', '08:00:27:54:10:0b')]:
    name = 's4h-lab-' + suffix
    disk = LAB / (name + '.vdi')
    if not disk.exists():
        subprocess.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'vdi', str(LAB / 'alpine.qcow2'), str(disk)], check=True)
    user = {'hostname': name, 'ssh_pwauth': False, 'disable_root': True, 'ssh_authorized_keys': [public_key],
            'write_files': [
                {'path': '/opt/s4h-lab/traffic.py', 'permissions': '0755', 'content': traffic},
                {'path': '/etc/local.d/s4h.start', 'permissions': '0755', 'content': '#!/bin/sh\nnohup /usr/bin/python3 /opt/s4h-lab/traffic.py serve > /var/log/s4h-service.log 2>&1 < /dev/null &\n'}],
            'runcmd': [['rc-update', 'add', 'local', 'default'],
                       ['sh', '-c', 'nohup /usr/bin/python3 /opt/s4h-lab/traffic.py serve > /var/log/s4h-service.log 2>&1 < /dev/null &']]}
    network = {'version': 1, 'config': [{'type': 'physical', 'name': 'eth0', 'mac_address': mac,
                 'subnets': [{'type': 'static', 'address': address, 'netmask': '255.255.255.0'}]}]}
    files = {'user-data': '#cloud-config\n' + json.dumps(user),
             'meta-data': json.dumps({'instance-id': name + '-v1', 'local-hostname': name}),
             'network-config': json.dumps(network)}
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge='1.09', vol_ident='cidata')
    streams = []
    for i, (filename, content) in enumerate(files.items()):
        raw = content.encode()
        stream = io.BytesIO(raw)
        streams.append(stream)
        iso.add_fp(stream, len(raw), iso_path=f'/SEED{i}.;1', rr_name=filename, joliet_path='/' + filename)
    iso.write(str(LAB / (name + '-seed.iso')))
    iso.close()
    print(f'{name}: disk and seed ready; {address}; 512 MB RAM; 1 vCPU', flush=True)
