#!/usr/bin/env python3
"""Generate a SHA-256 manifest for all Kosty plugin files.

Run this before every release to update plugins.sha256:

    python scripts/generate_manifest.py

The manifest is written to kosty/providers/aws/services/plugins.sha256
and must be committed alongside the plugin files. The loader reads it
at startup to verify plugin integrity before executing any code.

Format: one line per plugin, sha256sum(1)-compatible:
    <hex_digest>  <relative_path>
"""

import hashlib
import os
import sys

SERVICES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'kosty', 'providers', 'aws', 'services'
)
MANIFEST_PATH = os.path.join(SERVICES_DIR, 'plugins.sha256')


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    services_dir = os.path.abspath(SERVICES_DIR)
    if not os.path.isdir(services_dir):
        print(f'ERROR: services directory not found: {services_dir}', file=sys.stderr)
        sys.exit(1)

    entries = []
    for root, dirs, files in os.walk(services_dir):
        dirs[:] = sorted(d for d in dirs if d != '__pycache__')
        for filename in sorted(files):
            if not filename.endswith('.py') or filename.startswith('__'):
                continue
            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, services_dir)
            digest = sha256_file(abs_path)
            entries.append((rel_path, digest))

    with open(MANIFEST_PATH, 'w') as f:
        for rel_path, digest in entries:
            f.write(f'{digest}  {rel_path}\n')

    print(f'Written {len(entries)} entries to {os.path.relpath(MANIFEST_PATH)}')


if __name__ == '__main__':
    main()
