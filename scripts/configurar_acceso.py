#!/usr/bin/env python3
"""Crea la autenticación local del servidor de descargas."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--usuario', default='juan')
    p.add_argument('--directorio', type=Path, default=Path.home() / 'lan-rabbit' / 'config')
    args = p.parse_args()
    if not args.usuario or ':' in args.usuario:
        p.error('El usuario no puede estar vacío ni contener dos puntos.')
    destino = args.directorio / 'descargas_auth.json'
    if destino.exists():
        p.error('Ya existe la configuración. No se reemplazó.')
    password = getpass.getpass('Contraseña de descarga: ')
    if not password or password != getpass.getpass('Repetir contraseña: '):
        p.error('Las contraseñas están vacías o no coinciden.')
    args.directorio.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = {'usuario': args.usuario, 'sha256': hashlib.sha256(password.encode()).hexdigest()}
    fd = os.open(destino, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=2)
        file.write('\n')
    print('Autenticación creada en', destino)


if __name__ == '__main__':
    main()
