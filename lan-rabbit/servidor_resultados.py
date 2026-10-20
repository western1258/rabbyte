#!/usr/bin/env python3
"""Descarga de un único resultado LAN Rabbit."""
import argparse
import fcntl
import base64
import hmac
import ssl
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import tempfile
from urllib.parse import urlsplit
import zipfile


def archivos(s):
    if s.is_symlink() or (s / 'reporte.json').is_symlink():
        raise ValueError('No se permiten enlaces simbólicos.')
    meta = json.loads((s / 'reporte.json').read_text())
    if meta.get('estado') not in ('completa', 'parcial', 'error'):
        raise ValueError('La sesión no está finalizada.')
    manifest = s / 'SHA256SUMS'
    if manifest.is_symlink():
        raise ValueError('Manifiesto no válido.')
    if not manifest.is_file():
        raise ValueError("Resultado pendiente de finalizar.")
    result = []
    for line in manifest.read_text().splitlines():
        digest, name = line.split('  ', 1)
        rel = Path(name)
        if rel.is_absolute() or '..' in rel.parts or not rel.parts:
            raise ValueError('Ruta no válida.')
        f = s / rel
        if any((s / Path(*rel.parts[:i])).is_symlink() for i in range(1, len(rel.parts)+1)):
            raise ValueError('No se permiten enlaces simbólicos.')
        if not f.is_file():
            raise ValueError('Archivo ausente.')
        result.append((f, name, digest))
    if not {'reporte.json', 'resumen.txt', 'objetivos.txt'}.issubset({n for _, n, _ in result}):
        raise ValueError('Manifiesto incompleto.')
    return meta, result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directorio', default=str(Path.home() / 'lan-rabbit' / 'resultados'))
    p.add_argument('--puerto', type=int, default=8080)
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--tls-cert')
    p.add_argument('--tls-key')
    p.add_argument('--auth-file')
    p.add_argument('--http-pruebas', action='store_true')
    a = p.parse_args()
    auth = json.loads(Path(a.auth_file).read_text()) if a.auth_file else None
    if a.bind != '127.0.0.1' and not (auth and ((a.tls_cert and a.tls_key) or a.http_pruebas)):
        p.error('El acceso por red requiere autenticación y TLS o --http-pruebas.')
    base = Path(a.directorio).expanduser().absolute()
    if base.is_symlink():
        p.error('No se admite un directorio simbólico.')
    base.mkdir(parents=True, exist_ok=True)
    lock_path = base.parent / (base.name + '.lock')

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(15)
            super().setup()

        def do_GET(self):
            if auth:
                try:
                    scheme, encoded = self.headers.get('Authorization', '').split(' ', 1)
                    user, password = base64.b64decode(encoded, validate=True).decode().split(':', 1)
                    valid = (scheme.lower() == 'basic' and hmac.compare_digest(user.encode(), auth['usuario'].encode())
                             and hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), auth['sha256']))
                except (ValueError, UnicodeError):
                    valid = False
                if not valid:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="LAN Rabbit", charset="UTF-8"')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
            path = urlsplit(self.path).path
            if path == '/':
                with lock_path.open('a') as lock:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        meta, items = archivos(base)
                        pdf = next((x for x in items if x[1] == 'reporte.pdf'), None)
                        if pdf is None or hashlib.sha256(pdf[0].read_bytes()).hexdigest() != pdf[2]:
                            raise ValueError('PDF pendiente o modificado.')
                        content = '<h2>Listo para descargar</h2><p>Resultado: %s</p><p>Generado (UTC): %s</p><p><a href="/reporte.pdf">Ver reporte PDF con diagrama</a></p><p><a href="/resultados.zip">Descargar paquete completo</a></p>' % (
                            html.escape(str(meta['estado'])), html.escape(str(meta.get('generado_utc', 'No disponible'))))
                    except BlockingIOError:
                        content = '<h2>Proceso en curso</h2><p>Las descargas estarán disponibles al terminar.</p>'
                    except (OSError, ValueError, KeyError, TypeError):
                        content = '<h2>Esperando resultados</h2><p>Todavía no hay archivos listos para descargar.</p>'
                body = ('<!doctype html><html lang="es"><meta charset="utf-8">'
                        '<meta name="viewport" content="width=device-width"><title>Resultados LAN Rabbit</title>'
                        '<meta http-equiv="refresh" content="5">'
                        '<style>body{font:18px system-ui;max-width:850px;margin:40px auto;padding:20px}</style>'
                        '<h1>Resultados LAN Rabbit</h1><p>Se conserva un único resultado. La siguiente ejecución reemplaza el anterior.</p>'
                        + content + '<p>Esta página se actualiza cada 5 segundos.</p></html>').encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(body)
                return
            if path == '/reporte.pdf':
                try:
                    with lock_path.open('a') as lock:
                        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        _, items = archivos(base)
                        item = next((x for x in items if x[1] == path[1:]), None)
                        if item is None:
                            raise ValueError('No hay reporte PDF.')
                        body = item[0].read_bytes()
                        if hashlib.sha256(body).hexdigest() != item[2]:
                            raise ValueError('El reporte cambió.')
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/pdf')
                    self.send_header('Content-Length', str(len(body)))
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
                    self.end_headers()
                    self.wfile.write(body)
                except (OSError, ValueError, KeyError, TypeError):
                    self.send_error(409, 'Reporte no disponible o integridad incorrecta')
                return
            if path != '/resultados.zip':
                self.send_error(404)
                return
            try:
                with tempfile.TemporaryFile() as tmp:
                    with lock_path.open('a') as lock:
                        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        _, items = archivos(base)
                        with zipfile.ZipFile(tmp, 'w', compression=zipfile.ZIP_STORED) as z:
                            for f, rel, expected in items:
                                digest = hashlib.sha256()
                                with f.open('rb') as src, z.open('resultados/' + rel, 'w') as dest:
                                    while True:
                                        block = src.read(65536)
                                        if not block:
                                            break
                                        digest.update(block)
                                        dest.write(block)
                                if digest.hexdigest() != expected:
                                    raise ValueError('Los archivos cambiaron después del cierre.')
                            z.write(base / 'SHA256SUMS', 'resultados/SHA256SUMS')
                    length = tmp.tell()
                    tmp.seek(0)
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/zip')
                    self.send_header('Content-Length', str(length))
                    self.send_header('Content-Disposition', 'attachment; filename="resultados.zip"')
                    self.send_header('Cache-Control', 'no-store')
                    self.end_headers()
                    shutil.copyfileobj(tmp, self.wfile, length=65536)
            except (OSError, ValueError, KeyError, TypeError):
                self.send_error(409, 'Resultado no finalizado o integridad incorrecta')

    server = ThreadingHTTPServer((a.bind, a.puerto), Handler)
    server.daemon_threads = True
    if a.tls_cert and a.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(a.tls_cert, a.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print('Servidor de resultado único en puerto %s' % a.puerto, flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
