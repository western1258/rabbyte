#!/usr/bin/env python3
"""Reportes LAN Rabbit a partir de las salidas existentes de escaner.sh."""
import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
import xml.etree.ElementTree as ET
from diagrama_reporte import integrar
from reporte_pdf import generar_pdf

ORIGINALES = ('arp-scan.txt', 'arp-scan.stderr.txt', 'nmap.xml', 'nmap.nmap',
              'nmap.gnmap', 'nmap.stdout.txt', 'nmap.stderr.txt', 'comandos.txt', 'versiones.txt',
              'tracerOW.xml', 'tracerOW.txt', 'tracerOW.stderr.txt')


def fecha(epoch):
    try:
        return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def huellas(base):
    result = {}
    for name in ORIGINALES:
        p = base / name
        if p.is_symlink():
            raise ValueError('No se permiten originales simbólicos: ' + name)
        if p.is_file():
            result[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def equipo(ip):
    return dict(ip=ip, mac=None, fabricante=None, observado_arp=False,
                nombres=[], estado_nmap=None, sistema_operativo=[], puertos=[])


def leer(base, args):
    errores = list(args.error)
    avisos = ['El escáner añade datos a sus archivos: pueden contener varias ejecuciones. '
              'Este reporte describe los originales disponibles; no certifica una ejecución única.',
              'El escáner solo envía a Nmap las IP descubiertas mediante ARP.']
    equipos = {}
    arp = base / 'arp-scan.txt'
    if arp.exists():
        for linea in arp.read_text(errors='replace').splitlines():
            partes = linea.split()
            if len(partes) < 2:
                continue
            try:
                ipaddress.IPv4Address(partes[0])
            except ValueError:
                continue
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', partes[1]):
                continue
            e = equipos.setdefault(partes[0], equipo(partes[0]))
            e.update(mac=partes[1].lower(), observado_arp=True)
            if len(partes) > 2:
                e['fabricante'] = ' '.join(partes[2:])
    else:
        errores.append('Falta arp-scan.txt.')
    xml = base / 'nmap.xml'
    texto = xml.read_text(errors='replace') if xml.exists() else ''
    # Nmap puede concatenar varios XML en el mismo archivo.
    bloques = re.findall(r'<nmaprun\b[^>]*>.*?</nmaprun\s*>', texto, re.S)
    if not bloques:
        errores.append('No hay documentos Nmap completos en nmap.xml.')
    if texto.count('<nmaprun ') != len(bloques):
        errores.append('Hay un documento Nmap incompleto; se conservan los documentos completos.')
    ejecuciones = []
    for numero, bloque in enumerate(bloques, 1):
        try:
            root = ET.fromstring(bloque)
        except ET.ParseError as exc:
            errores.append('Documento Nmap %s inválido: %s' % (numero, exc))
            continue
        fin = root.find('runstats/finished')
        info = dict(comando=root.get('args'), version_nmap=root.get('version'),
                    inicio_utc=fecha(root.get('start')),
                    fin_utc=fecha(fin.get('time')) if fin is not None else None,
                    estado=fin.get('exit') if fin is not None else None,
                    alcance_puertos=[dict(x.attrib) for x in root.findall('scaninfo')])
        ejecuciones.append(info)
        if info['estado'] != 'success':
            errores.append('Documento Nmap %s sin finalización exitosa.' % numero)
        for host in root.findall('host'):
            addr = host.find("address[@addrtype='ipv4']")
            if addr is None:
                continue
            ip = addr.get('addr')
            try:
                ipaddress.IPv4Address(ip)
            except (ValueError, TypeError):
                continue
            e = equipos.setdefault(ip, equipo(ip))
            mac = host.find("address[@addrtype='mac']")
            if mac is not None:
                e['mac'] = mac.get('addr', '').lower() or e['mac']
                e['fabricante'] = mac.get('vendor') or e['fabricante']
            e['nombres'] = sorted(set(e['nombres'] + [n.get('name') for n in host.findall('hostnames/hostname') if n.get('name')]))
            status = host.find('status')
            e['estado_nmap'] = status.get('state') if status is not None else None
            e['sistema_operativo'] = [dict(o.attrib) for o in host.findall('os/osmatch')]
            # Conservar la última lectura de cada IP.
            e['ultima_observacion_utc'] = info['fin_utc']
            e['puertos'] = []
            for port in host.findall('ports/port'):
                st, sv = port.find('state'), port.find('service')
                servicio = dict(sv.attrib) if sv is not None else {}
                e['puertos'].append(dict(puerto=int(port.get('portid')), protocolo=port.get('protocol'),
                    estado=st.get('state') if st is not None else None,
                    servicio=servicio.get('name'), producto=servicio.get('product'),
                    version=servicio.get('version'), metodo_servicio=servicio.get('method'),
                    detalles=servicio, cpe=[c.text for c in sv.findall('cpe')] if sv is not None else []))
    for nombre in ('arp-scan.stderr.txt', 'nmap.stderr.txt'):
        p = base / nombre
        if p.exists() and p.read_text(errors='replace').strip():
            avisos.append('Hay mensajes en ' + nombre + '; consulta el original.')
    herramientas = {}
    for nombre, rc in [('arp-scan', args.arp_rc), ('nmap', args.nmap_rc)]:
        herramientas[nombre] = {'exit_code': rc}
        if rc is None:
            avisos.append('Código de salida de %s no proporcionado por el escáner.' % nombre)
        elif rc != 0:
            errores.append('%s terminó con código %s.' % (nombre, rc))
    return dict(schema_version='4.0', generado_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                estado='parcial' if equipos else 'error',
                interfaz=args.interfaz, ip_pi=args.ip_pi,
                objetivos_autorizados=args.red or [], puertos_tcp=args.puertos,
                herramientas=herramientas, ejecuciones_nmap=ejecuciones,
                equipos=sorted(equipos.values(), key=lambda e: ipaddress.IPv4Address(e['ip'])),
                errores=errores, avisos=avisos,
                nota_estado='Parcial: no hay delimitación fiable de una ejecución ni códigos de salida verificados.')


def resumen(r):
    lineas = ['LAN Rabbit — reporte de los archivos disponibles', 'Estado: ' + r['estado'],
              'Generado UTC: ' + r['generado_utc'],
              'Equipos observados: %s' % len(r['equipos']),
              'Documentos Nmap procesados: %s' % len(r['ejecuciones_nmap'])]
    for e in r['equipos']:
        lineas.append('\nIP: %s | MAC: %s | Fabricante: %s' % (e['ip'], e['mac'] or 'desconocida', e['fabricante'] or 'desconocido'))
        if e['nombres']:
            lineas.append('Nombres: ' + ', '.join(e['nombres']))
        if not e['puertos']:
            lineas.append('Sin puertos documentados en los XML disponibles.')
        for p in e['puertos']:
            lineas.append('  %s/%s %s | %s | %s | versión: %s' %
                (p['puerto'], p['protocolo'], p['estado'], p['servicio'] or 'desconocido',
                 p['producto'] or 'desconocido', p['version'] or 'desconocida'))
    lineas += ['\nErrores:'] + (r['errores'] or ['Ninguno detectado al leer los archivos.'])
    lineas += ['\nAvisos:'] + r['avisos']
    return '\n'.join(lineas) + '\n'


def principal():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('accion', choices=['guardar'])
    p.add_argument('--origen', default=str(Path.home() / 'rabbyte'))
    p.add_argument('--directorio', default=str(Path.home() / 'lan-rabbit' / 'resultados'))
    p.add_argument('--interfaz')
    p.add_argument('--ip-pi')
    p.add_argument('--red', '--objetivos', dest='red', nargs='+')
    p.add_argument('--puertos', default=None)
    p.add_argument('--arp-rc', type=int)
    p.add_argument('--nmap-rc', type=int)
    p.add_argument('--error', action='append', default=[])
    a = p.parse_args()
    origen = Path(a.origen).expanduser().absolute()
    salida = Path(a.directorio).expanduser().absolute()
    if origen == salida or origen in salida.parents or salida in origen.parents:
        p.error('Origen y salida deben ser carpetas independientes.')
    if origen.is_symlink() or salida.is_symlink() or not origen.is_dir():
        p.error('El origen debe existir y las carpetas no deben ser enlaces simbólicos.')
    salida.parent.mkdir(parents=True, exist_ok=True)
    with (salida.parent / (salida.name + '.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        antes = huellas(origen)
        if not antes:
            raise SystemExit('No hay originales para generar el reporte.')
        with tempfile.TemporaryDirectory(prefix='.reporte-', dir=salida.parent) as temp:
            stage = Path(temp)
            for nombre in antes:
                shutil.copyfile(origen / nombre, stage / nombre)
            time.sleep(1)
            if antes != huellas(origen) or antes != huellas(stage):
                raise SystemExit('Los originales están cambiando. Espera a que termine escaner.sh.')
            r = leer(stage, a)
            r['origen'] = str(origen)
            integrar(stage, r)
            generar_pdf(stage, r)
            (stage / 'reporte.json').write_text(json.dumps(r, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            (stage / 'resumen.txt').write_text(resumen(r), encoding='utf-8')
            (stage / 'objetivos.txt').write_text('\n'.join(a.red or []) + '\n', encoding='utf-8')
            hashes = [hashlib.sha256(f.read_bytes()).hexdigest() + '  ' + f.name for f in sorted(stage.iterdir())]
            (stage / 'SHA256SUMS').write_text('\n'.join(hashes) + '\n', encoding='utf-8')
            # Publicar con el bloqueo del servidor.
            salida.mkdir(mode=0o750, exist_ok=True)
            if any(x.is_symlink() or x.is_dir() for x in salida.iterdir()):
                raise SystemExit('La salida contiene enlaces o subcarpetas inesperadas; no se reemplazó.')
            manifest = salida / 'SHA256SUMS'
            if manifest.exists():
                manifest.unlink()
            for f in salida.iterdir():
                f.unlink()
            for f in stage.iterdir():
                if f.name != 'SHA256SUMS':
                    shutil.copyfile(f, salida / f.name)
            shutil.copyfile(stage / 'SHA256SUMS', manifest)
        print('Reporte generado: %s (%s equipos). Descarga: resultados.zip' % (salida, len(r['equipos'])))
        return 2 if r['errores'] else 0


if __name__ == '__main__':
    os.umask(0o027)
    raise SystemExit(principal())
