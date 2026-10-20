"""Lectura de rutas observadas para el reporte PDF."""
import csv
import json
import ipaddress
import re
import xml.etree.ElementTree as ET


def ipv4(texto):
    for valor in re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', texto):
        try:
            return str(ipaddress.IPv4Address(valor))
        except ValueError:
            continue
    return None


def leer_texto(texto):
    rutas = []
    actual = None
    en_trace = False
    for linea in texto.splitlines():
        if linea.startswith('Nmap scan report for '):
            destino = ipv4(linea)
            actual = dict(destino=destino, saltos=[]) if destino else None
            if actual is not None:
                rutas.append(actual)
            en_trace = False
        elif linea.startswith('TRACEROUTE'):
            en_trace = True
        elif en_trace and actual is not None:
            match = re.match(r'^\s*(\d{1,3})\s+(.+)$', linea)
            if match:
                ttl = int(match[1])
                if not 1 <= ttl <= 255:
                    continue
                resto = match[2]
                rtt = re.search(r'([\d.]+)\s*ms\b', resto)
                actual['saltos'].append(dict(salto=ttl, ip=ipv4(resto), rtt_ms=rtt[1] if rtt else None))
    return rutas


def integrar(base, reporte):
    rutas = []
    tracer = base / 'tracerOW.xml'
    texto = base / 'tracerOW.txt'
    if texto.exists():
        rutas = leer_texto(texto.read_text(errors='replace'))
        reporte['traceroute_fuente'] = 'tracerOW.txt'
    elif tracer.exists():
        try:
            raiz = ET.parse(tracer).getroot()
            reporte['traceroute_inicio_epoch'] = raiz.get('start')
            for host in raiz.findall('host'):
                addr = host.find("address[@addrtype='ipv4']")
                if addr is None:
                    continue
                saltos = []
                for h in host.findall('trace/hop'):
                    ttl = int(h.get('ttl'))
                    if ttl < 1 or ttl > 255:
                        raise ValueError('Número de salto fuera de rango')
                    saltos.append(dict(salto=ttl, ip=h.get('ipaddr'), rtt_ms=h.get('rtt')))
                rutas.append(dict(destino=addr.get('addr'), saltos=sorted(saltos, key=lambda x: x['salto'])))
        except (ET.ParseError, OSError, TypeError, ValueError) as exc:
            reporte['errores'].append('No se pudo integrar traceroute: ' + str(exc))
    else:
        reporte['avisos'].append('Sin archivos tracerOW.txt o tracerOW.xml.')
    reporte['rutas_traceroute'] = rutas
    reporte['avisos'].append('El diagrama muestra saltos observados, no cableado físico. '
                            'Traceroute y los servicios pueden corresponder a momentos distintos.')
    with (base / 'archivo.csv').open('w', encoding='utf-8', newline='') as f:
        csv.writer(f).writerows((s['salto'], s['ip'] or '*') for r in rutas for s in r['saltos'])
    (base / 'rutas_traceroute.json').write_text(json.dumps(rutas, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')



