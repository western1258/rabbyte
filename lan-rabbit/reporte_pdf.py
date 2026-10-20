"""Informe técnico PDF: árbol de rutas y tablas de servicios."""
from html import escape
import textwrap
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Flowable


class Arbol(Flowable):
    def __init__(self, filas, equipos, width):
        super().__init__()
        self.filas, self.equipos = filas, equipos
        self.width, self.height = width, (len(filas) + 1) * 55

    def draw(self):
        c = self.canv
        c.setStrokeColor(colors.black)
        c.setLineWidth(.65)
        c.setFont('Helvetica-Bold', 10)
        top = self.height - 12
        c.drawString(6, top, 'Origen del traceroute')
        c.setFont('Helvetica', 8)
        c.drawString(6, top - 13, 'Raspberry Pi')
        positions = {(): (6, top - 23)}
        for index, (path, ip, ttl) in enumerate(self.filas):
            y = top - (index + 1) * 55
            x = 22 + (len(path) - 1) * 18
            parent = positions.get(path[:-1], (6, top - 23))
            c.line(parent[0], parent[1], parent[0], y + 3)
            c.line(parent[0], y + 3, x - 4, y + 3)
            c.circle(x - 1, y + 3, 1.5, fill=1, stroke=0)
            c.setFont('Helvetica-Bold', 10)
            c.drawString(x + 8, y, ip or 'Sin respuesta')
            c.setFont('Helvetica', 8)
            c.drawRightString(self.width - 4, y, 'Salto %s' % ttl)
            e = self.equipos.get(ip)
            if e:
                puertos = ', '.join(str(p['puerto']) + '/' + str(p['protocolo']) for p in e['puertos'])
                detalle = 'Puertos: ' + puertos if puertos else 'Sin puertos documentados.'
            else:
                detalle = 'Sin información de servicios para esta IP.'
            for n, line in enumerate(textwrap.wrap(detalle, max(25, int((self.width-x-15)/4.1)))[:2]):
                c.drawString(x + 8, y - 13 - n * 10, line)
            positions[path] = (x - 1, y - 24)


def generar_pdf(base, r):
    width = A4[0] - 92
    normal = ParagraphStyle('Informe', fontName='Helvetica', fontSize=9, leading=13, spaceAfter=7)
    small = ParagraphStyle('Detalle', parent=normal, fontSize=8, leading=11, spaceAfter=4)
    title = ParagraphStyle('Titulo', parent=normal, fontName='Helvetica-Bold', fontSize=19, leading=23, spaceAfter=12)
    heading = ParagraphStyle('Encabezado', parent=normal, fontName='Helvetica-Bold', fontSize=12, leading=16, spaceBefore=12, spaceAfter=8)
    sub = ParagraphStyle('Equipo', parent=normal, fontName='Helvetica-Bold', fontSize=10, leading=14, spaceBefore=10, spaceAfter=5)
    def P(s, style=normal):
        return Paragraph(escape(str(s if s is not None else 'No disponible')), style)
    def footer(c, doc):
        c.saveState()
        c.setStrokeColor(colors.HexColor('#888888'))
        c.setLineWidth(.4)
        c.line(46, 38, A4[0]-46, 38)
        c.setFont('Helvetica', 8)
        c.drawString(46, 25, 'LAN Rabbit | Resultados de red')
        c.drawRightString(A4[0]-46, 25, str(doc.page))
        c.restoreState()
    equipos = {e['ip']: e for e in r['equipos']}
    tree = {}
    for route in r.get('rutas_traceroute', []):
        branch = tree
        last = 0
        for h in route['saltos']:
            for ttl in range(last+1, h['salto']):
                branch = branch.setdefault((ttl, None), {})
            branch = branch.setdefault((h['salto'], h['ip']), {})
            last = h['salto']
    filas = []
    def walk(nodes, path=()):
        for key, children in nodes.items():
            current = path + (key,)
            filas.append((current, key[1], key[0]))
            walk(children, current)
    walk(tree)
    story = [P('Reporte de red', title), P('Proyecto LAN Rabbit'),
             P('Generado (UTC): ' + r['generado_utc'], small),
             P('Inventario: %s equipos. Rutas: %s destinos. Estado: %s.' %
               (len(equipos), len(r.get('rutas_traceroute', [])), r['estado']), small),
             P('1. Diagrama de rutas', heading),
             P('Las líneas representan saltos observados por traceroute. El detalle de servicios aparece en las tablas de la sección 2.', small)]
    if filas:
        for start in range(0, len(filas), 9):
            if start:
                story += [PageBreak(), P('Diagrama de rutas (continuación)', heading)]
            story.append(Arbol(filas[start:start+9], equipos, width))
    else:
        story.append(P('No se obtuvieron saltos para dibujar.'))
    en_rutas = {ip for _, ip, _ in filas}
    sin_ruta = [ip for ip in equipos if ip not in en_rutas]
    if sin_ruta:
        story += [P('Sin ruta documentada: ' + ', '.join(sin_ruta), small)]
    story += [PageBreak(), P('2. Servicios por equipo', heading)]
    for ip, e in equipos.items():
        block = [P(ip, sub), P('MAC: %s | Fabricante: %s' % (e.get('mac') or 'No disponible', e.get('fabricante') or 'No disponible'), small)]
        if e.get('ultima_observacion_utc'):
            block.append(P('Última observación Nmap (UTC): ' + e['ultima_observacion_utc'], small))
        if e['puertos']:
            rows = [[P(s, small) for s in ('Puerto', 'Estado', 'Servicio', 'Producto / versión')]]
            for p in e['puertos']:
                rows.append([P('%s/%s' % (p['puerto'], p['protocolo']), small), P(p['estado'], small),
                             P(p.get('servicio') or 'No disponible', small),
                             P(' '.join(str(x) for x in (p.get('producto'), p.get('version')) if x) or 'No disponible', small)])
            table = Table(rows, colWidths=[65, 58, 100, width-223], repeatRows=1, hAlign='LEFT')
            table.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),
                ('LINEBELOW',(0,0),(-1,0),.7,colors.black),
                ('LINEBELOW',(0,1),(-1,-1),.25,colors.HexColor('#bbbbbb')),
                ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),3),
                ('LEFTPADDING',(0,0),(-1,-1),3)]))
            block.append(table)
        else:
            block.append(P('Sin puertos documentados en los XML disponibles.', small))
        story += [KeepTogether(block), Spacer(1, 5)]
    doc = SimpleDocTemplate(str(base/'reporte.pdf'), pagesize=A4, rightMargin=46, leftMargin=46,
                            topMargin=42, bottomMargin=52, title='Reporte de red - LAN Rabbit',
                            author='Proyecto LAN Rabbit')
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


if __name__ == '__main__':
    import json
    import sys
    from pathlib import Path
    target = Path(sys.argv[1])
    generar_pdf(target, json.loads((target/'reporte.json').read_text(encoding='utf-8')))
