import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lan-rabbit'))
from diagrama_reporte import leer_texto


class RutasTest(unittest.TestCase):
    def test_nombre_ip_y_salto_sin_respuesta(self):
        texto = '''Nmap scan report for destino (192.0.2.20)
TRACEROUTE
HOP RTT ADDRESS
1 2.0 ms router (192.0.2.1)
2 *
3 4.0 ms 192.0.2.20
'''
        ruta = leer_texto(texto)[0]
        self.assertEqual(ruta['destino'], '192.0.2.20')
        self.assertEqual([s['ip'] for s in ruta['saltos']], ['192.0.2.1', None, '192.0.2.20'])
        self.assertEqual([s['salto'] for s in ruta['saltos']], [1, 2, 3])

    def test_conserva_destinos_separados(self):
        texto = '''Nmap scan report for 192.0.2.20
TRACEROUTE
1 2.0 ms 192.0.2.20
Nmap scan report for 192.0.2.21
Host is up.
'''
        rutas = leer_texto(texto)
        self.assertEqual(len(rutas), 2)
        self.assertEqual(rutas[1]['saltos'], [])

    def test_no_inventa_rutas(self):
        self.assertEqual(leer_texto('Nmap done: 0 hosts up'), [])


if __name__ == '__main__':
    unittest.main()
