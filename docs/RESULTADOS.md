# Archivos y formatos

## Entradas del escáner

El orquestador ejecuta el escáner desde `/home/pi/rabbyte`, por lo que sus rutas relativas terminan en esa carpeta.

| Archivo | Uso |
| --- | --- |
| `arp-scan.txt` | IP y MAC encontradas. |
| `arp-scan.stderr.txt` | Errores y avisos de ARP. |
| `nmap.xml` | Documentos XML de las consultas de servicios. |
| `nmap.gnmap` | Salida grepable conservada como original. |
| `nmap.stdout.txt` | Consola de las consultas de servicios. |
| `nmap.stderr.txt` | Errores de las consultas de servicios. |
| `tracerOW.txt` | Salida de `nmap -sn --traceroute`. |

También se admiten `nmap.nmap`, `tracerOW.xml`, `tracerOW.stderr.txt`, `comandos.txt` y `versiones.txt` si existen. El escáner actual no genera necesariamente todos esos archivos. No se considera obligatorio inventar archivos vacíos para completarlos.

La primera fase de descubrimiento de puertos utiliza archivos temporales `/tmp/puertos-IP`, que el escáner elimina después de usarlos. El paquete conserva las salidas que quedan en la carpeta del escáner, no una captura completa de toda su consola.

## Publicación

El generador toma una copia de los originales, comprueba que no estén cambiando y escribe el paquete en `/home/pi/lan-rabbit/resultados`:

```text
resultados/
├── reporte.pdf
├── reporte.json
├── resumen.txt
├── archivo.csv
├── rutas_traceroute.json
├── objetivos.txt
├── SHA256SUMS
└── originales disponibles, en la misma carpeta
```

`resultados.zip` no se guarda permanentemente: el servidor lo construye al solicitarlo e incluye estos archivos bajo una carpeta `resultados/`.

## JSON del reporte

`reporte.json` incluye:

| Campo | Contenido |
| --- | --- |
| `schema_version` | Versión del formato del generador. |
| `generado_utc` | Fecha de generación del reporte; no sustituye la hora de cada escaneo. |
| `estado` | `parcial` o `error` en el generador actual. |
| `interfaz`, `ip_pi` | Datos que entrega el orquestador. Pueden ser nulos al generar un reporte manual sin parámetros. |
| `objetivos_autorizados` | Alcance recibido mediante `--red` o `--objetivos`. |
| `herramientas` | Códigos de salida si se proporcionan; de lo contrario, nulos. |
| `ejecuciones_nmap` | Comando, versión, fechas y alcance de cada documento Nmap. |
| `equipos` | Datos y puertos organizados por IP. |
| `rutas_traceroute` | Destinos con su secuencia de saltos. |
| `errores`, `avisos` | Fallos de lectura y límites de interpretación. No aparecen como sección en el PDF. |

Cada equipo puede contener MAC, fabricante, nombres, estado de Nmap, puertos y datos de sistema operativo cuando el XML los incluye. El escáner actual utiliza `-sV`, pero no un escaneo dedicado `-O`: no se garantiza identificar un modelo de dispositivo ni su sistema operativo.

## Rutas y árbol

Se prefiere `tracerOW.txt`; si no existe, se intenta leer `tracerOW.xml`. El parser de texto reconoce tanto IP directas como líneas con nombre de equipo seguido de su IP. No sustituye un salto sin respuesta por una dirección inventada.

Ejemplo ficticio de `rutas_traceroute.json`:

```json
[
  {
    "destino": "192.0.2.20",
    "saltos": [
      {"salto": 1, "ip": "192.0.2.1", "rtt_ms": "2.0"},
      {"salto": 2, "ip": "192.0.2.20", "rtt_ms": "4.0"}
    ]
  }
]
```

El PDF construye un árbol por prefijos de ruta. Una rama puede tener varios hijos: no es un árbol binario. La misma IP puede aparecer en rutas distintas. El inventario de Nmap se cruza por IP para añadir los puertos, y las tablas del PDF muestran servicios y versiones.

## CSV

`archivo.csv` no tiene encabezado; cada fila contiene `salto,IP`:

```csv
1,192.0.2.1
2,192.0.2.20
```

Un salto sin respuesta utiliza `*`. El CSV es una salida sencilla para el inventario inicial; no conserva por sí solo el destino al que pertenece cada ruta. Para reconstruir varias rutas usa el JSON, que sí mantiene esa asociación.

## Integridad y disponibilidad

`SHA256SUMS` contiene el hash de cada archivo publicado, excepto el propio manifiesto. Se escribe al final. El servidor exige un manifiesto y un reporte terminado; además verifica el PDF antes de anunciarlo disponible y los archivos al construir el ZIP.

Los bloqueos evitan que una descarga lea los archivos mientras se limpian o publican. No son contraseñas ni datos del experimento: los `.lock` son archivos de coordinación y se crean en tiempo de ejecución.

## Conservación

El orquestador elimina las salidas anteriores al comenzar una nueva ejecución completa. Una ejecución con `--solo-reportes` vuelve a interpretar los originales existentes y reemplaza el paquete publicado, sin volver a escanear.

Los comandos de uso normal son silenciosos. Si ocurre un error, revisa `orquestador.log`, `reporte.json`, `resumen.txt` y los archivos `stderr` originales.
