#!/usr/bin/env bash
set -uo pipefail
umask 027

BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
ORIGEN="$(dirname -- "$BASE")/rabbyte"
SALIDA="$BASE/resultados"
IFACE=wlan0
SOLO_REPORTES=0
COMPROBAR=0
TIEMPO_MAXIMO=${TIEMPO_MAXIMO:-3600}

fallar() { echo "$*" >&2; exit 1; }
uso() { echo "Uso: $0 [--interfaz wlan0|eth0] [--solo-reportes] [--comprobar]"; }
while (($#)); do
    case "$1" in
        --interfaz) (($# >= 2)) || { uso; exit 1; }; IFACE=$2; shift 2 ;;
        --solo-reportes) SOLO_REPORTES=1; shift ;;
        --comprobar) COMPROBAR=1; shift ;;
        -h|--help|--ayuda) uso; exit 0 ;;
        *) uso; exit 1 ;;
    esac
done
[[ "$TIEMPO_MAXIMO" =~ ^[1-9][0-9]*$ ]] || fallar 'TIEMPO_MAXIMO debe ser un entero positivo.'
[[ -f "$BASE/reportes.py" && -d "$ORIGEN" && ! -L "$ORIGEN" && ! -L "$SALIDA" ]] || fallar 'Revisa las carpetas del proyecto.'
if (( ! SOLO_REPORTES )); then
    (( EUID != 0 )) || fallar 'Ejecuta este archivo como pi, sin sudo delante.'
    for cmd in sudo timeout arp-scan nmap; do command -v "$cmd" >/dev/null || fallar "Falta $cmd."; done
    [[ -f "$ORIGEN/escaner.sh" ]] || fallar 'No se encontró escaner.sh.'
fi
if (( COMPROBAR )); then
    ip -4 -o addr show dev "$IFACE" || exit 1
    echo "Escáner: $ORIGEN/escaner.sh"
    echo "PDF: $SALIDA/reporte.pdf"
    exit 0
fi

exec 9>"$BASE/orquestador.lock"
flock -n 9 || { echo 'Ya hay un proceso en ejecución.' >&2; exit 3; }
exec > /dev/null 2> >(tee "$BASE/orquestador.log" >&2)
trap 'echo "Proceso interrumpido." >&2; exit 130' INT
trap 'echo "Proceso terminado antes de finalizar." >&2; exit 143' TERM
SCAN_RC=0
ARGS=(guardar --origen "$ORIGEN" --directorio "$SALIDA" --interfaz "$IFACE")

if (( ! SOLO_REPORTES )); then
    sudo -n true || fallar 'No hay permisos para escanear sin contraseña.'
    for ((i=0; i<60; i++)); do
        IP_CIDR=$(ip -4 -o addr show dev "$IFACE" scope global 2>/dev/null | awk '{print $4}')
        [[ -n "$IP_CIDR" && "$IP_CIDR" != *$'\n'* ]] && break
        sleep 2
    done
    [[ -n "$IP_CIDR" && "$IP_CIDR" != *$'\n'* ]] || fallar 'No se obtuvo una IPv4 única. Se conservaron los resultados.'
    IP_PI=${IP_CIDR%/*}
    RED=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$IP_CIDR") || exit 1
    ARGS+=(--ip-pi "$IP_PI" --red "$RED" --puertos 'Todos TCP; versiones en los puertos abiertos')

    exec 8>"$BASE/resultados.lock"
    flock -x 8 || exit 1
    mkdir -p -- "$SALIDA" || exit 1
    shopt -s nullglob
    archivos=("$SALIDA"/* "$SALIDA"/.[!.]* "$SALIDA"/..?*)
    for nombre in arp-scan.txt arp-scan.stderr.txt nmap.xml nmap.nmap nmap.gnmap nmap.stdout.txt nmap.stderr.txt tracerOW.txt tracerOW.xml tracerOW.stderr.txt comandos.txt versiones.txt; do
        [[ -e "$ORIGEN/$nombre" || -L "$ORIGEN/$nombre" ]] && archivos+=("$ORIGEN/$nombre")
    done
    # Borrar solo archivos de resultados.
    for archivo in "${archivos[@]}"; do
        [[ -f "$archivo" && ! -L "$archivo" ]] || fallar "No se limpió: entrada inesperada en $archivo"
    done
    if ((${#archivos[@]})); then rm -- "${archivos[@]}" || exit 1; fi

    (
        cd -- "$ORIGEN" || exit 1
        sudo -n env IFACE="$IFACE" timeout --signal=TERM --kill-after=15s "${TIEMPO_MAXIMO}s" bash escaner.sh
    )
    SCAN_RC=$?
    flock -u 8; exec 8>&-
    (( SCAN_RC == 0 )) || echo "El escáner terminó con código $SCAN_RC." >&2
    (( SCAN_RC == 0 )) || ARGS+=(--error "El escáner terminó con código $SCAN_RC (124: tiempo agotado).")
fi

python3 "$BASE/reportes.py" "${ARGS[@]}"
REPORTES_RC=$?
(( REPORTES_RC == 0 )) || { echo "Reportes terminó con código $REPORTES_RC." >&2; exit "$REPORTES_RC"; }
exit "$SCAN_RC"
