#!/usr/bin/env bash

interfaz="${IFACE:-wlan0}"

for i in $(seq 1 10); do
    echo "Escaneo ARP $i"
    arp-scan -l -q -x -I "$interfaz" 2>> arp-scan.stderr.txt | tee -a arp-scan.txt
done

echo "Direcciones a escanear:"
sort -u arp-scan.txt | tee /tmp/arp-scan.txt && mv /tmp/arp-scan.txt arp-scan.txt

[ -s arp-scan.txt ] || exit 1

for ip in $(grep -Po '^([0-9]{1,3}\.){3}[0-9]{1,3}' arp-scan.txt); do
    echo ""
    echo "Escaneo De $ip"
    echo ""
    echo ""
    nmap -sS -Pn -p- -n --min-rate 1000 --max-retries 1 "$ip" -oG "/tmp/puertos-$ip"
    [ -s "/tmp/puertos-$ip" ] || continue
    puertos=$(grep -Po '[0-9]+(?=/open)' "/tmp/puertos-$ip" | paste -sd ',')
    [ -n "$puertos" ] && nmap -sS -sV -Pn -n -p "$puertos" "$ip" --append-output -oX nmap.xml -oG nmap.gnmap >> nmap.stdout.txt 2>> nmap.stderr.txt
    rm -f "/tmp/puertos-$ip"
    echo ""
    echo "FINALIZACION DE Escaneo De $ip"
    echo ""
    echo ""
done

nmap -sn --traceroute "$(ip -4 -o addr show dev "$interfaz" | grep -Po "(([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2})")" > tracerOW.txt

exit 0
