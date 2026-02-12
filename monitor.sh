#!/bin/bash

echo "FloodGate Monitor"
echo "================"
echo ""

watch -n 1 '
echo "=== XDP Program Status ==="
bpftool net show 2>/dev/null | grep xdp || echo "Jo XDP program"
echo ""

echo "=== Statistika ==="
if [ -f /sys/kernel/debug/bpf/harta_statistika ]; then
    bpftool map dump name harta_statistika 2>/dev/null | head -20
else
    echo "Hartat nuk jane te disponueshme"
fi
echo ""

echo "=== Top 10 IP me me shume paketa ==="
bpftool map dump name harta_ip 2>/dev/null | grep -A2 "key:" | head -30
echo ""

echo "=== Interface Stats ==="
ip -s link show | grep -A3 "vlan50\|eno1" 2>/dev/null
'
