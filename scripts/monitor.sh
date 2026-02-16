#!/bin/bash

echo "FloodGate Monitor"
echo "================"
echo ""

watch -n 1 '
echo "=== XDP Program Status ==="
bpftool net show 2>/dev/null | grep -i xdp || echo "Jo XDP program"
echo ""

echo "=== Statistika ==="
bpftool map dump name harta_statistika 2>/dev/null | head -40
echo ""

echo "=== Top IP (harta_ip) ==="
bpftool map dump name harta_ip 2>/dev/null | head -50
echo ""

echo "=== Blacklist (harta_bllokuar) ==="
COUNT=$(bpftool map dump name harta_bllokuar 2>/dev/null | grep -c "key:")
echo "Total IP te bllokuara: $COUNT"
bpftool map dump name harta_bllokuar 2>/dev/null | head -20
echo ""

echo "=== Interface Stats ==="
ip -s link show vlan50 2>/dev/null || ip -s link show eno1 2>/dev/null
'
