#!/bin/bash

set -e

echo "FloodGate Deploy Script"
echo "======================="

if [ "$EUID" -ne 0 ]; then
    echo "Duhet ekzekutuar si root"
    exit 1
fi

echo "Duke kontrolluar varesi..."

apt-get update -qq

if ! command -v clang-12 &> /dev/null; then
    echo "Duke instaluar clang-12..."
    apt-get install -y clang-12
fi

if ! command -v llc-12 &> /dev/null; then
    echo "Duke instaluar llvm-12..."
    apt-get install -y llvm-12
fi

if ! dpkg -l | grep -q libbpf-dev; then
    echo "Duke instaluar libbpf-dev..."
    apt-get install -y libbpf-dev
fi

if ! dpkg -l | grep -q libelf-dev; then
    echo "Duke instaluar libelf-dev..."
    apt-get install -y libelf-dev
fi

if ! dpkg -l | grep -q linux-headers-$(uname -r); then
    echo "Duke instaluar linux headers..."
    apt-get install -y linux-headers-$(uname -r)
fi

if ! dpkg -l | grep -q linux-tools-$(uname -r); then
    echo "Duke instaluar linux-tools (bpftool)..."
    apt-get install -y linux-tools-$(uname -r) linux-tools-common
fi

echo ""
echo "Duke kompiluar FloodGate..."
make clean
make

echo ""
echo "Duke instaluar..."
make install

echo ""
echo "FloodGate u instalua me sukses!"
echo ""
echo "Komandat:"
echo "  systemctl start floodgate     - Fillo"
echo "  systemctl stop floodgate      - Ndalo"
echo "  systemctl enable floodgate    - Aktivizo ne boot"
echo "  journalctl -u floodgate -f    - Shiko logs"
echo ""
echo "Ose perdor manualisht:"
echo "  floodgate -i vlan50 -t 10000 -u 5000 -c 100 -Y 500 -S 6343 -a -w /etc/floodgate/whitelist.txt -s 5"
echo ""
echo "Per sFlow, konfiguro routerin/switchin te dergoje sFlow ne $(hostname -I | awk '{print $1}'):6343"
