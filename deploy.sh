#!/bin/bash

set -e

echo "FloodGate Deploy Script"
echo "======================="

if [ "$EUID" -ne 0 ]; then
    echo "Duhet ekzekutuar si root"
    exit 1
fi

echo "Duke kontrolluar varësi..."

if ! command -v clang &> /dev/null; then
    echo "Clang nuk u gjet. Duke instaluar..."
    apt-get update
    apt-get install -y clang
fi

if ! command -v llc &> /dev/null; then
    echo "LLVM nuk u gjet. Duke instaluar..."
    apt-get install -y llvm
fi

if [ ! -f /usr/include/bpf/bpf_helpers.h ]; then
    echo "libbpf nuk u gjet. Duke instaluar..."
    cd /tmp
    git clone https://github.com/libbpf/libbpf.git
    cd libbpf/src
    make
    make install
    cd ../../
    rm -rf libbpf
fi

echo "Duke kompiluar FloodGate..."
make clean
make

echo "FloodGate u kompilua me sukses!"
echo ""
echo "Perdorimi:"
echo "./floodgate -i <interface> [opsionet]"
