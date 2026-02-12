#!/bin/bash

INTERFACE="eno1"
PORTA=""
MENYRA=""

shfaq_ndihme() {
    echo "FloodGate Control Script"
    echo "========================"
    echo ""
    echo "Perdorimi: $0 [komanda] [opsionet]"
    echo ""
    echo "Komandat:"
    echo "  start         Fillo FloodGate"
    echo "  stop          Ndalo FloodGate"
    echo "  status        Shfaq statusin"
    echo "  stats         Shfaq statistikat"
    echo "  block-udp     Bloko te gjitha UDP ne port"
    echo "  block-tcp     Bloko te gjitha TCP ne port"
    echo "  ratelimit     Vendos rate limiting"
    echo ""
    echo "Opsionet:"
    echo "  -i <iface>    Interface (default: eno1)"
    echo "  -p <port>     Porta target"
    echo "  -t <limit>    TCP limit"
    echo "  -u <limit>    UDP limit"
    echo ""
}

start_floodgate() {
    if pgrep -x "floodgate" > /dev/null; then
        echo "FloodGate tashmë duke punuar"
        exit 0
    fi

    ARGS="-i $INTERFACE"

    if [ ! -z "$PORTA" ]; then
        ARGS="$ARGS -p $PORTA"
    fi

    if [ "$MENYRA" = "block-udp" ]; then
        ARGS="$ARGS -U"
    elif [ "$MENYRA" = "block-tcp" ]; then
        ARGS="$ARGS -T"
    fi

    if [ ! -z "$TCP_LIMIT" ]; then
        ARGS="$ARGS -t $TCP_LIMIT"
    fi

    if [ ! -z "$UDP_LIMIT" ]; then
        ARGS="$ARGS -u $UDP_LIMIT"
    fi

    echo "Duke startuar FloodGate me: $ARGS"
    nohup ./floodgate $ARGS > /var/log/floodgate.log 2>&1 &
    echo "FloodGate u startua (PID: $!)"
}

stop_floodgate() {
    if ! pgrep -x "floodgate" > /dev/null; then
        echo "FloodGate nuk është duke punuar"
        exit 0
    fi

    pkill -INT floodgate
    sleep 1

    if pgrep -x "floodgate" > /dev/null; then
        pkill -9 floodgate
    fi

    bpf_xdp_detach $INTERFACE 2>/dev/null || true

    echo "FloodGate u ndal"
}

shfaq_status() {
    if pgrep -x "floodgate" > /dev/null; then
        echo "FloodGate: AKTIV"
        echo "PID: $(pgrep -x floodgate)"
        echo "Interface: $(ip link show | grep -A1 xdp | head -1 | awk '{print $2}' | cut -d: -f1)"
    else
        echo "FloodGate: JO AKTIV"
    fi
}

if [ $# -eq 0 ]; then
    shfaq_ndihme
    exit 0
fi

KOMANDA=$1
shift

while getopts "i:p:t:u:h" opt; do
    case $opt in
        i) INTERFACE=$OPTARG ;;
        p) PORTA=$OPTARG ;;
        t) TCP_LIMIT=$OPTARG ;;
        u) UDP_LIMIT=$OPTARG ;;
        h) shfaq_ndihme; exit 0 ;;
    esac
done

case $KOMANDA in
    start)
        start_floodgate
        ;;
    stop)
        stop_floodgate
        ;;
    status)
        shfaq_status
        ;;
    stats)
        if [ ! -z "$PORTA" ]; then
            watch -n 1 "bpftool map dump name harta_statistika"
        else
            bpftool map dump name harta_statistika
        fi
        ;;
    block-udp)
        MENYRA="block-udp"
        start_floodgate
        ;;
    block-tcp)
        MENYRA="block-tcp"
        start_floodgate
        ;;
    *)
        echo "Komanda e panjohur: $KOMANDA"
        shfaq_ndihme
        exit 1
        ;;
esac
