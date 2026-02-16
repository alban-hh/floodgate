#!/bin/bash

INTERFACE="vlan50"
PORTA=""
MENYRA=""
TCP_LIMIT="10000"
UDP_LIMIT="5000"
ICMP_LIMIT="100"
PPS_LIMIT=""
SYN_LIMIT="500"
SFLOW_PORT="6343"
ACL_AKTIV=1
WHITELIST="/etc/floodgate/whitelist.txt"
BLACKLIST=""

shfaq_ndihme() {
    echo "FloodGate Control Script"
    echo "========================"
    echo ""
    echo "Perdorimi: $0 [komanda] [opsionet]"
    echo ""
    echo "Komandat:"
    echo "  start         Fillo FloodGate me sFlow + ACL"
    echo "  stop          Ndalo FloodGate"
    echo "  status        Shfaq statusin"
    echo "  stats         Shfaq statistikat"
    echo "  blacklist     Shfaq IP te bllokuara"
    echo "  block <ip>    Bloko nje IP manualisht"
    echo "  unblock <ip>  Zhbloko nje IP"
    echo "  block-udp     Bloko te gjitha UDP"
    echo "  block-tcp     Bloko te gjitha TCP"
    echo ""
    echo "Opsionet:"
    echo "  -i <iface>    Interface (default: vlan50)"
    echo "  -p <port>     Porta target"
    echo "  -t <limit>    TCP limit (default: 10000)"
    echo "  -u <limit>    UDP limit (default: 5000)"
    echo "  -S <port>     sFlow port (default: 6343)"
    echo "  --no-acl      Caktivo ACL automatik"
    echo "  --no-sflow    Caktivo sFlow"
    echo ""
}

start_floodgate() {
    if pgrep -x "floodgate" > /dev/null; then
        echo "FloodGate tashmë duke punuar"
        exit 0
    fi

    ARGS="-i $INTERFACE -s 5"

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

    if [ ! -z "$ICMP_LIMIT" ]; then
        ARGS="$ARGS -c $ICMP_LIMIT"
    fi

    if [ ! -z "$SYN_LIMIT" ]; then
        ARGS="$ARGS -Y $SYN_LIMIT"
    fi

    if [ ! -z "$PPS_LIMIT" ]; then
        ARGS="$ARGS -P $PPS_LIMIT"
    fi

    if [ "$SFLOW_PORT" != "0" ] && [ ! -z "$SFLOW_PORT" ]; then
        ARGS="$ARGS -S $SFLOW_PORT"
    fi

    if [ "$ACL_AKTIV" = "1" ]; then
        ARGS="$ARGS -a"
    fi

    if [ -f "$WHITELIST" ]; then
        ARGS="$ARGS -w $WHITELIST"
    fi

    if [ ! -z "$BLACKLIST" ] && [ -f "$BLACKLIST" ]; then
        ARGS="$ARGS -b $BLACKLIST"
    fi

    echo "Duke startuar FloodGate me: $ARGS"
    cd /usr/local/lib
    nohup /usr/local/bin/floodgate $ARGS > /var/log/floodgate.log 2>&1 &
    echo "FloodGate u startua (PID: $!)"
}

stop_floodgate() {
    if ! pgrep -x "floodgate" > /dev/null; then
        echo "FloodGate nuk eshte duke punuar"
        exit 0
    fi

    pkill -INT floodgate
    sleep 2

    if pgrep -x "floodgate" > /dev/null; then
        pkill -9 floodgate
    fi

    ip link set dev $INTERFACE xdp off 2>/dev/null || true

    echo "FloodGate u ndal"
}

shfaq_status() {
    if pgrep -x "floodgate" > /dev/null; then
        echo "FloodGate: AKTIV"
        echo "PID: $(pgrep -x floodgate)"
        echo ""
        echo "XDP Programs:"
        bpftool net show 2>/dev/null | grep -i xdp || echo "  (asgje)"
        echo ""
        echo "BPF Maps:"
        bpftool map show 2>/dev/null | grep -E "harta_" || echo "  (asgje)"
    else
        echo "FloodGate: JO AKTIV"
    fi
}

shfaq_blacklist() {
    echo "=== Blacklist ==="
    bpftool map dump name harta_bllokuar 2>/dev/null | while read -r line; do
        if echo "$line" | grep -q "key:"; then
            hex=$(echo "$line" | grep -oP 'key: \K.*' | tr -d ' ')
            if [ ! -z "$hex" ]; then
                echo "  $hex"
            fi
        fi
    done
    echo "================="
}

bloko_ip() {
    local IP=$1
    if [ -z "$IP" ]; then
        echo "Perdorimi: $0 block <ip>"
        exit 1
    fi

    HEX=$(python3 -c "import socket,struct; print(' '.join(f'{b:02x}' for b in socket.inet_aton('$IP')))")
    echo "Duke bllokuar $IP..."
    bpftool map update name harta_bllokuar key hex $HEX value hex 00 00 00 00 00 00 00 00 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "IP $IP u bllokua"
    else
        echo "Gabim ne bllokimin e $IP"
    fi
}

zhbloko_ip() {
    local IP=$1
    if [ -z "$IP" ]; then
        echo "Perdorimi: $0 unblock <ip>"
        exit 1
    fi

    HEX=$(python3 -c "import socket,struct; print(' '.join(f'{b:02x}' for b in socket.inet_aton('$IP')))")
    echo "Duke zhbllokuar $IP..."
    bpftool map delete name harta_bllokuar key hex $HEX 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "IP $IP u zhbllokua"
    else
        echo "Gabim ne zhbllokimin e $IP"
    fi
}

if [ $# -eq 0 ]; then
    shfaq_ndihme
    exit 0
fi

KOMANDA=$1
shift

while [ $# -gt 0 ]; do
    case $1 in
        -i) INTERFACE=$2; shift 2 ;;
        -p) PORTA=$2; shift 2 ;;
        -t) TCP_LIMIT=$2; shift 2 ;;
        -u) UDP_LIMIT=$2; shift 2 ;;
        -S) SFLOW_PORT=$2; shift 2 ;;
        --no-acl) ACL_AKTIV=0; shift ;;
        --no-sflow) SFLOW_PORT=0; shift ;;
        -h) shfaq_ndihme; exit 0 ;;
        *) break ;;
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
        bpftool map dump name harta_statistika 2>/dev/null
        ;;
    blacklist)
        shfaq_blacklist
        ;;
    block)
        bloko_ip "$1"
        ;;
    unblock)
        zhbloko_ip "$1"
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
