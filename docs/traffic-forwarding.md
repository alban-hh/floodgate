# Forwarding i Trafikut

## topologjia e rrjetit

floodgate punon si traffic scrubber qe qendron mes routerit upstream dhe rrjetit te mbrojtur. trafiku i sulmit drejtohet ne scrubber, pastrohet, dhe kthehet.

```
                    ┌──────────────────────────────────────────┐
                    │            FloodGate Server               │
   Internet         │                                          │
      │             │   eno1 (192.168.100.253)                 │
      │             │     │ management + sFlow                 │
      ▼             │     │                                    │
 ┌─────────┐        │   vlan50 (trafik i ndotur HYRE)          │
 │  Cisco   │ ──────│──►  XDP pastron ketu                     │
 │  Router  │       │     │                                    │
 │          │ ◄─────│───  vlan51 (trafik i paster DALJE)       │
 └─────────┘        │                                          │
      │             └──────────────────────────────────────────┘
      │
      ▼
  Rrjeti i
  Mbrojtur
```

## si arrin trafiku ne scrubber

### opsioni 1: devijimi me bgp (rekomanduar)

kur detektohet sulm (nga fastnetmon ose manualisht), announceohet nje route bgp qe devijion trafikun e viktimes nepermjet scrubberit.

**rrjedha:**
1. fastnetmon detekton sulm ddos ne ip target
2. fastnetmon injekton route bgp permes exabgp/gobgp
3. routeri cisco meson routen dhe forwardon trafikun e sulmit ne vlan e scrubberit
4. floodgate xdp proceson paketat ne `vlan50`
5. trafiku i paster kthehet permes `vlan51` ose vlan te njejte

### opsioni 2: routing statik

per setup me te thejshte, konfiguro route statike ne router:

```
ip route 10.0.0.0 255.255.255.0 192.168.50.253
```

kjo permanentisht routon nje subnet nepermjet scrubberit. e dobishme per mbrojtje always-on.

### opsioni 3: policy-based routing

routo trafik specifik (sipas source, destinacionit, ose protokollit) nepermjet scrubberit:

```
route-map SCRUB permit 10
 match ip address acl DDOS-TARGETS
 set ip next-hop 192.168.50.253
!
ip access-list extended DDOS-TARGETS
 permit ip any host 10.0.0.100
!
interface GigabitEthernet0/0
 ip policy route-map SCRUB
```

## setup i vlan dhe interface

### ana e routerit cisco

krijo vlane per trafikun e ndotur (hyrje) dhe te paster (dalje):

```
interface GigabitEthernet0/1
 description TO-FLOODGATE
 no shutdown
!
interface GigabitEthernet0/1.50
 description TRAFIK-I-NDOTUR-NE-SCRUBBER
 encapsulation dot1Q 50
 ip address 192.168.50.1 255.255.255.0
!
interface GigabitEthernet0/1.51
 description TRAFIK-I-PASTER-NGA-SCRUBBER
 encapsulation dot1Q 51
 ip address 192.168.51.1 255.255.255.0
```

### ana e serverit linux

```bash
ip link add link eno1 name vlan50 type vlan id 50
ip link add link eno1 name vlan51 type vlan id 51
ip addr add 192.168.50.253/24 dev vlan50
ip addr add 192.168.51.253/24 dev vlan51
ip link set vlan50 up
ip link set vlan51 up
```

beje persistent ne `/etc/netplan/01-floodgate.yaml`:

```yaml
network:
  version: 2
  vlans:
    vlan50:
      id: 50
      link: eno1
      addresses:
        - 192.168.50.253/24
    vlan51:
      id: 51
      link: eno1
      addresses:
        - 192.168.51.253/24
```

apliko: `sudo netplan apply`

## rruga e kthimit per trafikun e paster

pas scrubbing xdp, paketat e pastra qe kalojne duhet te forwardohen perseri ne router. disa menyra:

### opsioni a: kthimi ne te njejten vlan (me e thjeshta)

nese perdor nje vlan te vetme, paketat e scrubuara kalojne xdp (XDP_PASS) dhe vazhdojne ne network stack normal te linux. konfiguro serverin si router:

```bash
sysctl -w net.ipv4.ip_forward=1
```

shto route per rrugen e kthimit:

```bash
ip route add default via 192.168.50.1 dev vlan50
```

### opsioni b: kthimi me dy vlane

trafiku i ndotur arrin ne `vlan50`, trafiku i paster del ne `vlan51`. kjo kerkon forwarding te paketave mes interfaceve:

```bash
sysctl -w net.ipv4.ip_forward=1

iptables -A FORWARD -i vlan50 -o vlan51 -j ACCEPT
iptables -A FORWARD -i vlan51 -o vlan50 -j ACCEPT

ip route add 10.0.0.0/24 via 192.168.51.1 dev vlan51
```

### opsioni c: bridge mode

bridge `vlan50` dhe `vlan51` qe scruberi te jete transparent:

```bash
ip link add br-scrub type bridge
ip link set vlan50 master br-scrub
ip link set vlan51 master br-scrub
ip link set br-scrub up
```

floodgate lidh xdp ne `vlan50` (ingress). paketat qe kalojne xdp vazhdojne nepermjet bridge ne `vlan51` dhe perseri ne router.

## konfigurimi bgp ne cisco per devijim

### setup bgp ne router

```
router bgp 65000
 neighbor 192.168.100.253 remote-as 65000
 neighbor 192.168.100.253 description FLOODGATE
 neighbor 192.168.100.253 update-source Loopback0
 !
 address-family ipv4
  neighbor 192.168.100.253 activate
  neighbor 192.168.100.253 route-map SCRUB-IN in
```

### route map per scrubbing

```
route-map SCRUB-IN permit 10
 set ip next-hop 192.168.50.253
```

### integrimi me fastnetmon

konfiguro fastnetmon te announcoj route bgp kur detekton sulme:

```
/etc/fastnetmon.conf:
  notify_script_path = /opt/fastnetmon/notify.sh
  gobgp = on
  gobgp_next_hop = 192.168.50.253
  gobgp_announce_host = on
```

kur fastnetmon detekton sulm:
1. announceon route /32 per ip target permes bgp
2. routeri ridrejton trafikun ne scrubber
3. floodgate pastron trafikun
4. kur sulmi ndalon, fastnetmon terhek routen

## shembull setup komplet

### 1. konfigurimi i rrjetit te serverit

```bash
# vlane
ip link add link eno1 name vlan50 type vlan id 50
ip addr add 192.168.50.253/24 dev vlan50
ip link set vlan50 up

# aktivo forwarding
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# route default per trafikun e paster
ip route add default via 192.168.50.1 dev vlan50
```

### 2. instalo floodgate

```bash
cd /opt/floodgate
sudo bash scripts/deploy.sh
```

### 3. konfiguro dhe starto

```bash
sudo floodgate -i vlan50 \
  -t 10000 -u 5000 -c 100 -Y 500 \
  -S 6343 -a \
  -w /etc/floodgate/whitelist.txt \
  -s 5
```

### 4. verifiko

```bash
# kontrollo xdp eshte lidhur
bpftool net show

# kontrollo stats
bpftool map dump name harta_statistika

# kontrollo sflow po arrin
tcpdump -i eno1 udp port 6343 -c 3

# dergo test traffic
scripts/test-flood.sh 192.168.50.253 80 udp
```

### 5. konfiguro routerin cisco

```
! sflow ne floodgate
flow exporter FLOODGATE
 destination 192.168.100.253
 transport udp 6343

! routo trafikun e sulmit ne scrubber
ip route 10.0.0.100 255.255.255.255 192.168.50.253

! ose perdor bgp devijim (shiko me lart)
```

## troubleshooting

### xdp nuk lidhet

```
Gabim ne attach te XDP: Device or resource busy
```

nje program tjeter xdp eshte lidhur tashme. hiqe perpara:

```bash
ip link set dev vlan50 xdp off
```

### trafiku nuk arrin ne scrubber

1. kontrollo vlan eshte up: `ip link show vlan50`
2. kontrollo routing ne cisco: `show ip route`
3. kontrollo me tcpdump: `tcpdump -i vlan50 -c 10`
4. verifiko cisco po forwardon ne next-hop te sakte

### sflow nuk punon

1. kontrollo firewall: `ufw status` ose `iptables -L -n`
2. kontrollo porti eshte hapur: `ss -ulnp | grep 6343`
3. kontrollo konfig sflow ne router: `show sflow` (nx-os) ose `show flow monitor`
4. kontrollo me tcpdump: `tcpdump -i eno1 udp port 6343`

### gabime memorie

nese krijimi i bpf map deshton, rrit limitin e locked memory:

```bash
ulimit -l unlimited
```

ose ne service file (tashme konfiguruar):

```ini
LimitMEMLOCK=infinity
```
