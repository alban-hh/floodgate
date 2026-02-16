# Si ta perdoresh FloodGate

## cfare te duhet

- ubuntu 22.04+ (ose cdo linux me kernel 5.4+)
- root access (xdp kerkon root)
- interface rrjeti per te mbrojtur (vlan50, eth0, eno1 etj)

## instalimi

### automatik

```bash
sudo bash scripts/deploy.sh
```

instalon te gjitha dependencies, kompillon, vendos systemd service.

### manual

```bash
apt-get install clang-12 llvm-12 libbpf-dev libelf-dev linux-headers-$(uname -r) linux-tools-$(uname -r)
make
sudo make install
```

## start i shpejte

### vetem rate limiting

```bash
sudo floodgate -i vlan50 -t 10000 -u 5000 -c 100 -s 5
```

limiton cdo ip ne 10K tcp pps, 5K udp pps, 100 icmp pps ne vlan50, shfaq stats cdo 5 sekonda.

### me gjithcka - sflow + acl

```bash
sudo floodgate -i vlan50 \
  -t 10000 -u 5000 -c 100 \
  -Y 500 -P 50000 \
  -S 6343 -a \
  -w /etc/floodgate/whitelist.txt \
  -s 5
```

aktivon: rate limiting per protokoll, syn flood detection, pps limit global, sflow collector ne port 6343, acl automatik, dhe whitelist.

## opsionet e cli

| flag | argument | pershkrim |
|------|----------|-----------|
| `-i` | interface | interface rrjeti ku lidhet xdp (e detyrueshme) |
| `-p` | port | filtro vetem trafikun ne kete port destinacioni |
| `-t` | limit | tcp paketa per sekond limit per ip |
| `-u` | limit | udp paketa per sekond limit per ip |
| `-c` | limit | icmp paketa per sekond limit per ip |
| `-P` | limit | pps limit global per ip (te gjitha protokollet) |
| `-B` | limit | bytes per sekond limit per ip |
| `-Y` | limit | syn paketa per sekond limit per ip |
| `-U` | - | bloko te gjitha paketat udp |
| `-T` | - | bloko te gjitha paketat tcp |
| `-w` | file | ngarko whitelist nga file (nje ip per rresht) |
| `-b` | file | ngarko blacklist nga file (nje ip per rresht) |
| `-S` | port | aktivo sflow collector ne kete port udp |
| `-a` | - | aktivo acl engine automatik |
| `-s` | sekonda | shfaq statistika cdo x sekonda |
| `-h` | - | shfaq ndihme |

## skenareve te zakonshme

### dns amplification attack

```bash
sudo floodgate -i vlan50 -p 53 -U -w /etc/floodgate/whitelist.txt
```

bllokon te gjitha udp ne port 53 pervec ip te whitelisted.

### syn flood

```bash
sudo floodgate -i vlan50 -t 10000 -Y 500 -a -s 5
```

limiton tcp ne 10K pps dhe syn specifkisht ne 500 pps. acl bllokon automatikisht ip qe perseriten.

### ntp amplification

```bash
sudo floodgate -i vlan50 -p 123 -U -w /etc/floodgate/whitelist.txt
```

### sulm i perzierm me sflow intelligence

```bash
sudo floodgate -i vlan50 -t 10000 -u 5000 -c 100 -Y 500 -S 6343 -a -w /etc/floodgate/whitelist.txt -s 5
```

### monitor vetem (pa filtrim)

```bash
sudo floodgate -i vlan50 -s 2
```

pa limite, vetem lidh xdp dhe shfaq stats cdo 2 sekonda.

## file konfigurimi

### whitelist (`config/whitelist.txt`)

nje ip per rresht. rreshtat qe fillojne me `#` injorohen. ip ne whitelist kalojne pa asnje filtrim.

```
192.168.1.1
192.168.50.1
8.8.8.8
```

instalohet ne `/etc/floodgate/whitelist.txt` nga `make install`.

### blacklist (`config/blacklist.txt`)

e njejta format si whitelist. ip bllokohen menjehere ne wire speed.

```
1.2.3.4
5.6.7.8
```

## si service systemd

### start/stop

```bash
sudo systemctl start floodgate
sudo systemctl stop floodgate
sudo systemctl restart floodgate
```

### aktivo ne boot

```bash
sudo systemctl enable floodgate
```

### shiko logs

```bash
journalctl -u floodgate -f
```

### ndrysho konfigurimin e service

edito `config/floodgate.service` dhe riinstalo:

```bash
sudo cp config/floodgate.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart floodgate
```

## control script

```bash
scripts/floodgate-ctl.sh start              # starto me config default
scripts/floodgate-ctl.sh stop               # ndalo
scripts/floodgate-ctl.sh status             # shfaq statusin
scripts/floodgate-ctl.sh stats              # dump bpf map stats
scripts/floodgate-ctl.sh blacklist          # shfaq ip te bllokuara
scripts/floodgate-ctl.sh block 1.2.3.4      # bloko nje ip manualisht
scripts/floodgate-ctl.sh unblock 1.2.3.4    # hiq ip nga blacklist
```

## nivelet e kercenimit

cdo ip qe trackojme ka nje nivel kercenimt qe percakton si e trajtojme trafikun e tij:

| niveli | emri | cfare ndodh |
|--------|------|-------------|
| 0 | NORMAL | trafiku kalon normalisht |
| 1 | DYSHIMTE | dyshues - po monitorohet, tepricat dropohen |
| 2 | KUFIZUAR | rate limited me agresivisht |
| 3 | BLLOKUAR | te gjitha paketat dropohen |

### eskalimi

- kalon limitin me 1x: ngjitet ne DYSHIMTE
- kalon limitin me 2x: ngjitet ne KUFIZUAR
- kalon limitin me 3x: menjehere BLLOKUAR
- 5+ shkelje ne pps global: ngjitet nje nivel
- 10+ shkelje ne syn flood: ngjitet nje nivel

### dekadenca

pas 30 sekondash pa shkelje, niveli bie me 1. ip qe ndalojne sulmin kthehen ne NORMAL automatikisht.

### acl auto-block

kur acl eshte aktiv (`-a`), skanon tabelen e ip cdo 5 sekonda. ip me mbi 10 shkelje kalojne ne blacklist per 300 sekonda (5 minuta). kur ttl skadon, zhbllokohen automatikisht.

## statistikat

kur ekzekutohet me `-s`, floodgate shfaq dashboard me ngjyra:

- **LEJUAR** (jeshile): paketa/bytes qe kaluan
- **BLLOKUAR** (kuqe): paketa/bytes qe u dropuan
- **ACL** (vjollce): blacklist dhe numri i niveleve
- **TOP IP**: ip me me shume trafik me ngjyra sipas nivelit

## monitoring me bpftool

```bash
bpftool net show                           # verifiko xdp eshte lidhur
bpftool map dump name harta_statistika     # stats raw
bpftool map dump name harta_ip             # tracking data per ip
bpftool map dump name harta_bllokuar       # blacklist aktuale
bpftool map dump name harta_whitelist      # whitelist aktuale
```

## tuning i limiteve

vlera fillestare te rekomanduara per scrubbing server:

| parametri | vlera | pershkrimi |
|-----------|-------|-----------|
| `-t` | 10000 | tcp 10K pps per ip |
| `-u` | 5000 | udp 5K pps per ip |
| `-c` | 100 | icmp 100 pps per ip |
| `-Y` | 500 | syn 500 pps per ip |
| `-P` | 50000 | global 50K pps per ip |
| `-B` | 50000000 | 50 MB/s per ip |

rregulloji sipas trafikut tend. perdor monitor mode (`-s 2` pa limite) per te kuptuar baseline traffic perpara se te vendosesh limite.
