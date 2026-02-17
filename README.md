# FloodGate

> xdp/ebpf traffic scrubber me sflow intelligence dhe acl automatik - dropon ddos ne kernel level

---

## perse floodgate

- **10+ milion paketa/sekond** - xdp proceson para cpu stack
- **zero overhead** - hash maps ne hardware speed
- **sflow v5 collector** - merr telemetri nga routeri, bllokon proaktivisht
- **acl automatik** - eskalon/de-eskalon ip automatikisht
- **4 nivele threat** - normal → dyshimte → kufizuar → bllokuar
- **udp challenge-response** - verifikon source ip, bllokon spoofed traffic
- **blacklist + whitelist** - wire speed, pa delay

---

## vecorite

### 1. xdp/ebpf scrubbing ne kernel level

floodgate lidh nje program xdp direkt ne interfacen e rrjetit dhe proceson cdo paket perpara se ajo te arrije ne cpu stack te linux. kjo do te thote qe paketat e keqia dropohen ne nivelin me te ulet te mundshem, pa u prekur nga sistemi operativ. arrihet shpejtesi mbi 10 milion paketa ne sekond ne nje nic te vetme.

### 2. rate limiting per protokoll

cdo source ip ka limite te ndara per tcp, udp, icmp, syn, pps globale, dhe bytes ne sekond. kur nje ip kalon limitin, paketat e teperta dropohen dhe niveli i kercenimit rritet. nese kalon limitin me 3x, ip bllokohet menjehere. limitet konfigurohen nga cli dhe aplikohen ne wire speed.

### 3. sflow v5 collector me auto-detection

floodgate degjon per datagrame sflow v5 nga routeri/switchi. parson headerat e paketave te sampluara, nxjerr source ip, dhe numeron pps/bps per cdo ip. kur nje ip kalon pragun (100K pps ose 100MB/s), shtohet ne blacklist automatikisht. kjo jep visibilitet mbi trafikun perpara se te arrije ne scrubber dhe mundeson bllokimin proaktiv.

### 4. acl engine me eskalim dhe dekadence

acl engine ekzekutohet ne nje thread te vecante dhe skanon tabelen e ip cdo 5 sekonda. ip me mbi 10 shkelje kalojne ne blacklist per 300 sekonda. cdo ip ka nje nga 4 nivelet e kercenimit: normal, dyshimte, kufizuar, bllokuar. nivelet rriten automatikisht kur ip sillet keq dhe bien pas 30 sekondash pa shkelje. ip qe ndalon sulmin kthehet ne normal vet.

### 5. udp challenge-response

kur aktivohet, floodgate verifikon cdo source ip qe dergon udp. per ip te reja, xdp dergon mbrapa nje cookie te rastesishme me xdp_tx. nese ip pergjigjet me cookie-n e sakte brenda 5 sekondash, whitelistohet per 300 sekonda. ip e spoofuar nuk e merrin kurre pergjigjen, pra nuk kalojne kurre. kjo eshte ekuivalenti i syn cookies per udp dhe mbrojtje efektive kunder reflection/amplification attacks.

---

## si punon

```
                         sFlow (UDP 6343)
                    ┌────────────────────────┐
                    │                        ▼
 Internet ───► Cisco Router ───► FloodGate XDP ───► Clean Traffic
                    │                │
                    │           ┌────┴────┐
                    │           │  sFlow  │──► ACL ──► Blacklist
                    │           │Collector│
                    │           └─────────┘
                    ▼
              Protected Network
```

### pipeline per cdo paket

```
paketa arrin
    ├── ne blacklist? ──► DROP
    ├── ne whitelist? ──► PASS
    ├── udp + challenge aktiv?
    │   ├── tashme verifikuar? ──► vazhdo
    │   ├── cookie e sakte? ──► VERIFIKUAR per 300s
    │   └── ip e re? ──► dergo cookie (XDP_TX)
    ├── protokolli bllokuar? ──► DROP
    ├── syn flood? ──► DROP + eskalo nivel
    ├── mbi pps limit? ──► DROP + eskalo
    ├── mbi limit protokollit?
    │   ├── 3x limit ──► DROP + BLLOKUAR direkt
    │   ├── 2x limit ──► DROP + KUFIZUAR
    │   └── 1x limit ──► DROP + DYSHIMTE
    ├── mbi bps limit? ──► DROP + eskalo
    └── nen te gjitha limitet ──► PASS + ul nivelin
```

---

## quick start

```bash
# instalo gjithcka
sudo bash scripts/deploy.sh

# full protection me sflow + acl
sudo floodgate -i vlan50 -t 10000 -u 5000 -c 100 -Y 500 -S 6343 -a -C -w /etc/floodgate/whitelist.txt -s 5
```

---

## opsionet cli

```
floodgate -i <interface> [opsionet]

  -i <interface>    interface rrjeti (e detyrueshme)
  -p <port>         filtro vetem nje port destinacioni
  -t <limit>        tcp paketa/sek per ip
  -u <limit>        udp paketa/sek per ip
  -c <limit>        icmp paketa/sek per ip
  -P <limit>        pps limit global per ip
  -B <limit>        bytes/sek limit per ip
  -Y <limit>        syn paketa/sek per ip
  -U                bloko te gjitha udp
  -T                bloko te gjitha tcp
  -w <file>         ngarko whitelist
  -b <file>         ngarko blacklist
  -S <port>         sflow collector port
  -a                aktivo acl automatik
  -C                aktivo udp challenge-response
  -s <sekonda>      shfaq stats cdo x sekonda
```

---

## use cases

| skenari | komanda |
|---------|---------|
| dns amplification | `floodgate -i vlan50 -p 53 -U -w whitelist.txt` |
| syn flood | `floodgate -i vlan50 -t 10000 -Y 500 -a -s 5` |
| ntp amplification | `floodgate -i vlan50 -p 123 -U` |
| full protection | `floodgate -i vlan50 -t 10000 -u 5000 -c 100 -Y 500 -S 6343 -a -C -s 5` |
| udp anti-spoof | `floodgate -i vlan50 -u 5000 -C -a -s 5` |
| monitor vetem | `floodgate -i vlan50 -s 2` |

---

## struktura e projektit

```
floodgate/
├── include/
│   └── floodgate_common.h      # struct te perbashketa kern + user
├── src/
│   ├── kern/
│   │   └── floodgate_kern.c    # xdp/ebpf programi kernel
│   └── user/
│       ├── main.c              # entry point, cli, sinjalet
│       ├── globals.h/c         # state e perbashket mes moduleve
│       ├── config.h/c          # whitelist/blacklist ngarkim
│       ├── stats.h/c           # statistika display
│       ├── sflow.h/c           # sflow v5 collector
│       └── acl.h/c             # acl engine automatik
├── scripts/
│   ├── deploy.sh               # instalim automatik
│   ├── floodgate-ctl.sh        # start/stop/block/unblock
│   ├── monitor.sh              # bpftool dashboard
│   └── test-flood.sh           # test traffic generator
├── config/
│   ├── floodgate.service       # systemd service
│   ├── whitelist.txt           # ip qe bypassojne filtrat
│   └── blacklist.txt           # ip qe bllokohen menjehere
├── docs/
│   ├── how-to-use.md           # si ta perdoresh
│   ├── sflow-integration.md    # integrimi me sflow
│   └── traffic-forwarding.md   # forwarding i trafikut
└── Makefile
```

---

## bpf maps

| harta | tipi | kapaciteti | qellimi |
|-------|------|------------|---------|
| `harta_ip` | hash | 10M | paketa per ip, nivelet, shkeljet |
| `harta_config` | array | 1 | konfigurimi runtime |
| `harta_statistika` | per-cpu array | 16 | statistika pa lock |
| `harta_whitelist` | hash | 10K | ip qe kalojne pa filter |
| `harta_bllokuar` | hash | 1M | ip te bllokuara (drop instant) |
| `harta_challenge` | lru hash | 1M | cookies te derguara per verifikim |
| `harta_verifikuar` | lru hash | 2M | ip te verifikuara nga challenge |

---

## nivelet e kercenimit

| niveli | emri | cfare ndodh |
|--------|------|-------------|
| 0 | NORMAL | trafiku kalon normalisht |
| 1 | DYSHIMTE | po monitorohet, paketat e teperta dropohen |
| 2 | KUFIZUAR | rate limited me agresivisht |
| 3 | BLLOKUAR | te gjitha paketat dropohen |

eskalimi: mbi 1x limit → dyshimte, mbi 2x → kufizuar, mbi 3x → bllokuar direkt

dekadenca: pas 30 sekondash pa shkelje, niveli bie me 1. ip qe ndalon sulmin rikthehet ne normal automatikisht.

---

## dokumentacioni

- [Si ta perdoresh](docs/how-to-use.md) - instalimi, opsionet, tuning
- [Integrimi me sFlow](docs/sflow-integration.md) - konfigurimi i routerit, sflow setup
- [Forwarding i trafikut](docs/traffic-forwarding.md) - topologjia, vlan, bgp

---

## requirements

- kernel **5.4+** (per btf)
- clang **12+** (per ebpf)
- libbpf **1.x**
- testuar: ubuntu 22.04 me kernel 5.15

---

## variablat ne shqip

| variabla | anglisht |
|----------|----------|
| ip_burimi | source ip |
| porta_dest | destination port |
| protokoll | protocol |
| numrues_paketa | packet counter |
| koha_fundit | last seen timestamp |
| niveli | threat level |
| shkeljet | violations |
| harta_bllokuar | blacklist map |
| lejuar | allowed |
| bllokuar | blocked |
| dyshimte | suspect |
| kufizuar | throttled |
