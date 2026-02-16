# FloodGate

> xdp/ebpf traffic scrubber me sflow intelligence dhe acl automatik - dropon ddos ne kernel level

---

## perse floodgate

- **10+ milion paketa/sekond** - xdp proceson para cpu stack
- **zero overhead** - hash maps ne hardware speed
- **sflow v5 collector** - merr telemetri nga routeri, bllokon proaktivisht
- **acl automatik** - eskalon/de-eskalon ip automatikisht
- **4 nivele threat** - normal → dyshimte → kufizuar → bllokuar
- **blacklist + whitelist** - wire speed, pa delay

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
sudo floodgate -i vlan50 -t 10000 -u 5000 -c 100 -Y 500 -S 6343 -a -w /etc/floodgate/whitelist.txt -s 5
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
  -s <sekonda>      shfaq stats cdo x sekonda
```

---

## use cases

| skenari | komanda |
|---------|---------|
| dns amplification | `floodgate -i vlan50 -p 53 -U -w whitelist.txt` |
| syn flood | `floodgate -i vlan50 -t 10000 -Y 500 -a -s 5` |
| ntp amplification | `floodgate -i vlan50 -p 123 -U` |
| full protection | `floodgate -i vlan50 -t 10000 -u 5000 -c 100 -Y 500 -S 6343 -a -s 5` |
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
