# Skema e Rrjetit FloodGate

## Topologjia

```
                          INTERNET
                             │
                             ▼
                    ┌─────────────────┐
                    │  Mikrotik 4011  │
                    │   (upstream)    │
                    │                 │
                    │  Vlan10: 10.10.10.1
                    │  Vlan20: 10.10.20.1
                    │  Vlan50: 192.168.50.2
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    ASR 9001     │
                    │                 │
                    │  Be1.10: 10.10.10.2
                    │  Be1.20: 10.10.20.2
                    │  Be1.30: 192.168.10.1/24  ◄── rrjeti i mbrojtur
                    │  Be1.40: 192.168.1.1/24   ◄── menaxhim / sFlow
                    │  Be1.50: 192.168.50.1/24  ◄── scrubbing
                    └────────┬────────┘
                             │
                      TRUNK: vlan 30, 40, 50
                             │
                             ▼
                    ┌─────────────────┐
                    │    Nexus 3k     │
                    │    (switch)     │
                    └──┬──────┬───┬───┘
                       │      │   │
            TRUNK: 40,50  vlan30  │
                       │      │   │
                       ▼      │   │
          ┌────────────────┐  │   │
          │   FloodGate    │  │   │
          │    Server      │  │   │
          │                │  │   │
          │  vlan40: 192.168.1.101/24   (sFlow + menaxhim)
          │  vlan50: 192.168.50.101/24  (interface scrubbing)
          └────────────────┘  │   │
                              ▼   ▼
                     ┌─────────────────┐
                     │ Serverat e      │
                     │ Mbrojtur        │
                     │ 192.168.10.0/24 │
                     │                 │
                     │ p.sh. 192.168.10.102 (IP e sulmuar)
                     └─────────────────┘
```

## Rrjedha normale e trafikut (pa sulm)

```
Klienti ──► Mikrotik ──► ASR 9001 ──► Nexus 3k ──► vlan30 ──► 192.168.10.102
                                                                      │
Klienti ◄── Mikrotik ◄── ASR 9001 ◄── Nexus 3k ◄── vlan30 ◄─────────┘

FloodGate eshte ne pritje. Vetem telemetria sFlow arrin ne vlan40.
```

## Monitorimi sFlow (gjithmone aktiv)

```
ASR 9001 ──── sFlow UDP 6343 ────► Nexus 3k ──► vlan40 ──► FloodGate
                                                            192.168.1.101:6343

ASR samplon 1 nga cdo 512 paketa dhe dergon headerin e paketes
ne FloodGate. Kjo eshte vetem monitoring - NUK ndikon trafikun.
FloodGate e perdor kete per te detektuar sulme proaktivisht.
```

## Skenari i sulmit - hap pas hapi

### Hapi 1: Sulmi fillon

```
Sulmues(it) ──50Gbps──► Mikrotik ──► ASR 9001 ──► Nexus 3k ──► 192.168.10.102
                                                                     MBYTET!
```

### Hapi 2: ASR devijion IP-ne e sulmuar ne scrubber

Network engineer shton nje static route ne ASR 9001:

```
ip route 192.168.10.102/32 192.168.50.101
```

Tani I GJITHE trafiku per 192.168.10.102 kalon neper FloodGate:

```
                                    ASR 9001
                                       │
                        ┌──────────────┼──────────────┐
                        │              │              │
                     Be1.50         Be1.40         Be1.30
                     (scrub)        (sFlow)        (normal)
                        │              │              │
                        ▼              ▼              ▼
                  ┌──────────┐   ┌──────────┐   Serverat e tjere
                  │FloodGate │   │FloodGate │   (qe nuk sulmohen)
                  │  vlan50  │   │  vlan40  │   marrin trafik
                  │  SCRUB   │   │  MONITOR │   direkt
                  └──────────┘   └──────────┘
```

### Hapi 3: FloodGate pastron ne vlan50

```
Sulmues 45.67.89.10 ──────┐
Sulmues 91.23.45.67 ──────┤
Sulmues 103.44.55.66 ─────┤
Klient legjitim 8.8.4.4 ──┤
                            ▼
                    ┌───────────────────────────────────┐
                    │  FloodGate XDP ne vlan50           │
                    │                                   │
                    │  45.67.89.10   → 250K pps → DROP  │
                    │  91.23.45.67   → 180K pps → DROP  │
                    │  103.44.55.66  → 90K pps  → DROP  │
                    │  8.8.4.4       → 50 pps   → LEJO  │
                    │                                   │
                    │  XDP pipeline per cdo paket:      │
                    │  1. Kontrollo blacklist  → DROP    │
                    │  2. Kontrollo whitelist  → LEJO    │
                    │  3. Kontrollo rate limit → DROP/LEJO│
                    │  4. Eskalo nivelin e kercenimit    │
                    └──────────────┬────────────────────┘
                                   │
                            trafik i paster
                                   │
                                   ▼
                           192.168.10.102
                           (merr vetem trafik
                            legjitim)
```

### Hapi 4: sFlow auto-detektimi (paralel)

```
Nderkohe qe XDP pastron ne vlan50, sFlow collector ne vlan40
detekton te njejtet sulmues nga perspektiva e routerit:

Te dhenat sFlow tregojne:
  45.67.89.10   → 250,000 pps  → KALON PRAGUN 100K → AUTO BLACKLIST
  91.23.45.67   → 180,000 pps  → KALON PRAGUN 100K → AUTO BLACKLIST

Pasi te futen ne blacklist, XDP dropon TE GJITHA paketat nga keto IP
menjehere pa kontrolluar as rate limitet. Drop ne wire speed.
```

### Hapi 5: Sulmi ndalon

```
Pas 5 minutash pa trafik nga IP-te e bllokuara:
  FloodGate i heq nga blacklist automatikisht.
  Nivelet e kercenimit bien ne NORMAL.

Network engineer heq static route nga ASR:
  no ip route 192.168.10.102/32 192.168.50.101

Trafiku per 192.168.10.102 shkon direkt perseri:
  ASR 9001 ──► Nexus 3k ──► vlan30 ──► 192.168.10.102
```

## Cfare ben cdo pajisje

### ASR 9001 (konfigurohet nga network engineer)

| Detyra | Konfigurimi |
|--------|------------|
| Dergo sFlow ne FloodGate | `sflow collector-ip 192.168.1.101 vrf default` + `sflow collector-port 6343` |
| Devijo IP e sulmuar ne scrubber | `ip route <ip-e-sulmuar>/32 192.168.50.101` |
| Hiq devijimin pas sulmit | `no ip route <ip-e-sulmuar>/32 192.168.50.101` |

### Nexus 3k (konfigurohet nga network engineer)

| Detyra | Konfigurimi |
|--------|------------|
| Trunk drejt FloodGate | Lejo vlan 40 dhe 50 ne portin qe lidhet me serverin FloodGate |
| Trunk drejt ASR | Lejo vlan 30, 40, dhe 50 |

### Serveri FloodGate (tashme i konfiguruar)

| Detyra | Statusi |
|--------|--------|
| XDP scrubber ne vlan50 | GATI |
| sFlow collector ne port 6343 | GATI |
| ACL auto-blloko/zhblloko | GATI |
| Rate limiting (TCP/UDP/ICMP/SYN) | GATI |
| Whitelist/Blacklist | GATI |

### Komanda FloodGate

```bash
sudo floodgate -i vlan50 \
  -t 10000 \
  -u 5000 \
  -c 100 \
  -Y 500 \
  -S 6343 \
  -a \
  -w /etc/floodgate/whitelist.txt \
  -s 5
```

| Flag | Vlera | Qellimi |
|------|-------|---------|
| `-i vlan50` | vlan50 | Interface per scrubbing |
| `-t 10000` | 10K pps | TCP rate limit per source IP |
| `-u 5000` | 5K pps | UDP rate limit per source IP |
| `-c 100` | 100 pps | ICMP rate limit per source IP |
| `-Y 500` | 500 pps | SYN rate limit per source IP |
| `-S 6343` | port 6343 | Porti ku degjon sFlow collector |
| `-a` | - | Aktivo ACL engine automatik |
| `-w` | whitelist.txt | IP qe kalojne pa asnje filtrim |
| `-s 5` | 5 sek | Shfaq statistika cdo 5 sekonda |

## Rruga e kthimit per trafikun e paster

Serveri FloodGate duhet te kete IP forwarding aktiv dhe nje route kthimi:

```bash
sysctl -w net.ipv4.ip_forward=1
ip route add 192.168.10.0/24 via 192.168.50.1 dev vlan50
```

Paketat e pastra qe kalojne XDP → Linux i forwardon → kthehen ne ASR permes vlan50 → ASR i dergon ne vlan30 → viktima.

## IP qe duhen ne whitelist te FloodGate

Keto IP duhet te jene ne `/etc/floodgate/whitelist.txt` qe te mos bllokohen kurre:

```
192.168.50.1      # ASR gateway ne vlan50
192.168.50.2      # Mikrotik ne vlan50
192.168.1.1       # ASR gateway ne vlan40
192.168.10.1      # ASR gateway ne vlan30
10.10.10.1        # Mikrotik vlan10
10.10.10.2        # ASR vlan10
10.10.20.1        # Mikrotik vlan20
10.10.20.2        # ASR vlan20
```

## Permbledhje

```
┌──────────────────────────────────────────────────────────┐
│                  CFARE DUHET KONFIGURUAR                  │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  EKIPI I RRJETIT (ASR 9001 + Nexus 3k):                │
│  1. Konfiguro sFlow ne ASR → 192.168.1.101:6343        │
│  2. Siguro qe vlan 40,50 trunk arrin ne serverin FG     │
│  3. Kur ka sulm: shto static route ne 192.168.50.101    │
│  4. Kur sulmi mbaron: hiq routen                         │
│  5. (Opsionale) Konfiguro BGP per devijim automatik      │
│                                                          │
│  SERVERI FLOODGATE (tashme gati):                        │
│  1. Interface vlan40 + vlan50: KONFIGURUAR               │
│  2. FloodGate binary: KOMPILUAR                          │
│  3. sFlow collector: GATI ne port 6343                   │
│  4. XDP scrubber: GATI ne vlan50                         │
│  5. ACL engine: GATI                                     │
│  6. Vetem nis komanden dhe punon                          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```
