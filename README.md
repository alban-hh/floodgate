# floodgate

> xdp/ebpf traffic scrubber qe dropon ddos attacks ne kernel level

---

## perse xdp

- **10+ milion paketa/sekond** - performance ekstrem
- **zero cpu overhead** - proceson para se te arrije stack
- **hash tables** - 10m ip tracking ne hardware speed
- **kernel level** - nuk ka me shpejt se kaq

## statusi

```diff
! ne zhvillim aktiv
! testuar vetem lokalisht
! mos perdor ne production
```

---

## quick start

```bash
# instalo dependencies
apt-get install clang-12 llc-12 linux-tools-generic

# build
make

# run - bloko udp flood ne dns
./floodgate -i vlan50 -p 53 -U

# me whitelist - internal ips nuk bllokohen
./floodgate -i vlan50 -p 53 -U -w whitelist.txt

# monitor live
./floodgate -i vlan50 -s 5
```

---

## use cases

| skenar | komanda |
|--------|---------|
| dns amplification | `./floodgate -i vlan50 -p 53 -U` |
| syn flood | `./floodgate -i vlan50 -t 100000` |
| ntp amplification | `./floodgate -i vlan50 -p 123 -U` |
| me whitelist | `./floodgate -i vlan50 -U -w whitelist.txt` |
| monitor only | `./floodgate -i vlan50 -s 5` |

---

## si punon

```
fastnetmon detekton attack
        ↓
bgp announces route to cisco
        ↓
cisco forward attack traffic → vlan50
        ↓
floodgate XDP dropon malicious packets
        ↓
clean traffic kthehet ne cisco
```

---

## arkitektura

**maps**
- `harta_ip` - hash 10m entries per ip tracking
- `harta_config` - runtime configuration
- `harta_statistika` - zero-lock stats
- `harta_whitelist` - 10k whitelisted ips

**filtering**
- rate limiting per protocol
- selective tcp/udp/icmp blocking
- per-port granular control
- whitelist support - internal ips skip filtering

---

## requirements

- kernel **5.4+** (per btf support)
- clang **12+** (per modern ebpf)
- libbpf **1.x** (per hash maps)

tested: ubuntu 18.04 + hwe kernel 5.4

---

## integration

fastnetmon auto-trigger **coming soon**

```bash
# do behet automatik
fastnetmon detect → bgp inject → floodgate activate
```

---

**variablat ne shqip** - ip_burimi | porta_dest | protokoll | numrues_paketa

**zero comments** - kodin e lexon jo dokumentacion
