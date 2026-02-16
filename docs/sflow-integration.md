# Integrimi me sFlow

## cfare ben

floodgate merr sflow v5 telemetri nga routeri/switchi yt. kjo i jep visibilitet mbi trafikun perpara se paketat te arrijne ne interfacen e scrubbing, duke mundesuar bllokimin proaktiv te burimeve te sulmit.

## arkitektura

```
                         sFlow (UDP 6343)
                    ┌────────────────────────┐
                    │                        │
┌─────────┐    ┌────▼────┐    ┌──────────────▼───────────────┐
│ Internet │───►│  Cisco  │───►│  FloodGate Server            │
│          │    │ Router  │    │                               │
│          │    │         │    │  ┌─────────┐  ┌───────────┐  │
│          │    │ sFlow   │    │  │ sFlow   │  │ XDP       │  │
│          │    │ Agent   │    │  │ Collect │  │ Scrubber  │  │
│          │    │         │    │  │ :6343   │  │ vlan50    │  │
│          │    └────┬────┘    │  └────┬────┘  └─────┬─────┘  │
│          │         │         │       │             │         │
│          │         │         │  ┌────▼─────────────▼─────┐  │
│          │         │         │  │    ACL Engine           │  │
│          │         │         │  │    (auto-block/unblock) │  │
│          │         │         │  └────────────────────────┘  │
└──────────┘    ◄────┘         └──────────────────────────────┘
             clean traffic
```

## si funksionon hap pas hapi

1. routeri/switchi dergon sflow v5 datagrame ne floodgate ne udp port 6343
2. thread-i sflow collector i merr dhe i parson datagramat
3. nga cdo flow sample, nxjerr headerin e paketes se sampluar
4. parson ethernet/ip header per te marre source ip
5. numeron paketat per cdo ip, te skaluar me sampling rate
6. cdo 5 sekonda, acl engine skanon tabelen
7. ip qe kalojne pragun (default: 100K pps ose 100 MB/s) shtohen ne blacklist xdp
8. programi xdp dropon te gjitha paketat nga ip te bllokuara ne wire speed

## si ta aktivosh ne floodgate

```bash
sudo floodgate -i vlan50 -S 6343 -a -t 10000 -u 5000 -s 5
```

- `-S 6343`: degjo per sflow ne udp port 6343
- `-a`: aktivo acl engine (proceson sflow data dhe bllokon automatikisht)

pa `-a`, sflow collector vazhdon te punoj por nuk bllokon ip automatikisht.

## konfigurimi i routerit

### cisco ios-xe

```
flow record FLOODGATE-RECORD
 match ipv4 source address
 match ipv4 destination address
 match transport source-port
 match transport destination-port
 collect counter bytes
 collect counter packets
!
flow exporter FLOODGATE-EXPORT
 destination 192.168.100.253
 transport udp 6343
 source Loopback0
!
flow monitor FLOODGATE-MON
 record FLOODGATE-RECORD
 exporter FLOODGATE-EXPORT
!
interface GigabitEthernet0/0
 ip flow monitor FLOODGATE-MON input
```

zevendo `192.168.100.253` me ip e serverit floodgate.

### cisco nx-os (nexus)

```
feature sflow

sflow sampling-rate 512
sflow collector-ip 192.168.100.253 vrf default
sflow collector-port 6343
sflow agent-ip 192.168.100.1

interface Ethernet1/1
 sflow sampling-rate 512
```

### juniper junos

```
set protocols sflow polling-interval 10
set protocols sflow sample-rate ingress 512
set protocols sflow collector 192.168.100.253 udp-port 6343
set protocols sflow interfaces ge-0/0/0
```

### cdo pajisje tjeter me sflow

cdo pajisje qe suporton sflow v5 (rfc 3176) mund te dergoje samples ne floodgate. konfiguro:

- **collector ip**: ip e serverit floodgate
- **collector port**: 6343 (ose cfaredoqofte qe i jep `-S`)
- **sampling rate**: 1:512 rekomandohet per linke me trafik te larte
- **agent ip**: ip e menaxhimit te routerit

## cfare suporton parseri sflow

- **sflow version 5** datagrame
- **ipv4 dhe ipv6** agent addresses
- **flow_sample** (type 1) dhe **expanded_flow_sample** (type 3)
- **raw_packet_header** records (enterprise 0, format 1)
- **ethernet** header protocol (type 1)
- **802.1q vlan** tagged frames (ethertype 0x8100)
- **ipv4** source address extraction

counter samples dhe record type te tjera injorohen.

## si e proceson acl te dhenat sflow

acl engine ekzekutohet ne nje thread te vecante ne ciklin 5-sekondesh:

### faza 1: analiza sflow

1. lock tabelen sflow
2. per cdo ip te trackuar, llogarit pps dhe bps te vleresuar:
   - `pps_vleresuar = paketa_totale_sampled * sampling_rate / intervali`
   - `bps_vleresuar = bytes_totale_sampled * sampling_rate / intervali`
3. nese pps > 100,000 ose bps > 100,000,000 (100 MB/s):
   - kontrollo nese ip eshte ne whitelist (kalo nese po)
   - shto ne blacklist xdp me timestamp aktual
   - log: `[ACL-SFLOW] +BLOCK <ip> (pps:<n> bps:<n>)`
4. reseto te gjitha numruesit sflow per ciklin e ardhshem

### faza 2: skanimi i shkeljeve xdp

1. itero harten e trackimit per ip (`harta_ip`)
2. per ip me mbi 10 shkelje:
   - shto ne blacklist
   - reseto shkeljet dhe nivelin
   - log: `[ACL-XDP] +BLOCK <ip>`

### faza 3: pastrimi i ttl

1. itero harten e blacklistit (`harta_bllokuar`)
2. per hyrje me te vjetra se 300 sekonda (5 minuta):
   - hiq nga blacklist
   - log: `[ACL] -UNBLOCK <ip> (TTL skaduar)`

## si ta verifikosh qe sflow punon

### kontrollo qe paketat sflow po arrijne

```bash
tcpdump -i eno1 udp port 6343 -c 5
```

duhet te shohesh paketa udp nga ip e routerit.

### kontrollo logs e floodgate

kur floodgate niset me sflow, do shohesh:

```
sFlow degjues aktiv ne port 6343
ACL menaxher aktiv (intervali: 5s, bllokimi: 300s)
```

kur bllokon nje ip nga sflow:

```
[ACL-SFLOW] +BLOCK 45.67.89.10 (pps:250000 bps:150000000)
```

### kontrollo blacklistin

```bash
bpftool map dump name harta_bllokuar
```

ose me control script:

```bash
scripts/floodgate-ctl.sh blacklist
```

## konfigurimi i firewall

sigurohu qe serveri floodgate mund te marre datagrame sflow:

```bash
ufw allow 6343/udp
```

ose me iptables:

```bash
iptables -A INPUT -p udp --dport 6343 -j ACCEPT
```

## tuning i pragut sflow

vlerat default punojne mire per shumicen e setupeve, por mund te ndryshohen ne `src/user/globals.c`:

| parametri | default | pershkrimi |
|-----------|---------|-----------|
| `acl_pragu_pps` | 100,000 | pragu pps per bllokimin |
| `acl_pragu_bps` | 100,000,000 | pragu bps (100 MB/s) |
| `acl_pragu_shkeljet` | 10 | pragu i shkeljeve xdp |
| `acl_koha_bllokimit` | 300 | ttl blacklist ne sekonda (5 min) |
| `acl_intervali` | 5 | intervali i skanimit acl ne sekonda |

prag me te ulet = bllokimi me agresiv (me pak false negatives, me shume false positives).
prag me te larte = me permisiv (me pak false positives, pergjigje me e ngadlte).

## sampling rate

sampling rate ndikon ne saktesine e detektimit:

| sampling rate | volumi trafikut | latenca detektimit |
|---------------|-----------------|-------------------|
| 1:128 | < 1 Gbps | ~5 sekonda |
| 1:512 | 1-10 Gbps | ~5 sekonda |
| 1:1024 | 10-40 Gbps | ~10 sekonda |
| 1:2048 | 40-100 Gbps | ~15 sekonda |

sampling rate me i larte (ratio me e ulet) jep te dhena me te sakta por rrit cpu load ne router. per ddos detection, 1:512 eshte balance i mire.
