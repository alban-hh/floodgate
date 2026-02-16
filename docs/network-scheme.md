# FloodGate Network Scheme

## Topology

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
                    │  Be1.30: 192.168.10.1/24  ◄── protected network
                    │  Be1.40: 192.168.1.1/24   ◄── management / sFlow
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
          │  vlan40: 192.168.1.101/24   (sFlow + management)
          │  vlan50: 192.168.50.101/24  (scrubbing interface)
          └────────────────┘  │   │
                              ▼   ▼
                     ┌─────────────────┐
                     │ Protected       │
                     │ Servers         │
                     │ 192.168.10.0/24 │
                     │                 │
                     │ e.g. 192.168.10.102 (attacked IP)
                     └─────────────────┘
```

## Normal Traffic Flow (no attack)

```
Client ──► Mikrotik ──► ASR 9001 ──► Nexus 3k ──► vlan30 ──► 192.168.10.102
                                                                    │
Client ◄── Mikrotik ◄── ASR 9001 ◄── Nexus 3k ◄── vlan30 ◄────────┘

FloodGate is idle. Only sFlow telemetry arrives on vlan40.
```

## sFlow Monitoring (always active)

```
ASR 9001 ──── sFlow UDP 6343 ────► Nexus 3k ──► vlan40 ──► FloodGate
                                                            192.168.1.101:6343

ASR samples 1 in every 512 packets and sends the packet header
to FloodGate. This is monitoring only - does NOT affect traffic.
FloodGate uses this data to detect attack patterns proactively.
```

## Attack Scenario - Step by Step

### Step 1: Attack starts

```
Attacker(s) ──50Gbps──► Mikrotik ──► ASR 9001 ──► Nexus 3k ──► 192.168.10.102
                                                                    OVERLOADED!
```

### Step 2: ASR diverts attacked IP to scrubber

Network engineer adds a static route on ASR 9001:

```
ip route 192.168.10.102/32 192.168.50.101
```

Now ALL traffic for 192.168.10.102 goes through FloodGate:

```
                                    ASR 9001
                                       │
                        ┌──────────────┼──────────────┐
                        │              │              │
                     Be1.50         Be1.40         Be1.30
                     (scrub)        (sFlow)        (normal)
                        │              │              │
                        ▼              ▼              ▼
                  ┌──────────┐   ┌──────────┐   Other servers
                  │FloodGate │   │FloodGate │   (not attacked)
                  │  vlan50  │   │  vlan40  │   get traffic
                  │  SCRUB   │   │  MONITOR │   directly
                  └──────────┘   └──────────┘
```

### Step 3: FloodGate scrubs on vlan50

```
Attacker 45.67.89.10 ──────┐
Attacker 91.23.45.67 ──────┤
Attacker 103.44.55.66 ─────┤
Legit client 8.8.4.4 ──────┤
                            ▼
                    ┌───────────────────────────────────┐
                    │  FloodGate XDP on vlan50          │
                    │                                   │
                    │  45.67.89.10   → 250K pps → DROP  │
                    │  91.23.45.67   → 180K pps → DROP  │
                    │  103.44.55.66  → 90K pps  → DROP  │
                    │  8.8.4.4       → 50 pps   → PASS  │
                    │                                   │
                    │  XDP pipeline per packet:         │
                    │  1. Blacklist check  → DROP        │
                    │  2. Whitelist check  → PASS        │
                    │  3. Rate limit check → DROP/PASS   │
                    │  4. Escalate threat level          │
                    └──────────────┬────────────────────┘
                                   │
                              clean traffic
                                   │
                                   ▼
                           192.168.10.102
                           (receives only
                            legitimate traffic)
```

### Step 4: sFlow auto-detection (parallel)

```
While XDP scrubs on vlan50, sFlow collector on vlan40
detects the same attackers from the router's perspective:

sFlow data shows:
  45.67.89.10   → 250,000 pps  → EXCEEDS 100K threshold → AUTO BLACKLIST
  91.23.45.67   → 180,000 pps  → EXCEEDS 100K threshold → AUTO BLACKLIST

Once blacklisted, XDP drops ALL packets from these IPs
instantly without even checking rate limits. Wire speed drop.
```

### Step 5: Attack stops

```
After 5 minutes with no traffic from blocked IPs:
  FloodGate removes them from blacklist automatically.
  Threat levels decay back to NORMAL.

Network engineer removes the static route on ASR:
  no ip route 192.168.10.102/32 192.168.50.101

Traffic for 192.168.10.102 goes directly again:
  ASR 9001 ──► Nexus 3k ──► vlan30 ──► 192.168.10.102
```

## What Each Device Does

### ASR 9001 (network engineer configures)

| Task | Configuration |
|------|--------------|
| Send sFlow to FloodGate | `sflow collector-ip 192.168.1.101 vrf default` + `sflow collector-port 6343` |
| Divert attacked IP to scrubber | `ip route <attacked-ip>/32 192.168.50.101` |
| Remove diversion after attack | `no ip route <attacked-ip>/32 192.168.50.101` |

### Nexus 3k (network engineer configures)

| Task | Configuration |
|------|--------------|
| Trunk to FloodGate | Allow vlan 40 and 50 on the port connecting to FloodGate server |
| Trunk to ASR | Allow vlan 30, 40, and 50 |

### FloodGate Server (already configured)

| Task | Status |
|------|--------|
| XDP scrubber on vlan50 | READY |
| sFlow collector on port 6343 | READY |
| ACL auto-block/unblock | READY |
| Rate limiting (TCP/UDP/ICMP/SYN) | READY |
| Whitelist/Blacklist | READY |

### FloodGate command

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

| Flag | Value | Purpose |
|------|-------|---------|
| `-i vlan50` | vlan50 | Scrubbing interface |
| `-t 10000` | 10K pps | TCP rate limit per source IP |
| `-u 5000` | 5K pps | UDP rate limit per source IP |
| `-c 100` | 100 pps | ICMP rate limit per source IP |
| `-Y 500` | 500 pps | SYN rate limit per source IP |
| `-S 6343` | port 6343 | sFlow collector listening port |
| `-a` | - | Enable ACL auto-block engine |
| `-w` | whitelist.txt | IPs that bypass all filtering |
| `-s 5` | 5 sec | Show stats every 5 seconds |

## Return Path for Clean Traffic

FloodGate server needs IP forwarding enabled and a route back:

```bash
sysctl -w net.ipv4.ip_forward=1
ip route add 192.168.10.0/24 via 192.168.50.1 dev vlan50
```

Clean packets that pass XDP → Linux forwards them → back to ASR via vlan50 → ASR delivers to vlan30 → victim.

## IPs to Whitelist on FloodGate

These IPs must be in `/etc/floodgate/whitelist.txt` so they never get blocked:

```
192.168.50.1      # ASR gateway on vlan50
192.168.50.2      # Mikrotik on vlan50
192.168.1.1       # ASR gateway on vlan40
192.168.10.1      # ASR gateway on vlan30
10.10.10.1        # Mikrotik vlan10
10.10.10.2        # ASR vlan10
10.10.20.1        # Mikrotik vlan20
10.10.20.2        # ASR vlan20
```

## Summary

```
┌──────────────────────────────────────────────────────────┐
│                    WHAT TO CONFIGURE                      │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  NETWORK TEAM (ASR 9001 + Nexus 3k):                    │
│  1. Configure sFlow on ASR → 192.168.1.101:6343         │
│  2. Ensure vlan 40,50 trunk to FloodGate server          │
│  3. When attack: add static route to 192.168.50.101      │
│  4. When attack over: remove route                       │
│  5. (Optional) Set up BGP for automatic diversion        │
│                                                          │
│  FLOODGATE SERVER (already done):                        │
│  1. vlan40 + vlan50 interfaces: CONFIGURED               │
│  2. FloodGate binary: COMPILED                           │
│  3. sFlow collector: READY on port 6343                  │
│  4. XDP scrubber: READY on vlan50                        │
│  5. ACL engine: READY                                    │
│  6. Just run the command and it works                     │
│                                                          │
└──────────────────────────────────────────────────────────┘
```
