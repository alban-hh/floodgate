#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "floodgate_common.h"

#define BPF_ANY 0

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct rregull_trafikut);
    __uint(max_entries, MAX_HYRJE);
} harta_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct konfigurimi);
    __uint(max_entries, 1);
} harta_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} harta_statistika SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10000);
} harta_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_BLLOKUAR);
} harta_bllokuar SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct challenge_hyrje);
    __uint(max_entries, MAX_CHALLENGE);
} harta_challenge SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_VERIFIKUAR);
} harta_verifikuar SEC(".maps");

static __always_inline void ndrysho_stat(__u32 idx, __u64 val) {
    __u64 *s = bpf_map_lookup_elem(&harta_statistika, &idx);
    if (s)
        __sync_fetch_and_add(s, val);
}

static __always_inline __u16 llogarit_ip_checksum(struct iphdr *ip, void *data_end) {
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return 0;

    __u32 sum = 0;
    __u16 *ptr = (__u16 *)ip;

    ip->check = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        sum += ptr[i];
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static __always_inline void stat_lejuar_protokoll(__u8 protokoll, __u16 gjatesia_pkt) {
    if (protokoll == IPPROTO_TCP)
        ndrysho_stat(0, 1);
    else if (protokoll == IPPROTO_UDP)
        ndrysho_stat(1, 1);
    else if (protokoll == IPPROTO_ICMP)
        ndrysho_stat(2, 1);
    ndrysho_stat(10, gjatesia_pkt);
}

static __always_inline int procezo_paketen(__u32 ip_burimi, __u8 protokoll, __u16 porta_dest, __u16 gjatesia_pkt, __u8 eshte_syn) {
    struct rregull_trafikut *rregull;
    struct konfigurimi *cfg;
    __u32 celes = 0;
    __u64 koha_tani = bpf_ktime_get_ns();

    ndrysho_stat(8, 1);

    __u64 *bllokuar = bpf_map_lookup_elem(&harta_bllokuar, &ip_burimi);
    if (bllokuar) {
        ndrysho_stat(6, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    __u8 *whitelisted = bpf_map_lookup_elem(&harta_whitelist, &ip_burimi);
    if (whitelisted) {
        stat_lejuar_protokoll(protokoll, gjatesia_pkt);
        return XDP_PASS;
    }

    cfg = bpf_map_lookup_elem(&harta_config, &celes);
    if (!cfg || !cfg->aktiv)
        return XDP_PASS;

    if (protokoll == IPPROTO_UDP && cfg->bloko_udp) {
        ndrysho_stat(4, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    if (protokoll == IPPROTO_TCP && cfg->bloko_tcp) {
        ndrysho_stat(3, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    if (cfg->porta_target && porta_dest != cfg->porta_target)
        return XDP_PASS;

    rregull = bpf_map_lookup_elem(&harta_ip, &ip_burimi);
    if (!rregull) {
        struct rregull_trafikut i_ri = {};
        i_ri.numrues_paketa = 1;
        i_ri.koha_fundit = koha_tani;
        i_ri.bytes_totale = gjatesia_pkt;
        i_ri.koha_nivelit = koha_tani;
        i_ri.niveli = NIVELI_NORMAL;
        i_ri.shkeljet = 0;
        bpf_map_update_elem(&harta_ip, &ip_burimi, &i_ri, BPF_ANY);
        stat_lejuar_protokoll(protokoll, gjatesia_pkt);
        return XDP_PASS;
    }

    if (rregull->niveli >= NIVELI_BLLOKUAR) {
        ndrysho_stat(7, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    __u64 diferenca = koha_tani - rregull->koha_fundit;
    if (diferenca > DRITARJA_NS) {
        if (rregull->niveli > NIVELI_NORMAL) {
            __u64 koha_nivel = koha_tani - rregull->koha_nivelit;
            if (koha_nivel > DEKADENCA_NS) {
                rregull->niveli--;
                rregull->koha_nivelit = koha_tani;
            }
        }
        rregull->numrues_paketa = 1;
        rregull->bytes_totale = gjatesia_pkt;
        rregull->koha_fundit = koha_tani;
        stat_lejuar_protokoll(protokoll, gjatesia_pkt);
        return XDP_PASS;
    }

    rregull->numrues_paketa++;
    rregull->bytes_totale += gjatesia_pkt;

    if (eshte_syn && cfg->limit_syn && rregull->numrues_paketa > cfg->limit_syn) {
        rregull->shkeljet++;
        if (rregull->shkeljet > 20 && rregull->niveli < NIVELI_BLLOKUAR) {
            rregull->niveli++;
            rregull->koha_nivelit = koha_tani;
        }
        ndrysho_stat(9, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    __u64 limit = 0;
    __u32 idx_lejuar = 0;
    __u32 idx_bllokuar = 3;

    if (protokoll == IPPROTO_TCP) {
        limit = cfg->limit_tcp;
        idx_lejuar = 0;
        idx_bllokuar = 3;
    } else if (protokoll == IPPROTO_UDP) {
        limit = cfg->limit_udp;
        idx_lejuar = 1;
        idx_bllokuar = 4;
    } else if (protokoll == IPPROTO_ICMP) {
        limit = cfg->limit_icmp;
        idx_lejuar = 2;
        idx_bllokuar = 5;
    }

    if (cfg->limit_pps && rregull->numrues_paketa > cfg->limit_pps) {
        rregull->shkeljet++;
        if (rregull->shkeljet > 15 && rregull->niveli < NIVELI_BLLOKUAR) {
            rregull->niveli++;
            rregull->koha_nivelit = koha_tani;
        }
        ndrysho_stat(idx_bllokuar, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    if (limit && rregull->numrues_paketa > limit) {
        rregull->shkeljet++;

        if (rregull->numrues_paketa > limit * 6) {
            if (rregull->niveli < NIVELI_BLLOKUAR) {
                rregull->niveli = NIVELI_BLLOKUAR;
                rregull->koha_nivelit = koha_tani;
            }
        } else if (rregull->numrues_paketa > limit * 4) {
            if (rregull->niveli < NIVELI_KUFIZUAR) {
                rregull->niveli = NIVELI_KUFIZUAR;
                rregull->koha_nivelit = koha_tani;
            }
        } else if (rregull->numrues_paketa > limit * 2) {
            if (rregull->niveli < NIVELI_DYSHIMTE) {
                rregull->niveli = NIVELI_DYSHIMTE;
                rregull->koha_nivelit = koha_tani;
            }
        }

        ndrysho_stat(idx_bllokuar, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    if (cfg->limit_bps && rregull->bytes_totale > cfg->limit_bps) {
        rregull->shkeljet++;
        if (rregull->niveli < NIVELI_KUFIZUAR) {
            rregull->niveli = NIVELI_KUFIZUAR;
            rregull->koha_nivelit = koha_tani;
        }
        ndrysho_stat(idx_bllokuar, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    ndrysho_stat(idx_lejuar, 1);
    ndrysho_stat(10, gjatesia_pkt);
    return XDP_PASS;
}

SEC("xdp")
int floodgate_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *nh = (void *)(eth + 1);

    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(0x88a8)) {
        struct vlan_hdr {
            __u16 tci;
            __u16 inner_proto;
        } *vhdr = nh;
        if ((void *)(vhdr + 1) > data_end)
            return XDP_PASS;
        h_proto = vhdr->inner_proto;
        nh = (void *)(vhdr + 1);
    }

    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = nh;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_burimi = ip->saddr;
    __u8 protokoll = ip->protocol;
    __u16 porta_dest = 0;
    __u16 gjatesia_pkt = bpf_ntohs(ip->tot_len);
    __u8 eshte_syn = 0;

    {
        __u32 ck = 0;
        struct konfigurimi *c = bpf_map_lookup_elem(&harta_config, &ck);
        if (c) {
            if (protokoll == IPPROTO_UDP && c->bloko_udp) {
                __u8 *wl = bpf_map_lookup_elem(&harta_whitelist, &ip_burimi);
                if (!wl) {
                    ndrysho_stat(8, 1);
                    ndrysho_stat(4, 1);
                    ndrysho_stat(11, gjatesia_pkt);
                    return XDP_DROP;
                }
            }
            if (protokoll == IPPROTO_TCP && c->bloko_tcp) {
                __u8 *wl = bpf_map_lookup_elem(&harta_whitelist, &ip_burimi);
                if (!wl) {
                    ndrysho_stat(8, 1);
                    ndrysho_stat(3, 1);
                    ndrysho_stat(11, gjatesia_pkt);
                    return XDP_DROP;
                }
            }
        }
    }

    void *l4 = (void *)ip + sizeof(struct iphdr);

    if (protokoll == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        porta_dest = bpf_ntohs(tcp->dest);
        if (tcp->syn && !tcp->ack)
            eshte_syn = 1;
    } else if (protokoll == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        porta_dest = bpf_ntohs(udp->dest);

        __u32 cfg_key = 0;
        struct konfigurimi *cfg = bpf_map_lookup_elem(&harta_config, &cfg_key);

        if (cfg && cfg->challenge_aktiv) {
            if (bpf_map_lookup_elem(&harta_bllokuar, &ip_burimi))
                goto skip_challenge;
            if (bpf_map_lookup_elem(&harta_whitelist, &ip_burimi))
                goto skip_challenge;

            struct rregull_trafikut *rr = bpf_map_lookup_elem(&harta_ip, &ip_burimi);
            if (!rr || rr->niveli < NIVELI_DYSHIMTE)
                goto skip_challenge;

            __u64 *ver_ts = bpf_map_lookup_elem(&harta_verifikuar, &ip_burimi);
            if (ver_ts) {
                __u64 tani = bpf_ktime_get_ns();
                if (tani - *ver_ts < CHALLENGE_SKADIMI_NS)
                    goto skip_challenge;
            }

            void *payload = (void *)(udp + 1);
            if (payload + 4 <= data_end) {
                __u32 maybe_cookie = *(__u32 *)payload;
                struct challenge_hyrje *ch = bpf_map_lookup_elem(&harta_challenge, &ip_burimi);
                if (ch && ch->cookie == maybe_cookie) {
                    __u64 tani = bpf_ktime_get_ns();
                    if (tani - ch->koha < 5000000000ULL) {
                        bpf_map_update_elem(&harta_verifikuar, &ip_burimi, &tani, BPF_ANY);
                        bpf_map_delete_elem(&harta_challenge, &ip_burimi);
                        ndrysho_stat(13, 1);
                        goto skip_challenge;
                    }
                }
            }

            if (ip->ihl != 5)
                goto skip_challenge;

            __u32 cookie = bpf_get_prandom_u32();
            struct challenge_hyrje new_ch = {};
            new_ch.koha = bpf_ktime_get_ns();
            new_ch.cookie = cookie;
            bpf_map_update_elem(&harta_challenge, &ip_burimi, &new_ch, BPF_ANY);

            unsigned char tmp_mac[ETH_ALEN];
            __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

            __u32 tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;
            ip->ttl = 64;
            ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 4);

            __u16 tmp_port = udp->source;
            udp->source = udp->dest;
            udp->dest = tmp_port;
            udp->len = bpf_htons(sizeof(struct udphdr) + 4);
            udp->check = 0;

            if (payload + 4 <= data_end)
                *(__u32 *)payload = cookie;

            ip->check = llogarit_ip_checksum(ip, data_end);

            ndrysho_stat(12, 1);
            return XDP_TX;
        }
    } else if (protokoll == IPPROTO_ICMP) {
        if (l4 + sizeof(struct icmphdr) > data_end)
            return XDP_PASS;
    }

skip_challenge:
    return procezo_paketen(ip_burimi, protokoll, porta_dest, gjatesia_pkt, eshte_syn);
}

char _license[] SEC("license") = "GPL";
