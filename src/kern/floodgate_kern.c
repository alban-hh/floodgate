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

static __always_inline void ndrysho_stat(__u32 idx, __u64 val) {
    __u64 *s = bpf_map_lookup_elem(&harta_statistika, &idx);
    if (s)
        __sync_fetch_and_add(s, val);
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
        ndrysho_stat(10, gjatesia_pkt);
        return XDP_PASS;
    }

    cfg = bpf_map_lookup_elem(&harta_config, &celes);
    if (!cfg || !cfg->aktiv)
        return XDP_PASS;

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
        ndrysho_stat(10, gjatesia_pkt);
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
        ndrysho_stat(10, gjatesia_pkt);
        return XDP_PASS;
    }

    rregull->numrues_paketa++;
    rregull->bytes_totale += gjatesia_pkt;

    if (protokoll == IPPROTO_TCP && cfg->bloko_tcp) {
        ndrysho_stat(3, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    if (protokoll == IPPROTO_UDP && cfg->bloko_udp) {
        ndrysho_stat(4, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    if (eshte_syn && cfg->limit_syn && rregull->numrues_paketa > cfg->limit_syn) {
        rregull->shkeljet++;
        if (rregull->shkeljet > 10 && rregull->niveli < NIVELI_BLLOKUAR) {
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
        if (rregull->shkeljet > 5 && rregull->niveli < NIVELI_BLLOKUAR) {
            rregull->niveli++;
            rregull->koha_nivelit = koha_tani;
        }
        ndrysho_stat(idx_bllokuar, 1);
        ndrysho_stat(11, gjatesia_pkt);
        return XDP_DROP;
    }

    if (limit && rregull->numrues_paketa > limit) {
        rregull->shkeljet++;

        if (rregull->numrues_paketa > limit * 3) {
            if (rregull->niveli < NIVELI_BLLOKUAR) {
                rregull->niveli = NIVELI_BLLOKUAR;
                rregull->koha_nivelit = koha_tani;
            }
        } else if (rregull->numrues_paketa > limit * 2) {
            if (rregull->niveli < NIVELI_KUFIZUAR) {
                rregull->niveli = NIVELI_KUFIZUAR;
                rregull->koha_nivelit = koha_tani;
            }
        } else {
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

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_burimi = ip->saddr;
    __u8 protokoll = ip->protocol;
    __u16 porta_dest = 0;
    __u16 gjatesia_pkt = bpf_ntohs(ip->tot_len);
    __u8 eshte_syn = 0;

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
    } else if (protokoll == IPPROTO_ICMP) {
        if (l4 + sizeof(struct icmphdr) > data_end)
            return XDP_PASS;
    }

    return procezo_paketen(ip_burimi, protokoll, porta_dest, gjatesia_pkt, eshte_syn);
}

char _license[] SEC("license") = "GPL";
