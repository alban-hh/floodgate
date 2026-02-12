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

#define MAX_HYRJE 10000000
#define BPF_ANY 0

struct rregull_trafikut {
    __u64 numrues_paketa;
    __u64 koha_fundit;
    __u32 politika;
};

struct konfigurimi {
    __u64 limit_tcp;
    __u64 limit_udp;
    __u64 limit_icmp;
    __u32 bloko_udp;
    __u32 bloko_tcp;
    __u32 porta_target;
    __u32 aktiv;
};

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
    __uint(max_entries, 10);
} harta_statistika SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10000);
} harta_whitelist SEC(".maps");

static __always_inline int procezo_paketen(void *data, void *data_end, __u32 ip_burimi, __u8 protokoll, __u16 porta_dest) {
    struct rregull_trafikut *rregull;
    struct konfigurimi *cfg;
    __u32 celes = 0;
    __u64 koha_tani = bpf_ktime_get_ns();
    __u64 *stat;
    __u8 *whitelisted;

    whitelisted = bpf_map_lookup_elem(&harta_whitelist, &ip_burimi);
    if (whitelisted)
        return XDP_PASS;

    cfg = bpf_map_lookup_elem(&harta_config, &celes);
    if (!cfg || !cfg->aktiv)
        return XDP_PASS;

    if (cfg->porta_target && porta_dest != cfg->porta_target)
        return XDP_PASS;

    rregull = bpf_map_lookup_elem(&harta_ip, &ip_burimi);
    if (!rregull) {
        struct rregull_trafikut rregull_ri = {0};
        rregull_ri.numrues_paketa = 1;
        rregull_ri.koha_fundit = koha_tani;
        rregull_ri.politika = 0;
        bpf_map_update_elem(&harta_ip, &ip_burimi, &rregull_ri, BPF_ANY);
        return XDP_PASS;
    }

    __u64 diferenca_kohe = koha_tani - rregull->koha_fundit;
    if (diferenca_kohe > 1000000000) {
        rregull->numrues_paketa = 1;
        rregull->koha_fundit = koha_tani;
        return XDP_PASS;
    }

    rregull->numrues_paketa++;

    __u64 limit = 0;
    __u32 idx_stat = 0;

    if (protokoll == IPPROTO_TCP) {
        limit = cfg->limit_tcp;
        idx_stat = 0;
        if (cfg->bloko_tcp) {
            __u32 drop_idx = 3;
            stat = bpf_map_lookup_elem(&harta_statistika, &drop_idx);
            if (stat)
                __sync_fetch_and_add(stat, 1);
            return XDP_DROP;
        }
    } else if (protokoll == IPPROTO_UDP) {
        limit = cfg->limit_udp;
        idx_stat = 1;
        if (cfg->bloko_udp) {
            __u32 drop_idx = 4;
            stat = bpf_map_lookup_elem(&harta_statistika, &drop_idx);
            if (stat)
                __sync_fetch_and_add(stat, 1);
            return XDP_DROP;
        }
    } else if (protokoll == IPPROTO_ICMP) {
        limit = cfg->limit_icmp;
        idx_stat = 2;
    }

    if (limit && rregull->numrues_paketa > limit) {
        idx_stat += 3;
        stat = bpf_map_lookup_elem(&harta_statistika, &idx_stat);
        if (stat)
            __sync_fetch_and_add(stat, 1);
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp")
int floodgate_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        __u32 ip_burimi = ip->saddr;
        __u8 protokoll = ip->protocol;
        __u16 porta_dest = 0;

        void *l4 = (void *)ip + sizeof(struct iphdr);
        if (l4 + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;

        if (protokoll == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            porta_dest = bpf_ntohs(tcp->dest);
        } else if (protokoll == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            porta_dest = bpf_ntohs(udp->dest);
        }

        return procezo_paketen(data, data_end, ip_burimi, protokoll, porta_dest);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
