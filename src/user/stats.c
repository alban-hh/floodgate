#include "stats.h"
#include "globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUF_MAX 16384
#define P(...) pos += snprintf(buf + pos, BUF_MAX - pos, __VA_ARGS__)

static void formato_bytes(char *buf, size_t len, __u64 bytes) {
    if (bytes >= 1000000000ULL)
        snprintf(buf, len, "%.2f GB", (double)bytes / 1000000000.0);
    else if (bytes >= 1000000ULL)
        snprintf(buf, len, "%.2f MB", (double)bytes / 1000000.0);
    else if (bytes >= 1000ULL)
        snprintf(buf, len, "%.2f KB", (double)bytes / 1000.0);
    else
        snprintf(buf, len, "%llu B", (unsigned long long)bytes);
}

static void formato_numri(char *buf, size_t len, __u64 n) {
    if (n >= 1000000000ULL)
        snprintf(buf, len, "%.2fB", (double)n / 1000000000.0);
    else if (n >= 1000000ULL)
        snprintf(buf, len, "%.2fM", (double)n / 1000000.0);
    else if (n >= 1000ULL)
        snprintf(buf, len, "%.2fK", (double)n / 1000.0);
    else
        snprintf(buf, len, "%llu", (unsigned long long)n);
}

static const char *emri_nivelit(__u32 niveli) {
    switch (niveli) {
        case NIVELI_NORMAL: return "NORMAL";
        case NIVELI_DYSHIMTE: return "DYSHIMTE";
        case NIVELI_KUFIZUAR: return "KUFIZUAR";
        case NIVELI_BLLOKUAR: return "BLLOKUAR";
        default: return "???";
    }
}

void shfaq_dashboard(int max_top_ip) {
    char buf[BUF_MAX];
    int pos = 0;

    int nr_cpu = libbpf_num_possible_cpus();
    if (nr_cpu < 1) nr_cpu = 1;
    __u64 *percpu = calloc(nr_cpu, sizeof(__u64));
    if (!percpu) return;

    __u64 vlerat[16] = {0};
    for (__u32 celes = 0; celes < 16; celes++) {
        memset(percpu, 0, nr_cpu * sizeof(__u64));
        if (bpf_map_lookup_elem(fd_harta_stat, &celes, percpu) == 0) {
            for (int i = 0; i < nr_cpu; i++)
                vlerat[celes] += percpu[i];
        }
    }
    free(percpu);

    char buf_bytes_lej[32], buf_bytes_bl[32], buf_total[32];
    formato_bytes(buf_bytes_lej, sizeof(buf_bytes_lej), vlerat[10]);
    formato_bytes(buf_bytes_bl, sizeof(buf_bytes_bl), vlerat[11]);
    formato_numri(buf_total, sizeof(buf_total), vlerat[8]);

    P("\033[2J\033[H");
    P("\033[1;36m============= FloodGate Statistika =============\033[0m\n");
    P("\033[1;33m  Total paketa:     %-15s\033[0m\n", buf_total);
    P("\n");
    P("  \033[1;32mLEJUAR:\033[0m\n");
    P("    TCP:            %-15llu\n", (unsigned long long)vlerat[0]);
    P("    UDP:            %-15llu\n", (unsigned long long)vlerat[1]);
    P("    ICMP:           %-15llu\n", (unsigned long long)vlerat[2]);
    P("    Bytes:          %-15s\n", buf_bytes_lej);
    P("\n");
    P("  \033[1;31mBLLOKUAR:\033[0m\n");
    P("    TCP:            %-15llu\n", (unsigned long long)vlerat[3]);
    P("    UDP:            %-15llu\n", (unsigned long long)vlerat[4]);
    P("    ICMP:           %-15llu\n", (unsigned long long)vlerat[5]);
    P("    Blacklist:      %-15llu\n", (unsigned long long)vlerat[6]);
    P("    Auto-block:     %-15llu\n", (unsigned long long)vlerat[7]);
    P("    SYN flood:      %-15llu\n", (unsigned long long)vlerat[9]);
    P("    Bytes:          %-15s\n", buf_bytes_bl);
    P("\n");
    P("  \033[1;34mCHALLENGE:\033[0m\n");
    P("    Derguar:        %-15llu\n", (unsigned long long)vlerat[12]);
    P("    Verifikuar:     %-15llu\n", (unsigned long long)vlerat[13]);

    if (acl_aktiv || sflow_porta > 0) {
        int nr_bllokuar = 0;
        __u32 bl_key;
        int ret = bpf_map_get_next_key(fd_harta_bllokuar, NULL, &bl_key);
        while (ret == 0 && nr_bllokuar < 100000) {
            nr_bllokuar++;
            __u32 prev = bl_key;
            ret = bpf_map_get_next_key(fd_harta_bllokuar, &prev, &bl_key);
        }

        int nr_dyshimte = 0, nr_kufizuar = 0, nr_auto_bl = 0;
        int nr_iter = 0;
        __u32 ip_key;
        struct rregull_trafikut rr;
        ret = bpf_map_get_next_key(fd_harta_ip, NULL, &ip_key);
        while (ret == 0 && nr_iter < 100000) {
            nr_iter++;
            if (bpf_map_lookup_elem(fd_harta_ip, &ip_key, &rr) == 0) {
                if (rr.niveli == NIVELI_DYSHIMTE) nr_dyshimte++;
                else if (rr.niveli == NIVELI_KUFIZUAR) nr_kufizuar++;
                else if (rr.niveli >= NIVELI_BLLOKUAR) nr_auto_bl++;
            }
            __u32 prev = ip_key;
            ret = bpf_map_get_next_key(fd_harta_ip, &prev, &ip_key);
        }

        P("\n");
        P("  \033[1;35mACL:\033[0m\n");
        P("    Blacklist:      %-15d\n", nr_bllokuar);
        P("    Dyshimte:       %-15d\n", nr_dyshimte);
        P("    Kufizuar:       %-15d\n", nr_kufizuar);
        P("    Auto-bllokuar:  %-15d\n", nr_auto_bl);
    }

    P("\033[1;36m=================================================\033[0m\n");

    struct ip_renditje {
        __u32 ip;
        __u64 paketa;
        __u32 niveli;
        __u32 shkeljet;
    } top[64];
    int nr_top = 0;

    __u32 ip_key;
    struct rregull_trafikut rr;
    int nr_iter = 0;
    int ret = bpf_map_get_next_key(fd_harta_ip, NULL, &ip_key);
    while (ret == 0 && nr_iter < 100000) {
        nr_iter++;
        if (bpf_map_lookup_elem(fd_harta_ip, &ip_key, &rr) == 0 && rr.numrues_paketa > 0) {
            if (nr_top < 64) {
                top[nr_top].ip = ip_key;
                top[nr_top].paketa = rr.numrues_paketa;
                top[nr_top].niveli = rr.niveli;
                top[nr_top].shkeljet = rr.shkeljet;
                nr_top++;
            } else {
                int min_idx = 0;
                for (int j = 1; j < 64; j++) {
                    if (top[j].paketa < top[min_idx].paketa)
                        min_idx = j;
                }
                if (rr.numrues_paketa > top[min_idx].paketa) {
                    top[min_idx].ip = ip_key;
                    top[min_idx].paketa = rr.numrues_paketa;
                    top[min_idx].niveli = rr.niveli;
                    top[min_idx].shkeljet = rr.shkeljet;
                }
            }
        }
        __u32 prev = ip_key;
        ret = bpf_map_get_next_key(fd_harta_ip, &prev, &ip_key);
    }

    for (int i = 0; i < nr_top - 1; i++) {
        for (int j = i + 1; j < nr_top; j++) {
            if (top[j].paketa > top[i].paketa) {
                struct ip_renditje tmp = top[i];
                top[i] = top[j];
                top[j] = tmp;
            }
        }
    }

    if (nr_top > max_top_ip)
        nr_top = max_top_ip;

    if (nr_top > 0) {
        P("\n");
        P("\033[1;33m  TOP %d IP:\033[0m\n", nr_top);
        P("    %-18s %-12s %-12s %-10s\n", "IP", "PPS", "NIVELI", "SHKELJET");
        for (int i = 0; i < nr_top; i++) {
            struct in_addr a;
            a.s_addr = top[i].ip;
            char pps_buf[16];
            formato_numri(pps_buf, sizeof(pps_buf), top[i].paketa);

            const char *ngjyra;
            if (top[i].niveli >= NIVELI_BLLOKUAR)
                ngjyra = "\033[1;31m";
            else if (top[i].niveli >= NIVELI_KUFIZUAR)
                ngjyra = "\033[1;33m";
            else if (top[i].niveli >= NIVELI_DYSHIMTE)
                ngjyra = "\033[0;33m";
            else
                ngjyra = "\033[0;32m";

            P("    %-18s %-12s %s%-12s\033[0m %-10u\n",
                   inet_ntoa(a), pps_buf,
                   ngjyra, emri_nivelit(top[i].niveli),
                   top[i].shkeljet);
        }
    }

    write(STDOUT_FILENO, buf, pos);
}
