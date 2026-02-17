#include "acl.h"
#include "globals.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

void *acl_menaxher(void *arg) {
    printf("ACL menaxher aktiv (intervali: %ds, bllokimi: %ds)\n", acl_intervali, acl_koha_bllokimit);

    while (vazhdo) {
        sleep(acl_intervali);
        if (!vazhdo) break;

        int bllokime_reja = 0;
        int zhbllokime = 0;

        pthread_mutex_lock(&sflow_mutex);
        for (int i = 0; i < SFLOW_TABELA_MADHESIA; i++) {
            if (!sflow_tabela[i].aktiv)
                continue;

            __u64 pps = sflow_tabela[i].paketa / acl_intervali;
            __u64 bps = sflow_tabela[i].bytes / acl_intervali;
            __u32 ip = sflow_tabela[i].ip;

            if (pps > acl_pragu_pps || bps > acl_pragu_bps) {
                __u8 wl_val;
                if (bpf_map_lookup_elem(fd_harta_whitelist, &ip, &wl_val) == 0)
                    continue;

                __u64 koha = time(NULL);
                bpf_map_update_elem(fd_harta_bllokuar, &ip, &koha, BPF_ANY);
                bllokime_reja++;

                struct in_addr a;
                a.s_addr = ip;
                printf("[ACL-SFLOW] +BLOCK %s (pps:%llu bps:%llu)\n",
                       inet_ntoa(a), (unsigned long long)pps, (unsigned long long)bps);
            }
        }
        memset(sflow_tabela, 0, sizeof(struct sflow_hyrje) * SFLOW_TABELA_MADHESIA);
        pthread_mutex_unlock(&sflow_mutex);

        __u32 ip_key = 0, next_key;
        struct rregull_trafikut rregull;
        int nr_iter = 0;
        int ret = bpf_map_get_next_key(fd_harta_ip, NULL, &next_key);
        while (ret == 0 && nr_iter < 100000) {
            nr_iter++;
            ip_key = next_key;
            if (bpf_map_lookup_elem(fd_harta_ip, &ip_key, &rregull) == 0) {
                if (rregull.shkeljet > acl_pragu_shkeljet) {
                    __u64 koha = time(NULL);
                    bpf_map_update_elem(fd_harta_bllokuar, &ip_key, &koha, BPF_ANY);
                    bllokime_reja++;

                    rregull.shkeljet = 0;
                    rregull.niveli = NIVELI_NORMAL;
                    bpf_map_update_elem(fd_harta_ip, &ip_key, &rregull, BPF_ANY);

                    struct in_addr a;
                    a.s_addr = ip_key;
                    printf("[ACL-XDP] +BLOCK %s (shkeljet:%u)\n",
                           inet_ntoa(a), rregull.shkeljet);
                }
            }
            ret = bpf_map_get_next_key(fd_harta_ip, &ip_key, &next_key);
        }

        __u32 bl_key = 0, bl_next;
        __u32 per_fshirje[4096];
        int nr_fshirje = 0;
        __u64 koha_tani = time(NULL);

        nr_iter = 0;
        ret = bpf_map_get_next_key(fd_harta_bllokuar, NULL, &bl_next);
        while (ret == 0 && nr_iter < 100000) {
            nr_iter++;
            bl_key = bl_next;
            __u64 koha_bl;
            if (bpf_map_lookup_elem(fd_harta_bllokuar, &bl_key, &koha_bl) == 0) {
                if (koha_tani - koha_bl > acl_koha_bllokimit) {
                    if (nr_fshirje < 4096)
                        per_fshirje[nr_fshirje++] = bl_key;
                }
            }
            ret = bpf_map_get_next_key(fd_harta_bllokuar, &bl_key, &bl_next);
        }

        for (int i = 0; i < nr_fshirje; i++) {
            bpf_map_delete_elem(fd_harta_bllokuar, &per_fshirje[i]);
            zhbllokime++;

            struct in_addr a;
            a.s_addr = per_fshirje[i];
            printf("[ACL] -UNBLOCK %s (TTL skaduar)\n", inet_ntoa(a));
        }

        if (bllokime_reja > 0 || zhbllokime > 0) {
            printf("[ACL] cikli: +%d bllokime, -%d zhbllokime\n", bllokime_reja, zhbllokime);
            fflush(stdout);
        }
    }

    return NULL;
}
