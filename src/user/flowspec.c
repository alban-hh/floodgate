#include "flowspec.h"
#include "globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

struct mitigimi {
    __u32 ip;
    __u64 koha_fillimit;
    __u64 koha_nen_prag;
    int aktiv;
    int mode;
};

static struct mitigimi lista[FLOWSPEC_MAX_MITIGIME];
static int nr_aktiv = 0;

int flowspec_nr_aktiv(void) {
    return nr_aktiv;
}

int flowspec_merr_listen(struct flowspec_info *dst, int max) {
    int n = 0;
    for (int i = 0; i < FLOWSPEC_MAX_MITIGIME && n < max; i++) {
        if (lista[i].aktiv) {
            dst[n].ip = lista[i].ip;
            dst[n].koha_fillimit = lista[i].koha_fillimit;
            dst[n].aktiv = 1;
            dst[n].mode = lista[i].mode;
            n++;
        }
    }
    return n;
}

static int ekzekuto_cmd(const char *cmd) {
    int ret = system(cmd);
    if (ret != 0)
        acl_log_shto("[FLOWSPEC] cmd deshtoi (%d): %.80s", ret, cmd);
    return ret;
}

static void fshi_rregull(__u32 ip, int mode) {
    struct in_addr a;
    a.s_addr = ip;
    char cmd[256];
    if (mode == FLOWSPEC_MODE_BLACKHOLE) {
        snprintf(cmd, sizeof(cmd),
            "gobgp global rib del %s/32",
            inet_ntoa(a));
    } else {
        snprintf(cmd, sizeof(cmd),
            "gobgp global rib -a ipv4-flowspec del "
            "match destination %s/32",
            inet_ntoa(a));
    }
    if (ekzekuto_cmd(cmd) == 0) {
        acl_log_shto("[FLOWSPEC] -REMOVE %s (%s)", inet_ntoa(a),
            mode == FLOWSPEC_MODE_BLACKHOLE ? "RTBH" : "redirect");
    }
}

static void shto_redirect(__u32 ip) {
    struct in_addr a;
    a.s_addr = ip;
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "gobgp global rib -a ipv4-flowspec add "
        "match destination %s/32 then redirect 666:666",
        inet_ntoa(a));
    if (ekzekuto_cmd(cmd) == 0) {
        acl_log_shto("[FLOWSPEC] +REDIRECT %s (RT 666:666)", inet_ntoa(a));
    }
}

static void shto_blackhole(__u32 ip) {
    struct in_addr a;
    a.s_addr = ip;
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "gobgp global rib add %s/32 community 65001:666",
        inet_ntoa(a));
    if (ekzekuto_cmd(cmd) == 0) {
        acl_log_shto("[FLOWSPEC] +BLACKHOLE %s (RTBH community 65001:666)", inet_ntoa(a));
    }
}

static int gjej_mitigim(__u32 ip) {
    for (int i = 0; i < FLOWSPEC_MAX_MITIGIME; i++) {
        if (lista[i].aktiv && lista[i].ip == ip)
            return i;
    }
    return -1;
}

static int gjej_slot_lire(void) {
    for (int i = 0; i < FLOWSPEC_MAX_MITIGIME; i++) {
        if (!lista[i].aktiv)
            return i;
    }
    return -1;
}

void *flowspec_menaxher(void *arg) {
    printf("Flowspec menaxher aktiv (intervali: %ds, pragu: %llu bps, blackhole: %llu bps)\n",
           flowspec_intervali, (unsigned long long)flowspec_pragu_bps,
           (unsigned long long)flowspec_pragu_blackhole);

    struct sflow_hyrje snapshot[SFLOW_TABELA_MADHESIA];

    while (vazhdo) {
        sleep(flowspec_intervali);
        if (!vazhdo) break;

        __u64 koha_tani = time(NULL);

        pthread_mutex_lock(&sflow_mutex);
        memcpy(snapshot, sflow_tabela_dst, sizeof(snapshot));
        memset(sflow_tabela_dst, 0, sizeof(struct sflow_hyrje) * SFLOW_TABELA_MADHESIA);
        pthread_mutex_unlock(&sflow_mutex);

        for (int i = 0; i < SFLOW_TABELA_MADHESIA; i++) {
            if (!snapshot[i].aktiv)
                continue;

            __u32 ip = snapshot[i].ip;
            __u64 bps = (snapshot[i].bytes / flowspec_intervali) * 8;
            int idx = gjej_mitigim(ip);

            if (bps >= flowspec_pragu_blackhole) {
                if (idx < 0) {
                    int slot = gjej_slot_lire();
                    if (slot < 0) continue;
                    shto_blackhole(ip);
                    lista[slot].ip = ip;
                    lista[slot].koha_fillimit = koha_tani;
                    lista[slot].koha_nen_prag = 0;
                    lista[slot].aktiv = 1;
                    lista[slot].mode = FLOWSPEC_MODE_BLACKHOLE;
                    nr_aktiv++;
                } else if (lista[idx].mode == FLOWSPEC_MODE_REDIRECT) {
                    fshi_rregull(ip, FLOWSPEC_MODE_REDIRECT);
                    shto_blackhole(ip);
                    lista[idx].mode = FLOWSPEC_MODE_BLACKHOLE;
                    lista[idx].koha_nen_prag = 0;
                    acl_log_shto("[FLOWSPEC] ESCALATE %s redirect -> blackhole",
                        inet_ntoa((struct in_addr){.s_addr = ip}));
                } else {
                    lista[idx].koha_nen_prag = 0;
                }
            } else if (bps >= flowspec_pragu_bps) {
                if (idx < 0) {
                    int slot = gjej_slot_lire();
                    if (slot < 0) continue;
                    shto_redirect(ip);
                    lista[slot].ip = ip;
                    lista[slot].koha_fillimit = koha_tani;
                    lista[slot].koha_nen_prag = 0;
                    lista[slot].aktiv = 1;
                    lista[slot].mode = FLOWSPEC_MODE_REDIRECT;
                    nr_aktiv++;
                } else if (lista[idx].mode == FLOWSPEC_MODE_BLACKHOLE) {
                    fshi_rregull(ip, FLOWSPEC_MODE_BLACKHOLE);
                    shto_redirect(ip);
                    lista[idx].mode = FLOWSPEC_MODE_REDIRECT;
                    lista[idx].koha_nen_prag = 0;
                    acl_log_shto("[FLOWSPEC] DE-ESCALATE %s blackhole -> redirect",
                        inet_ntoa((struct in_addr){.s_addr = ip}));
                } else {
                    lista[idx].koha_nen_prag = 0;
                }
            } else if (idx >= 0) {
                if (bps < flowspec_pragu_pastrim) {
                    if (lista[idx].koha_nen_prag == 0)
                        lista[idx].koha_nen_prag = koha_tani;
                } else {
                    lista[idx].koha_nen_prag = 0;
                }
            }
        }

        for (int i = 0; i < FLOWSPEC_MAX_MITIGIME; i++) {
            if (!lista[i].aktiv) continue;

            __u64 koha_aktiv = koha_tani - lista[i].koha_fillimit;
            if (koha_aktiv < flowspec_koha_min)
                continue;

            if (lista[i].koha_nen_prag == 0) {
                int gjetur = 0;
                for (int j = 0; j < SFLOW_TABELA_MADHESIA; j++) {
                    if (snapshot[j].aktiv && snapshot[j].ip == lista[i].ip) {
                        gjetur = 1;
                        break;
                    }
                }
                if (!gjetur) {
                    lista[i].koha_nen_prag = koha_tani;
                }
                continue;
            }

            __u64 koha_stabile = koha_tani - lista[i].koha_nen_prag;
            if (koha_stabile >= flowspec_koha_stabile) {
                fshi_rregull(lista[i].ip, lista[i].mode);
                lista[i].aktiv = 0;
                nr_aktiv--;
            }
        }
    }

    for (int i = 0; i < FLOWSPEC_MAX_MITIGIME; i++) {
        if (lista[i].aktiv) {
            fshi_rregull(lista[i].ip, lista[i].mode);
            lista[i].aktiv = 0;
            nr_aktiv--;
        }
    }

    return NULL;
}
