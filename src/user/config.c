#include "config.h"
#include "globals.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>

void vendos_konfig(struct konfigurimi *cfg) {
    __u32 celes = 0;
    if (bpf_map_update_elem(fd_harta_config, &celes, cfg, BPF_ANY) != 0)
        fprintf(stderr, "Gabim ne vendosjen e konfigurimit: %s\n", strerror(errno));
}

int ngarko_whitelist(const char *fajlli) {
    FILE *fp = fopen(fajlli, "r");
    if (!fp) {
        fprintf(stderr, "Gabim ne hapjen e whitelist: %s\n", strerror(errno));
        return -1;
    }

    char line[128];
    int numri = 0;
    __u8 vlera = 1;

    while (fgets(line, sizeof(line), fp)) {
        struct in_addr addr;
        line[strcspn(line, "\n\r")] = 0;

        if (strlen(line) == 0 || line[0] == '#')
            continue;

        char *space = strchr(line, ' ');
        if (space) *space = 0;
        char *tab = strchr(line, '\t');
        if (tab) *tab = 0;

        if (inet_pton(AF_INET, line, &addr) != 1)
            continue;

        __u32 ip = addr.s_addr;
        if (bpf_map_update_elem(fd_harta_whitelist, &ip, &vlera, BPF_ANY) == 0)
            numri++;
    }

    fclose(fp);
    printf("Whitelist: %d IP te ngarkuara\n", numri);
    return numri;
}

int ngarko_blacklist(const char *fajlli) {
    FILE *fp = fopen(fajlli, "r");
    if (!fp) {
        fprintf(stderr, "Gabim ne hapjen e blacklist: %s\n", strerror(errno));
        return -1;
    }

    char line[128];
    int numri = 0;
    __u64 koha = time(NULL);

    while (fgets(line, sizeof(line), fp)) {
        struct in_addr addr;
        line[strcspn(line, "\n\r")] = 0;

        if (strlen(line) == 0 || line[0] == '#')
            continue;

        char *space = strchr(line, ' ');
        if (space) *space = 0;
        char *tab = strchr(line, '\t');
        if (tab) *tab = 0;

        if (inet_pton(AF_INET, line, &addr) != 1)
            continue;

        __u32 ip = addr.s_addr;
        if (bpf_map_update_elem(fd_harta_bllokuar, &ip, &koha, BPF_ANY) == 0)
            numri++;
    }

    fclose(fp);
    printf("Blacklist: %d IP te ngarkuara\n", numri);
    return numri;
}
