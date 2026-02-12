#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdarg.h>

struct konfigurimi {
    __u64 limit_tcp;
    __u64 limit_udp;
    __u64 limit_icmp;
    __u32 bloko_udp;
    __u32 bloko_tcp;
    __u32 porta_target;
    __u32 aktiv;
};

static int fd_harta_config = -1;
static int fd_harta_stat = -1;
static int fd_harta_ip = -1;
static int fd_harta_whitelist = -1;
static int ifindex = -1;
static struct bpf_object *obj = NULL;

static int print_libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list args) {
    return vfprintf(stderr, fmt, args);
}

static void pastrimi(int sig) {
    __u32 celes = 0;
    struct konfigurimi cfg = {0};

    if (fd_harta_config >= 0) {
        bpf_map_update_elem(fd_harta_config, &celes, &cfg, BPF_ANY);
    }

    if (ifindex > 0) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    }

    if (obj) {
        bpf_object__close(obj);
    }

    printf("\nFloodGate ndalur\n");
    exit(0);
}

static void shfaq_statistika() {
    __u64 vlera;
    __u32 celes;

    const char *etiketat[] = {
        "TCP paketa",
        "UDP paketa",
        "ICMP paketa",
        "TCP DROP",
        "UDP DROP",
        "ICMP DROP"
    };

    printf("\n=== FloodGate Statistika ===\n");
    for (celes = 0; celes < 6; celes++) {
        if (bpf_map_lookup_elem(fd_harta_stat, &celes, &vlera) == 0) {
            printf("%s: %llu\n", etiketat[celes], vlera);
        }
    }
    printf("===========================\n\n");
}

static void vendos_konfig(struct konfigurimi *cfg) {
    __u32 celes = 0;
    if (bpf_map_update_elem(fd_harta_config, &celes, cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Gabim ne vendosjen e konfigurimit: %s\n", strerror(errno));
    }
}

static int ngarko_whitelist(const char *fajlli) {
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
        line[strcspn(line, "\n")] = 0;

        if (strlen(line) == 0 || line[0] == '#')
            continue;

        if (inet_pton(AF_INET, line, &addr) != 1) {
            fprintf(stderr, "IP invalid: %s\n", line);
            continue;
        }

        __u32 ip = addr.s_addr;
        if (bpf_map_update_elem(fd_harta_whitelist, &ip, &vlera, BPF_ANY) == 0) {
            numri++;
        }
    }

    fclose(fp);
    printf("Whitelist: %d IP te ngarkuara\n", numri);
    return numri;
}

static void shfaq_perdorimi(const char *programi) {
    printf("FloodGate - XDP Traffic Scrubber\n\n");
    printf("Perdorimi: %s -i <interface> [opsionet]\n\n", programi);
    printf("Opsionet:\n");
    printf("  -i <interface>    Interface rrjeti (e detyrueshme)\n");
    printf("  -p <port>         Porta target\n");
    printf("  -t <limit>        TCP limit (paketa/sek)\n");
    printf("  -u <limit>        UDP limit (paketa/sek)\n");
    printf("  -c <limit>        ICMP limit (paketa/sek)\n");
    printf("  -U                Bloko te gjitha UDP\n");
    printf("  -T                Bloko te gjitha TCP\n");
    printf("  -w <file>         Whitelist IPs (file me IP per rresht)\n");
    printf("  -s <sec>          Shfaq statistika cdo X sekonda\n");
    printf("  -h                Shfaq kete ndihme\n\n");
    printf("Shembull:\n");
    printf("  %s -i eth0 -p 53 -U\n", programi);
    printf("  Bloko te gjitha UDP ne port 53\n\n");
}

int main(int argc, char **argv) {
    struct bpf_program *prog;
    int opt;
    char *interface = NULL;
    struct konfigurimi cfg = {
        .limit_tcp = 0,
        .limit_udp = 0,
        .limit_icmp = 0,
        .bloko_udp = 0,
        .bloko_tcp = 0,
        .porta_target = 0,
        .aktiv = 1
    };
    int intervali_stat = 0;
    char *whitelist_fajlli = NULL;

    libbpf_set_print(print_libbpf_log);

    while ((opt = getopt(argc, argv, "i:p:t:u:c:w:UTs:h")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'p':
                cfg.porta_target = atoi(optarg);
                break;
            case 't':
                cfg.limit_tcp = atoll(optarg);
                break;
            case 'u':
                cfg.limit_udp = atoll(optarg);
                break;
            case 'c':
                cfg.limit_icmp = atoll(optarg);
                break;
            case 'U':
                cfg.bloko_udp = 1;
                break;
            case 'T':
                cfg.bloko_tcp = 1;
                break;
            case 'w':
                whitelist_fajlli = optarg;
                break;
            case 's':
                intervali_stat = atoi(optarg);
                break;
            case 'h':
                shfaq_perdorimi(argv[0]);
                return 0;
            default:
                shfaq_perdorimi(argv[0]);
                return 1;
        }
    }

    if (!interface) {
        fprintf(stderr, "Gabim: Interface eshte e detyrueshme\n\n");
        shfaq_perdorimi(argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Gabim: Interface '%s' nuk u gjet\n", interface);
        return 1;
    }

    obj = bpf_object__open("floodgate_kern.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Gabim ne hapjen e BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Gabim ne ngarkimin e BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "floodgate_filter");
    if (!prog) {
        fprintf(stderr, "Gabim: BPF program nuk u gjet\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Gabim ne marrjen e prog FD\n");
        return 1;
    }

    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) < 0) {
        fprintf(stderr, "Gabim ne attach te XDP: %s\n", strerror(errno));
        return 1;
    }

    fd_harta_config = bpf_object__find_map_fd_by_name(obj, "harta_config");
    fd_harta_stat = bpf_object__find_map_fd_by_name(obj, "harta_statistika");
    fd_harta_ip = bpf_object__find_map_fd_by_name(obj, "harta_ip");
    fd_harta_whitelist = bpf_object__find_map_fd_by_name(obj, "harta_whitelist");

    if (fd_harta_config < 0 || fd_harta_stat < 0 || fd_harta_ip < 0 || fd_harta_whitelist < 0) {
        fprintf(stderr, "Gabim ne gjetjen e maps\n");
        return 1;
    }

    vendos_konfig(&cfg);

    if (whitelist_fajlli) {
        if (ngarko_whitelist(whitelist_fajlli) < 0) {
            return 1;
        }
    }

    signal(SIGINT, pastrimi);
    signal(SIGTERM, pastrimi);

    printf("FloodGate aktiv ne %s\n", interface);
    if (cfg.porta_target) printf("Porta target: %u\n", cfg.porta_target);
    if (cfg.bloko_udp) printf("Menyra: Bloko te gjitha UDP\n");
    if (cfg.bloko_tcp) printf("Menyra: Bloko te gjitha TCP\n");
    if (cfg.limit_tcp) printf("TCP limit: %llu paketa/sek\n", cfg.limit_tcp);
    if (cfg.limit_udp) printf("UDP limit: %llu paketa/sek\n", cfg.limit_udp);
    if (cfg.limit_icmp) printf("ICMP limit: %llu paketa/sek\n", cfg.limit_icmp);
    printf("\nShtype Ctrl+C per te ndalur...\n");

    if (intervali_stat > 0) {
        while (1) {
            sleep(intervali_stat);
            shfaq_statistika();
        }
    } else {
        while (1) {
            pause();
        }
    }

    return 0;
}
