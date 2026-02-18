#include "globals.h"
#include "config.h"
#include "stats.h"
#include "sflow.h"
#include "acl.h"
#include "flowspec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <stdarg.h>

extern int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags);

static pthread_t sflow_thread;
static pthread_t acl_thread;
static pthread_t flowspec_thread;

static int print_libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list args) {
    if (lvl == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void pastrimi(int sig) {
    vazhdo = 0;

    if (ifindex > 0)
        bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);

    if (obj)
        bpf_object__close(obj);

    printf("\033[?25h\nFloodGate ndalur\n");
    _exit(0);
}

static void shfaq_perdorimi(const char *programi) {
    printf("FloodGate - XDP Traffic Scrubber + sFlow ACL\n\n");
    printf("Perdorimi: %s -i <interface> [opsionet]\n\n", programi);
    printf("Opsionet:\n");
    printf("  -i <interface>    Interface rrjeti (e detyrueshme)\n");
    printf("  -p <port>         Porta target\n");
    printf("  -t <limit>        TCP limit (paketa/sek)\n");
    printf("  -u <limit>        UDP limit (paketa/sek)\n");
    printf("  -c <limit>        ICMP limit (paketa/sek)\n");
    printf("  -P <limit>        PPS limit global per IP\n");
    printf("  -B <limit>        Bytes/sek limit per IP\n");
    printf("  -Y <limit>        SYN limit per IP\n");
    printf("  -U                Bloko te gjitha UDP\n");
    printf("  -T                Bloko te gjitha TCP\n");
    printf("  -w <file>         Whitelist file\n");
    printf("  -b <file>         Blacklist file\n");
    printf("  -S <port>         sFlow port (default 6343)\n");
    printf("  -a                Aktivo ACL automatik\n");
    printf("  -F                Aktivo Flowspec auto-redirect (BGP)\n");
    printf("  -C                Aktivo UDP challenge-response\n");
    printf("  -s <sec>          Shfaq statistika cdo X sekonda\n");
    printf("  -h                Shfaq ndihme\n\n");
    printf("Shembull:\n");
    printf("  %s -i vlan50 -t 10000 -u 5000 -c 100 -S 6343 -a -C -w whitelist.txt -s 5\n", programi);
    printf("  %s -i eth0 -P 50000 -Y 500 -S 6343 -a -C -b blacklist.txt\n\n", programi);
}

int main(int argc, char **argv) {
    struct bpf_program *prog;
    int opt;
    char *interface = NULL;
    struct konfigurimi cfg = {
        .limit_tcp = 0,
        .limit_udp = 0,
        .limit_icmp = 0,
        .limit_pps = 0,
        .limit_bps = 0,
        .limit_syn = 0,
        .bloko_udp = 0,
        .bloko_tcp = 0,
        .porta_target = 0,
        .aktiv = 1
    };
    int intervali_stat = 0;
    char *whitelist_fajlli = NULL;
    char *blacklist_fajlli = NULL;

    setlinebuf(stdout);
    libbpf_set_print(print_libbpf_log);

    while ((opt = getopt(argc, argv, "i:p:t:u:c:P:B:Y:w:b:UTS:aFCs:h")) != -1) {
        switch (opt) {
            case 'i': interface = optarg; break;
            case 'p': cfg.porta_target = atoi(optarg); break;
            case 't': cfg.limit_tcp = atoll(optarg); break;
            case 'u': cfg.limit_udp = atoll(optarg); break;
            case 'c': cfg.limit_icmp = atoll(optarg); break;
            case 'P': cfg.limit_pps = atoll(optarg); break;
            case 'B': cfg.limit_bps = atoll(optarg); break;
            case 'Y': cfg.limit_syn = atoll(optarg); break;
            case 'U': cfg.bloko_udp = 1; break;
            case 'T': cfg.bloko_tcp = 1; break;
            case 'w': whitelist_fajlli = optarg; break;
            case 'b': blacklist_fajlli = optarg; break;
            case 'S': sflow_porta = atoi(optarg); break;
            case 'a': acl_aktiv = 1; break;
            case 'F': flowspec_aktiv = 1; break;
            case 'C': cfg.challenge_aktiv = 1; break;
            case 's': intervali_stat = atoi(optarg); break;
            case 'h': shfaq_perdorimi(argv[0]); return 0;
            default: shfaq_perdorimi(argv[0]); return 1;
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
        obj = bpf_object__open("/usr/local/lib/floodgate_kern.o");
        if (libbpf_get_error(obj)) {
            fprintf(stderr, "Gabim ne hapjen e BPF object\n");
            return 1;
        }
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

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        fprintf(stderr, "Gabim ne attach te XDP: %s\n", strerror(errno));
        return 1;
    }

    fd_harta_config = bpf_object__find_map_fd_by_name(obj, "harta_config");
    fd_harta_stat = bpf_object__find_map_fd_by_name(obj, "harta_statistika");
    fd_harta_ip = bpf_object__find_map_fd_by_name(obj, "harta_ip");
    fd_harta_whitelist = bpf_object__find_map_fd_by_name(obj, "harta_whitelist");
    fd_harta_bllokuar = bpf_object__find_map_fd_by_name(obj, "harta_bllokuar");
    fd_harta_challenge = bpf_object__find_map_fd_by_name(obj, "harta_challenge");
    fd_harta_verifikuar = bpf_object__find_map_fd_by_name(obj, "harta_verifikuar");

    if (fd_harta_config < 0 || fd_harta_stat < 0 || fd_harta_ip < 0 ||
        fd_harta_whitelist < 0 || fd_harta_bllokuar < 0) {
        fprintf(stderr, "Gabim ne gjetjen e maps\n");
        return 1;
    }

    vendos_konfig(&cfg);

    if (whitelist_fajlli) {
        if (ngarko_whitelist(whitelist_fajlli) < 0)
            return 1;
    }

    if (blacklist_fajlli) {
        if (ngarko_blacklist(blacklist_fajlli) < 0)
            return 1;
    }

    signal(SIGINT, pastrimi);
    signal(SIGTERM, pastrimi);

    printf("\n\033[1;36m========================================\033[0m\n");
    printf("\033[1;36m  FloodGate XDP Scrubber + sFlow ACL\033[0m\n");
    printf("\033[1;36m========================================\033[0m\n\n");
    printf("Interface:     %s\n", interface);
    if (cfg.porta_target) printf("Porta target:  %u\n", cfg.porta_target);
    if (cfg.bloko_udp)    printf("Menyra:        Bloko te gjitha UDP\n");
    if (cfg.bloko_tcp)    printf("Menyra:        Bloko te gjitha TCP\n");
    if (cfg.limit_tcp)    printf("TCP limit:     %llu pps\n", (unsigned long long)cfg.limit_tcp);
    if (cfg.limit_udp)    printf("UDP limit:     %llu pps\n", (unsigned long long)cfg.limit_udp);
    if (cfg.limit_icmp)   printf("ICMP limit:    %llu pps\n", (unsigned long long)cfg.limit_icmp);
    if (cfg.limit_pps)    printf("PPS limit:     %llu pps\n", (unsigned long long)cfg.limit_pps);
    if (cfg.limit_bps)    printf("BPS limit:     %llu bps\n", (unsigned long long)cfg.limit_bps);
    if (cfg.limit_syn)    printf("SYN limit:     %llu pps\n", (unsigned long long)cfg.limit_syn);
    if (sflow_porta)      printf("sFlow:         port %d\n", sflow_porta);
    if (acl_aktiv)        printf("ACL:           aktiv\n");
    if (flowspec_aktiv)   printf("Flowspec:      aktiv (BGP redirect)\n");
    if (cfg.challenge_aktiv) printf("Challenge:     aktiv (UDP)\n");
    printf("\n");

    if (sflow_porta > 0) {
        if (pthread_create(&sflow_thread, NULL, sflow_degjues, NULL) != 0) {
            fprintf(stderr, "Gabim ne krijimin e sFlow thread\n");
            return 1;
        }
    }

    if (acl_aktiv) {
        if (pthread_create(&acl_thread, NULL, acl_menaxher, NULL) != 0) {
            fprintf(stderr, "Gabim ne krijimin e ACL thread\n");
            return 1;
        }
    }

    if (flowspec_aktiv) {
        if (sflow_porta <= 0) {
            fprintf(stderr, "Gabim: Flowspec kerkon sFlow (-S port)\n");
            return 1;
        }
        if (pthread_create(&flowspec_thread, NULL, flowspec_menaxher, NULL) != 0) {
            fprintf(stderr, "Gabim ne krijimin e Flowspec thread\n");
            return 1;
        }
    }

    printf("Shtype Ctrl+C per te ndalur...\n\n");

    if (intervali_stat > 0) {
        while (vazhdo) {
            sleep(intervali_stat);
            if (!vazhdo) break;
            shfaq_dashboard(20);
        }
    } else {
        while (vazhdo) {
            pause();
        }
    }

    return 0;
}
