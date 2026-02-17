#ifndef FLOODGATE_COMMON_H
#define FLOODGATE_COMMON_H

#include <linux/types.h>

#define MAX_HYRJE 10000000
#define MAX_BLLOKUAR 1000000

#define NIVELI_NORMAL 0
#define NIVELI_DYSHIMTE 1
#define NIVELI_KUFIZUAR 2
#define NIVELI_BLLOKUAR 3

#define DRITARJA_NS 1000000000ULL
#define DEKADENCA_NS 30000000000ULL
#define CHALLENGE_SKADIMI_NS 300000000000ULL
#define MAX_CHALLENGE 1000000
#define MAX_VERIFIKUAR 2000000

struct rregull_trafikut {
    __u64 numrues_paketa;
    __u64 koha_fundit;
    __u64 bytes_totale;
    __u64 koha_nivelit;
    __u32 niveli;
    __u32 shkeljet;
};

struct konfigurimi {
    __u64 limit_tcp;
    __u64 limit_udp;
    __u64 limit_icmp;
    __u64 limit_pps;
    __u64 limit_bps;
    __u64 limit_syn;
    __u32 bloko_udp;
    __u32 bloko_tcp;
    __u32 porta_target;
    __u32 aktiv;
    __u32 challenge_aktiv;
    __u32 _pad;
};

struct challenge_hyrje {
    __u64 koha;
    __u32 cookie;
    __u32 _pad;
};

#endif
