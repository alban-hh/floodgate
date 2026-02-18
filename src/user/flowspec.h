#ifndef FLOWSPEC_H
#define FLOWSPEC_H

#include <linux/types.h>

#define FLOWSPEC_MAX_MITIGIME 64

#define FLOWSPEC_MODE_REDIRECT  0
#define FLOWSPEC_MODE_BLACKHOLE 1

struct flowspec_info {
    __u32 ip;
    __u64 koha_fillimit;
    int aktiv;
    int mode;
};

void *flowspec_menaxher(void *arg);
int flowspec_nr_aktiv(void);
int flowspec_merr_listen(struct flowspec_info *dst, int max);

#endif
