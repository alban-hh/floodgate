#ifndef GLOBALS_H
#define GLOBALS_H

#include "floodgate_common.h"
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define SFLOW_TABELA_MADHESIA 65536

struct sflow_hyrje {
    __u32 ip;
    __u64 paketa;
    __u64 bytes;
    __u32 aktiv;
};

extern int fd_harta_config;
extern int fd_harta_stat;
extern int fd_harta_ip;
extern int fd_harta_whitelist;
extern int fd_harta_bllokuar;
extern int fd_harta_challenge;
extern int fd_harta_verifikuar;
extern int ifindex;
extern struct bpf_object *obj;
extern volatile int vazhdo;

extern struct sflow_hyrje sflow_tabela[];
extern pthread_mutex_t sflow_mutex;

extern int sflow_porta;
extern int acl_aktiv;
extern __u64 acl_pragu_pps;
extern __u64 acl_pragu_bps;
extern __u32 acl_pragu_shkeljet;
extern __u32 acl_koha_bllokimit;
extern __u32 acl_intervali;

#define ACL_LOG_MAX 8
#define ACL_LOG_GJATESIA 160
extern char acl_log[ACL_LOG_MAX][ACL_LOG_GJATESIA];
extern int acl_log_idx;
extern int acl_log_nr;
extern pthread_mutex_t acl_log_mutex;
void acl_log_shto(const char *fmt, ...);

#endif
