#include "globals.h"
#include <stdio.h>
#include <stdarg.h>

int fd_harta_config = -1;
int fd_harta_stat = -1;
int fd_harta_ip = -1;
int fd_harta_whitelist = -1;
int fd_harta_bllokuar = -1;
int fd_harta_challenge = -1;
int fd_harta_verifikuar = -1;
int ifindex = -1;
struct bpf_object *obj = NULL;
volatile int vazhdo = 1;

struct sflow_hyrje sflow_tabela[SFLOW_TABELA_MADHESIA];
pthread_mutex_t sflow_mutex = PTHREAD_MUTEX_INITIALIZER;

int sflow_porta = 0;
int acl_aktiv = 0;
__u64 acl_pragu_pps = 100000;
__u64 acl_pragu_bps = 100000000;
__u32 acl_pragu_shkeljet = 10;
__u32 acl_koha_bllokimit = 300;
__u32 acl_intervali = 5;

char acl_log[ACL_LOG_MAX][ACL_LOG_GJATESIA];
int acl_log_idx = 0;
int acl_log_nr = 0;
pthread_mutex_t acl_log_mutex = PTHREAD_MUTEX_INITIALIZER;

void acl_log_shto(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    pthread_mutex_lock(&acl_log_mutex);
    vsnprintf(acl_log[acl_log_idx], ACL_LOG_GJATESIA, fmt, args);
    acl_log_idx = (acl_log_idx + 1) % ACL_LOG_MAX;
    if (acl_log_nr < ACL_LOG_MAX) acl_log_nr++;
    pthread_mutex_unlock(&acl_log_mutex);
    va_end(args);
}
