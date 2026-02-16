#ifndef STATS_H
#define STATS_H

#include <linux/types.h>
#include <stddef.h>

void formato_bytes(char *buf, size_t len, __u64 bytes);
void formato_numri(char *buf, size_t len, __u64 n);
const char *emri_nivelit(__u32 niveli);
void shfaq_statistika(void);
void shfaq_top_ip(int max_shfaq);

#endif
