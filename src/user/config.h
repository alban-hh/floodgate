#ifndef CONFIG_H
#define CONFIG_H

#include "floodgate_common.h"

void vendos_konfig(struct konfigurimi *cfg);
int ngarko_whitelist(const char *fajlli);
int ngarko_blacklist(const char *fajlli);

#endif
