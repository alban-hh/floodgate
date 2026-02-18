#include "sflow.h"
#include "globals.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SFLOW_MAX_DATAGRAM 65536
#define SFLOW_VERSION_5 5

struct sflow_kursor {
    const __u8 *data;
    int pos;
    int len;
};

static __u32 lexo_u32(const __u8 *buf) {
    return ((__u32)buf[0] << 24) | ((__u32)buf[1] << 16) | ((__u32)buf[2] << 8) | buf[3];
}

static int sflow_lexo_u32(struct sflow_kursor *k, __u32 *val) {
    if (k->pos + 4 > k->len)
        return -1;
    *val = lexo_u32(k->data + k->pos);
    k->pos += 4;
    return 0;
}

static int sflow_kerce(struct sflow_kursor *k, int bytes) {
    if (k->pos + bytes > k->len)
        return -1;
    k->pos += bytes;
    return 0;
}

static __u32 sflow_hash(__u32 ip) {
    ip ^= ip >> 16;
    ip *= 0x45d9f3b;
    ip ^= ip >> 16;
    return ip & (SFLOW_TABELA_MADHESIA - 1);
}

static void sflow_regjistro(__u32 ip, __u32 frame_len, __u32 sampling_rate) {
    __u32 idx = sflow_hash(ip);

    pthread_mutex_lock(&sflow_mutex);

    for (int i = 0; i < 64; i++) {
        __u32 pos = (idx + i) & (SFLOW_TABELA_MADHESIA - 1);
        if (!sflow_tabela[pos].aktiv || sflow_tabela[pos].ip == ip) {
            sflow_tabela[pos].ip = ip;
            sflow_tabela[pos].paketa += sampling_rate;
            sflow_tabela[pos].bytes += (__u64)frame_len * sampling_rate;
            sflow_tabela[pos].aktiv = 1;
            break;
        }
    }

    pthread_mutex_unlock(&sflow_mutex);
}

static void sflow_regjistro_dst(__u32 ip, __u32 frame_len, __u32 sampling_rate) {
    __u32 idx = sflow_hash(ip);

    pthread_mutex_lock(&sflow_mutex);

    for (int i = 0; i < 64; i++) {
        __u32 pos = (idx + i) & (SFLOW_TABELA_MADHESIA - 1);
        if (!sflow_tabela_dst[pos].aktiv || sflow_tabela_dst[pos].ip == ip) {
            sflow_tabela_dst[pos].ip = ip;
            sflow_tabela_dst[pos].paketa += sampling_rate;
            sflow_tabela_dst[pos].bytes += (__u64)frame_len * sampling_rate;
            sflow_tabela_dst[pos].aktiv = 1;
            break;
        }
    }

    pthread_mutex_unlock(&sflow_mutex);
}

static void proceso_raw_header(const __u8 *hdr, int hdr_len, __u32 frame_len, __u32 sampling_rate) {
    if (hdr_len < 14)
        return;

    __u16 ethertype = (hdr[12] << 8) | hdr[13];
    int ip_offset = 14;

    if (ethertype == 0x8100) {
        if (hdr_len < 18)
            return;
        ethertype = (hdr[16] << 8) | hdr[17];
        ip_offset = 18;
    }

    if (ethertype != 0x0800)
        return;

    if (hdr_len < ip_offset + 20)
        return;

    const __u8 *ip_hdr = hdr + ip_offset;
    __u8 version = (ip_hdr[0] >> 4) & 0xF;
    if (version != 4)
        return;

    __u32 ip_burimi;
    memcpy(&ip_burimi, ip_hdr + 12, 4);

    __u32 ip_destinacioni;
    memcpy(&ip_destinacioni, ip_hdr + 16, 4);

    sflow_regjistro(ip_burimi, frame_len, sampling_rate);
    sflow_regjistro_dst(ip_destinacioni, frame_len, sampling_rate);
}

static void proceso_flow_records(struct sflow_kursor *k, __u32 num_records, __u32 sampling_rate) {
    for (__u32 r = 0; r < num_records && r < 32; r++) {
        __u32 record_type, record_len;
        if (sflow_lexo_u32(k, &record_type) < 0) return;
        if (sflow_lexo_u32(k, &record_len) < 0) return;

        int record_end = k->pos + record_len;
        __u32 enterprise = record_type >> 12;
        __u32 format = record_type & 0xFFF;

        if (enterprise == 0 && format == 1) {
            __u32 header_protocol, frame_length, stripped, header_length;
            if (sflow_lexo_u32(k, &header_protocol) < 0) goto next_record;
            if (sflow_lexo_u32(k, &frame_length) < 0) goto next_record;
            if (sflow_lexo_u32(k, &stripped) < 0) goto next_record;
            if (sflow_lexo_u32(k, &header_length) < 0) goto next_record;

            if (header_protocol == 1 && k->pos + (int)header_length <= k->len) {
                proceso_raw_header(k->data + k->pos, header_length, frame_length, sampling_rate);
            }
        }

next_record:
        k->pos = record_end;
    }
}

static void proceso_sflow(const __u8 *data, int len) {
    struct sflow_kursor k = {data, 0, len};
    __u32 version, addr_type, num_samples;

    if (sflow_lexo_u32(&k, &version) < 0) return;
    if (version != SFLOW_VERSION_5) return;

    if (sflow_lexo_u32(&k, &addr_type) < 0) return;
    if (addr_type == 1) {
        if (sflow_kerce(&k, 4) < 0) return;
    } else if (addr_type == 2) {
        if (sflow_kerce(&k, 16) < 0) return;
    } else {
        return;
    }

    if (sflow_kerce(&k, 12) < 0) return;

    if (sflow_lexo_u32(&k, &num_samples) < 0) return;

    for (__u32 i = 0; i < num_samples && i < 128; i++) {
        __u32 sample_type, sample_len;
        if (sflow_lexo_u32(&k, &sample_type) < 0) return;
        if (sflow_lexo_u32(&k, &sample_len) < 0) return;

        int sample_end = k.pos + sample_len;
        __u32 enterprise = sample_type >> 12;
        __u32 format = sample_type & 0xFFF;

        if (enterprise == 0 && (format == 1 || format == 3)) {
            __u32 seq, sampling_rate, sample_pool, drops, num_records;

            if (sflow_lexo_u32(&k, &seq) < 0) goto next_sample;

            if (format == 1) {
                if (sflow_kerce(&k, 4) < 0) goto next_sample;
            } else {
                if (sflow_kerce(&k, 8) < 0) goto next_sample;
            }

            if (sflow_lexo_u32(&k, &sampling_rate) < 0) goto next_sample;
            if (sflow_lexo_u32(&k, &sample_pool) < 0) goto next_sample;
            if (sflow_lexo_u32(&k, &drops) < 0) goto next_sample;

            if (format == 1) {
                if (sflow_kerce(&k, 8) < 0) goto next_sample;
            } else {
                if (sflow_kerce(&k, 16) < 0) goto next_sample;
            }

            if (sflow_lexo_u32(&k, &num_records) < 0) goto next_sample;

            proceso_flow_records(&k, num_records, sampling_rate);
        }

next_sample:
        k.pos = sample_end;
    }
}

void *sflow_degjues(void *arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "sFlow: gabim ne hapjen e socket: %s\n", strerror(errno));
        return NULL;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(sflow_porta);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "sFlow: gabim ne bind port %d: %s\n", sflow_porta, strerror(errno));
        close(sock);
        return NULL;
    }

    printf("sFlow degjues aktiv ne port %d\n", sflow_porta);

    __u8 buffer[SFLOW_MAX_DATAGRAM];

    while (vazhdo) {
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
                             (struct sockaddr *)&sender, &sender_len);
        if (n <= 0)
            continue;

        proceso_sflow(buffer, n);
    }

    close(sock);
    return NULL;
}
