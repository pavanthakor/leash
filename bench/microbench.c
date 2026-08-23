// Phase 8 per-syscall microbenchmark. Measures the ALLOW path of the two LSM
// hooks -- the cost every syscall pays, not the rare deny path. One warm process,
// N syscalls, each timed individually with CLOCK_MONOTONIC (vDSO, ~20ns, a
// common-mode bias that cancels in any in-vs-out delta). Raw per-sample latencies
// are written to a CSV so the distribution -- not one cherry-picked number -- is
// what gets reported. Unprivileged; does no BPF and touches no map.
//
//   microbench file    N <path>    out.csv [warmup]   open()+close(), time open()
//   microbench connect N <ip:port> out.csv [warmup]   NON-BLOCKING connect(), timed
//
// Why non-blocking connect: security_socket_connect (the LSM hook) fires at the
// START of connect(), before the protocol handshake, regardless of O_NONBLOCK.
// A non-blocking socket returns EINPROGRESS right after the hook, so the timed
// region is [syscall entry + hook], NOT the loopback TCP round-trip -- which
// would otherwise swamp a sub-µs hook. The hook runs identically either way.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <file|connect> N <target> out.csv [warmup]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    long N = atol(argv[2]);
    const char *target = argv[3];
    const char *out = argv[4];
    long W = argc > 5 ? atol(argv[5]) : 1000;
    if (N <= 0) { fprintf(stderr, "N must be > 0\n"); return 2; }

    // pin to one CPU so scheduler migration does not add variance; the same pin
    // applies in every condition, so it is a controlled constant, not a thumb.
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    uint64_t *lat = malloc(sizeof(uint64_t) * (size_t)N);
    if (!lat) { fprintf(stderr, "oom\n"); return 1; }

    int is_file = strcmp(mode, "file") == 0;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    if (!is_file) {
        const char *c = strrchr(target, ':');
        if (!c) { fprintf(stderr, "connect target must be ip:port\n"); return 2; }
        char ip[64]; size_t l = (size_t)(c - target);
        if (l >= sizeof(ip)) { fprintf(stderr, "ip too long\n"); return 2; }
        memcpy(ip, target, l); ip[l] = 0;
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)atoi(c + 1));
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { fprintf(stderr, "bad ip %s\n", ip); return 2; }
    }

    long got = 0;
    for (long i = -W; i < N; i++) {
        uint64_t t0, t1;
        if (is_file) {
            t0 = now_ns();
            int fd = open(target, O_RDONLY);
            t1 = now_ns();
            if (fd < 0) { if (i == -W) { fprintf(stderr, "open %s: %s\n", target, strerror(errno)); return 1; } continue; }
            close(fd);
        } else {
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (fd < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return 1; }
            t0 = now_ns();
            connect(fd, (struct sockaddr *)&sa, sizeof(sa));   // EINPROGRESS ok: hook already ran
            t1 = now_ns();
            close(fd);
        }
        if (i >= 0) lat[got++] = t1 - t0;
    }

    FILE *f = fopen(out, "w");
    if (!f) { perror("fopen out"); return 1; }
    for (long i = 0; i < got; i++) fprintf(f, "%llu\n", (unsigned long long)lat[i]);
    fclose(f);

    qsort(lat, (size_t)got, sizeof(uint64_t), cmp_u64);
    uint64_t p50 = lat[got / 2], p90 = lat[(long)(got * 0.90)], p99 = lat[(long)(got * 0.99)];
    printf("%-7s N=%ld min=%llu p50=%llu p90=%llu p99=%llu ns  -> %s\n",
           mode, got, (unsigned long long)lat[0], (unsigned long long)p50,
           (unsigned long long)p90, (unsigned long long)p99, out);
    free(lat);
    return 0;
}
