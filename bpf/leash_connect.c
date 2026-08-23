// Phase 4 userspace half: load + attach the socket_connect enforcer, populate
// the sessions map (agent cgroup) and the allowlist (ip:port), and stream every
// in-session connect with the (ip,port) the KERNEL read and its verdict.
// Mirrors Phase 3's loader: cgid re-sync follows systemd's relaunch churn;
// SIGUSR1 permanently freezes + clears (fail-open 3a); kill/detach (fail-open 3b).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "leash_connect.skel.h"

#define KIND_DENY  0
#define KIND_ALLOW 1

struct dest { unsigned int ip; unsigned short port; unsigned short _pad; };
struct conn_event {
    unsigned char kind;
    unsigned int pid, uid;
    unsigned int ip;        // network order
    unsigned short port;    // host order
    char comm[16];
};

static volatile sig_atomic_t stop;
static sig_atomic_t clear_req;
static void on_sigint(int s){ (void)s; stop = 1; }
static void on_sigusr1(int s){ (void)s; clear_req = 1; }

static unsigned long long cgroup_id_of(const char *path){
    struct { struct file_handle h; unsigned char buf[64]; } fh;
    int mid = 0; fh.h.handle_bytes = 64;
    if (name_to_handle_at(AT_FDCWD, path, &fh.h, &mid, 0)){ perror("name_to_handle_at"); return 0; }
    unsigned long long id = 0; memcpy(&id, fh.h.f_handle, sizeof(id));
    return id;
}

// Userspace copy of the allowlist, for the self-verifying print.
#define MAXA 64
static struct { unsigned int ip; unsigned short port; } allow[MAXA];
static int nallow;
static int is_allowed(unsigned int ip, unsigned short port){
    for (int i = 0; i < nallow; i++) if (allow[i].ip==ip && allow[i].port==port) return 1;
    return 0;
}

static int on_event(void *ctx, void *data, size_t len){
    (void)ctx; (void)len;
    struct conn_event *e = data;
    char ips[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->ip, ips, sizeof(ips));   // e->ip is network order
    if (e->kind == KIND_ALLOW){
        printf("  ALLOW   socket_connect  pid=%-6u comm=%-14s -> %s:%u (kernel-read)\n"
               "          == allowlisted %s:%u  ->  MATCH (permitted)\n",
               e->pid, e->comm, ips, e->port, ips, e->port);
    } else {
        printf("  DENIED  socket_connect  pid=%-6u uid=%-5u comm=%-14s -> %s:%u (kernel-read)\n"
               "          not on allowlist  ->  -EPERM\n",
               e->pid, e->uid, e->comm, ips, e->port);
    }
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv){
    // stdout is a pipe under leashd -> glibc fully buffers it, so the attach
    // banner would sit unflushed until the first ring-buffer event. Line-buffer
    // so ATTACHED is observable at attach time, not at first deny.
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 3){
        fprintf(stderr, "usage: %s <agent-cgroup-path> <allow ip:port> [more ip:port...]\n", argv[0]);
        return 2;
    }
    unsigned long long session_cgid = cgroup_id_of(argv[1]);
    if (!session_cgid){ fprintf(stderr, "could not resolve cgroup id for %s\n", argv[1]); return 1; }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct leash_connect_bpf *skel = leash_connect_bpf__open_and_load();
    if (!skel){ fprintf(stderr, "open/load failed -- run with sudo?\n"); return 1; }

    int err = leash_connect_bpf__attach(skel);
    if (err){ fprintf(stderr, "attach failed: %d (is 'bpf' in /sys/kernel/security/lsm?)\n", err); goto cleanup; }

    unsigned long long zero = 0;
    err = bpf_map__update_elem(skel->maps.sessions, &session_cgid, sizeof(session_cgid),
                               &zero, sizeof(zero), 0);
    if (err){ fprintf(stderr, "sessions update failed: %d\n", err); goto cleanup; }

    printf("session cgid = %llu\n", session_cgid);
    for (int i = 2; i < argc; i++){
        char host[64]; unsigned int port = 0;
        char *colon = strrchr(argv[i], ':');
        if (!colon){ fprintf(stderr, "bad allow entry %s (want ip:port)\n", argv[i]); continue; }
        size_t hlen = colon - argv[i];
        if (hlen >= sizeof(host)) hlen = sizeof(host)-1;
        memcpy(host, argv[i], hlen); host[hlen] = 0;
        port = (unsigned)atoi(colon+1);
        struct in_addr ina;
        if (inet_pton(AF_INET, host, &ina) != 1){ fprintf(stderr, "bad ip %s\n", host); continue; }
        struct dest d = {};
        d.ip = ina.s_addr;            // network order, matches sin_addr.s_addr
        d.port = (unsigned short)port; // host order, matches bpf_ntohs(sin_port)
        unsigned char one = 1;
        if (bpf_map__update_elem(skel->maps.allowed_dests, &d, sizeof(d), &one, sizeof(one), 0)){
            fprintf(stderr, "allow update failed for %s\n", argv[i]); continue;
        }
        if (nallow < MAXA){ allow[nallow].ip = d.ip; allow[nallow].port = d.port; nallow++; }
        printf("allow: %s:%u  (ip_be=0x%08x port=%u)\n", host, port, d.ip, port);
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.denies),
                                              on_event, NULL, NULL);
    if (!rb){ fprintf(stderr, "ringbuf failed\n"); err = 1; goto cleanup; }

    signal(SIGINT, on_sigint); signal(SIGTERM, on_sigint); signal(SIGUSR1, on_sigusr1);

    printf("\nATTACHED lsm/socket_connect enforcer (default-deny).  loader pid = %d\n", getpid());
    printf("  proof 3a (map cleared): sudo kill -USR1 %d\n", getpid());
    printf("  proof 3b (detach):      sudo kill -INT  %d\n", getpid());
    printf("streaming in-session connects...\n\n");

    int frozen = 0, tick = 0;   // frozen is PERMANENT for this process.
    while (!stop){
        if (clear_req){
            clear_req = 0;
            frozen = 1;                                  // never reset for this process
            bpf_map__delete_elem(skel->maps.sessions, &session_cgid, sizeof(session_cgid), 0);
            printf(">>> SIGUSR1: sessions cleared + re-sync FROZEN (permanent) --\n"
                   ">>> egress enforcement FAILS OPEN. Re-enforcing requires a fresh enforcer.\n\n");
            fflush(stdout);
        }
        if (!frozen && (++tick % 5 == 0)){              // ~1s: follow cgid drift
            unsigned long long now = cgroup_id_of(argv[1]);
            if (now && now != session_cgid){
                bpf_map__delete_elem(skel->maps.sessions, &session_cgid, sizeof(session_cgid), 0);
                bpf_map__update_elem(skel->maps.sessions, &now, sizeof(now), &zero, sizeof(zero), 0);
                printf(">>> session cgid changed %llu -> %llu (re-synced)\n", session_cgid, now);
                fflush(stdout);
                session_cgid = now;
            }
        }
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    printf("\ndetaching -- program unloads, egress enforcement gone (fails open).\n");
    ring_buffer__free(rb);

cleanup:
    leash_connect_bpf__destroy(skel);
    return err != 0;
}
