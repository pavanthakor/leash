// Phase 3 userspace half: load + attach the file_open enforcer, populate the
// sessions map (the agent's cgroup) and the protected_files map (inode identity
// of the decoy key), and stream every real -EPERM. SIGUSR1 clears the sessions
// map to demonstrate fail-open on lost session state (proof 3a); Ctrl-C / kill
// detaches, which also fails open via the no-program path (proof 3b).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>
#include "leash_enforce.skel.h"

struct fileid { unsigned long long dev, ino; };
#define KIND_DENY  0
#define KIND_DEBUG 1
struct deny_event {
    unsigned char kind;
    unsigned int pid, uid;
    unsigned long long dev, ino;
    char comm[16];
};

// Userspace table: (dev,ino) -> protected path, filled from argv at load time.
#define MAXP 64
static struct { unsigned long long dev, ino; const char *path; } prot[MAXP];
static int nprot;
static const char *path_of(unsigned long long dev, unsigned long long ino){
    for (int i = 0; i < nprot; i++)
        if (prot[i].dev == dev && prot[i].ino == ino) return prot[i].path;
    return "(protected)";
}
static unsigned long long expected_dev(unsigned long long ino){
    for (int i = 0; i < nprot; i++) if (prot[i].ino == ino) return prot[i].dev;
    return 0;
}

static volatile sig_atomic_t stop;
static sig_atomic_t clear_req;
static void on_sigint(int s){ (void)s; stop = 1; }
static void on_sigusr1(int s){ (void)s; clear_req = 1; }

// kernel new_encode_dev(): how s_dev is stored in struct super_block.
static unsigned long long kdev(dev_t st_dev){
    // Match struct super_block.s_dev, which BPF reads directly: a KERNEL dev_t,
    // MKDEV(ma,mi) = (ma << MINORBITS) | mi, MINORBITS = 20. (new_encode_dev is
    // the userspace/stat form and is WRONG for comparing against i_sb->s_dev.)
    unsigned maj = major(st_dev), min = minor(st_dev);
    return ((unsigned long long)maj << 20) | (min & 0xFFFFF);
}

static unsigned long long cgroup_id_of(const char *path){
    struct { struct file_handle h; unsigned char buf[64]; } fh;
    int mid = 0; fh.h.handle_bytes = 64;
    if (name_to_handle_at(AT_FDCWD, path, &fh.h, &mid, 0)){ perror("name_to_handle_at"); return 0; }
    unsigned long long id = 0; memcpy(&id, fh.h.f_handle, sizeof(id));
    return id;
}

static int on_deny(void *ctx, void *data, size_t len){
    (void)ctx; (void)len;
    struct deny_event *e = data;
    if (e->kind == KIND_DEBUG) {
        unsigned long long exp = expected_dev(e->ino);
        printf("  DEBUG   in-session open of protected inode  pid=%-6u comm=%-14s\n"
               "          kernel-read dev=%llu ino=%llu | map-stored dev=%llu  ->  %s\n",
               e->pid, e->comm, e->dev, e->ino, exp,
               (e->dev == exp) ? "MATCH" : "MISMATCH (deny will not fire!)");
        fflush(stdout);
        return 0;
    }
    printf("  DENIED  file_open  pid=%-6u uid=%-5u comm=%-14s dev=%llu ino=%llu\n"
           "          path=%s  ->  -EPERM\n",
           e->pid, e->uid, e->comm, e->dev, e->ino, path_of(e->dev, e->ino));
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv){
    if (argc < 3){
        fprintf(stderr, "usage: %s <agent-cgroup-path> <protected-file> [more-files...]\n", argv[0]);
        return 2;
    }
    unsigned long long session_cgid = cgroup_id_of(argv[1]);
    if (!session_cgid){ fprintf(stderr, "could not resolve cgroup id for %s\n", argv[1]); return 1; }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct leash_enforce_bpf *skel = leash_enforce_bpf__open_and_load();
    if (!skel){ fprintf(stderr, "open/load failed -- run with sudo?\n"); return 1; }

    int err = leash_enforce_bpf__attach(skel);
    if (err){ fprintf(stderr, "attach failed: %d (is 'bpf' in /sys/kernel/security/lsm?)\n", err); goto cleanup; }

    // sessions: the agent's cgroup (same gate as Phase 2).
    unsigned long long zero = 0;
    err = bpf_map__update_elem(skel->maps.sessions, &session_cgid, sizeof(session_cgid),
                               &zero, sizeof(zero), 0);
    if (err){ fprintf(stderr, "sessions update failed: %d\n", err); goto cleanup; }

    // protected_files: inode identity of each protected path.
    printf("session cgid = %llu\n", session_cgid);
    for (int i = 2; i < argc; i++){
        struct stat st;
        if (stat(argv[i], &st)){ fprintf(stderr, "stat %s: %s\n", argv[i], strerror(errno)); continue; }
        struct fileid id = { .dev = kdev(st.st_dev), .ino = (unsigned long long)st.st_ino };
        unsigned char one = 1;
        if (bpf_map__update_elem(skel->maps.protected_files, &id, sizeof(id),
                                 &one, sizeof(one), 0)){
            fprintf(stderr, "protected update failed for %s\n", argv[i]); continue;
        }
        unsigned char one2 = 1;
        bpf_map__update_elem(skel->maps.debug_inos, &id.ino, sizeof(id.ino),
                             &one2, sizeof(one2), 0);
        if (nprot < MAXP){ prot[nprot].dev = id.dev; prot[nprot].ino = id.ino; prot[nprot].path = argv[i]; nprot++; }
        printf("protected: %s  (dev=%llu ino=%llu)\n", argv[i], id.dev, id.ino);
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.denies),
                                              on_deny, NULL, NULL);
    if (!rb){ fprintf(stderr, "ringbuf failed\n"); err = 1; goto cleanup; }

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGUSR1, on_sigusr1);

    printf("\nATTACHED lsm/file_open enforcer.  loader pid = %d\n", getpid());
    printf("  proof 3a (map cleared): sudo kill -USR1 %d\n", getpid());
    printf("  proof 3b (detach):      sudo kill -INT  %d   (or Ctrl-C)\n", getpid());
    printf("streaming denials...\n\n");

    int frozen = 0, tick = 0;   // frozen is PERMANENT: once daemon-death is
                                // simulated this process never re-enforces.
    while (!stop){
        if (clear_req){
            clear_req = 0;
            frozen = 1;                                  // never reset for this process
            bpf_map__delete_elem(skel->maps.sessions, &session_cgid,
                                 sizeof(session_cgid), 0);
            printf(">>> SIGUSR1: sessions cleared + re-sync FROZEN (permanent) --\n"
                   ">>> enforcement FAILS OPEN. Re-enforcing requires a fresh enforcer.\n\n");
            fflush(stdout);
        }
        // Follow cgid drift (systemd recreates the cgroup on relaunch: same path,
        // new id). Skipped forever once frozen.
        if (!frozen && (++tick % 5 == 0)){
            unsigned long long now = cgroup_id_of(argv[1]);
            if (now && now != session_cgid){
                bpf_map__delete_elem(skel->maps.sessions, &session_cgid,
                                     sizeof(session_cgid), 0);
                bpf_map__update_elem(skel->maps.sessions, &now, sizeof(now),
                                     &zero, sizeof(zero), 0);
                printf(">>> session cgid changed %llu -> %llu (re-synced)\n", session_cgid, now);
                fflush(stdout);
                session_cgid = now;
            }
        }
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    printf("\ndetaching -- program unloads, enforcement gone (fails open).\n");
    ring_buffer__free(rb);

cleanup:
    leash_enforce_bpf__destroy(skel);
    return err != 0;
}
