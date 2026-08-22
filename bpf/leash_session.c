// Phase 2 userspace half: load + attach the session tracepoints, populate the
// `sessions` map from the agent's cgroup path, consume the ring buffer, and
// reconstruct the agent's process tree from kernel events ALONE -- no /proc
// walking, no cooperation from the agent.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "leash_session.skel.h"

#define EV_FORK 1
#define EV_EXEC 2
#define MAXN 8192
#define READY_FILE "/home/pavan/leash-demo/session_ready"

struct event {
    unsigned char kind;
    unsigned int  pid;
    unsigned int  ppid;
    unsigned long long cgid;
    char comm[16];
    char pcomm[16];
};

// In-memory forest, rebuilt purely from events.
struct node { int used, pid, ppid, execd; char comm[16], pcomm[16]; };
static struct node nodes[MAXN];
static unsigned long long session_cgid;
static unsigned long long root_pid;

static volatile sig_atomic_t stop;
static void on_sigint(int s){ (void)s; stop = 1; }

static struct node *find_or_add(int pid){
    int free_slot = -1;
    for (int i=0;i<MAXN;i++){
        if (nodes[i].used && nodes[i].pid==pid) return &nodes[i];
        if (!nodes[i].used && free_slot<0) free_slot=i;
    }
    if (free_slot<0) return NULL;
    nodes[free_slot].used=1; nodes[free_slot].pid=pid; nodes[free_slot].ppid=0;
    nodes[free_slot].execd=0; nodes[free_slot].comm[0]=0; nodes[free_slot].pcomm[0]=0;
    return &nodes[free_slot];
}

// Resolve a cgroupfs path to the 64-bit id bpf_get_current_cgroup_id() returns.
static unsigned long long cgroup_id_of(const char *path){
    struct { struct file_handle h; unsigned char buf[64]; } fh;
    int mid = 0;
    fh.h.handle_bytes = 64;
    if (name_to_handle_at(AT_FDCWD, path, &fh.h, &mid, 0)) { perror("name_to_handle_at"); return 0; }
    unsigned long long id = 0;
    memcpy(&id, fh.h.f_handle, sizeof(id));
    return id;
}

static unsigned long long fork_count, exec_count;

static int handle_event(void *ctx, void *data, size_t len){
    (void)ctx; (void)len;
    struct event *e = data;

    // FORK: proof we see every spawn live and ordered. Not used for structure
    // (threads also fork); the tree is built from EXEC, which threads never do.
    if (e->kind == EV_FORK){
        fork_count++;
        printf("  [spawn] FORK pid=%-6u ppid=%-6u  cgid=%llu\n", e->pid, e->ppid, e->cgid);
        fflush(stdout);
        return 0;
    }

    // EXEC: authoritative node -- real comm, real parent edge.
    exec_count++;
    struct node *n = find_or_add(e->pid);
    if (!n) return 0;
    n->ppid = e->ppid; n->execd = 1;
    memcpy(n->comm, e->comm, 16);
    memcpy(n->pcomm, e->pcomm, 16);
    // Label the parent node from this exec's parent comm (covers the root too).
    struct node *p = find_or_add(e->ppid);
    if (p && !p->comm[0] && e->pcomm[0]) memcpy(p->comm, e->pcomm, 16);

    printf("  [spawn] EXEC pid=%-6u ppid=%-6u comm=%-14s (parent=%s) cgid=%llu\n",
           e->pid, e->ppid, e->comm[0]?e->comm:"?", e->pcomm[0]?e->pcomm:"?", e->cgid);
    fflush(stdout);
    return 0;
}

static void print_subtree(int pid, int depth){
    for (int i=0;i<MAXN;i++){
        if (nodes[i].used && nodes[i].ppid==pid && nodes[i].pid!=pid){
            for (int d=0; d<depth; d++) printf("   ");
            printf("%s(%d)%s\n", nodes[i].comm[0]?nodes[i].comm:"?",
                   nodes[i].pid, nodes[i].execd?"":"  [forked, no exec]");
            print_subtree(nodes[i].pid, depth+1);
        }
    }
}

static void print_tree(void){
    printf("\n==================== SESSION PROCESS TREE ====================\n");
    printf("session cgid = %llu   (reconstructed from kernel events only)\n", session_cgid);
    printf("events: %llu fork, %llu exec\n", fork_count, exec_count);
    // Root: the seeded root pid if known, else any node whose parent isn't a node.
    int printed_root = 0;
    if (root_pid){
        struct node *r = NULL;
        for (int i=0;i<MAXN;i++) if (nodes[i].used && (unsigned)nodes[i].pid==root_pid) r=&nodes[i];
        const char *rc = (r && r->comm[0]) ? r->comm : "agent(uvicorn)";
        printf("%s(%llu)   <- session root\n", rc, root_pid);
        print_subtree((int)root_pid, 1);
        printed_root = 1;
    }
    if (!printed_root){
        for (int i=0;i<MAXN;i++){
            if (!nodes[i].used) continue;
            int has_parent_node=0;
            for (int j=0;j<MAXN;j++) if (nodes[j].used && nodes[j].pid==nodes[i].ppid){ has_parent_node=1; break; }
            if (!has_parent_node){
                printf("%s(%d)   <- root\n", nodes[i].comm[0]?nodes[i].comm:"?", nodes[i].pid);
                print_subtree(nodes[i].pid, 1);
            }
        }
    }
    printf("=============================================================\n");
    fflush(stdout);
}

int main(int argc, char **argv){
    if (argc < 2){
        fprintf(stderr, "usage: %s <agent-cgroup-path> [root-pid]\n", argv[0]);
        fprintf(stderr, "  e.g. sudo %s /sys/fs/cgroup/.../leash-agent.service 12345\n", argv[0]);
        return 2;
    }
    session_cgid = cgroup_id_of(argv[1]);
    if (!session_cgid){ fprintf(stderr, "could not resolve cgroup id for %s\n", argv[1]); return 1; }
    if (argc >= 3) root_pid = strtoull(argv[2], NULL, 10);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct leash_session_bpf *skel = leash_session_bpf__open_and_load();
    if (!skel){ fprintf(stderr, "open/load failed -- run with sudo?\n"); return 1; }

    int err = leash_session_bpf__attach(skel);
    if (err){ fprintf(stderr, "attach failed: %d\n", err); goto cleanup; }

    // Populate the sessions map BEFORE announcing readiness.
    unsigned long long val = root_pid;
    err = bpf_map__update_elem(skel->maps.sessions, &session_cgid, sizeof(session_cgid),
                               &val, sizeof(val), 0);
    if (err){ fprintf(stderr, "map update failed: %d\n", err); goto cleanup; }

    if (root_pid){
        struct node *r = find_or_add((int)root_pid);
        if (r && !r->comm[0]) strcpy(r->comm, "agent(uvicorn)");
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                              handle_event, NULL, NULL);
    if (!rb){ fprintf(stderr, "ringbuf failed\n"); err=1; goto cleanup; }

    // Announce readiness ONLY now: tracepoints attached + session cgid loaded.
    // The attack script hard-gates on this file (attach-before-spawn).
    FILE *rf = fopen(READY_FILE, "w");
    if (rf){ fprintf(rf, "cgid=%llu root=%llu\n", session_cgid, root_pid); fclose(rf); }

    printf("ATTACHED sched_process_fork + sched_process_exec\n");
    printf("session cgid=%llu  root_pid=%llu\n", session_cgid, root_pid);
    printf("readiness written -> %s\n", READY_FILE);
    printf("streaming session spawns (Ctrl-C to print the final tree)...\n\n");

    signal(SIGINT, on_sigint);
    while (!stop){
        int n = ring_buffer__poll(rb, 200);
        if (n < 0 && n != -EINTR) break;
    }
    print_tree();
    ring_buffer__free(rb);
    unlink(READY_FILE);

cleanup:
    leash_session_bpf__destroy(skel);
    return err != 0;
}
