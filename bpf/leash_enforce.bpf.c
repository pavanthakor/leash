// Phase 3 kernel half: the first real refusal.
//
// An LSM file_open program that returns -EPERM when an IN-SESSION process tries
// to open a protected file (matched by inode identity). The Phase 2 session gate
// runs FIRST: a process outside the agent's cgroup can never be denied. That
// ordering is what makes enforcement safe (scoping) and fail-open (empty
// sessions map => nobody is in-session => nothing is denied).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define KIND_DENY  0
#define KIND_DEBUG 1

// File identity = (st_dev, st_ino). dev is the kernel's new_encode_dev() form,
// which the loader computes from the file's major/minor.
struct fileid { __u64 dev; __u64 ino; };

struct deny_event {
    __u8  kind;          // KIND_DENY | KIND_DEBUG
    __u32 pid;
    __u32 uid;
    __u64 dev;
    __u64 ino;
    char  comm[16];
};

// Reused from Phase 2: key = agent's dedicated cgroup id, value = root pid.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key,   __u64);
    __type(value, __u64);
} sessions SEC(".maps");

// The protected set: (dev,ino) -> 1. Populated by userspace at load time.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   struct fileid);
    __type(value, __u8);
} protected_files SEC(".maps");

// Evidence stream: one record per real -EPERM, plus debug records.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} denies SEC(".maps");

// Protected INODE NUMBERS (ino -> 1). Populated by userspace alongside
// protected_files. Used ONLY to emit the self-verifying (dev,ino) debug record
// for in-session opens of a protected inode -- so the kernel reports the dev it
// actually reads, independent of the full (dev,ino) match. Not a deny input.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u64);
    __type(value, __u8);
} debug_inos SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(leash_enforce_open, struct file *file, int ret)
{
    // Respect an earlier LSM module's verdict -- never turn a deny into an allow.
    if (ret != 0)
        return ret;

    // ---- SESSION GATE (Phase 2), runs BEFORE any deny logic ----
    // Out-of-session -> allow immediately. This single check delivers BOTH:
    //   * scoping   : a non-session process can never reach the deny below;
    //   * fail-open : clear the sessions map and nobody is in-session, so
    //                 nothing is ever denied.
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&sessions, &cgid))
        return 0;

    // ---- FILE IDENTITY ----
    struct fileid id = {};
    id.ino = BPF_CORE_READ(file, f_inode, i_ino);
    id.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

    // SELF-VERIFYING DEBUG (observability only -- NOT the deny decision).
    // If this inode number is one we protect, report the (dev,ino) the kernel
    // actually placed in i_sb->s_dev, so map-stored == kernel-read can be
    // confirmed on the running kernel rather than calculated on paper.
    if (bpf_map_lookup_elem(&debug_inos, &id.ino)) {
        struct deny_event *d = bpf_ringbuf_reserve(&denies, sizeof(*d), 0);
        if (d) {
            d->kind = KIND_DEBUG;
            d->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            d->uid = (__u32)bpf_get_current_uid_gid();
            d->dev = id.dev;
            d->ino = id.ino;
            bpf_get_current_comm(d->comm, sizeof(d->comm));
            bpf_ringbuf_submit(d, 0);
        }
    }

    // ---- DENY DECISION (unchanged) ----
    __u8 *protected = bpf_map_lookup_elem(&protected_files, &id);
    if (!protected)
        return 0;  // in-session, but not a protected file -> allow

    // ---- THE REFUSAL ----
    struct deny_event *e = bpf_ringbuf_reserve(&denies, sizeof(*e), 0);
    if (e) {
        e->kind = KIND_DENY;
        e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        e->uid = (__u32)bpf_get_current_uid_gid();
        e->dev = id.dev;
        e->ino = id.ino;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        // Path is NOT read in-kernel: the deny only fires on a known-protected
        // inode, so userspace resolves (dev,ino) -> path from what it loaded.
        // (Avoids bpf_d_path's LSM-hook allowlist risk; see docs/phase3.md.)
        bpf_ringbuf_submit(e, 0);
    }
    return -EPERM;  // a negative errno here fails the open() syscall
}
