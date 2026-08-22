// Phase 2 kernel half: session attribution via cgroup.
//
// Two tracepoints watch every process spawn on the box. Each reads
// bpf_get_current_cgroup_id() and checks it against the `sessions` map that
// userspace populated with the agent's dedicated cgroup id. A process NOT in a
// session cgroup makes the program `return 0` immediately -- that early exit is
// both the performance guarantee (we don't inspect the whole system) and the
// blast-radius guarantee (Leash can only ever see the agent's own tree).
//
// Children inherit the cgroup by kernel guarantee, so a forked sh/curl is
// attributed automatically -- no cooperation from the agent required.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EV_FORK 1
#define EV_EXEC 2

struct event {
    __u8  kind;          // EV_FORK | EV_EXEC
    __u32 pid;           // the new/exec'd process (tgid)
    __u32 ppid;          // its parent (tgid)
    __u64 cgid;          // session cgroup id it was attributed to
    char  comm[16];      // the process's own comm
    char  pcomm[16];     // its parent's comm (labels the tree root)
};

// Populated by userspace: key = agent's dedicated cgroup id, value = root pid.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key,   __u64);
    __type(value, __u64);
} sessions SEC(".maps");

// Stream of attributed spawn events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// fork: current == the parent doing the fork; its cgroup is the session cgroup,
// and the child inherits it. The tracepoint hands us both pids and both comms.
SEC("tp/sched/sched_process_fork")
int on_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&sessions, &cgid))
        return 0;  // out-of-session: leave immediately

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->kind = EV_FORK;
    e->cgid = cgid;
    e->pid  = (__u32)ctx->child_pid;
    e->ppid = (__u32)ctx->parent_pid;
    // The tracepoint's comms are __data_loc dynamic strings; we don't decode
    // them -- EXEC events carry the authoritative post-exec names. Leave empty.
    e->comm[0]  = 0;
    e->pcomm[0] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// exec: current == the process that just called execve. Its comm is now the
// real binary (sh, curl). real_parent gives the true parent for the tree edge.
SEC("tp/sched/sched_process_exec")
int on_exec(void *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&sessions, &cgid))
        return 0;  // out-of-session: leave immediately

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *p = BPF_CORE_READ(t, real_parent);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->kind = EV_EXEC;
    e->cgid = cgid;
    e->pid  = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->ppid = (__u32)BPF_CORE_READ(p, tgid);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    BPF_CORE_READ_STR_INTO(&e->pcomm, p, comm);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
