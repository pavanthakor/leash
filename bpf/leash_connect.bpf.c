// Phase 4 kernel half: egress enforcement (the second layer).
//
// An LSM socket_connect program that returns -EPERM when an IN-SESSION process
// connects to a destination NOT on the allowlist (default-deny). Same shape as
// Phase 3: the Phase 2 session gate runs FIRST, so a process outside the agent's
// cgroup can never be denied -- scoping and fail-open are consequences of that
// ordering, not separate logic.
//
// Byte order: sin_addr.s_addr and sin_port are NETWORK order. We keep the IP raw
// (inet_pton in userspace yields the identical __be32 -- nothing to convert, so
// nothing to get wrong) and normalise the port to HOST order on both sides.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2
#define KIND_DENY  0
#define KIND_ALLOW 1   // self-verifying debug: an in-session connect we permitted

struct dest { __be32 ip; __u16 port; __u16 _pad; };  // ip network-order, port host-order

struct conn_event {
    __u8  kind;          // KIND_DENY | KIND_ALLOW
    __u32 pid;
    __u32 uid;
    __be32 ip;           // network order, as read from the sockaddr
    __u16 port;          // host order
    char  comm[16];
};

// Reused verbatim from Phase 2/3: agent's dedicated cgroup id -> root pid.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key,   __u64);
    __type(value, __u64);
} sessions SEC(".maps");

// The allowlist: (ip,port) -> 1. Populated by userspace. Default-deny: anything
// not here is refused for in-session processes.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   struct dest);
    __type(value, __u8);
} allowed_dests SEC(".maps");

// Evidence stream: one record per in-session AF_INET connect (allow or deny).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} denies SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(leash_connect, struct socket *sock, struct sockaddr *address,
             int addrlen, int ret)
{
    // Respect an earlier LSM module's verdict -- never turn a deny into an allow.
    if (ret != 0)
        return ret;

    // ---- SESSION GATE (Phase 2, verbatim), BEFORE any decision ----
    // Out-of-session -> allow. Delivers scoping (a non-session connect never
    // reaches the decision) and fail-open (empty sessions -> nothing denied).
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&sessions, &cgid))
        return 0;

    // Only IPv4 is enforced. AF_INET6 / AF_UNIX pass (documented known gap).
    if (BPF_CORE_READ(address, sa_family) != AF_INET)
        return 0;

    struct sockaddr_in *sin = (struct sockaddr_in *)address;
    struct dest d = {};
    d.ip   = BPF_CORE_READ(sin, sin_addr.s_addr);        // network order, raw
    d.port = bpf_ntohs(BPF_CORE_READ(sin, sin_port));    // -> host order

    __u8 *allowed = bpf_map_lookup_elem(&allowed_dests, &d);

    // One event per in-session connect: the kernel reports the (ip,port) it read
    // AND the verdict, so map-stored == kernel-read is confirmed on the kernel.
    struct conn_event *e = bpf_ringbuf_reserve(&denies, sizeof(*e), 0);
    if (e) {
        e->kind = allowed ? KIND_ALLOW : KIND_DENY;
        e->pid  = (__u32)(bpf_get_current_pid_tgid() >> 32);
        e->uid  = (__u32)bpf_get_current_uid_gid();
        e->ip   = d.ip;
        e->port = d.port;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    if (allowed)
        return 0;          // ALLOW a listed destination
    return -EPERM;         // DEFAULT-DENY everything else
}
