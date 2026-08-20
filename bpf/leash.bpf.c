// The kernel half. Runs inside the kernel at the file_open LSM hook.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// A counter, so we have evidence independent of printk.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} opens SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(leash_file_open, struct file *file, int ret)
{
    __u32 key = 0;
    __u64 *count;

    // An earlier LSM in the chain already denied this. Respect that verdict
    // and get out of the way -- never turn another module's deny into an allow.
    if (ret != 0)
        return ret;

    count = bpf_map_lookup_elem(&opens, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    // 0 = allow. This return value is the whole enforcement mechanism:
    // a negative errno here (e.g. -EPERM) makes the syscall fail.
    return 0;
}
