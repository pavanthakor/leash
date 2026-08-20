// The userspace half. Loads, attaches, and reads the counter.
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "leash.skel.h"

static volatile sig_atomic_t stop;
static void on_sigint(int sig) { (void)sig; stop = 1; }

int main(void)
{
    struct leash_bpf *skel;
    int err = 0;
    __u32 key = 0;
    __u64 count = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = leash_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "open/load failed -- run with sudo?\n");
        return 1;
    }

    err = leash_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "attach failed: %d\n", err);
        fprintf(stderr, "is 'bpf' in /sys/kernel/security/lsm ?\n");
        goto cleanup;
    }

    printf("ATTACHED to lsm/file_open. Ctrl-C to detach.\n");
    printf("In another shell:  sudo bpftool prog list | grep -B2 -A4 lsm\n\n");

    signal(SIGINT, on_sigint);
    while (!stop) {
        sleep(1);
        if (bpf_map__lookup_elem(skel->maps.opens,
                                 &key,   sizeof(key),
                                 &count, sizeof(count), 0) == 0)
            printf("\ropens seen: %llu   ", (unsigned long long)count);
        fflush(stdout);
    }
    printf("\ndetaching.\n");

cleanup:
    leash_bpf__destroy(skel);
    return err != 0;
}
