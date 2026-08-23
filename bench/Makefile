# Phase 8 microbench. Plain C, no BPF, no privilege. -O2 so the measured cost is
# the syscall+hook, not un-optimised loop overhead.
CFLAGS ?= -O2 -Wall -Wextra
microbench: microbench.c
	$(CC) $(CFLAGS) microbench.c -o microbench
clean:
	rm -f microbench
.PHONY: clean
