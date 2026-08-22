CLANG ?= clang
ARCH  := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

all: leash leash_session

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

leash.bpf.o: leash.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@

leash.skel.h: leash.bpf.o
	bpftool gen skeleton $< > $@

leash: loader.c leash.skel.h
	$(CLANG) -g -O2 -I. loader.c -lbpf -lelf -lz -o $@

leash_session.bpf.o: leash_session.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@

leash_session.skel.h: leash_session.bpf.o
	bpftool gen skeleton $< > $@

leash_session: leash_session.c leash_session.skel.h
	$(CLANG) -g -O2 -I. leash_session.c -lbpf -lelf -lz -o $@

clean:
	rm -f leash leash.bpf.o leash.skel.h leash_session leash_session.bpf.o leash_session.skel.h

.PHONY: all clean
