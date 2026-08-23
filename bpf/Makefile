CLANG ?= clang
ARCH  := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

all: leash leash_session leash_enforce leash_connect

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

leash_enforce.bpf.o: leash_enforce.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@

leash_enforce.skel.h: leash_enforce.bpf.o
	bpftool gen skeleton $< > $@

leash_enforce: leash_enforce.c leash_enforce.skel.h
	$(CLANG) -g -O2 -I. leash_enforce.c -lbpf -lelf -lz -o $@

leash_connect.bpf.o: leash_connect.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@

leash_connect.skel.h: leash_connect.bpf.o
	bpftool gen skeleton $< > $@

leash_connect: leash_connect.c leash_connect.skel.h
	$(CLANG) -g -O2 -I. leash_connect.c -lbpf -lelf -lz -o $@

clean:
	rm -f leash leash.bpf.o leash.skel.h leash_session leash_session.bpf.o leash_session.skel.h leash_enforce leash_enforce.bpf.o leash_enforce.skel.h leash_connect leash_connect.bpf.o leash_connect.skel.h

.PHONY: all clean
