#!/usr/bin/env bash
# Shared helpers for the Phase 9 lifecycle scripts. The kernel-clean check is the
# heart of it: today's teardown pain was "signal sent, program STILL attached",
# caught only by asking the kernel directly. So down/uninstall gate on bpftool,
# not on whether a process happens to be gone.
LEASH_ROOT="${LEASH_ROOT:-$HOME/leash}"
DEMO="${DEMO:-$HOME/leash-demo}"
EV="${LEASH_EVENTS:-$DEMO/leashd.events.jsonl}"
SCRIPTS="$LEASH_ROOT/scripts"

# The two leash LSM programs, by their in-kernel names (bpftool truncates to 15
# chars: leash_enforce_open -> leash_enforce_o; leash_connect fits). Matching
# these -- never a generic 'lsm' -- is what keeps Ubuntu's resident
# restrict_filesystems LSM program from false-positiving the clean check.
LEASH_PROG_RE='leash_enforce|leash_connect'

leashd_pids() { { pgrep -f 'daemon/leashd\.py' 2>/dev/null | tr '\n' ' '; } || true; }
loader_pids() { { { pgrep -x leash_enforce; pgrep -x leash_connect; } 2>/dev/null | tr '\n' ' '; } || true; }
bridge_pids() { { pgrep -f 'leash_bridge\.py' 2>/dev/null | tr '\n' ' '; } || true; }

# Programs leash currently has ON THE KERNEL. Needs root (bpftool is root-only
# here); callers ensure a cached sudo credential first. Empty output = none.
kernel_leash_progs() { sudo -n bpftool prog show 2>/dev/null | grep -iE "$LEASH_PROG_RE" || true; }
# Can we even query the kernel? A FAILED bpftool call must never read as "clean"
# -- that false clean is the exact failure this whole script guards against.
kernel_queryable()   { sudo -n bpftool prog show >/dev/null 2>&1; }
kernel_clean()       { kernel_queryable && [[ -z "$(kernel_leash_progs)" ]]; }

procs_present() { local p; p="$(leashd_pids)$(loader_pids)"; [[ -n "${p// }" ]]; }

attach_count() {  # how many "type":"attached" are in the stream right now
  grep -c '"type": "attached"' "$EV" 2>/dev/null || echo 0
}

agent_cgid() {
  local cg="/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/leash-agent.service"
  stat -c %i "$cg" 2>/dev/null || echo '?'
}

say()  { printf '%s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
