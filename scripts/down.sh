#!/usr/bin/env bash
# scripts/down.sh -- tear everything down and PROVE the kernel is clean.
#
# Today's teardown pain is this script's spec: three times a Ctrl-C did not
# actually kill leashd, once there were two instances, and only bpftool caught
# it. So the signal escalation is gated by the KERNEL, not by the process table:
# after each signal we ask bpftool whether the leash programs are still attached,
# and escalate SIGINT -> SIGTERM -> SIGKILL while they are. "Clean" is reported
# only when bpftool shows zero leash programs AND pgrep is empty.
#
# Processes are rediscovered by pgrep every pass -- never a remembered pid or a
# foreground terminal that may have been lost. leashd is root-owned, so this
# reuses the sudo credential up.sh already cached (re-prompts only if expired).
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/lib_leash.sh

say "leash down"

# ensure a usable sudo credential (reuses up.sh's grant; prompts only if expired)
if procs_present || ! sudo -n true 2>/dev/null; then
  sudo -v || { bad "sudo required to signal the root enforcer and verify the kernel."; exit 1; }
fi

# ---- kill leashd + loaders, escalation GATED ON THE KERNEL CHECK ------------
signals=(INT TERM KILL)
si=0
while true; do
  progs="$(kernel_leash_progs)"
  pl="$(leashd_pids)"; ld="$(loader_pids)"
  if [[ -z "${progs// }" && -z "${pl// }" && -z "${ld// }" ]]; then
    ok "kernel clean: no leash programs attached, no leash processes"
    break
  fi

  sig="${signals[$si]}"
  targets="$pl $ld"
  if [[ -n "${targets// }" ]]; then
    say "  SIG$sig -> leashd[$pl] loaders[$ld]"
    sudo kill -"$sig" $targets 2>/dev/null || true
  else
    # no processes but kernel still shows a program (orphaned link): nothing to
    # signal -- wait a moment for the link refcount to drop, then re-check
    warn "no processes but kernel still shows: $(echo "$progs" | awk '{print $1,$2,$3,$4}' | tr '\n' ';')"
  fi

  # bounded wait, re-polling the KERNEL (not just the process table)
  cleared=0
  for _ in $(seq 1 10); do
    sleep 0.5
    progs="$(kernel_leash_progs)"; pl="$(leashd_pids)"; ld="$(loader_pids)"
    if [[ -z "${progs// }" && -z "${pl// }" && -z "${ld// }" ]]; then cleared=1; break; fi
  done
  [[ "$cleared" -eq 1 ]] && continue   # loop re-checks and prints CLEAN

  # still attached after the wait -> escalate
  si=$((si + 1))
  if [[ "$si" -ge "${#signals[@]}" ]]; then
    bad "leash STILL on the kernel after SIGKILL:"
    kernel_leash_progs | sed 's/^/      /'
    say "      leashd[$(leashd_pids)] loaders[$(loader_pids)] -- manual bpftool inspection needed."
    exit 1
  fi
  warn "still attached -- escalating to SIG${signals[$si]}"
done

# ---- agent + bridge + gap sink (all unprivileged) --------------------------
scripts/launch_session.sh --stop >/dev/null 2>&1 || true
[[ "$(systemctl --user is-active leash-agent 2>/dev/null)" != active ]] && ok "agent session stopped" || warn "agent unit still active"

for p in $(bridge_pids); do kill "$p" 2>/dev/null || true; done
[[ -z "$(bridge_pids)" ]] && ok "dashboard bridge stopped" || warn "bridge still running: $(bridge_pids)"

for p in $(pgrep -f 'sink6\.py' 2>/dev/null); do kill "$p" 2>/dev/null || true; done

# ---- final independent verdict ---------------------------------------------
say ""
if kernel_clean && [[ -z "$(leashd_pids)$(loader_pids)" ]]; then
  ok "VERIFIED CLEAN -- bpftool shows no leash programs on the kernel; nothing attached."
  exit 0
else
  bad "NOT CLEAN:"; kernel_leash_progs | sed 's/^/      /'; exit 1
fi
