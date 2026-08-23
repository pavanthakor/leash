#!/usr/bin/env bash
# scripts/uninstall.sh -- leave the machine as leash found it.
#
# leash installs nothing persistent: no boot units, no files outside the repo and
# ~/leash-demo, no BPF pins. "Uninstall" is therefore (1) down.sh's kernel-clean
# teardown -- the load-bearing guarantee that nothing stays attached -- plus
# (2) removing the artifacts leash GENERATED at runtime. Source is left intact;
# rebuildable binaries and captured evidence are yours to keep or purge.
#
#   uninstall.sh          teardown + remove generated runtime artifacts
#   uninstall.sh --purge  also remove built loaders + the demo secrets/docs tree
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/lib_leash.sh

say "leash uninstall"

# 1. the core guarantee: nothing left attached to the kernel
scripts/down.sh || { bad "teardown did not reach a clean kernel -- aborting uninstall."; exit 1; }

# 2. remove RUNTIME-GENERATED artifacts (never source)
say ""
say "removing generated runtime artifacts:"
rm -f  "$DEMO/leashd.events.jsonl" "$DEMO/leashd.stdout" "$DEMO/bridge.log" \
       "$DEMO/sink6.log" "$DEMO/sink6.stdout" "$DEMO/leash-sink.sock" \
       "$DEMO"/atk*.sh "$DEMO"/rbench.sh "$DEMO"/q2_alias.txt \
       "$DEMO"/isfile.csv "$DEMO"/isconn.csv 2>/dev/null || true
ok "event stream, logs, sink socket, stray helpers removed"

# built dashboard is a rebuildable artifact, not source
[[ -d dashboard/dist ]] && { rm -rf dashboard/dist; ok "dashboard/dist removed (npm run build to rebuild)"; }

if [[ "${1:-}" == "--purge" ]]; then
  say ""
  say "--purge: removing built loaders and the demo data tree:"
  (cd bpf && make clean >/dev/null 2>&1) || true
  rm -f bpf/leash_enforce bpf/leash_connect bpf/leash_session bench/microbench 2>/dev/null || true
  ok "built binaries removed (make to rebuild)"
  warn "leaving $DEMO/secrets and $DEMO/docs in place (decoys only, no real creds) -- 'rm -rf $DEMO' to remove."
fi

# 3. final proof
say ""
if kernel_clean && [[ -z "$(leashd_pids)$(loader_pids)" ]]; then
  ok "UNINSTALL COMPLETE -- kernel clean, nothing attached, generated artifacts removed."
  say "    source is intact; scripts/up.sh brings it all back."
  exit 0
else
  bad "residual leash state remains:"; kernel_leash_progs | sed 's/^/      /'; exit 1
fi
