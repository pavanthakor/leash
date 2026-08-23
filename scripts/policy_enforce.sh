#!/usr/bin/env bash
# Phase 5 wrapper: validate the WHOLE policy, then attach the UNCHANGED Phase 3/4
# enforcer with the compiled args. If validation fails, NOTHING is attached --
# validation-before-load is structural (an invalid policy never reaches a map).
#
#   policy_enforce.sh file            attach leash_enforce  from policy (sudo)
#   policy_enforce.sh egress          attach leash_connect  from policy (sudo)
#   add --print to only show the compiled command (no sudo, no attach)
#   POLICY=/path/to/other.yaml policy_enforce.sh ...   override the policy file
set -euo pipefail
LEASH="$HOME/leash"; BPF="$LEASH/bpf"
PY="$LEASH/.venv/bin/python"; POLICC="$LEASH/daemon/policc.py"
POLICY="${POLICY:-$LEASH/policy/policy.yaml}"
LAYER="${1:-}"; MODE="${2:-}"
[[ "$LAYER" == file || "$LAYER" == egress ]] || { echo "usage: policy_enforce.sh <file|egress> [--print]"; exit 2; }

echo "[policy] validating $POLICY ..."
if ! "$PY" "$POLICC" validate "$POLICY"; then
  echo "[policy] REFUSING to attach any enforcer -- policy invalid (nothing reached a map)."
  exit 2
fi

CG="/sys/fs/cgroup$(systemctl --user show -p ControlGroup --value leash-agent)"
if [[ "$LAYER" == file ]]; then
  mapfile -t ARGS < <("$PY" "$POLICC" files "$POLICY")
  CMD=(sudo "$BPF/leash_enforce" "$CG" "${ARGS[@]}")
else
  mapfile -t ARGS < <("$PY" "$POLICC" egress "$POLICY")
  CMD=(sudo "$BPF/leash_connect" "$CG" "${ARGS[@]}")
fi
echo "[policy] compiled from policy -> ${CMD[*]}"
[[ "$MODE" == "--print" ]] && exit 0
exec "${CMD[@]}"
