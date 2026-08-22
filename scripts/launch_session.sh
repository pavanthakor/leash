#!/usr/bin/env bash
# Phase 2 launcher (NO sudo). Places the agent in a dedicated cgroup via the
# systemd user manager's delegated subtree, so the kernel can tell the agent's
# process tree apart from everything else. The attacker listener runs as a
# SEPARATE unit (its own cgroup) -- it is not part of the agent's session.
#
#   ./launch_session.sh          start the session, print the loader command
#   ./launch_session.sh --stop   tear everything down
set -euo pipefail

LEASH="$HOME/leash"
DEMO="$HOME/leash-demo"
VENV="$LEASH/.venv/bin"
AGENT_UNIT=leash-agent
LISTENER_UNIT=leash-listener
READY="$DEMO/session_ready"

stop_all() {
  systemctl --user stop   "$AGENT_UNIT" "$LISTENER_UNIT" 2>/dev/null || true
  systemctl --user reset-failed "$AGENT_UNIT" "$LISTENER_UNIT" 2>/dev/null || true
  rm -f "$READY"
  echo "[launch] stopped $AGENT_UNIT + $LISTENER_UNIT"
}

if [[ "${1:-}" == "--stop" ]]; then stop_all; exit 0; fi

[[ -f "$DEMO/secrets/api_key.txt" ]] || bash "$LEASH/scripts/setup_demo.sh" >/dev/null
[[ -f "$DEMO/docs/report_fork.txt" ]] || bash "$LEASH/scripts/setup_demo.sh" >/dev/null

# clean slate (also clears any stale readiness file -> enforces the hard gate)
stop_all >/dev/null 2>&1 || true
rm -f "$READY"

# attacker listener: its OWN unit => own cgroup => out of the agent's session
systemd-run --user --unit="$LISTENER_UNIT" --quiet \
  "$VENV/python" "$LEASH/agent/listener.py"

# the agent: dedicated cgroup, working dir under the repo (never home)
systemd-run --user --unit="$AGENT_UNIT" --quiet \
  -p WorkingDirectory="$LEASH/agent" \
  "$VENV/uvicorn" agent:app --host 127.0.0.1 --port 8000 --log-level warning

# wait for the agent to answer
for _ in $(seq 1 40); do
  curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1 && break || sleep 1
done

CG_REL="$(systemctl --user show -p ControlGroup --value "$AGENT_UNIT")"
CGROUP="/sys/fs/cgroup${CG_REL}"
AGENTPID="$(systemctl --user show -p MainPID --value "$AGENT_UNIT")"
CGID="$(stat -c %i "$CGROUP" 2>/dev/null || echo '?')"

echo "=================================================================="
echo " Phase 2 session is up (agent in a dedicated cgroup)."
echo "   AGENT unit    : $AGENT_UNIT   MainPID=$AGENTPID"
echo "   LISTENER unit : $LISTENER_UNIT (separate cgroup, out of session)"
echo "   CGROUP        : $CGROUP"
echo "   cgid (st_ino) : $CGID"
echo "------------------------------------------------------------------"
echo " OPERATOR (sudo) -- attach the kernel tree reconstructor:"
echo "   cd $LEASH/bpf && make leash_session"
echo "   sudo ./leash_session '$CGROUP' $AGENTPID"
echo "------------------------------------------------------------------"
echo " Then, in another shell (no sudo): $LEASH/scripts/run_attack_p2.sh"
echo " Tear down when done:              $LEASH/scripts/launch_session.sh --stop"
echo "=================================================================="
