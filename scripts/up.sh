#!/usr/bin/env bash
# scripts/up.sh -- bring the whole demo up with ONE conscious privileged grant,
# and never declare "up" unless it verifiably is.
#
# leash needs root ONCE per session, granted here at startup (a deliberate act --
# no auto-attach on boot); teardown reuses the cached credential. Every gate is
# checked EXPLICITLY and fails loud with a reason -- correctness never rides on
# `set -e` (a pgrep no-match under -e once made this script die silently after
# printing one line). We wait for the enforcers to ACTUALLY attach in a stream
# THIS run truncated -- a stale events file must never false-pass.
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/lib_leash.sh

die() { bad "$*"; exit 1; }

say "leash up"

# ---- GATE 1: refuse to double-attach ---------------------------------------
nlp="$(leashd_pids)"; nc=$(printf '%s' "$nlp" | wc -w)
if [[ "$nc" -gt 0 ]]; then
  [[ "$nc" -gt 1 ]] && bad "$nc leashd instances already running (stray): $nlp" \
                    || bad "leashd already running (pid$nlp)"
  die "run scripts/down.sh first."
fi
[[ -z "$(loader_pids)" ]] || die "loaders attached without leashd (stray): $(loader_pids) -- run scripts/down.sh first."
ok "no existing leash session"

# ---- GATE 2: agent session (unprivileged, fresh cgid), VERIFIED -------------
if ! scripts/launch_session.sh >/tmp/leash_up_agent.$$ 2>&1; then
  cat /tmp/leash_up_agent.$$; rm -f /tmp/leash_up_agent.$$; die "agent session failed to launch."
fi
rm -f /tmp/leash_up_agent.$$
[[ "$(systemctl --user is-active leash-agent 2>/dev/null)" == active ]] || die "agent unit is not active."
curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1 || die "agent /health not answering on :8000."
cgid="$(agent_cgid)"
ok "agent session up and healthy (cgid $cgid)"

# ---- GATE 3: dashboard bridge, VERIFIED serving ----------------------------
if [[ -z "$(bridge_pids)" ]]; then
  if [[ ! -f dashboard/dist/index.html && -s "$HOME/.nvm/nvm.sh" ]]; then
    warn "building dashboard (first run)..."
    ( export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh" >/dev/null; nvm use --lts >/dev/null 2>&1
      cd dashboard && { [[ -d node_modules ]] || npm install >/dev/null 2>&1; } && npm run build >/dev/null 2>&1 ) \
      || warn "dashboard build failed -- bridge will still serve the event API"
  fi
  nohup python3 dashboard/bridge/leash_bridge.py >"$DEMO/bridge.log" 2>&1 &
fi
code=""
for _ in $(seq 1 20); do
  code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/api/health 2>/dev/null || true)"
  [[ "$code" == 200 ]] && break; sleep 0.25
done
[[ "$code" == 200 ]] || die "dashboard bridge not serving on :8765 (got '$code'; see $DEMO/bridge.log)."
ok "dashboard bridge serving -> http://127.0.0.1:8765"

# ---- GATE 4: the one deliberate sudo, UP FRONT -----------------------------
say ""
say ">>> leash needs root ONCE now (teardown reuses this grant)."
sudo -v || die "sudo grant declined -- not attaching."

# ---- GATE 5: attach leashd, then verify a LIVE process + a FRESH stream -----
old_pid="$(head -1 "$EV" 2>/dev/null | grep -o '"pid": [0-9]*' | head -1 || true)"
nohup sudo -n .venv/bin/python daemon/leashd.py </dev/null >"$DEMO/leashd.stdout" 2>&1 &
say "    leashd starting; waiting for a live daemon + both enforcers (fresh stream)..."

attached=0
for _ in $(seq 1 60); do
  # (a) leashd must be a LIVE process -- if it died, say why and stop
  if [[ -z "$(leashd_pids)" ]]; then
    sleep 0.3
    if [[ -z "$(leashd_pids)" ]]; then
      bad "leashd is not running (it exited during startup):"
      tail -n 8 "$DEMO/leashd.stdout" 2>/dev/null | sed 's/^/      /'
      die "attach aborted."
    fi
  fi
  # (b) stream truncated THIS run: line-1 session_start pid changed
  new_pid="$(head -1 "$EV" 2>/dev/null | grep -o '"pid": [0-9]*' | head -1 || true)"
  first_type="$(head -1 "$EV" 2>/dev/null | grep -o '"type": "[a-z_]*"' | head -1 || true)"
  # (c) two attaches in that fresh stream
  if [[ "$first_type" == '"type": "session_start"' && "$new_pid" != "$old_pid" && "$(attach_count)" -ge 2 ]]; then
    attached=1; break
  fi
  sleep 0.5
done
[[ "$attached" -eq 1 ]] || { bad "enforcers did not attach in a fresh stream within 30s:"; tail -n 8 "$DEMO/leashd.stdout" 2>/dev/null | sed 's/^/      /'; die "not up."; }

# ---- GATE 6: final re-verification before declaring UP ----------------------
lp="$(leashd_pids)"
[[ -n "$lp" ]]                        || die "leashd vanished after attach."
pgrep -x leash_enforce >/dev/null     || die "file enforcer not running after attach."
pgrep -x leash_connect >/dev/null     || die "egress enforcer not running after attach."
[[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/api/health 2>/dev/null)" == 200 ]] \
                                      || die "bridge stopped serving."
ok "leashd live (pid$lp), both enforcers attached on cgid $cgid, fresh stream"

# ---- status ----------------------------------------------------------------
say ""
say "leash is UP:"
say "    leashd pid     :$lp"
say "    agent cgid     : $cgid"
say "    file enforcer  : attached (pid $(pgrep -x leash_enforce | tr '\n' ' '))"
say "    egress enforcer: attached (pid $(pgrep -x leash_connect | tr '\n' ' '))"
say "    dashboard      : http://127.0.0.1:8765   (open it, then run scripts/demo.sh)"
say "    teardown       : scripts/down.sh"
