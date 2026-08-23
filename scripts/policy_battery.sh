#!/usr/bin/env bash
# Phase 5 negative battery (pure userspace, NO sudo). Feeds a series of MALFORMED
# policies to the compiler; each MUST be rejected loudly (specific message) with a
# NON-ZERO exit and produce NO compiled output. Saved to ~/leash-demo/policy_battery.log.
set -uo pipefail
LEASH="$HOME/leash"; DEMO="$HOME/leash-demo"
PY="$LEASH/.venv/bin/python"; POLICC="$LEASH/daemon/policc.py"
KEY="$DEMO/secrets/api_key.txt"
TMP="$(mktemp -d)"; LOG="$DEMO/policy_battery.log"
PASS=0; FAIL=0

exec > >(tee "$LOG") 2>&1
echo "================ Phase 5 malformed-policy battery ================"
echo "date (host): $(date -Is)"
echo "each case MUST be rejected (non-zero exit) with a specific message."
echo

# expect_reject <name> <policyfile>  -- passes if validate exits non-zero
expect_reject() {
  local name="$1" file="$2"
  echo "---- CASE: $name ----"
  "$PY" "$POLICC" validate "$file" >/tmp/pb.out 2>/tmp/pb.err
  local rc=$?
  sed 's/^/    /' /tmp/pb.err
  if [[ $rc -ne 0 ]]; then echo "    => REJECTED (exit $rc)  [PASS]"; PASS=$((PASS+1))
  else echo "    => ACCEPTED (exit 0)  [FAIL -- should have been rejected]"; cat /tmp/pb.out | sed 's/^/    /'; FAIL=$((FAIL+1)); fi
  echo
}

w(){ cat > "$TMP/$1"; }   # write a policy file

w unknown_top.yaml <<Y
version: 1
network: { foo: bar }
files: { protect: [ $KEY ] }
egress: { default: deny, allow: [ { ip: 127.0.0.1, port: 11434 } ] }
Y
expect_reject "unknown top-level key (network:)" "$TMP/unknown_top.yaml"

w nonexistent_path.yaml <<Y
version: 1
files: { protect: [ $DEMO/secrets/DOES-NOT-EXIST.txt ] }
egress: { default: deny, allow: [ { ip: 127.0.0.1, port: 11434 } ] }
Y
expect_reject "file rule points at nonexistent path" "$TMP/nonexistent_path.yaml"

w bad_ip.yaml <<Y
version: 1
files: { protect: [ $KEY ] }
egress: { default: deny, allow: [ { ip: 999.1.2.3, port: 11434 } ] }
Y
expect_reject "malformed IP (999.1.2.3)" "$TMP/bad_ip.yaml"

w port_range.yaml <<Y
version: 1
files: { protect: [ $KEY ] }
egress: { default: deny, allow: [ { ip: 127.0.0.1, port: 70000 } ] }
Y
expect_reject "port out of range (70000)" "$TMP/port_range.yaml"

w port_nonnum.yaml <<Y
version: 1
files: { protect: [ $KEY ] }
egress: { default: deny, allow: [ { ip: 127.0.0.1, port: "abc" } ] }
Y
expect_reject "non-numeric port (\"abc\")" "$TMP/port_nonnum.yaml"

w wrong_type.yaml <<Y
version: 1
files: { protect: "$KEY" }
egress: { default: deny, allow: [ { ip: 127.0.0.1, port: 11434 } ] }
Y
expect_reject "wrong type: protect is a string, not a list" "$TMP/wrong_type.yaml"

w missing_section.yaml <<Y
version: 1
files: { protect: [ $KEY ] }
Y
expect_reject "missing required section (egress:)" "$TMP/missing_section.yaml"

w empty_list.yaml <<Y
version: 1
files: { protect: [] }
egress: { default: deny, allow: [ { ip: 127.0.0.1, port: 11434 } ] }
Y
expect_reject "empty required list (files.protect: [])" "$TMP/empty_list.yaml"

# duplicate key -- strict loader must reject (PyYAML would silently keep the last)
cat > "$TMP/dup_key.yaml" <<Y
version: 1
version: 1
files: { protect: [ $KEY ] }
egress: { default: deny, allow: [ { ip: 127.0.0.1, port: 11434 } ] }
Y
expect_reject "duplicate top-level key (version:)" "$TMP/dup_key.yaml"

cat > "$TMP/dup_dest.yaml" <<Y
version: 1
files: { protect: [ $KEY ] }
egress:
  default: deny
  allow:
    - ip: 127.0.0.1
      port: 11434
      port: 22
Y
expect_reject "duplicate key inside a dest (port:)" "$TMP/dup_dest.yaml"

w default_allow.yaml <<Y
version: 1
files: { protect: [ $KEY ] }
egress: { default: allow, allow: [ { ip: 127.0.0.1, port: 11434 } ] }
Y
expect_reject "unsupported posture (egress.default: allow)" "$TMP/default_allow.yaml"

w bad_version.yaml <<Y
version: 2
files: { protect: [ $KEY ] }
egress: { default: deny, allow: [ { ip: 127.0.0.1, port: 11434 } ] }
Y
expect_reject "unknown schema version (2)" "$TMP/bad_version.yaml"

# 90%-VALID: 1 good file + 1 good dest + 1 BAD dest -> whole thing rejected,
# and NO partial output from the compile subcommands.
cat > "$TMP/ninety.yaml" <<Y
version: 1
files: { protect: [ $KEY ] }
egress:
  default: deny
  allow:
    - { ip: 127.0.0.1, port: 11434 }
    - { ip: 127.0.0.1, port: 70000 }
Y
expect_reject "90%-valid (one bad port among good rules)" "$TMP/ninety.yaml"
echo "---- CASE: 90%-valid must NOT load its valid 90% (compile emits nothing) ----"
OUT="$("$PY" "$POLICC" files "$TMP/ninety.yaml" 2>/dev/null)"; rc=$?
if [[ $rc -ne 0 && -z "$OUT" ]]; then echo "    => 'policc files' exit=$rc, stdout empty  [PASS: no partial load]"; PASS=$((PASS+1))
else echo "    => LEAKED partial output: '$OUT' (exit $rc)  [FAIL]"; FAIL=$((FAIL+1)); fi
echo

# sanity: the KNOWN-GOOD policy must still be ACCEPTED
echo "---- CONTROL: the valid policy.yaml must be ACCEPTED ----"
"$PY" "$POLICC" validate "$LEASH/policy/policy.yaml" >/tmp/pb.out 2>&1; rc=$?
sed 's/^/    /' /tmp/pb.out
if [[ $rc -eq 0 ]]; then echo "    => ACCEPTED (exit 0)  [PASS]"; PASS=$((PASS+1)); else echo "    => REJECTED  [FAIL -- valid policy must pass]"; FAIL=$((FAIL+1)); fi
echo

rm -rf "$TMP"
echo "=================================================================="
echo "RESULT: $PASS passed, $FAIL failed"
echo "=================================================================="
[[ $FAIL -eq 0 ]]
