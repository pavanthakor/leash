# Phase 5 — Policy layer (pure userspace)

**Exit criterion:** a declarative `policy.yaml` is validated and compiled into
exactly the inputs the proven Phase 3/4 enforcers consume — without changing the
BPF programs or the enforcement logic. Positive: enforcers run FROM the compiled
policy and stop the real attack. Negative (the teeth): a battery of malformed
policies is each rejected loudly, all-or-nothing. Idempotent across runs.

## Design decisions (operator-approved)
- **Unified `policy.yaml`** (one file, `files:` + `egress:`): single source of the
  whole posture; eliminates the two-files-drift failure mode; validates atomically.
- **Refuse-to-load / all-or-nothing** on ANY invalid rule (nonzero exit, nothing
  enforced). Load-valid/warn-on-bad would let a typo silently drop a protection
  while the operator sees a running enforcer — the worst false confidence a
  security tool can create. A policy fully validates or nothing loads.

## Compiler front-end, loaders UNCHANGED
The proven Phase 3/4 loaders are already input-driven: `leash_enforce` takes file
PATHS (it stats them into `(dev,ino)`); `leash_connect` takes `ip:port` (it
`inet_pton`s them into `(ip_be,port)`). So Phase 5 adds a **compiler front-end**,
not a loader rewrite: `daemon/policc.py` validates `policy.yaml` and emits those
exact args; `scripts/policy_enforce.sh` validates then attaches the UNCHANGED
loader. Map contents are identical by construction — this phase inherits the
Phase 3/4 kernel proofs instead of re-opening them.

## Schema
```yaml
version: 1                       # must == 1
files:
  protect: [ <absolute existing path>, ... ]      # non-empty list
egress:
  default: deny                  # default-deny only
  allow: [ { ip: <ipv4>, port: <1-65535> }, ... ]
```

## Validation (four layers, collect ALL errors, then refuse if any)
1. **Strict parse** — a `SafeLoader` subclass that **raises on duplicate keys**
   (PyYAML otherwise silently keeps the last — a footgun that drops a rule).
2. **Structural** — top-level keys exactly `{version,files,egress}`; required
   sections/fields present; correct container types.
3. **Semantic** — `version==1`; each path absolute + exists + regular file; each
   `ip` valid IPv4; each `port` int in `[1,65535]`; `egress.default=="deny"`.
4. **All-or-nothing** — every subcommand validates the WHOLE file first; on any
   error it prints every path-qualified error to stderr, exits 2, emits NOTHING
   to stdout. You can never extract the valid subset of a broken policy.

## Subcommands (`daemon/policc.py <cmd> policy.yaml`)
- `validate` — OK / errors.  `files` / `egress` — the loader args (sorted).
- `resolve` — resolved `(dev,ino)`/`(ip_be,port)` view. **Fast userspace PRE-check
  only** — see equivalence note below.
- `explain` — plain-language: what is protected, what egress is allowed, that
  everything else is denied, and that scope is the agent's session only. This is
  the auditability answer: a valid policy can still be not-what-you-meant, which
  no validator catches — a human runs `explain` and reads it.

## Equivalence = the KERNEL confirms it, not policc's arithmetic
`policc resolve` printing `dev=264241152 ino=920726` / `ip_be=0x0100007f` is only
a fast PRE-check — that is the paper-arithmetic trap Phase 3 taught us. The REAL
equivalence proof is the operator running the enforcer FROM the compiled policy
and seeing the kernel's own self-verifying debug (`DEBUG ... kernel-read dev=...
== map-stored dev=... MATCH`, `ALLOW ... 11434 MATCH`) and then denying the real
exfil. Equivalence = "policy-loaded enforcer denies the real attack with the
kernel confirming the same dev/ino", not "my formula produced the right integer."

## How the operator runs the end-to-end (enforcers FROM compiled policy)
```
# Terminal A: session up
scripts/launch_session.sh
# Terminal B (SUDO): FILE enforcement from policy
scripts/policy_enforce.sh file
   # validates policy.yaml, then: sudo leash_enforce <cgroup> <compiled path>
   # window shows: protected: .../api_key.txt (dev=264241152 ino=920726); loader pid=...
# Terminal B2 (SUDO): EGRESS enforcement from policy
scripts/policy_enforce.sh egress
   # validates, then: sudo leash_connect <cgroup> 127.0.0.1:11434
# Terminal C: the SAME Phase 3/4 probes -- now enforced from policy
scripts/enforce_probe.sh         # P3: in-session read of key -> -EPERM, key absent
scripts/egress_probe.sh          # P4: connect to :9000 -> -EPERM (both shapes); :11434 allowed
```
An invalid policy makes `policy_enforce.sh` refuse and attach nothing (exit 2) —
validation-before-load is structural.

## Files
- `policy/policy.yaml` — the unified policy.
- `daemon/policc.py` — validator/compiler.  `daemon/test_policc.py` — unit tests.
- `scripts/policy_enforce.sh` — validate-then-attach wrapper (loaders unchanged).
- `scripts/policy_battery.sh` -> `~/leash-demo/policy_battery.log` — the rejection battery.

## Proven without sudo
- `policy_battery.sh`: 15/15 — every malformed case rejected with a specific
  message + exit 2; the 90%-valid policy rejected AND compile emits nothing
  (no partial load); the valid policy accepted.
- `test_policc.py`: 14/14 unit tests, incl. `resolve == P3/P4 numbers`.
- Idempotence: `files`/`egress`/`resolve` byte-identical across 5 runs.
- Compiled args == the P3/P4 proven args (`.../api_key.txt`, `127.0.0.1:11434`).
- New dep pinned: `pyyaml==6.0.2`.
