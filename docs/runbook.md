# Demo runbook

The whole flow is three commands. leash needs root **once per session**, granted
at `up.sh`; teardown reuses that grant (re-prompts only if the ~15-min sudo
timestamp expired). The only thing you type by hand is that one password.

## Prerequisites (once)

- Kernel with BPF LSM enabled (this build: 7.0.0-30-generic).
- Python venv at `~/leash/.venv` (agent + leashd).
- Ollama running locally with `llama3.2:3b` on `127.0.0.1:11434`.
- Node LTS via nvm (for the dashboard). `up.sh` builds `dashboard/dist` on first
  run if it is missing and node is available.
- Loaders built: `cd bpf && make` (leaves `leash_enforce`, `leash_connect`).

## Run it

```bash
cd ~/leash

# 1. bring it up  (enter your password once when prompted)
scripts/up.sh
#    -> waits for BOTH enforcers to attach, prints cgid + dashboard URL

# 2. open the console
#    http://127.0.0.1:8765

# 3. drive the demo
scripts/demo.sh
#    -> 7 attack shapes, paced, each captioned; watch denials stream in

# 4. tear down and prove the kernel is clean
scripts/down.sh
#    -> SIGINT->TERM->KILL escalation gated on bpftool; "VERIFIED CLEAN" or a loud fail
```

Set `LEASH_DEMO_BEAT=2.5 scripts/demo.sh` to slow the pacing for a live audience.

## What you should see on the dashboard

- **Status bar:** `leashd` pid + uptime, two green enforcer dots (file, egress).
- **Session panel:** the live cgid, the protected inode's real `dev`/`ino`, the
  egress allowlist, and the `scope AF_INET (IPv6/UNIX unenforced)` disclosure.
- **Containment chain:** the `cat`→`curl` exfil forming with real seq numbers,
  topped by a dashed **"injection · not observed by leash, by design"** node, and
  a terminal node that says *no successful read of the protected inode; no egress
  to a non-allowlisted destination* — not "the secret never left".
- **Event log:** `-EPERM` denials streaming in. The permitted `:11434` Ollama
  chatter and the file-layer debug rows are **folded by default** so the denials
  stand out — use the `allow` / `debug` toggles to reveal them for a proof run.
- **Attack #7** lands as **NOT CONTAINED** with the disclosed-gap reason.

## If teardown ever looks wrong

`down.sh` is built for exactly the failure we hit repeatedly: a signal that did
not actually detach the program. It asks the kernel (`bpftool`), not the process
table, and escalates until the kernel is clear. If it prints **NOT CLEAN**, it
also prints the surviving `bpftool prog show` lines — that is a real,
kernel-confirmed leftover, not a false alarm. Re-run `down.sh`; if it still
fails, inspect with `sudo bpftool prog show | grep -E 'leash_enforce|leash_connect'`.

Do **not** use `grep -i lsm` to check — Ubuntu ships a resident
`restrict_filesystems` LSM program that will look like a leftover but is not
leash. The scripts match leash's own program names only.

## Cold-run checklist (reproduce from nothing)

From a state with nothing up:

1. `scripts/up.sh` → reaches "leash is UP", both enforcers attached.
2. dashboard at `:8765` shows the session, enforcers green.
3. `scripts/demo.sh` → denials appear live; #7 shows NOT CONTAINED.
4. `scripts/down.sh` → ends "VERIFIED CLEAN".

Three consecutive clean cold runs is the packaging exit criterion.

## Uninstall

```bash
scripts/uninstall.sh          # teardown + remove generated artifacts
scripts/uninstall.sh --purge  # also remove built binaries (source stays)
```

Leash installs nothing persistent (no boot units, no files outside the repo and
`~/leash-demo`), so uninstall is really "prove nothing is attached, then tidy".
