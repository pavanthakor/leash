#!/usr/bin/env python3
"""Leash policy compiler (Phase 5). Pure userspace.

Reads a unified policy.yaml, validates it WHOLE (refuse-to-load / all-or-nothing),
and compiles it into exactly the inputs the proven Phase 3/4 loaders already
consume: protected file PATHS (leash_enforce turns them into (dev,ino)) and
egress ip:port strings (leash_connect turns them into (ip_be,port)). The BPF
programs and loaders are unchanged -- map contents are identical by construction.

Subcommands (each validates the WHOLE policy first; on any error it prints every
error to stderr, exits 2, and emits NOTHING to stdout -- so no partial load):
  validate  OK / errors
  files     protected paths, sorted (leash_enforce args)
  egress    ip:port destinations, sorted (leash_connect args)
  resolve   the resolved (dev,ino)/(ip_be,port) view (fast userspace PRE-check;
            the REAL equivalence proof is the kernel's self-verifying debug)
  explain   plain-language description of what the policy protects
"""
import os
import socket
import struct
import sys

import yaml


# --- strict parse: reject duplicate keys (PyYAML silently keeps the last) -----
class StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping", node.start_mark,
                    f"found duplicate key: {key!r}", key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep)


ALLOWED_TOP = {"version", "files", "egress"}


def _validate(doc):
    """Return a list of path-qualified error strings ([] == valid)."""
    E = []
    def err(where, msg): E.append(f"{where}: {msg}")

    if not isinstance(doc, dict):
        return [f"<root>: policy must be a mapping, got {type(doc).__name__}"]

    for k in doc:
        if k not in ALLOWED_TOP:
            err(k, f"unknown top-level key (allowed: {sorted(ALLOWED_TOP)})")

    # version
    if "version" not in doc:
        err("version", "required")
    elif doc["version"] != 1:
        err("version", f"must be 1, got {doc['version']!r}")

    # files.protect: non-empty list of absolute, existing regular files
    if "files" not in doc:
        err("files", "required section missing")
    elif not isinstance(doc["files"], dict):
        err("files", f"must be a mapping, got {type(doc['files']).__name__}")
    else:
        f = doc["files"]
        for k in f:
            if k != "protect":
                err(f"files.{k}", "unknown key (allowed: protect)")
        if "protect" not in f:
            err("files.protect", "required")
        elif not isinstance(f["protect"], list):
            err("files.protect", f"must be a list, got {type(f['protect']).__name__}")
        elif len(f["protect"]) == 0:
            err("files.protect", "must not be empty")
        else:
            for i, item in enumerate(f["protect"]):
                loc = f"files.protect[{i}]"
                if not isinstance(item, str):
                    err(loc, f"must be a string path, got {type(item).__name__}")
                elif not item.startswith("/"):
                    err(loc, f"must be an absolute path: {item!r}")
                elif not os.path.exists(item):
                    err(loc, f"path does not exist: {item}")
                elif not os.path.isfile(item):
                    err(loc, f"not a regular file: {item}")

    # egress: default-deny only, allow is a list of {ip, port}
    if "egress" not in doc:
        err("egress", "required section missing")
    elif not isinstance(doc["egress"], dict):
        err("egress", f"must be a mapping, got {type(doc['egress']).__name__}")
    else:
        e = doc["egress"]
        for k in e:
            if k not in {"default", "allow"}:
                err(f"egress.{k}", "unknown key (allowed: default, allow)")
        if "default" not in e:
            err("egress.default", "required")
        elif e["default"] != "deny":
            err("egress.default", f'must be "deny" (default-deny only), got {e["default"]!r}')
        if "allow" not in e:
            err("egress.allow", "required")
        elif not isinstance(e["allow"], list):
            err("egress.allow", f"must be a list, got {type(e['allow']).__name__}")
        else:
            for i, item in enumerate(e["allow"]):
                loc = f"egress.allow[{i}]"
                if not isinstance(item, dict):
                    err(loc, f"must be a mapping {{ip, port}}, got {type(item).__name__}")
                    continue
                for k in item:
                    if k not in {"ip", "port"}:
                        err(f"{loc}.{k}", "unknown key (allowed: ip, port)")
                if "ip" not in item:
                    err(f"{loc}.ip", "required")
                elif not isinstance(item["ip"], str):
                    err(f"{loc}.ip", f"must be a string, got {type(item['ip']).__name__}")
                else:
                    try:
                        socket.inet_pton(socket.AF_INET, item["ip"])
                    except OSError:
                        err(f"{loc}.ip", f"not a valid IPv4 address: {item['ip']!r}")
                if "port" not in item:
                    err(f"{loc}.port", "required")
                elif isinstance(item["port"], bool) or not isinstance(item["port"], int):
                    err(f"{loc}.port", f"must be an integer, got {type(item['port']).__name__}: {item['port']!r}")
                elif not (1 <= item["port"] <= 65535):
                    err(f"{loc}.port", f"out of range 1-65535: {item['port']}")
    return E


def load_and_validate(path):
    try:
        with open(path) as fh:
            doc = yaml.load(fh, Loader=StrictLoader)
    except FileNotFoundError:
        return None, [f"<file>: policy file not found: {path}"]
    except yaml.YAMLError as ex:
        # covers syntax errors AND the strict duplicate-key rejection
        return None, [f"<parse>: {str(ex).strip()}"]
    return doc, _validate(doc)


def die_if_invalid(errors):
    if errors:
        print(f"POLICY REJECTED -- {len(errors)} error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(2)


# --- compiled views (only reached after full validation) ----------------------
def compiled_files(doc):
    return sorted(set(doc["files"]["protect"]))


def compiled_egress(doc):
    return sorted({f"{d['ip']}:{d['port']}" for d in doc["egress"]["allow"]},
                  key=lambda s: (s.rsplit(":", 1)[0], int(s.rsplit(":", 1)[1])))


def resolve_file(path):
    st = os.stat(path)
    dev = (os.major(st.st_dev) << 20) | (os.minor(st.st_dev) & 0xFFFFF)  # kernel MKDEV
    return dev, st.st_ino


def resolve_dest(ip, port):
    ip_be = struct.unpack("<I", socket.inet_pton(socket.AF_INET, ip))[0]  # == sin_addr.s_addr
    return ip_be, port


def main(argv):
    if len(argv) != 3:
        print("usage: policc <validate|files|egress|resolve|explain> <policy.yaml>",
              file=sys.stderr)
        return 2
    cmd, path = argv[1], argv[2]
    doc, errors = load_and_validate(path)
    die_if_invalid(errors)  # exits 2 with all errors; nothing below runs on failure

    if cmd == "validate":
        nf = len(compiled_files(doc))
        na = len(compiled_egress(doc))
        print(f"OK: policy valid ({nf} protected file(s), {na} allowed destination(s), egress default-deny)")
    elif cmd == "files":
        for p in compiled_files(doc):
            print(p)
    elif cmd == "egress":
        for d in compiled_egress(doc):
            print(d)
    elif cmd == "resolve":
        print("# files: path -> (dev, ino)  [leash_enforce protected_files]")
        for p in compiled_files(doc):
            dev, ino = resolve_file(p)
            print(f"file  {p}  dev={dev} ino={ino}")
        print("# egress: ip:port -> (ip_be, port)  [leash_connect allowed_dests]")
        for d in compiled_egress(doc):
            ip, port = d.rsplit(":", 1)
            ip_be, port = resolve_dest(ip, int(port))
            print(f"dest  {d}  ip_be=0x{ip_be:08x} port={port}")
    elif cmd == "explain":
        files = compiled_files(doc)
        dests = compiled_egress(doc)
        print("Leash policy (what this actually enforces):")
        print(f"  Files -- {len(files)} protected (in-session reads DENIED):")
        for p in files:
            print(f"      - {p}")
        print(f"  Egress -- default-deny; only these destinations are ALLOWED,")
        print(f"            every other destination is DENIED for in-session processes:")
        for d in dests:
            print(f"      - {d}")
        print("  Scope -- enforcement applies ONLY to the agent's session cgroup;")
        print("           all other processes on the host are unaffected.")
    else:
        print(f"unknown subcommand: {cmd!r}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
