#!/usr/bin/env python3
"""Unit tests for policc's validator/compiler in isolation (no BPF, no sudo).
Run: .venv/bin/python daemon/test_policc.py"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import policc

KEY = os.path.expanduser("~/leash-demo/secrets/api_key.txt")

def good():
    return {"version":1,
            "files":{"protect":[KEY]},
            "egress":{"default":"deny","allow":[{"ip":"127.0.0.1","port":11434}]}}

def check(name, doc, want_valid):
    errs = policc._validate(doc)
    ok = (len(errs)==0) == want_valid
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
          + ("" if ok else f"  errors={errs}"))
    return ok

def main():
    n = 0; p = 0
    cases = [
        ("valid policy accepted", good(), True),
        ("unknown top key", {**good(), "extra":1}, False),
        ("missing files", {k:v for k,v in good().items() if k!="files"}, False),
        ("protect not a list", {**good(), "files":{"protect":KEY}}, False),
        ("protect empty", {**good(), "files":{"protect":[]}}, False),
        ("nonexistent path", {**good(), "files":{"protect":["/no/such/file.xyz"]}}, False),
        ("relative path", {**good(), "files":{"protect":["relative.txt"]}}, False),
        ("bad ip", {**good(), "egress":{"default":"deny","allow":[{"ip":"999.1.2.3","port":1}]}}, False),
        ("port range", {**good(), "egress":{"default":"deny","allow":[{"ip":"127.0.0.1","port":70000}]}}, False),
        ("port str", {**good(), "egress":{"default":"deny","allow":[{"ip":"127.0.0.1","port":"x"}]}}, False),
        ("port bool", {**good(), "egress":{"default":"deny","allow":[{"ip":"127.0.0.1","port":True}]}}, False),
        ("default allow", {**good(), "egress":{"default":"allow","allow":[]}}, False),
        ("version 2", {**good(), "version":2}, False),
    ]
    for name, doc, wv in cases:
        n += 1; p += 1 if check(name, doc, wv) else 0

    # resolve() must equal the kernel-proven Phase 3/4 numbers
    dev, ino = policc.resolve_file(KEY)
    ipbe, port = policc.resolve_dest("127.0.0.1", 11434)
    r_ok = (dev==264241152 and ino==920726 and ipbe==0x0100007f and port==11434)
    n += 1; p += 1 if r_ok else 0
    print(f"  [{'PASS' if r_ok else 'FAIL'}] resolve == P3/P4 numbers  "
          f"dev={dev} ino={ino} ip_be=0x{ipbe:08x} port={port}")

    print(f"\n  {p}/{n} unit tests passed")
    sys.exit(0 if p==n else 1)

if __name__ == "__main__":
    main()
