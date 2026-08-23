#!/usr/bin/env python3
"""Aggregate raw per-syscall latencies into a distribution + the enforcement
deltas. Reads bench/results/raw_<hook>_<cond>_run<k>.csv (one latency-ns per
line), writes summary.csv, and prints the two deltas that carry the phase:

  (a) - (b)  in-session vs out-of-session  = the ENFORCEMENT cost (scoped to the
                                             leashed session)
  (b) - (c)  out-of-session vs no-program  = the HOST-WIDE tax of merely having
                                             leash loaded (the Scalability claim)

Reports median-of-per-run-medians + the run-to-run spread, so a delta smaller
than the spread is stated as "below measurement resolution", not faked to a
precise number.
"""
import csv, glob, os, statistics, sys

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
COND = {"in": "(a) in-session", "out": "(b) out-of-session", "floor": "(c) no-program"}
HOOKS = {"file": "file_open  open()", "conn": "socket_connect  connect()"}


def load(path):
    import gzip
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt") as f:
        return [int(x) for x in f if x.strip()]


def pct(sorted_vals, q):
    if not sorted_vals: return 0
    i = min(len(sorted_vals) - 1, int(len(sorted_vals) * q))
    return sorted_vals[i]


def per_run(hook, cond):
    """-> list of per-run dicts (one per raw file)."""
    runs = []
    for path in sorted(glob.glob(os.path.join(RES, f"raw_{hook}_{cond}_run*.csv*"))):
        v = sorted(load(path))
        if not v: continue
        runs.append({
            "n": len(v), "min": v[0], "p50": pct(v, 0.50),
            "p90": pct(v, 0.90), "p99": pct(v, 0.99),
            "mean": statistics.mean(v),
        })
    return runs


def summarize(hook, cond):
    runs = per_run(hook, cond)
    if not runs: return None
    medians = [r["p50"] for r in runs]
    return {
        "hook": hook, "cond": cond, "runs": len(runs), "n_per_run": runs[0]["n"],
        "median_of_medians": int(statistics.median(medians)),
        "run_spread": max(medians) - min(medians),          # run-to-run noise floor
        "run_medians": medians,
        "pooled_min": min(r["min"] for r in runs),
        "p90_of_medians": int(statistics.median([r["p90"] for r in runs])),
        "p99_of_medians": int(statistics.median([r["p99"] for r in runs])),
    }


def main():
    rows = []
    have = {}
    for hook in HOOKS:
        for cond in COND:
            s = summarize(hook, cond)
            if s:
                rows.append(s); have[(hook, cond)] = s

    out = os.path.join(RES, "summary.csv")
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["hook", "condition", "runs", "n_per_run",
                    "median_ns", "run_spread_ns", "pooled_min_ns",
                    "p90_ns", "p99_ns", "run_medians_ns"])
        for s in rows:
            w.writerow([s["hook"], COND[s["cond"]], s["runs"], s["n_per_run"],
                        s["median_of_medians"], s["run_spread"], s["pooled_min"],
                        s["p90_of_medians"], s["p99_of_medians"],
                        "|".join(str(x) for x in s["run_medians"])])

    print(f"{'hook':<26} {'condition':<20} {'median':>9} {'spread':>8} {'p90':>8} {'p99':>9}")
    print("-" * 84)
    for s in rows:
        print(f"{HOOKS[s['hook']]:<26} {COND[s['cond']]:<20} "
              f"{s['median_of_medians']:>7}ns {s['run_spread']:>6}ns "
              f"{s['p90_of_medians']:>6}ns {s['p99_of_medians']:>7}ns")

    def paired(hook, ca, cb):
        """Per-trial (ca - cb) deltas -- cancels per-trial drift; the interleaved
        design's intended statistic. -> (list, all_same_sign) or None."""
        import glob as _g
        a = {os.path.basename(p).split("_run")[1].split(".")[0]: sorted(load(p))
             for p in _g.glob(os.path.join(RES, f"raw_{hook}_{ca}_run*.csv*"))}
        b = {os.path.basename(p).split("_run")[1].split(".")[0]: sorted(load(p))
             for p in _g.glob(os.path.join(RES, f"raw_{hook}_{cb}_run*.csv*"))}
        keys = sorted(set(a) & set(b))
        if not keys: return None
        d = [a[k][len(a[k])//2] - b[k][len(b[k])//2] for k in keys]
        return d

    print("\nPAIRED per-trial deltas (in-vs-out cancels drift -- the primary statistic):")
    for hook in HOOKS:
        d = paired(hook, "in", "out")
        if not d: continue
        allpos = all(x > 0 for x in d)
        verdict = (f"consistent {int(statistics.median(d))} ns/syscall (positive in all "
                   f"{len(d)} trials)" if allpos else
                   f"~{int(statistics.median(d))} ns median but NOT consistently positive "
                   f"(range {min(d)}..{max(d)}) -- at/near the noise floor")
        print(f"  {HOOKS[hook]:<26} (a)-(b) per trial {d} -> {verdict}")
        df = paired(hook, "out", "floor")
        if df:
            allsig = all(abs(x) > 0 for x in df)
            print(f"  {HOOKS[hook]:<26} (b)-(c) per trial {df} -> "
                  f"median {int(statistics.median(df))} ns (host-wide tax)")

    print("\nDELTAS (median-of-medians; resolution = larger of the two run spreads):")
    for hook in HOOKS:
        a, b, c = have.get((hook, "in")), have.get((hook, "out")), have.get((hook, "floor"))
        print(f"\n  {HOOKS[hook]}")
        if a and b:
            d = a["median_of_medians"] - b["median_of_medians"]
            res = max(a["run_spread"], b["run_spread"])
            claim = (f"{d} ns" if d > res else f"below resolution (~{res} ns): not separable from run-to-run noise")
            print(f"    (a)-(b) enforcement cost (scoped) : {d:>6} ns   [resolution ~{res} ns] -> {claim}")
        if b and c:
            d = b["median_of_medians"] - c["median_of_medians"]
            res = max(b["run_spread"], c["run_spread"])
            claim = (f"{d} ns" if abs(d) > res else f"below resolution (~{res} ns): host-wide tax not measurable")
            print(f"    (b)-(c) host-wide tax (loaded)    : {d:>6} ns   [resolution ~{res} ns] -> {claim}")
        elif not c:
            print(f"    (b)-(c): floor (c) not yet measured -- run `run_bench.sh floor` with leashd down")
    print(f"\nsummary.csv -> {out}")


if __name__ == "__main__":
    main()
