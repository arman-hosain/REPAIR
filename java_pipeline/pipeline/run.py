"""Java pipeline CLI.  Input = (codebase path, CWE); nothing else is read.

    python -m pipeline.run analyze --codebase PATH --cwe CWE-22 --out DIR [--endpoint URL] [--model NAME] [--arm s3]
        Whole pipeline in one call: Stage 1-3 (static) then Stage 4 (evidence tracing, inline) + Stage 5 (LLM).  Writes DIR/flags.jsonl, DIR/s1|s2|s3.jsonl,
        DIR/stage5.jsonl (every assessed unit with its verdict) and DIR/candidates.jsonl (units NOT judged UNEXPLOITABLE; fallbacks fail open).
        Needs MEDICALJAVA_ALLOW_LLM=1 (live calls are opt-in); with --cache-only no model is contacted (replay from pipeline/cache/llm).
    python -m pipeline.run static --codebase PATH --cwe CWE-22 --out DIR
        S1/S2/S3 flags only (no LLM).  Writes DIR/flags.jsonl (every S1 unit with its s1/s2/s3 flags), DIR/s1.jsonl s2.jsonl s3.jsonl, DIR/meta.json.
    python -m pipeline.run dry --codebase PATH --cwe CWE-22 --flags DIR [--arm s3]
        Stage-5 dry run: number of LLM calls and (estimated, or exact with a tokenizer) tokens; NO model is contacted.
    python -m pipeline.run llm --codebase PATH --cwe CWE-22 --flags DIR [--arm s3] -o stage5.jsonl
        Stage 4 (evidence tracing) + Stage 5 (LLM assessment) only, on the flags written by `static`.
--label is an opaque tag copied into the output (default: basename of the codebase).
"""
import argparse, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from pipeline import units as U, callgraph, s123, stage5     # noqa: E402


def _load_llm_config():
    """Reads <repo root>/config.json (copied by the user from config.example.json) for default
    --endpoint/--model/api-key values, so they don't need to be retyped on every run. Returns {}
    if no config.json exists. CLI flags (--endpoint/--model) always override whatever this
    returns; OPENAI_API_KEY (if set) always overrides the config file's api_key -- see cmd_llm()."""
    repo_root = os.path.dirname(os.path.dirname(HERE))   # java_pipeline/pipeline -> java_pipeline -> repo root
    path = os.path.join(repo_root, "config.json")
    if not os.path.exists(path):
        return {}
    try:
        cfg = json.load(open(path))
    except Exception as ex:
        print(f"[run] WARNING: could not read {path}: {ex}  (using built-in defaults)")
        return {}
    merged = dict(cfg.get("default", {}))
    merged.update(cfg.get("java", {}))
    return {k: v for k, v in merged.items() if not k.startswith("_")}


def supported_cwes():
    return sorted(f[:-5] for f in os.listdir(s123.RULES_DIR) if f.startswith("CWE-") and f.endswith(".json"))


def check_cwe(cwe):
    if cwe not in supported_cwes():
        raise SystemExit(f"no Java sink rule for {cwe}. Supported: {', '.join(supported_cwes())}  (add pipeline/rules/{cwe}.json to extend; see README)")


def cmd_static(a):
    check_cwe(a.cwe)
    t0 = time.time()
    cb = U.load_codebase(a.codebase, use_cache=not a.no_cache)
    cg = callgraph.load(cb, use_cache=not a.no_cache)
    recs, stats = s123.run(cb, cg, a.cwe)
    os.makedirs(a.out, exist_ok=True)
    pred = lambda r: dict(file=r["file"], function=r["function"], line_start=r["line_start"], line_end=r["line_end"], cwe=a.cwe, slice=a.label,
                          verdict="candidate", test=r["test"])
    with open(os.path.join(a.out, "flags.jsonl"), "w") as fh:
        for r in recs:
            fh.write(json.dumps(dict(r, cwe=a.cwe, slice=a.label)) + "\n")
    for stage in ("s1", "s2", "s3"):
        with open(os.path.join(a.out, f"{stage}.jsonl"), "w") as fh:
            for r in recs:
                if r[stage]:
                    fh.write(json.dumps(pred(r)) + "\n")
    meta = dict(label=a.label, cwe=a.cwe, cache_key=cb["key"], units_total=len(cb["units"]), files=len(cb["files"]), stats=stats,
                callgraph=cg["stats"], seconds=round(time.time() - t0, 1), sha256=s123.sha_manifest())
    json.dump(meta, open(os.path.join(a.out, "meta.json"), "w"), indent=1)
    print(f"[static] {a.label} {a.cwe}: units={len(cb['units'])} S1={stats['s1']} S2={stats['s2']} S3={stats['s3']} ({meta['seconds']}s)")


def _load_flags(a, cb):
    meta = json.load(open(os.path.join(a.flags, "meta.json")))
    if meta["cache_key"] != cb["key"]:
        raise SystemExit("flags were produced from a different codebase/extractor version: re-run `static`")
    return [json.loads(l) for l in open(os.path.join(a.flags, "flags.jsonl"))]


def cmd_dry(a):
    cb = U.load_codebase(a.codebase)
    cg = callgraph.load(cb)
    stage5.dry_run(a.codebase, cb, cg, _load_flags(a, cb), a.cwe, a.label, a.arm, a.window, a.tok_python, a.tokenizer, a.prompts)


def cmd_llm(a):
    cb = U.load_codebase(a.codebase)
    cg = callgraph.load(cb)
    recs = _load_flags(a, cb)
    # hosted endpoints need a real bearer token; local vLLM servers don't check it, so "dummy"
    # stays the default when no key is available (see README "Running with frontier models").
    # Precedence: OPENAI_API_KEY env var > config.json's api_key > "dummy".
    api_key = os.environ.get("OPENAI_API_KEY") or _load_llm_config().get("api_key", "dummy")
    client = stage5.LLMClient(a.endpoint, a.model, api_key=api_key, cache_only=a.cache_only)
    stage5.run_stage5(a.codebase, cb, cg, recs, a.cwe, a.label, a.arm, a.window, client, a.o, workers=a.workers)


def cmd_analyze(a):
    os.makedirs(a.out, exist_ok=True)
    a.flags = a.out
    cmd_static(a)
    a.o = os.path.join(a.out, "stage5.jsonl")
    cmd_llm(a)
    n = kept = 0
    with open(a.o) as fh, open(os.path.join(a.out, "candidates.jsonl"), "w") as out:
        for line in fh:
            r = json.loads(line); n += 1
            if str(r.get("verdict", "")).lower() != "unexploitable":
                out.write(line); kept += 1
    print(f"[analyze] {a.cwe}: {n} units assessed by Stage 5 -> {kept} candidates -> {os.path.join(a.out, 'candidates.jsonl')}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("static", "dry", "llm", "analyze"):
        s = sub.add_parser(name)
        s.add_argument("--codebase", required=True)
        s.add_argument("--cwe", required=True)
        s.add_argument("--label", default=None)
        if name in ("static", "analyze"):
            s.add_argument("--out", required=True)
            s.add_argument("--no-cache", action="store_true")
        if name in ("dry", "llm"):
            s.add_argument("--flags", required=True)
        if name in ("dry", "llm", "analyze"):
            s.add_argument("--arm", default="s3", choices=["s1", "s2", "s3"], help="which static stage feeds Stage 4/5 (default s3 = after path analysis)")
            s.add_argument("--window", type=int, default=32768)
        if name == "dry":
            s.add_argument("--tok-python")
            s.add_argument("--tokenizer")
            s.add_argument("--prompts")
        if name in ("llm", "analyze"):
            cfg = _load_llm_config()
            s.add_argument("--endpoint", default=cfg.get("endpoint", "http://127.0.0.1:8002/v1"),
                          help="OpenAI-compatible endpoint base URL (default comes from config.json if present)")
            s.add_argument("--model", default=cfg.get("model", stage5.PARAMS["model"]))
            s.add_argument("--cache-only", action="store_true", help="serve every request from the response cache; any miss is a hard error (no model contact)")
            s.add_argument("--workers", type=int, default=8)
        if name == "llm":
            s.add_argument("-o", required=True)
    a = ap.parse_args(argv)
    a.label = a.label or os.path.basename(os.path.abspath(a.codebase.rstrip("/")))
    {"static": cmd_static, "dry": cmd_dry, "llm": cmd_llm, "analyze": cmd_analyze}[a.cmd](a)


if __name__ == "__main__":
    main()
