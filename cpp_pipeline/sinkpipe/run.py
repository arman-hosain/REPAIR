#!/usr/bin/env python3
"""
sinkpipe/run.py — GONDAR-inspired static analysis pipeline for C codebases (CLI implementation).

Implements §3.1 of arxiv:2604.01645 adapted for C (instead of Java/CodeQL):

  Stage 1 — Sink Identification:     regex-based pattern matching (≈ CodeQL)
  Stage 2 — Candidate Validation:    constant-arg detection + test-file heuristic
  Stage 3 — Path Analysis:           call-graph BFS from fuzzer entry points (≈ Joern)
  Stage 4 — Evidence Tracing:        deterministic argument-origin trace (param_tracer.py)
  Stage 5 — LLM Assessment:          two-phase LLM agent (≈ atlantis-java filtering-agent)

Usage (via the top-level cpp_pipeline/pipeline.py wrapper, kept so the public CLI is unchanged):
  python pipeline.py run \\
      --codebase  C:\\path\\to\\repo \\
      --cwe       CWE-121 \\
      --cwe       CWE-476 \\
      --harness   curl_fuzzer_http \\
      --endpoint  http://129.108.156.67:8001/v1 \\
      --model     meta-llama/Llama-3.1-8B-Instruct \\
      --output    results/
"""

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))      # cpp_pipeline/ on sys.path, so `sinkpipe` resolves whether
                                                # this module is run via the pipeline.py wrapper, `python -m
                                                # sinkpipe.run`, or imported directly

from sinkpipe.sink_finder import scan_codebase, sinks_to_json     # noqa: E402
from sinkpipe.call_graph import build_call_graph, mark_reachability  # noqa: E402
from sinkpipe.llm_agent import LLMClient, run_exploitability_filter  # noqa: E402


def _load_llm_config():
    """Reads <repo root>/config.json (copied by the user from config.example.json) for default
    --endpoint/--model/--api-key values, so they don't need to be retyped on every run. Returns {}
    if no config.json exists. CLI flags always override whatever this returns -- see make_parser()."""
    repo_root = os.path.dirname(os.path.dirname(HERE))   # cpp_pipeline/sinkpipe -> cpp_pipeline -> repo root
    path = os.path.join(repo_root, "config.json")
    if not os.path.exists(path):
        return {}
    try:
        cfg = json.load(open(path))
    except Exception as ex:
        print(f"[pipeline] WARNING: could not read {path}: {ex}  (using built-in defaults)")
        return {}
    merged = dict(cfg.get("default", {}))
    merged.update(cfg.get("cpp", {}))
    return {k: v for k, v in merged.items() if not k.startswith("_")}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        GONDAR-Inspired Sink Detection Pipeline (C)          ║
║        arxiv:2604.01645  §3.1  —  adapted for C             ║
╚══════════════════════════════════════════════════════════════╝
"""


# ---------------------------------------------------------------------------
# Pretty summary printer
# ---------------------------------------------------------------------------


def _check_cwes(cwes):
    """Normalise CWE ids (CWE-78 -> CWE-078) and refuse CWEs with no registered sink detector instead of silently returning no sinks."""
    from sinkpipe.sink_finder import CWE_SINK_PATTERNS
    out = []
    for c in cwes:
        m = re.fullmatch(r"(?i)cwe-(\d+)", c.strip())
        key = f"CWE-{int(m.group(1)):03d}" if m else c
        if key not in CWE_SINK_PATTERNS:
            key = f"CWE-{int(m.group(1))}" if m else c
        if key not in CWE_SINK_PATTERNS:
            sys.exit(f"no C/C++ sink detector for {c}. Supported: {', '.join(sorted(CWE_SINK_PATTERNS))}  (see CWE_COVERAGE.md; add one in sink_finder.py)")
        out.append(key)
    return out

def print_summary(sinks: list[dict], stage: str):
    valid = [s for s in sinks
             if not s.get('filtered_out_flow') and not s.get('filtered_out_test')]
    reachable = [s for s in valid if s.get('reachable', True)]
    final = [s for s in sinks if s.get('in_final_result')]

    print(f"\n{'─'*62}")
    print(f"  {stage}")
    print(f"{'─'*62}")
    print(f"  Total sinks found:          {len(sinks)}")
    print(f"  After candidate validation: {len(valid)}")
    print(f"  After path analysis:        {len(reachable)}")
    print(f"  After LLM assessment (final): {len(final)}")
    print(f"{'─'*62}\n")

    if final:
        print("  FINAL ACTIONABLE SINKS:")
        for s in final:
            conf = s.get('confidence', '?')
            fn = s.get('containing_function', '?')
            print(f"  ✓ [{s['cwe']}]  {s['coord']['file_name']}:{s['coord']['line_num']}")
            print(f"      call:  {s.get('call_text', '')}")
            print(f"      func:  {fn}   confidence: {conf}")
            print(f"      note:  {s.get('reasoning','')[:100]}")
            print()


def save_results(sinks: list[dict], output_dir: Path):
    """Save all pipeline outputs to the output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Full results (all sinks with all metadata)
    (output_dir / "sinks_all.json").write_text(json.dumps(sinks, indent=2))

    # Final actionable sinks only
    final = [s for s in sinks if s.get('in_final_result')]
    (output_dir / "sinks_final.json").write_text(json.dumps(final, indent=2))

    # Human-readable report
    lines = []
    lines.append("SINK DETECTION PIPELINE REPORT")
    lines.append("=" * 62)
    lines.append(f"Total sinks scanned:  {len(sinks)}")
    lines.append(f"Valid (non-const):     {sum(1 for s in sinks if not s.get('filtered_out_flow') and not s.get('filtered_out_test'))}")
    lines.append(f"Path analysis reachable: {sum(1 for s in sinks if s.get('reachable'))}")
    lines.append(f"Final (LLM-assessed exploitable): {len(final)}")
    lines.append("")

    for s in final:
        lines.append(f"[{s['cwe']}] {s['coord']['file_name']}:{s['coord']['line_num']}")
        lines.append(f"  Sink:       {s.get('call_text','')}")
        lines.append(f"  Function:   {s.get('containing_function','?')}")
        lines.append(f"  Confidence: {s.get('confidence','?')}")
        lines.append(f"  Reasoning:  {s.get('reasoning','')[:200]}")
        lines.append("")

    lines.append("=" * 62)
    lines.append("FILTERED-OUT SINKS (for audit):")
    lines.append("")
    for s in sinks:
        if not s.get('in_final_result') and not s.get('unexploitable'):
            reason = []
            if s.get('filtered_out_flow'):
                reason.append("constant-arg")
            if s.get('filtered_out_test'):
                reason.append("test-code")
            if not s.get('reachable', True):
                reason.append("unreachable")
            if s.get('unexploitable'):
                reason.append(f"LLM-unexploitable[{s.get('confidence','?')}]")
            lines.append(f"  [{s['cwe']}] {s['coord']['file_name']}:{s['coord']['line_num']}"
                         f"  ← {', '.join(reason) or 'LLM filtered'}")

    (output_dir / "report.txt").write_text("\n".join(lines))
    print(f"[pipeline] Results saved to: {output_dir}/")
    print(f"           sinks_all.json, sinks_final.json, report.txt")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(args):
    print(BANNER)
    root = Path(args.codebase).resolve()
    if not root.exists():
        print(f"ERROR: codebase path does not exist: {root}")
        return 1

    output_dir = Path(args.output)
    cwes = _check_cwes(args.cwe or ["CWE-121", "CWE-476"])
    harness = args.harness
    endpoint = args.endpoint
    model = args.model

    print(f"  Codebase:  {root}")
    print(f"  CWEs:      {cwes}")
    print(f"  Harness:   {harness}")
    print(f"  LLM:       {model}")
    print(f"  Endpoint:  {endpoint}")
    print(f"  Output:    {output_dir}\n")

    # ── Stage 1 + 2: Sink Identification + Candidate Validation ─────────────
    print("━" * 62)
    print("  STAGE 1 + 2: Sink Identification + Candidate Validation")
    print("━" * 62)

    raw_sinks = scan_codebase(root, cwes, include_dirs=args.include_dir or None)
    sinks = sinks_to_json(raw_sinks)

    valid = [s for s in sinks if not s['filtered_out_flow'] and not s['filtered_out_test']]
    print(f"\n  Found {len(sinks)} total sinks")
    print(f"  Constant-arg filtered:  {sum(1 for s in sinks if s['filtered_out_flow'])}")
    print(f"  Test-code filtered:     {sum(1 for s in sinks if s['filtered_out_test'])}")
    print(f"  Valid after Stage 1+2:  {len(valid)}")

    # Early exit: if already ≤ threshold, skip reachability too
    THRESHOLD = args.llm_threshold

    # ── Stage 3: Path Analysis ───────────────────────────────────────────────
    print("\n" + "━" * 62)
    print("  STAGE 3: Path Analysis")
    print("━" * 62)

    if len(valid) > 0:
        graph = build_call_graph(root, source_dirs=args.source_dir or None)
        sinks = mark_reachability(sinks, graph, harness, root=root)
        reachable = [s for s in sinks
                     if s.get('reachable') and
                     not s.get('filtered_out_flow') and
                     not s.get('filtered_out_test')]
        print(f"\n  Reachable candidate sinks: {len(reachable)}")
        for s in reachable:
            print(f"    [{s['cwe']}] {s['coord']['file_name']}:{s['coord']['line_num']}"
                  f"  fn={s.get('containing_function','?')}  ({s['message']})")
    else:
        print("  No valid sinks to check reachability for.")
        graph = {}
        reachable = []

    # ── Stage 4 + 5: Evidence Tracing + LLM Assessment ──────────────────────
    print("\n" + "━" * 62)
    print("  STAGE 4 + 5: Evidence Tracing + LLM Assessment")
    print("━" * 62)

    if args.skip_llm:
        print("  --skip-llm: skipping LLM stage, all reachable sinks marked as final")
        for s in sinks:
            if s.get('reachable') and not s.get('filtered_out_flow') and not s.get('filtered_out_test'):
                s['in_final_result'] = True
                s['unexploitable'] = False
                s['reasoning'] = "LLM stage skipped"
                s['confidence'] = "N/A"
    else:
        llm = LLMClient(
            base_url=endpoint,
            model=model,
            api_key=args.api_key or "dummy",
            timeout=args.llm_timeout,
        )
        sinks = run_exploitability_filter(
            sinks, llm, root, harness,
            threshold=THRESHOLD,
            force=args.force_llm,
            verbose=args.verbose,
            cwe_context=args.cwe_context,
            graph=graph,
        )

    # ── Summary + Save ───────────────────────────────────────────────────────
    print_summary(sinks, f"Pipeline Results — {root.name}")
    save_results(sinks, output_dir)
    return 0


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_scan(args):
    """Just run Stage 1 (sink identification) + Stage 2 (candidate validation)."""
    from sinkpipe.sink_finder import scan_codebase, sinks_to_json
    root = Path(args.codebase).resolve()
    cwes = _check_cwes(args.cwe or ["CWE-121", "CWE-476"])
    sinks = scan_codebase(root, cwes, include_dirs=args.include_dir or None)
    data = sinks_to_json(sinks)
    out = Path(args.output)
    out.write_text(json.dumps(data, indent=2))
    valid = [s for s in data if not s['filtered_out_flow'] and not s['filtered_out_test']]
    print(f"\nFound {len(data)} sinks, {len(valid)} valid after candidate validation")
    print(f"Written to {out}")
    if args.list:
        for s in valid:
            print(f"  [{s['cwe']}] {s['coord']['file_name']}:{s['coord']['line_num']}  {s['message']}")


def cmd_reachability(args):
    """Just run Stage 3 (path analysis/reachability) on existing sinks file."""
    from sinkpipe.call_graph import build_call_graph, mark_reachability
    root = Path(args.codebase).resolve()
    sinks = json.loads(Path(args.sinks).read_text())
    graph = build_call_graph(root, source_dirs=args.source_dir or None)
    updated = mark_reachability(sinks, graph, args.harness, root=root)
    out = Path(args.output)
    out.write_text(json.dumps(updated, indent=2))
    reachable = [s for s in updated if s.get('reachable') and
                 not s.get('filtered_out_flow') and not s.get('filtered_out_test')]
    print(f"\nReachable sinks: {len(reachable)}")
    for s in reachable:
        print(f"  [{s['cwe']}] {s['coord']['file_name']}:{s['coord']['line_num']}  fn={s.get('containing_function','?')}")
    print(f"Written to {out}")


def cmd_llm(args):
    """Just run Stage 4 (evidence tracing) + Stage 5 (LLM assessment) on existing sinks file."""
    from sinkpipe.llm_agent import LLMClient, run_exploitability_filter
    from sinkpipe.call_graph import build_call_graph
    root = Path(args.codebase).resolve()
    sinks = json.loads(Path(args.sinks).read_text())
    graph = build_call_graph(root, source_dirs=args.source_dir or None)
    llm = LLMClient(base_url=args.endpoint, model=args.model, api_key=args.api_key or "dummy")
    updated = run_exploitability_filter(
        sinks, llm, root, args.harness,
        threshold=args.llm_threshold,
        force=args.force_llm,
        verbose=args.verbose,
        cwe_context=args.cwe_context,
        graph=graph,
    )
    out = Path(args.output)
    out.write_text(json.dumps(updated, indent=2))
    final = [s for s in updated if s.get('in_final_result')]
    print(f"\nFinal actionable sinks: {len(final)}")
    for s in final:
        print(f"  [{s['cwe']}] {s['coord']['file_name']}:{s['coord']['line_num']}  conf={s.get('confidence','?')}")
    print(f"Written to {out}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def make_parser():
    parser = argparse.ArgumentParser(
        description="GONDAR-inspired sink detection pipeline for C codebases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline (all 4 stages)
  python pipeline.py run \\
      --codebase C:\\path\\to\\curl \\
      --cwe CWE-121 --cwe CWE-476 \\
      --harness curl_fuzzer_http \\
      --endpoint http://129.108.156.67:8001/v1 \\
      --model meta-llama/Llama-3.1-8B-Instruct \\
      --output results/

  # Skip LLM (stages 1-3 only)
  python pipeline.py run --codebase ... --skip-llm

  # Run only sink scanning
  python pipeline.py scan --codebase ... --cwe CWE-121 --list

  # Run only reachability on existing sinks
  python pipeline.py reachability --codebase ... --sinks sinks.json --harness curl_fuzzer_http

  # Run only LLM filter on existing sinks
  python pipeline.py llm --codebase ... --sinks sinks_reachable.json --endpoint ...
""")

    sub = parser.add_subparsers(dest="command")

    # Common args factory
    def add_common(p):
        p.add_argument("--codebase", required=True, help="Path to repository root")
        p.add_argument("--cwe", action="append", default=[], metavar="CWE-XXX",
                       help="CWE to scan (repeat for multiple). Default: CWE-121 CWE-476")
        p.add_argument("--include-dir", action="append", default=[], dest="include_dir",
                       help="Only scan files under these subdirs")
        p.add_argument("--source-dir", action="append", default=[], dest="source_dir",
                       help="Dirs to build the call graph from (repeat for multiple). "
                            "Default: lib, src. Needed e.g. for xz where the OSS-Fuzz "
                            "harness lives under tests/ossfuzz/ instead.")

    def add_llm_args(p):
        cfg = _load_llm_config()
        p.add_argument("--endpoint", default=cfg.get("endpoint", "http://129.108.156.67:8001/v1"),
                       help="vLLM/OpenAI endpoint base URL (default comes from config.json if present)")
        p.add_argument("--model", default=cfg.get("model", "meta-llama/Llama-3.1-8B-Instruct"))
        p.add_argument("--api-key", default=cfg.get("api_key"), dest="api_key")
        p.add_argument("--llm-timeout", type=int, default=120, dest="llm_timeout")
        p.add_argument("--llm-threshold", type=int, default=10, dest="llm_threshold",
                       help="Skip LLM if candidates ≤ this (paper uses 10)")
        p.add_argument("--cwe-context", choices=["hardcoded", "extended", "none", "bare", "nohint", "mitre"],
                       default="hardcoded", dest="cwe_context",
                       help="CWE guidance spliced into the Stage 5 prompt: the built-in "
                            "CWE_INFO factors (default), those plus MITRE CWE text from "
                            "cwe_extended_info.json, or none")
        p.add_argument("--force-llm", action="store_true", dest="force_llm",
                       help="Force LLM even if below threshold")
        p.add_argument("--skip-llm", action="store_true", dest="skip_llm",
                       help="Skip LLM stage entirely")

    # ── run (full pipeline) ──
    run_p = sub.add_parser("run", help="Run full pipeline (all stages)")
    add_common(run_p)
    run_p.add_argument("--harness", default="curl_fuzzer_http",
                       help="Fuzzer harness name, or 'none' for codebases without a fuzzer")
    add_llm_args(run_p)
    run_p.add_argument("--output", "-o", default="results/", help="Output directory")
    run_p.add_argument("--verbose", "-v", action="store_true")
    run_p.set_defaults(func=run_pipeline)

    # ── scan ──
    scan_p = sub.add_parser("scan", help="Stage 1+2 only: sink identification + candidate validation")
    add_common(scan_p)
    scan_p.add_argument("--output", "-o", default="sinks.json")
    scan_p.add_argument("--list", action="store_true", help="Print valid sinks")
    scan_p.set_defaults(func=cmd_scan)

    # ── reachability ──
    reach_p = sub.add_parser("reachability", help="Stage 3 only: path analysis (call-graph reachability)")
    add_common(reach_p)
    reach_p.add_argument("--sinks", required=True, help="Input sinks JSON")
    reach_p.add_argument("--harness", default="curl_fuzzer_http")
    reach_p.add_argument("--output", "-o", default="sinks_reachable.json")
    reach_p.set_defaults(func=cmd_reachability)

    # ── llm ──
    llm_p = sub.add_parser("llm", help="Stage 4 + 5 only: evidence tracing + LLM assessment")
    add_common(llm_p)
    llm_p.add_argument("--sinks", required=True, help="Input sinks JSON (with reachability)")
    llm_p.add_argument("--harness", default="curl_fuzzer_http")
    add_llm_args(llm_p)
    llm_p.add_argument("--output", "-o", default="sinks_filtered.json")
    llm_p.add_argument("--verbose", "-v", action="store_true")
    llm_p.set_defaults(func=cmd_llm)

    return parser


def main():
    parser = make_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
