#!/usr/bin/env python3
"""
param_tracer.py -- Stage 4 (Evidence Tracing) for C/C++ (BLIND side).

Mirrors the Java pipeline's `pipeline/param_tracer.py`, adapted to this pipeline's regex-based
call graph (`call_graph.py`: per-function `file`, `start_line`, `end_line`, `calls` -- a set of
callee names, no parameter lists or call-site argument text).

What it does
------------
For a sink argument such as the length in `memcpy(dst, src, n)`, it traces where the value
textually originates: a local reassignment earlier in the same function (`n = strlen(src);`),
or -- if the variable is itself a parameter of the containing function -- interprocedurally up
through that function's real callers (found by re-scanning the call graph for callers whose
`calls` set includes it, then re-reading each caller's body to find the actual call-site text and
substitute the matching argument), continuing from there. It is deterministic: no LLM is
involved, and it never labels anything tainted, safe or exploitable -- it only reports facts
about where a value textually originates, leaving the verdict to the LLM (see
`render_evidence_for_llm` and its use in `llm_agent.py`'s Stage 5 prompt builder).

Stop rules (same shape as the Java version): max depth, max callers explored per hop, max total
nodes, cycle detection on (file, func, variable). Classification scheme: constant / bare
identifier / call / field access (`->`/`.`) / array index / complex.
"""
import re
from pathlib import Path

MAX_DEPTH = 5
MAX_CALLERS_PER_HOP = 3
MAX_NODES = 30

_IDENT_RE = re.compile(r'^[A-Za-z_]\w*$')
_NUMERIC_RE = re.compile(r'^(?:0[xX][0-9a-fA-F]+|\d+\.?\d*[uUlLfF]*)$')
_STRING_RE = re.compile(r'^(?:".*"|\'.*\')$')


def classify(expr: str) -> str:
    """-> one of constant | identifier | call | field | index | complex"""
    e = expr.strip()
    if not e:
        return "complex"
    if _NUMERIC_RE.match(e) or _STRING_RE.match(e) or (e.isupper() and _IDENT_RE.match(e)):
        return "constant"
    if _IDENT_RE.match(e):
        return "identifier"
    if re.match(r'^[A-Za-z_]\w*\s*\(', e) and e.endswith(')'):
        return "call"
    if '->' in e or re.search(r'\w\.\w', e):
        return "field"
    if '[' in e and e.endswith(']'):
        return "index"
    return "complex"


def _extract_args(call_text: str) -> list[str]:
    """Same one-level-of-nesting splitter as sink_finder._extract_args (duplicated to avoid a
    cross-module dependency on sink_finder's sink-specific helpers)."""
    start = call_text.find('(')
    if start == -1:
        return []
    depth, args, current = 0, [], []
    for ch in call_text[start:]:
        if ch == '(':
            depth += 1
            if depth > 1:
                current.append(ch)
        elif ch == ')':
            depth -= 1
            if depth == 0:
                args.append(''.join(current).strip())
                break
            current.append(ch)
        elif ch == ',' and depth == 1:
            args.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    return [a for a in args if a]


def _balanced_call_at(text: str, name_start: int) -> str | None:
    """text[name_start:] starts with an identifier; -> the full `name(...)` call text with
    balanced parens, or None if the parens never close (shouldn't happen in well-formed code)."""
    paren = text.find('(', name_start)
    if paren == -1:
        return None
    depth = 0
    for i in range(paren, len(text)):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return text[name_start:i + 1]
    return None


def _read_file(root: Path, rel_file: str) -> str | None:
    for candidate in (root / rel_file, Path(rel_file)):
        try:
            return candidate.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
    return None


def _func_text(root: Path, info: dict) -> str | None:
    text = _read_file(root, info['file'])
    if text is None:
        return None
    lines = text.splitlines()
    s, e = max(0, info['start_line'] - 1), min(len(lines), info['end_line'])
    return '\n'.join(lines[s:e])


def _param_names(func_text: str) -> list[str]:
    """Parse the parameter list out of a function's signature (the text up to its first '{')."""
    head = func_text.split('{', 1)[0]
    m = re.search(r'\(([^()]*)\)\s*$', head.strip(), re.S) or re.search(r'\(([^()]*)\)', head, re.S)
    if not m:
        return []
    raw = m.group(1).strip()
    if raw in ('', 'void'):
        return []
    names = []
    for part in raw.split(','):
        part = part.strip()
        if not part or part == '...':
            continue
        nm = re.search(r'([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?$', part)
        names.append(nm.group(1) if nm else part)
    return names


def _local_assignment(func_text: str, var: str, before_line_in_func: int) -> str | None:
    """-> the right-hand side of the LAST `var = expr;` (not `==`, not `var->x =`/`var.x =`,
    not `var[i] =`) found strictly before line `before_line_in_func` (1-based, relative to the
    start of func_text), or None."""
    lines = func_text.split('\n')
    pat = re.compile(r'(?<![\w.>])\b' + re.escape(var) + r'\b\s*=(?!=)\s*(.+?);')
    last = None
    for i, line in enumerate(lines[:max(0, before_line_in_func - 1)], start=1):
        if re.search(r'\b' + re.escape(var) + r'\s*(?:\[[^\]]*\])?\s*->', line):
            continue
        m = pat.search(line)
        if m and not re.search(re.escape(var) + r'\s*(?:\[[^\]]*\])?\s*\.', line[:m.start()]):
            last = m.group(1).strip()
    return last


def _find_callers(graph: dict, func_name: str) -> list[str]:
    return sorted(n for n, info in graph.items() if func_name in info.get('calls', ()))


def _find_call_site_args(root: Path, caller_info: dict, callee_name: str, limit=MAX_CALLERS_PER_HOP) -> list[list[str]]:
    """-> up to `limit` argument lists found at real `callee_name(...)` call sites inside
    caller_info's body."""
    text = _func_text(root, caller_info)
    if text is None:
        return []
    out = []
    for m in re.finditer(r'\b' + re.escape(callee_name) + r'\s*\(', text):
        call = _balanced_call_at(text, m.start())
        if call:
            out.append(_extract_args(call))
        if len(out) >= limit:
            break
    return out


def trace(root: Path, graph: dict, start_func: str, start_var_or_expr: str,
          start_line_in_func: int, max_depth=MAX_DEPTH, max_callers=MAX_CALLERS_PER_HOP,
          max_nodes=MAX_NODES) -> list[dict]:
    """-> ordered list of hop dicts: {func, expr, classification, note}. Stops at a non-identifier
    expression, a depth/node limit, or when no callers/assignment are found."""
    hops = []
    seen = set()
    nodes = 0

    def walk(func, expr, line_in_func, depth):
        nonlocal nodes
        kind = classify(expr)
        hops.append(dict(func=func, expr=expr, classification=kind))
        nodes += 1
        if kind != "identifier" or depth >= max_depth or nodes >= max_nodes:
            if kind == "identifier" and depth >= max_depth:
                hops.append(dict(func=func, expr=expr, classification="stopped", note="max depth reached"))
            return
        info = graph.get(func)
        func_text = _func_text(root, info) if info else None
        if func_text is None:
            hops.append(dict(func=func, expr=expr, classification="stopped", note="function source unavailable"))
            return
        reassigned = _local_assignment(func_text, expr, line_in_func)
        if reassigned is not None:
            key = (func, reassigned)
            if key in seen:
                hops.append(dict(func=func, expr=expr, classification="stopped", note="cycle detected"))
                return
            seen.add(key)
            # position of the assignment line within func_text, for the NEXT hop's "before" cursor
            assign_line = next((i + 1 for i, l in enumerate(func_text.split('\n')[:line_in_func - 1])
                                if re.search(r'(?<![\w.>])\b' + re.escape(expr) + r'\b\s*=(?!=)', l)), line_in_func)
            walk(func, reassigned, assign_line, depth)
            return
        params = _param_names(func_text)
        if expr not in params:
            hops.append(dict(func=func, expr=expr, classification="stopped", note="not a local assignment or a parameter; untraceable"))
            return
        callers = _find_callers(graph, func)[:max_callers]
        if not callers:
            hops.append(dict(func=func, expr=expr, classification="stopped", note="no callers found in the analyzed call graph (entry point, or invoked via a function pointer / outside the scanned source dirs)"))
            return
        arg_idx = params.index(expr)
        for caller in callers:
            caller_info = graph[caller]
            for args in _find_call_site_args(root, caller_info, func, limit=1):
                if arg_idx < len(args):
                    hops.append(dict(func=caller, expr=f"(as caller of {func}, arg #{arg_idx + 1})",
                                     classification="caller", note=f"passes: {args[arg_idx]}"))
                    walk(caller, args[arg_idx], caller_info['end_line'] - caller_info['start_line'] + 1, depth + 1)
                    return
        hops.append(dict(func=func, expr=expr, classification="stopped", note="callers found but no matching call-site argument text located"))

    walk(start_func, start_var_or_expr, start_line_in_func, 0)
    return hops


def render_evidence_for_llm(hops: list[dict]) -> str:
    """Flatten a hop list into plain prose, one line per hop -- the format injected into the
    Stage 5 prompt via llm_agent.build_research_prompt's `traced_evidence` parameter."""
    lines = []
    for h in hops:
        if h["classification"] == "stopped":
            lines.append(f"  in {h['func']}: trace stops at `{h['expr']}` ({h.get('note', '')})")
        elif h["classification"] == "caller":
            lines.append(f"  {h['note']}  [{h['func']} {h['expr']}]")
        else:
            lines.append(f"  in {h['func']}: `{h['expr']}`  ({h['classification']})")
    return "\n".join(lines)


def trace_sink_arg(root: Path, graph: dict, sink: dict, max_args: int = 2) -> str | None:
    """Convenience wrapper for llm_agent.build_research_prompt: traces up to `max_args` of the
    sink's non-constant call arguments back through local assignments and real callers.
    -> rendered evidence text, or None if the sink's containing function isn't in the graph."""
    containing = sink.get('containing_function')
    if not containing or containing not in graph:
        return None
    call_text = sink.get('call_text', '')
    args = _extract_args(call_text)
    line_num = sink.get('coord', {}).get('line_num', graph[containing]['start_line'])
    line_in_func = max(1, line_num - graph[containing]['start_line'] + 1)
    sections = []
    traced = 0
    for arg in args:
        if traced >= max_args:
            break
        if classify(arg) != "identifier":
            continue
        hops = trace(root, graph, containing, arg, line_in_func)
        if hops:
            sections.append(f"Argument `{arg}`:\n" + render_evidence_for_llm(hops))
            traced += 1
    return "\n\n".join(sections) if sections else None
