"""Stage 4 (Evidence Tracing / parameter-origin tracer) for Java units (BLIND side).

Ported from the C/C++ pipeline's design (sink-pipeline/param_tracer.py), adapted to Java and to the
infrastructure this pipeline already builds: unit extraction (pipeline/units.py: per-unit `assigns`,
`types`, `param_names`, `calls`) and the name+arity call graph (pipeline/callgraph.py: `callers`/`callees`
keyed by unit id).

What it does
------------
For a flagged sink call such as `new FileOutputStream(path)`, it traces where the dangerous argument's
VALUE comes from: a local reassignment inside the same unit, or -- if the variable is itself a method
parameter -- interprocedurally up through the unit's callers in the call graph, substituting the matching
call-site argument and continuing from there. It is deterministic: no LLM is involved, and it never labels
anything tainted, safe or exploitable -- it only reports facts about where a value textually originates,
and leaves the verdict to the LLM (see `render_evidence_for_llm` below and its use in `stage5.build_prompt`).

Mirrors the C/C++ version's stop rules: max depth, max callers explored per hop, max total nodes, cycle
detection on (unit_id, variable). Also mirrors its classification scheme (constant / bare identifier /
call / field access / array index / complex), adapted to Java: `recv.field` instead of `recv->field`,
`arr[i]` is identical, and a Java method call is classified the same way a C function call is.
"""
import re

from pipeline.s123 import _IDENT, _CALL, _NEW, _LIT, split_top

MAX_DEPTH = 5
MAX_CALLERS_PER_HOP = 5
MAX_NODES = 60

FILE_SCOPE = "(file scope)"

_ARRAY_INDEX = re.compile(r"^(?P<recv>.+)\[(?P<idx>.*)\]$", re.S)
_FIELD = re.compile(r"^(?P<recv>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.(?P<field>[A-Za-z_]\w*)$")
# names whose return value is "the same data, reshaped" -- worth continuing through, same spirit as the
# Java sink rules' own treatment of these calls as taint-preserving (s123._PASS)
_PASS_THROUGH = {"toString", "valueOf", "trim", "strip", "toLowerCase", "toUpperCase", "substring", "replace",
                 "replaceAll", "replaceFirst", "concat", "format", "formatted", "join", "getPath",
                 "getAbsolutePath", "toPath", "toFile", "toURI", "append", "toURL", "normalize", "getName"}


def classify(expr):
    """-> (kind, detail). kind in constant|bare_identifier|function_call|field_access|array_index|complex."""
    e = expr.strip()
    if not e:
        return "complex", "(empty expression)"
    if _LIT.match(e):
        return "constant", e[:60]
    if _IDENT.match(e):
        return "bare_identifier", e
    m = _ARRAY_INDEX.match(e)
    if m and _balanced(m.group("recv")) and _balanced(m.group("idx")):
        return "array_index", e[:80]
    m = _NEW.match(e)
    if m:
        return "function_call", e[:80]
    m = _CALL.match(e)
    if m and _balanced(m.group("args") or ""):
        return "function_call", e[:80]
    m = _FIELD.match(e)
    if m:
        return "field_access", e[:80]
    return "complex", e[:80]


def _balanced(s):
    d = 0
    for c in s:
        d += (c in "([{") - (c in ")]}")
        if d < 0:
            return False
    return d == 0


def _first_bare_identifier_arg(expr):
    """For a function_call expression, the argument worth descending into: the first bare-identifier
    argument (mirrors the C tracer's 'keep tracing via the first bare-identifier argument'). None if the
    call has no such argument (e.g. all arguments are literals, or it is a receiver-only call like
    `.toString()` with no arguments -- in that case the receiver is the better thing to trace)."""
    m = _CALL.match(expr.strip())
    if m:
        args = [a.strip() for a in split_top(m.group("args") or "", ",") if a.strip()]
        for a in args:
            if _IDENT.match(a):
                return a
        recv = (m.group("recv") or "").strip()
        if recv and m.group("name") in _PASS_THROUGH and _IDENT.match(recv):
            return recv
        return None
    m = _NEW.match(expr.strip())
    if m:
        args = [a.strip() for a in split_top(m.group("args") or "", ",") if a.strip()]
        for a in args:
            if _IDENT.match(a):
                return a
    return None


def _local_assignment(u, var):
    """-> last recorded assignment RHS text for `var` inside unit `u`, or None.
    `units.py` records every `var = <rhs>` (declaration or reassignment) it sees in source order; the last
    entry is the closest thing to 'the last assignment before the sink line' available from that structure
    without re-walking the AST."""
    hist = (u.get("assigns") or {}).get(var)
    return hist[-1] if hist else None


def _is_parameter(u, var):
    return var in (u.get("param_names") or [])


_RETURN = re.compile(r"\breturn\s+([^;]+);")


def _unit_return_exprs(u, limit=3):
    """-> up to `limit` `return <expr>;` expressions found textually in the unit's own body (not in a
    nested anonymous class/lambda -- those would need real scoping to attribute correctly, so this is a
    best-effort regex scan, consistent with the rest of this file's syntactic approach). Used to descend
    INTO a called unit when tracing a call with no bare-identifier argument to continue through on the
    caller's side -- e.g. `path = getPathForResource(mod, name)` where the helper builds its return value
    from string concatenation, not from one of its own parameters directly passed through."""
    out = []
    for m in _RETURN.finditer(u.get("text") or ""):
        e = m.group(1).strip()
        if e and e not in out:
            out.append(e)
        if len(out) >= limit:
            break
    return out


def _resolve_callee_unit(cb, cg, caller_unit_id, call_name, k):
    """-> unit id of a same-codebase method this call site could be invoking, or None. Reuses the call
    graph edges already computed from this exact call site (cg["callees"][caller_unit_id]) rather than
    re-resolving receiver types, so it only ever follows an edge the call graph itself already trusts."""
    for j in cg["callees"][caller_unit_id]:
        cu = cb["units"][j]
        if cu.get("bare") == call_name and (cu["arity"] == k or (cu.get("varargs") and k >= cu["arity"] - 1)):
            return j
    return None


def _find_call_site_args(caller_unit, callee_unit, k, limit=MAX_CALLERS_PER_HOP):
    """-> list of (args list) for call sites in `caller_unit` that could plausibly be invoking `callee_unit`
    (bare name matches, arity matches or is a varargs fit). Up to `limit` call sites, mirroring the C
    tracer's 'up to 2 literal call sites per caller' (here capped a little higher since Java overloads on
    name+arity are already disambiguated by the call graph that produced this edge)."""
    name = callee_unit["bare"]
    out = []
    for c in caller_unit.get("calls", []):
        if c["name"] != name:
            continue
        nargs = len(c["args"])
        if nargs == k or (callee_unit.get("varargs") and nargs >= k - 1):
            out.append(c["args"])
        if len(out) >= limit:
            break
    return out


def trace(cb, cg, start_unit_id, start_var, max_depth=MAX_DEPTH, max_callers=MAX_CALLERS_PER_HOP, max_nodes=MAX_NODES):
    """-> list of hop dicts, root first. Each hop:
      {depth, unit, kind, detail, note}                              -- a classification step, or
      {depth, unit, ascend_to: [{caller_unit, via_arg, note}, ...]}   -- an interprocedural ascent (fan-out)
    Stops on: constant / field_access / array_index / complex (nothing left to trace), a parameter with no
    resolvable caller, max depth, max nodes, or a (unit_id, var) cycle.
    """
    units = cb["units"]
    hops = []
    seen = set()
    nodes = [0]

    def _resolve_call_target(unit_id, expr):
        m = _CALL.match(expr.strip())
        if not m or not _balanced(m.group("args") or ""):
            return None
        args = [a for a in split_top(m.group("args") or "", ",") if a.strip()]
        return _resolve_callee_unit(cb, cg, unit_id, m.group("name"), len(args))

    def walk_into_callee(callee_id, depth):
        """Descend into a called unit's own return value when the caller side gives us nothing left to
        trace (no bare-identifier argument) -- this is what lets the tracer follow a helper method like
        `getPathForResource(mod, name)` into its own `return base + File.separator + ...` body instead of
        stopping at the call site, mirroring the Stage-1 return-taint propagation in s123.py."""
        if nodes[0] >= max_nodes:
            hops.append(dict(depth=depth, unit=units[callee_id]["name"], kind="stop", note="trace budget exhausted (max nodes reached)"))
            return
        rets = _unit_return_exprs(units[callee_id])
        if not rets:
            hops.append(dict(depth=depth, unit=units[callee_id]["name"], kind="stop",
                              note=f"{units[callee_id]['name']} has no `return` statement found by this scan -- not traced further "
                                   f"(void method, early-return-only via other control flow, or a return inside a nested lambda/class)"))
            return
        hops.append(dict(depth=depth, unit=units[callee_id]["name"], kind="descend",
                          note=f"-> descending into {units[callee_id]['name']}'s own return value"))
        walk(callee_id, rets[0], depth + 1, is_var=False)

    def walk(unit_id, var_or_expr, depth, is_var):
        if nodes[0] >= max_nodes:
            hops.append(dict(depth=depth, unit=units[unit_id]["name"], kind="stop", note="trace budget exhausted (max nodes reached)"))
            return
        nodes[0] += 1
        u = units[unit_id]
        key = (unit_id, var_or_expr, is_var)
        if key in seen:
            hops.append(dict(depth=depth, unit=u["name"], kind="stop", note=f"cycle detected on ({u['name']!r}, {var_or_expr!r})"))
            return
        seen.add(key)
        if depth > max_depth:
            hops.append(dict(depth=depth, unit=u["name"], kind="stop", note="max trace depth reached"))
            return

        if is_var:
            rhs = _local_assignment(u, var_or_expr)
            if rhs is not None:
                hops.append(dict(depth=depth, unit=u["name"], kind="local_assignment", detail=f"{var_or_expr} = {rhs.strip()[:80]}"))
                walk(unit_id, rhs, depth + 1, is_var=False)
                return
            if _is_parameter(u, var_or_expr):
                pos = (u.get("param_names") or []).index(var_or_expr)
                callers = sorted(cg["callers"][unit_id])
                if not callers:
                    hops.append(dict(depth=depth, unit=u["name"],
                                      note=f"{var_or_expr} is parameter #{pos} with no caller in the analyzed codebase "
                                           f"(externally callable, or reflection/framework-dispatched)"))
                    return
                fan = []
                for cu_id in callers[:max_callers]:
                    cu = units[cu_id]
                    sites = _find_call_site_args(cu, u, u["arity"])
                    if not sites:
                        fan.append(dict(caller_unit=cu["name"], note="caller found by the call graph but no matching literal call site "
                                                                      "located in its own text (indirect/variable call target, or arity mismatch)"))
                        continue
                    for args in sites:
                        if pos >= len(args):
                            continue
                        fan.append(dict(caller_unit=cu["name"], via_arg=args[pos].strip()[:80]))
                note = f"{var_or_expr} is parameter #{pos} of {u['name']}; {len(callers)} caller(s) in the analyzed codebase" + \
                       ("" if len(callers) <= max_callers else f" (showing {max_callers})")
                hops.append(dict(depth=depth, unit=u["name"], kind="ascend", note=note, ascend_to=fan))
                for f in fan:
                    if "via_arg" in f and nodes[0] < max_nodes:
                        cu_id = next(cid for cid in callers if units[cid]["name"] == f["caller_unit"])
                        walk(cu_id, f["via_arg"], depth + 1, is_var=False)
                return
            hops.append(dict(depth=depth, unit=u["name"], kind="stop",
                              note=f"{var_or_expr} is not a local variable with a recorded assignment, and not a declared parameter "
                                   f"of {u['name']} -- likely a field, a loop/catch variable, or an unresolved lvalue"))
            return

        expr = var_or_expr.strip()
        kind, detail = classify(expr)
        if kind == "bare_identifier":
            walk(unit_id, detail, depth, is_var=True)   # same depth: classifying isn't a hop by itself
            return
        if kind == "function_call":
            # prefer descending into an in-codebase callee's own return value over grabbing the
            # first bare-identifier argument -- the first argument is often an unrelated object
            # (a receiver-like parameter, e.g. `getPathForResource(module, maliciousPath)`'s
            # `module`) while the real taint-relevant logic lives inside the callee itself.
            callee_id = _resolve_call_target(unit_id, expr)
            if callee_id is not None and _unit_return_exprs(units[callee_id]):
                hops.append(dict(depth=depth, unit=u["name"], kind="function_call", detail=detail))
                walk_into_callee(callee_id, depth + 1)
                return
            inner = _first_bare_identifier_arg(expr)
            if inner is None:
                hops.append(dict(depth=depth, unit=u["name"], kind="stop",
                                  note=f"-> {detail} is a method call with no bare-identifier argument to continue tracing "
                                       f"(result of a computation, or a no-argument call) -- not traced further"))
                return
            hops.append(dict(depth=depth, unit=u["name"], kind="function_call", detail=detail))
            walk(unit_id, inner, depth + 1, is_var=True)
            return
        if kind == "field_access":
            hops.append(dict(depth=depth, unit=u["name"], kind="stop", note=f"-> {detail} is a field access -- not traced further (field-level tracing out of scope)"))
            return
        if kind == "array_index":
            hops.append(dict(depth=depth, unit=u["name"], kind="stop", note=f"-> {detail} is an array/index access -- not traced further"))
            return
        if kind == "constant":
            hops.append(dict(depth=depth, unit=u["name"], kind="constant", detail=detail))
            return
        hops.append(dict(depth=depth, unit=u["name"], kind="stop", note=f"-> {detail} is a complex expression (cast, ternary, arithmetic, lambda, ...) -- not traced further"))

    walk(start_unit_id, start_var, 0, is_var=True)
    return hops


def trace_sink_arg(cb, cg, unit_id, expr):
    """Entry point for a sink's actual argument text (not necessarily a bare variable, e.g. `new File(base, name)`'s
    second argument might itself be `entry.getName()`). Classifies first, then traces."""
    kind, detail = classify(expr)
    if kind == "bare_identifier":
        return trace(cb, cg, unit_id, detail)
    if kind == "function_call":
        root = [dict(depth=0, unit=cb["units"][unit_id]["name"], kind="function_call", detail=detail[:80])]
        m = _CALL.match(expr.strip())
        callee_id = None
        if m and _balanced(m.group("args") or ""):
            args = [a for a in split_top(m.group("args") or "", ",") if a.strip()]
            callee_id = _resolve_callee_unit(cb, cg, unit_id, m.group("name"), len(args))
        rets = _unit_return_exprs(cb["units"][callee_id]) if callee_id is not None else []
        if rets:
            root.append(dict(depth=1, unit=cb["units"][callee_id]["name"], kind="descend",
                              note=f"-> descending into {cb['units'][callee_id]['name']}'s own return value"))
            return root + trace_sink_arg(cb, cg, callee_id, rets[0])
        inner = _first_bare_identifier_arg(expr)
        if inner is None:
            root.append(dict(depth=1, unit=cb["units"][unit_id]["name"], kind="stop",
                              note=f"-> {detail[:80]} is a method call with no bare-identifier argument to continue tracing"))
            return root
        return root + trace(cb, cg, unit_id, inner)
    if kind in ("constant", "field_access", "array_index", "complex"):
        note = {"constant": None, "field_access": "field access", "array_index": "array/index access", "complex": "complex expression"}[kind]
        h = dict(depth=0, unit=cb["units"][unit_id]["name"], kind=kind, detail=detail[:80])
        if note:
            h["note"] = f"-> not traced further ({note})"
        return [h]
    return [dict(depth=0, unit=cb["units"][unit_id]["name"], kind="stop", detail=detail[:80])]


# ----------------------------------------------------------------------------- render for the LLM prompt
def render_evidence_for_llm(hops):
    """Flatten a hop list into plain prose, one line per hop -- the format injected into the Stage-4
    research prompt. Returns "" if there is nothing worth showing (a bare constant with one hop)."""
    if not hops:
        return ""
    lines = []
    for h in hops:
        indent = "  " * h["depth"]
        if h.get("kind") == "local_assignment":
            lines.append(f"{indent}`{h['detail']}` (local reassignment in {h['unit']})")
        elif h.get("kind") == "function_call":
            lines.append(f"{indent}`{h['detail']}` is a method call in {h['unit']}; continuing via its first identifier argument")
        elif h.get("kind") == "descend":
            lines.append(f"{indent}{h['note']}")
        elif h.get("kind") == "constant":
            lines.append(f"{indent}`{h['detail']}` is a literal/constant -- trace ends here")
        elif h.get("kind") == "ascend":
            lines.append(f"{indent}{h['note']}:")
            for f in h.get("ascend_to", []):
                if "via_arg" in f:
                    lines.append(f"{indent}  called from {f['caller_unit']}, passing `{f['via_arg']}`")
                else:
                    lines.append(f"{indent}  {f['caller_unit']}: {f['note']}")
        elif h.get("kind") == "stop" or "note" in h:
            lines.append(f"{indent}{h.get('note', '(stopped)')}")
        else:
            lines.append(f"{indent}{h}")
    return "\n".join(lines)


def trace_unit_sinks(cb, cg, u, descs, max_sinks=3):
    """Convenience wrapper for stage5.build_prompt: traces up to `max_sinks` of the unit's flagged sink
    arguments (from the S1/S2 descriptors already computed by s123.eval_sink_unit) and renders them as one
    combined prose block, or "" if there is nothing to trace (no descriptors, or every sink's args were
    already constants with nothing to say)."""
    blocks = []
    for d in (descs or [])[:max_sinks]:
        line, name = d.get("line"), d.get("name")
        if line is None or name is None:
            continue
        call = next((c for c in u.get("calls", []) if c["line"] == line and c["name"] == name), None)
        if call is None or not call["args"]:
            continue
        for idx, arg in enumerate(call["args"]):
            hops = trace_sink_arg(cb, cg, u["id"], arg)
            prose = render_evidence_for_llm(hops)
            if prose and not (len(hops) == 1 and hops[0].get("kind") == "constant"):
                blocks.append(f"Argument {idx} of `{name}(...)` at line {line}:\n{prose}")
    return "\n\n".join(blocks)
