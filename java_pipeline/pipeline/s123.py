"""S1 / S2 / S3 candidate flags for Java units (BLIND side).

    (Stage 1: Sink Identification, Stage 2: Candidate Validation, Stage 3: Path Analysis)

    FLAGS ONLY - nothing is deleted, so recall can be reported after every stage.
    sink rules (22, 94, 611, 79):   S1 = the unit contains a rule sink          (a .gsp template is a file-scope unit)
                                    S2 = some sink is unsafe: its dangerous argument is dynamic (not a literal, constant or
                                         neutralised value; one level of local `x = ...` resolution, depth <= 3), or - for
                                         "missing hardening" sinks - no hardening vocabulary appears in the unit
    pred rules (20):                S1 = every `op_all` regex matches the unit
                                    S2 = S1 and no guard vocabulary in the unit and not every in-slice caller chain is guarded
    S3 (all kinds)                  S2 and (the unit has a request/data source itself, or is reachable in the call graph from
                                    a unit that has one; units with no in-slice caller are kept as "externally callable")
Rules are declarative JSON in pipeline/rules/ (frozen by sha256 in notes/ before any scored run).
"""
import collections, hashlib, json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(HERE, "rules")
FILE_SCOPE = "(file scope)"
_IDENT = re.compile(r"^[A-Za-z_]\w*$")
_STATIC = re.compile(r"^(?:[a-z_]\w*\.)*([A-Z]\w*)$")
_CALL = re.compile(r"^(?:(?P<recv>.+)\.)?(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)$", re.S)
_NEW = re.compile(r"^new\s+[\w.$<>\[\], ?]+\s*\((?P<args>.*)\)\s*$", re.S)
_LIT = re.compile(r"""^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|-?\d[\w.]*|true|false|null|\"\"\"[\s\S]*\"\"\")$""")
_PASS = {"toString", "valueOf", "trim", "strip", "toLowerCase", "toUpperCase", "substring", "replace", "replaceAll", "replaceFirst",
         "concat", "format", "formatted", "join", "getPath", "getAbsolutePath", "toPath", "toFile", "toURI", "append", "toURL", "normalize"}


def rules_files():
    return sorted(os.path.join(RULES_DIR, f) for f in os.listdir(RULES_DIR) if f.endswith(".json"))


def flag_files():
    """every file whose content can change an S1/S2/S3 flag: rules + extractor + call graph + engine + the java unit plugin"""
    return rules_files() + [os.path.join(HERE, f) for f in ("units.py", "callgraph.py", "s123.py")] + \
        [os.path.join(os.path.dirname(HERE), "core/plugins/java.py")]


def sha_manifest(files=None):
    """{relative file -> sha256}; default = the flag-affecting files (this is what notes/java_rules_freeze.json pins)"""
    base = os.path.dirname(HERE)
    return {os.path.relpath(f, base): hashlib.sha256(open(f, "rb").read()).hexdigest() for f in (files or flag_files()) if os.path.exists(f)}


class Rule:
    def __init__(self, cwe):
        self.common = json.load(open(os.path.join(RULES_DIR, "_common.json")))
        self.d = json.load(open(os.path.join(RULES_DIR, f"{cwe}.json")))
        self.cwe, self.kind = cwe, self.d["kind"]
        c = self.common
        self.const = re.compile(c["constants"])
        self.safe_num = re.compile(c["safe_numeric"])
        self.safe_call = re.compile(self.d.get("safe_call_names", r"^$"))
        src = c["input"] + (("|" + c[self.d["source_extra"]]) if self.d.get("source_extra") else "")
        self.source = re.compile(self.d.get("source", src))
        self.guard = re.compile(self.d["guard"]) if self.d.get("guard") else None
        self.unless = re.compile(self.d["unless"]) if self.d.get("unless") else None
        self.sinks = [dict(s, _n=re.compile(s["name"]) if "name" in s else None, _rt=re.compile(s["recv_type"]) if "recv_type" in s else None,
                           _rh=re.compile(s["recv_hint"]) if "recv_hint" in s else None, _r=re.compile(s["recv"]) if "recv" in s else None,
                           _u=re.compile(s["unless"]) if s.get("unless") else None, _fmt=re.compile(s["fmt"]) if s.get("fmt") else None,
                           _cc=re.compile(s["concat"]) if s.get("concat") else None) for s in self.d.get("sinks", [])]
        g = self.d.get("gsp")
        self.gsp = None if not g else dict(expr=[re.compile(x, re.S) for x in g["expr"]], safe=[re.compile(x) for x in g["safe"]])
        self.op_all = [re.compile((c["input"] + "|" + c["handler"]) if x == "@input_or_handler" else x) for x in self.d.get("op_all", [])]


# ----------------------------------------------------------------------------- expression analysis
def split_top(e, ch):
    out, depth, q, cur, i = [], 0, None, "", 0
    while i < len(e):
        c = e[i]
        if q:
            cur += c
            if c == "\\" and i + 1 < len(e):
                cur += e[i + 1]; i += 1
            elif c == q:
                q = None
        elif c in "\"'":
            q = c; cur += c
        elif c in "([{":
            depth += 1; cur += c
        elif c in ")]}":
            depth -= 1; cur += c
        elif c == ch and depth == 0:
            out.append(cur); cur = ""
        else:
            cur += c
        i += 1
    out.append(cur)
    return out


def dyn(e, u, R, depth=0, seen=frozenset()):
    """True if the expression may carry an attacker-influenced / non-constant value"""
    e = e.strip()
    if not e or depth > 3:
        return depth > 3
    while e.startswith("(") and e.endswith(")") and _balanced(e[1:-1]):
        e = e[1:-1].strip()
    m = re.match(r"^\(\s*[A-Za-z_][\w.<>\[\], ]*\)\s*(.+)$", e, re.S)         # cast
    if m and not _CALL.match(e):
        return dyn(m.group(1), u, R, depth, seen)
    if _LIT.match(e):
        return False
    parts = split_top(e, "+")
    if len(parts) > 1:
        return any(dyn(p, u, R, depth, seen) for p in parts)
    q = split_top(e, "?")
    if len(q) == 2 and ":" in q[1]:
        a, b = split_top(q[1], ":")[:2]
        return dyn(a, u, R, depth, seen) or dyn(b, u, R, depth, seen)
    if R.const.match(e):
        return False
    if e.startswith("this.") and _IDENT.match(e[5:]):
        e = e[5:]
    if _IDENT.match(e):
        if e in seen:
            return False
        names = set(u.get("param_names", ()))
        if e in names:
            return True
        asg = u["assigns"].get(e)
        if asg:
            return any(dyn(x, u, R, depth + 1, seen | {e}) for x in asg)
        f = (u.get("fields") or {}).get(e)
        if f and f["final"] and f["value"] is not None:
            return dyn(f["value"], u, R, depth + 1, seen | {e})
        return True
    mn = _NEW.match(e)
    if mn:
        a = [x for x in split_top(mn.group("args"), ",") if x.strip()]
        return any(dyn(x, u, R, depth + 1, seen) for x in a)
    mc = _CALL.match(e)
    if mc and _balanced(mc.group("args")):
        name, recv = mc.group("name"), (mc.group("recv") or "")
        if R.safe_num.match(name) or R.safe_call.match(name):
            return False
        if name in _PASS:
            a = [x for x in split_top(mc.group("args"), ",") if x.strip()]
            return (bool(recv) and dyn(recv, u, R, depth + 1, seen)) or any(dyn(x, u, R, depth + 1, seen) for x in a)
        return True
    return True


def _balanced(s):
    d = 0
    for c in s:
        d += (c in "([{") - (c in ")]}")
        if d < 0:
            return False
    return d == 0


def trace_call_origin(e, u, R, depth=0, seen=frozenset()):
    """Resolve `e` the same way dyn() does (literals/casts/concat/ternary/local reassignment/
    pass-through calls), but instead of a yes/no answer, return the bare name of the innermost
    method call the value is traced back to -- or None if it bottoms out in something that is
    not a call (a parameter, a field, a `new`, or an unresolvable expression). This is what lets
    S1 catch a sink's *caller* even when the sink argument is not the result of a call made
    directly at the sink site but of a helper method several assignments upstream, e.g.
    `path = getPathForResource(name); new File(base, path)` -- the helper itself may contain no
    sink call of its own and would otherwise be invisible to Stage 1."""
    e = e.strip()
    if not e or depth > 3:
        return None
    while e.startswith("(") and e.endswith(")") and _balanced(e[1:-1]):
        e = e[1:-1].strip()
    m = re.match(r"^\(\s*[A-Za-z_][\w.<>\[\], ]*\)\s*(.+)$", e, re.S)
    if m and not _CALL.match(e):
        return trace_call_origin(m.group(1), u, R, depth, seen)
    if _LIT.match(e) or R.const.match(e):
        return None
    parts = split_top(e, "+")
    if len(parts) > 1:
        for p in parts:
            o = trace_call_origin(p, u, R, depth, seen)
            if o:
                return o
        return None
    q = split_top(e, "?")
    if len(q) == 2 and ":" in q[1]:
        a, b = split_top(q[1], ":")[:2]
        return trace_call_origin(a, u, R, depth, seen) or trace_call_origin(b, u, R, depth, seen)
    if e.startswith("this.") and _IDENT.match(e[5:]):
        e = e[5:]
    if _IDENT.match(e):
        if e in seen:
            return None
        asg = u["assigns"].get(e)
        if asg:
            for x in asg:
                o = trace_call_origin(x, u, R, depth + 1, seen | {e})
                if o:
                    return o
            return None
        return None                                                  # parameter / field / unresolved -- not a call origin
    mc = _CALL.match(e)
    if mc and _balanced(mc.group("args")):
        name, recv = mc.group("name"), (mc.group("recv") or "")
        if name in _PASS:
            if recv:
                o = trace_call_origin(recv, u, R, depth + 1, seen)
                if o:
                    return o
            for x in split_top(mc.group("args"), ","):
                o = trace_call_origin(x, u, R, depth + 1, seen)
                if o:
                    return o
            return None
        return name
    return None


def recv_type(c, u):
    r = c["recv"].strip()
    if not r:
        return None
    if r.startswith("this.") and _IDENT.match(r[5:]):
        r = r[5:]
    if _IDENT.match(r):
        t = u["types"].get(r) or ((u.get("fields") or {}).get(r) or {}).get("type")
        return t or (r if r[:1].isupper() else None)
    m = _STATIC.match(r)
    return m.group(1) if m else None


def spec_match(s, c, u):
    if "k" in s and s["k"] != c["k"]:
        return False
    if s["_n"] is not None and not s["_n"].search(c["name"]):
        return False
    if s["_rt"] is None and s["_r"] is None and s["_rh"] is None:
        return True
    rt, rtxt = recv_type(c, u), c["recv"]
    if s["_rt"] is not None and rt and s["_rt"].search(rt):
        return True
    if s["_r"] is not None and s["_r"].search(rtxt):
        return True
    if s["_rh"] is not None and (rt is None or s["_rt"] is None) and s["_rh"].search(rtxt):
        return True
    return False


def eval_sink_unit(R, u):
    """-> (total, bad, [descriptors])"""
    total = bad = 0
    desc = []
    unit_guard = bool(R.unless and R.unless.search(u["text"]))
    if u["name"] == FILE_SCOPE and not u["file"].endswith(".java"):
        if R.gsp is None:
            return 0, 0, []
        txt = u["text"]
        for rx in R.gsp["expr"]:
            for m in rx.finditer(txt):
                total += 1
                ex = m.group(1)
                if not any(s.search(ex) for s in R.gsp["safe"]):
                    bad += 1
                    if len(desc) < 6:
                        desc.append(dict(id="gsp-expr", line=txt.count("\n", 0, m.start()) + 1, expr=ex.strip()[:80], dyn=True))
        return total, bad, desc
    for s in R.sinks:
        if s["_cc"] is not None:                                             # string concatenation that builds markup
            for cc in u["concats"]:
                if any(s["_cc"].search(l) for l in cc["lits"]) and cc["dyn"]:
                    total += 1
                    d = any(dyn(x, u, R) for x in cc["dyn"])
                    bad += d
                    if len(desc) < 6:
                        desc.append(dict(id=s["id"], line=cc["line"], dyn=d))
            continue
        for c in u["calls"]:
            if not spec_match(s, c, u):
                continue
            args = c["args"]
            if s["_fmt"] is not None:
                if not args or not _LIT.match(args[0].strip()) or not s["_fmt"].search(args[0]):
                    continue
                sel = args[1:]
            else:
                a = s.get("args", "*")
                sel = args if a == "*" else [args[i] for i in a if i < len(args)]
            total += 1
            if s.get("dyn", True):
                d = any(dyn(x, u, R) for x in sel) if sel else False
            else:
                d = True                                                      # "missing hardening" sink: unsafe unless guarded
            guarded = unit_guard or bool(s["_u"] and s["_u"].search(u["text"]))      # rule-level / spec-level hardening seen in the unit
            bad += bool(d and not guarded)
            origin = None
            if d and not guarded and sel:
                for x in sel:
                    origin = trace_call_origin(x, u, R)
                    if origin:
                        break
            if len(desc) < 6:
                desc.append(dict(id=s["id"], line=c["line"], name=c["name"], dyn=bool(d), guarded=bool(guarded), origin=origin))
    return total, bad, desc


# ----------------------------------------------------------------------------- stages
def run(cb, cg, cwe, log=print):
    """-> (records for every S1 unit, stats).  record: id, file, function, line_start, line_end, test, s1, s2, s3, guarded, sinks, bad, via"""
    R = Rule(cwe)
    units, callers, callees = cb["units"], cg["callers"], cg["callees"]
    n = len(units)
    s1, s2, guarded, desc, nsink, nbad = [False] * n, [False] * n, [False] * n, [None] * n, [0] * n, [0] * n
    if R.kind == "sink":
        for u in units:
            i = u["id"]
            t, b, d = eval_sink_unit(R, u)
            s1[i], s2[i], nsink[i], nbad[i], desc[i] = t > 0, b > 0, t, b, d
            guarded[i] = bool(R.guard and R.guard.search(u["text"])) if t else False
    else:
        for u in units:
            i = u["id"]
            if u["name"] == FILE_SCOPE and not u["file"].endswith(".java"):
                continue
            s1[i] = all(r.search(u["text"]) for r in R.op_all)
            guarded[i] = bool(R.guard and R.guard.search(u["text"]))
        if R.d.get("propagate"):                                               # guarded if every in-slice caller is (cycles stay unguarded)
            pend = [len(callers[i]) for i in range(n)]
            q = collections.deque(i for i in range(n) if guarded[i])
            while q:
                g = q.popleft()
                for c in callees[g]:
                    pend[c] -= 1
                    if pend[c] == 0 and not guarded[c] and callers[c]:
                        guarded[c] = True
                        q.append(c)
        for i in range(n):
            s2[i] = s1[i] and not guarded[i]
    reach = [bool(R.source.search(u["text"])) or not callers[u["id"]] for u in units]
    q = collections.deque(i for i in range(n) if reach[i])
    while q:
        g = q.popleft()
        for c in callees[g]:
            if not reach[c]:
                reach[c] = True
                q.append(c)
    # --- return-taint propagation: a unit with no sink of its own (s1 False) whose return value
    # is the traced origin of a *bad* sink argument in one of its callers is still a real
    # candidate -- Stage 1's unit-local sink matching alone would miss it entirely (see
    # trace_call_origin's docstring for the motivating example). Flag it synthetically: s1/s2
    # are set from the caller's own already-validated bad verdict, not re-derived, since the
    # callee's own text has no sink to evaluate.
    by_name = collections.defaultdict(list)
    for u in units:
        bare = u.get("bare")
        if bare and not bare.startswith("<"):
            by_name[bare].append(u["id"])
    return_taint = {}                                                    # callee unit id -> desc dict
    if R.kind == "sink":
        for u in units:
            i = u["id"]
            if not s1[i] or not desc[i]:
                continue
            for d in desc[i]:
                origin = d.get("origin")
                if not origin or origin not in by_name:
                    continue
                cands = [j for j in by_name[origin] if j in callees[i] and not s1[j]]
                for j in cands:
                    if j not in return_taint:
                        return_taint[j] = dict(id="return-taint", line=units[j]["start"], name=origin,
                                               dyn=True, guarded=False, via_caller=u["name"], via_line=d.get("line"))
    recs = []
    for u in units:
        i = u["id"]
        if not s1[i] and i not in return_taint:
            continue
        has_src = bool(R.source.search(u["text"]))
        if i in return_taint:
            rt = return_taint[i]
            recs.append(dict(id=i, file=u["file"], function=u["name"], line_start=u["start"], line_end=u["end"], test=u["test"], s1=True,
                             s2=True, s3=bool(reach[i]), guarded=False, sinks=1, bad=1, desc=[rt],
                             own_source=has_src, callers=len(callers[i]),
                             via=f"return-taint(caller={rt['via_caller']}:{rt['via_line']})"))
            continue
        recs.append(dict(id=i, file=u["file"], function=u["name"], line_start=u["start"], line_end=u["end"], test=u["test"], s1=True,
                         s2=s2[i], s3=bool(s2[i] and reach[i]), guarded=guarded[i], sinks=nsink[i], bad=nbad[i], desc=desc[i] or [],
                         own_source=has_src, callers=len(callers[i]), via=("own-source" if has_src else ("no-caller" if not callers[i] else "caller-chain"))))
    stats = dict(cwe=cwe, units_total=n, s1=sum(s1), s2=sum(s2), s3=sum(r["s3"] for r in recs), return_taint=len(return_taint))
    return recs, stats
