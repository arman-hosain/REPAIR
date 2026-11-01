"""Name + arity static call graph over pipeline units (BLIND side).  Edges are caller -> callee unit ids.

Resolution of one invocation `recv.name(a1..ak)` / `new T(a1..ak)` made inside unit u:
    candidates = units whose bare method name == name and arity == k   (varargs units match any k >= arity-1)
                 constructors:  units named <init> of a class whose simple name == T
    receiver narrowing, best effort and syntactic only:
      no receiver / `this`      same-class candidates if any, else all candidates
      identifier with a type    type known from a local/parameter/field declaration -> candidates whose class simple name == type;
                                if that type has the method only as a bodiless (interface/abstract) declaration, widen to ALL
                                candidates (implementations); if the type is not in the codebase at all the call is EXTERNAL: no edge
      Capitalized/qualified     static call `Foo.bar()` -> same as a known type `Foo`
      call chain / unknown      all candidates
    then, for every kind of call: if several candidates remain, keep only those whose directory shares the LONGEST path prefix with the
    caller's file (package proximity: r4 code calls r4 classes, not the r2/r3/r5 copies); if more than CAP candidates still remain the
    call is dropped as over-broad (get, add, ...)
KNOWN GAPS (graph is an under- AND over-approximation; documented in notes/phase2_pipeline.md):
  * interfaces / abstract classes: an implementation is linked only when the call site's declared type or the name/arity heuristic
    reaches it; subtype relations are NOT computed
  * dependency injection / service locators (Spring @Autowired, OpenMRS Context.getXService()): the receiver type is a call chain,
    so the callee set is "all name+arity matches" or dropped when over-broad
  * reflection (Method.invoke, Class.forName, ServiceLoader), Spring @RequestMapping dispatch, servlet-container entry points,
    JSP/GSP -> Java calls, annotation processing, lambdas/method references as callbacks (the call inside a lambda is attributed to
    the enclosing unit; the lambda target is not an edge)
  * inherited methods called on a subclass-typed receiver whose class does not itself declare the method are treated as external
  * overloads with the same arity are indistinguishable (all candidates are linked)
Units with no in-slice caller are treated as externally callable by S3.
"""
import collections, gzip, hashlib, os, pickle, re

CAP = 20
HERE = os.path.dirname(os.path.abspath(__file__))
_STATIC = re.compile(r"^(?:[a-z_][\w]*\.)*([A-Z]\w*)$")          # Foo | pkg.Foo | a.b.Foo
_IDENT = re.compile(r"^[A-Za-z_]\w*$")


def _lcp(a, b):
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def _last(cls):
    return cls.rsplit(".", 1)[-1] if cls else ""


def build(cb, log=print):
    units = cb["units"]
    n = len(units)
    by_name = collections.defaultdict(list)                 # bare method name -> unit ids
    by_ctor = collections.defaultdict(list)                 # class simple name -> ctor unit ids
    for u in units:
        if u["arity"] < 0 or u["name"] == "(file scope)":
            continue
        if u["bare"] == "<init>":
            by_ctor[_last(u["cls"])].append(u["id"])
        elif u["bare"] and not u["bare"].startswith("<"):
            by_name[u["bare"]].append(u["id"])

    def arity_ok(j, k):
        v = units[j]
        return v["arity"] == k or (v.get("varargs") and k >= v["arity"] - 1)

    dirs = {f: tuple(f.split("/")[:-1]) for f in {u["file"] for u in units}}
    callers = [set() for _ in range(n)]
    callees = [set() for _ in range(n)]
    st = collections.Counter()
    for u in units:
        i = u["id"]
        fields = u.get("fields") or {}
        for c in u["calls"]:
            st["calls"] += 1
            k = len(c["args"])
            if c["k"] == "new":
                cands = [j for j in by_ctor.get(c["name"], ()) if arity_ok(j, k)]
                if not cands:
                    st["external"] += 1
                    continue
            else:
                cands = [j for j in by_name.get(c["name"], ()) if arity_ok(j, k)]
                if not cands:
                    st["external"] += 1
                    continue
                recv = c["recv"].strip()
                typ = None
                if recv in ("", "this"):
                    same = [j for j in cands if units[j]["cls"] == u["cls"]]
                    cands = same or cands
                elif recv == "super":
                    pass
                elif _IDENT.match(recv):
                    typ = u["types"].get(recv) or (fields.get(recv) or {}).get("type") or (recv if recv[:1].isupper() else None)
                elif _STATIC.match(recv):
                    typ = _STATIC.match(recv).group(1)
                if typ:
                    r = [j for j in cands if _last(units[j]["cls"]) == typ]
                    if not r:
                        st["external"] += 1                       # declared type is not (a class of) this codebase
                        continue
                    cands = r if any(units[j]["has_body"] for j in r) else [j for j in by_name[c["name"]] if arity_ok(j, k)]
            if len(cands) > 20 * CAP:                                # hopelessly generic name (cheap prune before the proximity pass)
                st["overbroad"] += 1
                continue
            if len(cands) > 1:                                       # package proximity, then the over-broad cap
                cd = dirs[u["file"]]
                best = max(_lcp(cd, dirs[units[j]["file"]]) for j in cands)
                cands = [j for j in cands if _lcp(cd, dirs[units[j]["file"]]) == best]
            if len(cands) > CAP:
                st["overbroad"] += 1
                continue
            st["resolved"] += 1
            for j in cands:
                if j != i:
                    callees[i].add(j)
                    callers[j].add(i)
    st["edges"] = sum(len(s) for s in callees)
    log(f"[callgraph] {dict(st)}")
    return dict(callers=callers, callees=callees, stats=dict(st))


def load(cb, log=print, use_cache=True):
    me = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()[:8]
    cp = os.path.join(HERE, "cache", f"{cb['key']}.cg{me}.pkl.gz")
    if use_cache and os.path.exists(cp):
        log(f"[callgraph] cache hit {os.path.basename(cp)}")
        return pickle.load(gzip.open(cp, "rb"))
    cg = build(cb, log)
    os.makedirs(os.path.dirname(cp), exist_ok=True)
    pickle.dump(cg, gzip.open(cp + ".tmp", "wb", compresslevel=3))
    os.replace(cp + ".tmp", cp)
    return cg
