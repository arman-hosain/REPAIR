"""Unit extraction for the Java pipeline (BLIND side: input = codebase path only; see CLAUDE.md rule 7).

Unit NAMES and SPANS come from core.plugins.java (the same code the scorer uses), so a pipeline unit key equals a scorer key
exactly.  Per-unit FEATURES (own text with comments blanked, invocations, local variable types, assignments, string
concatenations) come from a second tree-sitter pass; each feature is attributed to the smallest enclosing unit.

A unit is one of
    method / constructor / initializer   name from the plugin, e.g. "ModuleUtil.getPathForResource(Module,String)"
    "(file scope)"                       one per scorable file (.java: code outside every unit; .gsp: the whole template)
Unit text ("own text") has every nested unit (anonymous-class methods, local classes' methods) blanked, so each source line
belongs to exactly one unit and a sink is never counted twice.

Results are cached per repo@ref (basename of the codebase directory + HEAD commit + extractor hash) under pipeline/cache/,
so two slices over the same worktree (openmrs-core@2.8.5) share one extraction.
"""
import collections, gzip, hashlib, os, pickle, re, subprocess, sys, time
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from core import plugins                                  # noqa: E402  (only core.plugins.* is allowed here)
from core.plugins.java import norm_type                   # noqa: E402

P = plugins.get("java")
FILE_SCOPE = "(file scope)"
CACHE_DIR = os.path.join(HERE, "cache")
_METHOD_NODES = ("method_declaration", "constructor_declaration", "compact_constructor_declaration")
_TYPE_NODES = ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration", "annotation_type_declaration")
_TEST_PATH = re.compile(r"(^|/)(src/)?(test|tests|testing|it|integration-test|integrationtest)(/|$)|(Tests?|IT|TestCase)\.java$|(^|/)Test[A-Z]\w*\.java$")
_PARSER = None


def parser():
    global _PARSER
    if _PARSER is None:
        import tree_sitter_java
        from tree_sitter import Language, Parser
        _PARSER = Parser(Language(tree_sitter_java.language()))
    return _PARSER


def is_test_path(rel):
    return bool(_TEST_PATH.search(rel))


def _blank(buf, s, e):
    buf[s:e] = re.sub(rb"[^\n]", b" ", bytes(buf[s:e]))


def _txt(masked, n, cap=400):
    return masked[n.start_byte:n.end_byte].decode("utf-8", "replace")[:cap]


def _simple_type(t):
    return norm_type(t) if t else ""


def _enclosing(spans, line):
    """index of the smallest unit span containing the line, else 0 (file scope).  spans[i] = (s, e) for unit i >= 1"""
    best, bi = None, 0
    for i in range(1, len(spans)):
        s, e = spans[i]
        if s <= line <= e and (best is None or e - s < best):
            best, bi = e - s, i
    return bi


def extract_file(args):
    """-> {"file", "test", "units": [unit dict...]}; unit 0 is the file scope"""
    root, rel = args
    path = os.path.join(root, rel)
    src = open(path, "rb").read()
    is_test = is_test_path(rel)
    if not rel.endswith(".java"):                         # .gsp (and any other scorable non-Java file): file scope only
        masked = bytearray(src)
        for m in re.finditer(rb"<%--.*?--%>", src, re.S):
            _blank(masked, m.start(), m.end())
        text = masked.decode("utf-8", "replace")
        u = dict(name=FILE_SCOPE, start=1, end=src.count(b"\n") + 1, text=text, sig="", calls=[], concats=[], types={}, assigns={},
                 params=[], annots=[], arity=-1, has_body=True, cls="")
        return dict(file=rel, test=is_test, units=[u], fields={})
    funcs = P.functions(path)                             # [(qname, s, e)] sorted by (s, e, q)  -- same as scorer keys
    tree = parser().parse(src)
    masked = bytearray(src)
    nodes_by_span = collections.defaultdict(list)
    call_nodes, decl, assign, concat_nodes, field_nodes = [], [], [], [], []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        t = n.type
        if t in ("line_comment", "block_comment"):
            _blank(masked, n.start_byte, n.end_byte)
            continue
        if t in _METHOD_NODES or t == "static_initializer" or (
                t == "block" and n.parent is not None and n.parent.type == "class_body" and n.parent.parent is not None
                and (n.parent.parent.type in _TYPE_NODES or n.parent.parent.type == "object_creation_expression")):
            nodes_by_span[(n.start_point[0] + 1, n.end_point[0] + 1)].append(n)
        if t in ("method_invocation", "object_creation_expression"):
            call_nodes.append(n)
        elif t in ("local_variable_declaration", "formal_parameter", "spread_parameter", "enhanced_for_statement", "resource"):
            decl.append(n)
        elif t == "field_declaration":
            field_nodes.append(n)
        elif t == "assignment_expression":
            assign.append(n)
        elif t == "binary_expression" and any(c.type == "+" for c in n.children):
            p = n.parent
            if not (p is not None and p.type == "binary_expression" and any(c.type == "+" for c in p.children)):
                concat_nodes.append(n)
        stack.extend(reversed(n.children))
    # --- units: plugin names/spans paired with AST nodes
    used = collections.Counter()
    unit_nodes = [None]
    spans = [(1, src.count(b"\n") + 1)]
    for q, s, e in funcs:
        cand = nodes_by_span.get((s, e), [])
        node = cand[used[(s, e)]] if used[(s, e)] < len(cand) else None
        used[(s, e)] += 1
        unit_nodes.append(node)
        spans.append((s, e))
    # parent/children among unit nodes (byte ranges) -> own text excludes nested units
    order = sorted((i for i in range(1, len(unit_nodes)) if unit_nodes[i] is not None),
                   key=lambda i: (unit_nodes[i].start_byte, -unit_nodes[i].end_byte))
    children, top, st = collections.defaultdict(list), [], []
    for i in order:
        n = unit_nodes[i]
        while st and not (unit_nodes[st[-1]].start_byte <= n.start_byte and n.end_byte <= unit_nodes[st[-1]].end_byte):
            st.pop()
        (children[st[-1]] if st else top).append(i)
        st.append(i)
    line_off = [0]
    for m in re.finditer(rb"\n", masked):
        line_off.append(m.end())

    def own_text(i):
        if i == 0:
            buf = bytearray(masked)
            for c in top:
                _blank(buf, unit_nodes[c].start_byte, unit_nodes[c].end_byte)
            return buf.decode("utf-8", "replace")
        n = unit_nodes[i]
        if n is None:                                     # span without a node (should not happen): fall back to lines
            return "\n".join(masked.decode("utf-8", "replace").split("\n")[spans[i][0] - 1:spans[i][1]])
        a = line_off[spans[i][0] - 1] if spans[i][0] - 1 < len(line_off) else n.start_byte
        buf = bytearray(masked[a:n.end_byte])
        for c in children[i]:
            _blank(buf, unit_nodes[c].start_byte - a, unit_nodes[c].end_byte - a)
        return buf.decode("utf-8", "replace")

    units = []
    for i in range(len(spans)):
        name = FILE_SCOPE if i == 0 else funcs[i - 1][0]
        n = unit_nodes[i]
        sig, params, annots, arity, has_body = "", [], [], -1, True
        if i and n is not None and n.type in _METHOD_NODES:
            body = n.child_by_field_name("body")
            has_body = body is not None
            sig = masked[n.start_byte:(body.start_byte if body is not None else n.end_byte)].decode("utf-8", "replace")
            ps = n.child_by_field_name("parameters")
            arity = 0
            if ps is not None:
                for c in ps.named_children:
                    if c.type in ("formal_parameter", "spread_parameter"):
                        arity += 1
                        params.append(_txt(masked, c, 200))
            annots = re.findall(r"@(\w+)", sig)
        elif i:
            arity = 0
        bare = re.sub(r"\([^()]*\)$", "", name).rsplit(".", 1)[-1] if i else ""
        cls = re.sub(r"\([^()]*\)$", "", name).rsplit(".", 1)[0] if (i and "." in re.sub(r"\([^()]*\)$", "", name)) else ""
        units.append(dict(name=name, start=spans[i][0], end=spans[i][1], text=own_text(i), sig=sig, calls=[], concats=[], types={},
                          assigns={}, params=params, annots=annots, arity=arity, has_body=has_body, cls=cls, bare=bare,
                          varargs=bool(re.search(r"\.\.\.", sig))))
    # --- features attributed to the smallest enclosing unit
    for n in call_nodes:
        u = units[_enclosing(spans, n.start_point[0] + 1)]
        args_n = n.child_by_field_name("arguments")
        args = [_txt(masked, a, 300) for a in args_n.named_children] if args_n is not None else []
        if n.type == "method_invocation":
            ob, nm = n.child_by_field_name("object"), n.child_by_field_name("name")
            u["calls"].append(dict(k="call", name=_txt(masked, nm) if nm is not None else "?", recv=_txt(masked, ob, 200) if ob is not None else "",
                                   args=args, line=n.start_point[0] + 1))
        else:
            ty = n.child_by_field_name("type")
            tn = _simple_type(_txt(masked, ty)) if ty is not None else "?"
            u["calls"].append(dict(k="new", name=tn, recv="", args=args, line=n.start_point[0] + 1, anon=n.child_by_field_name("body") is not None
                                   or any(c.type == "class_body" for c in n.children)))
    fields = {}
    for n in decl:
        u = units[_enclosing(spans, n.start_point[0] + 1)]
        if n.type == "local_variable_declaration":
            ty = _simple_type(_txt(masked, n.child_by_field_name("type")))
            for d in n.named_children:
                if d.type == "variable_declarator":
                    nm, v = d.child_by_field_name("name"), d.child_by_field_name("value")
                    if nm is not None:
                        u["types"][_txt(masked, nm)] = ty
                        if v is not None:
                            u["assigns"].setdefault(_txt(masked, nm), []).append(_txt(masked, v, 500))
        elif n.type in ("formal_parameter", "spread_parameter"):
            ty = n.child_by_field_name("type") or next((c for c in n.named_children if c.type not in ("modifiers", "variable_declarator")), None)
            nm = n.child_by_field_name("name") or next((c for c in n.named_children if c.type == "variable_declarator"), None)
            if ty is not None and nm is not None:
                u["types"][_txt(masked, nm.child_by_field_name("name") or nm)] = _simple_type(_txt(masked, ty))
                u.setdefault("param_names", []).append(_txt(masked, nm.child_by_field_name("name") or nm))
        else:                                             # enhanced_for / resource
            ty, nm = n.child_by_field_name("type"), n.child_by_field_name("name")
            if ty is not None and nm is not None:
                u["types"][_txt(masked, nm)] = _simple_type(_txt(masked, ty))
                v = n.child_by_field_name("value")
                if v is not None:
                    u["assigns"].setdefault(_txt(masked, nm), []).append(_txt(masked, v, 500))
    for n in field_nodes:
        mods = next((c for c in n.children if c.type == "modifiers"), None)
        mt = _txt(masked, mods) if mods is not None else ""
        ty = _simple_type(_txt(masked, n.child_by_field_name("type")))
        for d in n.named_children:
            if d.type == "variable_declarator":
                nm, v = d.child_by_field_name("name"), d.child_by_field_name("value")
                if nm is not None:
                    fields[_txt(masked, nm)] = dict(type=ty, final=bool(re.search(r"\bfinal\b", mt)), static=bool(re.search(r"\bstatic\b", mt)),
                                                    value=_txt(masked, v, 200) if v is not None else None)
    for n in assign:
        l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
        if l is not None and r is not None and l.type == "identifier":
            units[_enclosing(spans, n.start_point[0] + 1)]["assigns"].setdefault(_txt(masked, l), []).append(_txt(masked, r, 500))
    for n in concat_nodes:
        lv = []

        def walk(x):
            if x is not None and x.type == "binary_expression" and any(c.type == "+" for c in x.children):
                walk(x.child_by_field_name("left")); walk(x.child_by_field_name("right"))
            elif x is not None:
                lv.append(x)
        walk(n)
        lits = [_txt(masked, x, 300) for x in lv if x.type == "string_literal"]
        if lits:
            units[_enclosing(spans, n.start_point[0] + 1)]["concats"].append(
                dict(line=n.start_point[0] + 1, lits=lits, dyn=[_txt(masked, x, 200) for x in lv if x.type != "string_literal"]))
    return dict(file=rel, test=is_test, units=units, fields=fields)


def list_files(root):
    out = []
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x != ".git"]
        out.extend(os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/") for f in fs if f.endswith(P.extensions))
    return sorted(out)


def _cache_key(root):
    h = hashlib.sha256()
    for f in (os.path.abspath(__file__), os.path.join(os.path.dirname(HERE), "core/plugins/java.py")):
        h.update(open(f, "rb").read())
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout.strip()
    except OSError:
        head = ""
    return f"{os.path.basename(os.path.abspath(root))}.{head[:12] or 'nogit'}.{h.hexdigest()[:10]}"


def assemble(per_file, label, key):
    flat = []
    for ff in per_file:
        for u in ff["units"]:
            u["id"] = len(flat)
            u["file"] = ff["file"]
            u["test"] = ff["test"]
            u["fields"] = ff["fields"]               # shared reference per file (pickle keeps it once per file)
            flat.append(u)
    return dict(label=label, key=key, files=[f["file"] for f in per_file], units=flat)


def load_codebase(root, workers=None, use_cache=True, log=print):
    """-> dict(label, files=[{file,test,units}], units=[flat list with global ids], fields={file: {...}}); cached per repo@ref"""
    root = os.path.abspath(root)
    key = _cache_key(root)
    cp = os.path.join(CACHE_DIR, key + ".units.pkl.gz")
    if use_cache and os.path.exists(cp):
        log(f"[units] cache hit {os.path.basename(cp)}")
        return pickle.load(gzip.open(cp, "rb"))
    t0 = time.time()
    files = list_files(root)
    log(f"[units] extracting {len(files)} files from {os.path.basename(root)} ...")
    with Pool(workers or min(32, os.cpu_count() or 4)) as pool:
        per_file = pool.map(extract_file, [(root, f) for f in files], chunksize=8)
    cb = assemble(per_file, os.path.basename(root), key)
    cb["seconds"] = round(time.time() - t0, 1)
    flat = cb["units"]
    os.makedirs(CACHE_DIR, exist_ok=True)
    pickle.dump(cb, gzip.open(cp + ".tmp", "wb", compresslevel=3))
    os.replace(cp + ".tmp", cp)
    log(f"[units] {len(flat)} units in {cb['seconds']}s -> cache {os.path.basename(cp)}")
    return cb
