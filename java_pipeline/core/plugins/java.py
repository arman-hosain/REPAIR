"""Java plugin.  Unit key = qualified name + parameter types:

    Outer.Inner.method(String,int[])        method; types are SIMPLE names (package dropped), generics erased,
                                            varargs written as [] ; parameter names / modifiers / annotations ignored
    Outer.<init>(String)                    constructor              Outer.<clinit>   static initializer
    Outer.<init-block>                      instance initializer     (a 2nd+ identical name gets "#2", "#3" in source order)
    Outer.m(int)$1.run()                    method of the 1st anonymous class created inside Outer.m(int)
    Outer.m(int)$Local.f()                  method of local class Local declared inside Outer.m(int)
Lambdas are part of their enclosing unit.  Field initializers, class-level annotations and anything else outside a
method/constructor/initializer belong to the pseudo-unit "(file scope)" (one per scorable file).
Names are case-sensitive.  The package is NOT part of the key (the file path already identifies it).
Non-.java scorable files (extensions below, e.g. Grails .gsp views) have no function notion: "(file scope)" only.
"""
import re

_TYPE_NODES = {"class_declaration": 1, "interface_declaration": 1, "enum_declaration": 1, "record_declaration": 1,
               "annotation_type_declaration": 1}
_METHOD_NODES = ("method_declaration", "constructor_declaration", "compact_constructor_declaration")


def norm_type(t):
    """'java.util.Map.Entry<K,V>[]' -> 'Entry[]'; '@Nullable final String' -> 'String'; 'String...' -> 'String[]'"""
    t = re.sub(r"@\w+(?:\.\w+)*(?:\([^)]*\))?", "", t)
    t = re.sub(r"\bfinal\b", "", t)
    prev = None
    while prev != t:                                     # erase (possibly nested) generic arguments
        prev, t = t, re.sub(r"<[^<>]*>", "", t)
    t = re.sub(r"\s+", "", t)
    dims = ""
    if t.endswith("..."):
        t, dims = t[:-3], "[]"
    m = re.match(r"^([\w.$]*?)((?:\[\])*)$", t)
    base, arr = (m.group(1), m.group(2)) if m else (t, "")
    return base.rsplit(".", 1)[-1] + arr + dims


def _split_params(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def strip_params(q):
    return re.sub(r"\([^()]*\)$", "", q)


class JavaPlugin:
    name = "java"
    extensions = (".java", ".gsp")
    case_sensitive = True

    def __init__(self):
        self._parser = None
        self._cache = {}

    def _p(self):
        if self._parser is None:
            try:
                import tree_sitter_java
                from tree_sitter import Language, Parser
            except ImportError as e:
                raise SystemExit(f"java plugin needs tree_sitter + tree_sitter_java ({e})")
            self._parser = Parser(Language(tree_sitter_java.language()))
        return self._parser

    def fold(self, s):
        return s

    # ------------------------------------------------------------------ extraction
    def _params(self, node):
        ps = node.child_by_field_name("parameters")
        out = []
        if ps is None:
            return "()"
        for c in ps.named_children:
            if c.type == "formal_parameter":
                t = c.child_by_field_name("type")
                s = norm_type(t.text.decode()) if t is not None else "?"
                d = c.child_by_field_name("dimensions")
                if d is not None:
                    s += "[]" * d.text.decode().count("[")
                out.append(s)
            elif c.type == "spread_parameter":
                t = next((x for x in c.named_children if x.type not in ("modifiers", "variable_declarator")), None)
                out.append(norm_type(t.text.decode() if t is not None else "?") + "[]")
        return "(" + ",".join(out) + ")"

    def functions(self, path):
        """-> [(qualified_name, start_line1, end_line1)]; non-.java files have no functions"""
        if path in self._cache:
            return self._cache[path]
        if not path.endswith(".java"):
            self._cache[path] = []
            return []
        tree = self._p().parse(open(path, "rb").read())
        out, anon = [], {}
        # stack items: (node, prefix, method_qname_or_None)
        stack = [(tree.root_node, "", None)]
        while stack:
            n, prefix, meth = stack.pop()
            t = n.type
            npre, nmeth = prefix, meth
            if t in _TYPE_NODES:
                nm = n.child_by_field_name("name")
                name = nm.text.decode() if nm else "?"
                npre = f"{meth}${name}" if meth else (f"{prefix}.{name}" if prefix else name)
                nmeth = None
            elif t == "class_body" and n.parent is not None and n.parent.type == "object_creation_expression":
                base = meth or prefix
                anon[base] = anon.get(base, 0) + 1
                npre, nmeth = f"{base}${anon[base]}", None
            elif t in _METHOD_NODES:
                nm = n.child_by_field_name("name")
                name = "<init>" if t != "method_declaration" else (nm.text.decode() if nm else "?")
                q = f"{prefix}.{name}{self._params(n)}" if prefix else f"{name}{self._params(n)}"
                out.append((q, n.start_point[0] + 1, n.end_point[0] + 1))
                nmeth = q
            elif t == "static_initializer":
                q = f"{prefix}.<clinit>" if prefix else "<clinit>"
                out.append((q, n.start_point[0] + 1, n.end_point[0] + 1))
                nmeth = q
            elif t == "block" and n.parent is not None and n.parent.type == "class_body" and \
                    n.parent.parent is not None and (n.parent.parent.type in _TYPE_NODES or n.parent.parent.type == "object_creation_expression"):
                q = f"{prefix}.<init-block>" if prefix else "<init-block>"
                out.append((q, n.start_point[0] + 1, n.end_point[0] + 1))
                nmeth = q
            stack.extend((c, npre, nmeth) for c in reversed(n.children))
        out.sort(key=lambda x: (x[1], x[2], x[0]))
        seen, uniq = {}, []
        for q, s, e in out:                              # identical names (initializers, odd code) -> #2, #3 in source order
            seen[q] = seen.get(q, 0) + 1
            uniq.append((q if seen[q] == 1 else f"{q}#{seen[q]}", s, e))
        self._cache[path] = uniq
        return uniq

    # ------------------------------------------------------------------ names in keys / predictions
    def norm_name(self, fn):
        fn = fn.strip()
        if fn == "(file scope)":
            return fn
        fn = fn.replace("::", ".")
        fn = re.sub(r"^([\w.$]+)#(?=[A-Za-z_<])", r"\1.", fn)          # Javadoc style Class#method(T) -> Class.method(T)
        dup = ""
        m = re.search(r"#\d+$", fn)                      # our own duplicate suffix
        if m:
            fn, dup = fn[:m.start()], m.group(0)
        if re.search(r"\)\$", fn):                       # member of an anonymous/local class: used verbatim
            return fn + dup
        m = re.match(r"^([^()]*?)(\((.*)\))?$", fn, re.S)
        if not m or m.group(3) is None:                  # no parameter list
            head, params = fn, None
        else:
            head, params = m.group(1), m.group(3)
        segs = head.split(".")
        while len(segs) > 1 and segs[0][:1].islower():   # drop a leading package: org.x.Cls.m -> Cls.m
            segs = segs[1:]
        head = ".".join(segs)
        if params is None:
            return head + dup
        return head + "(" + ",".join(norm_type(p) for p in _split_params(params)) + ")" + dup

    def candidates(self, n, names):
        if "(" in n:                                     # full signature given but not an exact name: do not guess
            return set(), False
        if "." in n:                                     # Class.method without parameters
            return {q for q in names if strip_params(q) == n}, True
        return {q for q in names if strip_params(q).rsplit(".", 1)[-1] == n}, True


PLUGIN = JavaPlugin()
