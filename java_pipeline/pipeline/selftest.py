"""Engine self-test on SYNTHETIC Java/GSP sources written to a temp dir (never touches the benchmark repos or any key).

Each case asserts the expected (S1, S2) of one unit for one CWE, plus unit-name parity with core.plugins.java and call-graph/S3
behaviour.  Run before freezing the rules:   .venv/bin/python -m pipeline.selftest
"""
import os, sys, tempfile, textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline import units as U, callgraph, s123
from core import plugins

SRC = {
 "a/Paths1.java": """
    import java.io.*; import java.nio.file.*;
    public class Paths1 {
      private Path base;
      static final String ROOT = "/srv/data";
      void a(HttpServletRequest r) { File f = new File(r.getParameter("p")); }
      void b() { File f = new File("/etc/x"); }
      void c(String n) { Path p = base.resolve(n); }
      void d(String n) { File f = new File(FilenameUtils.getName(n)); }
      void e() { File f = new File(ROOT, "x.txt"); }
      void f(String n) { String q = "dir/" + n; File f = new File(q); }
      void g(ZipEntry en, File dir) { File out = new File(dir, en.getName()); }
    }""",
 "a/Xml1.java": """
    import javax.xml.parsers.*;
    public class Xml1 {
      void e() throws Exception { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); f.newDocumentBuilder(); }
      void f() throws Exception { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
         f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); f.newDocumentBuilder(); }
      void g() { TransformerFactory f = XMLUtil.newXXEProtectedTransformerFactory(); }
      void h() { TransformerFactory f = new net.sf.saxon.TransformerFactoryImpl(); }
      void i() throws Exception { SAXParserFactory f = SAXParserFactory.newInstance();
         f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); }
    }""",
 "a/Code1.java": """
    public class Code1 {
      void i(String crit) { VelocityEngine ve = new VelocityEngine(); ve.init(); String t = "#set($c = " + crit + ")";
         ve.evaluate(ctx, w, "tag", t); }
      void j() { VelocityEngine ve = new VelocityEngine(); ve.evaluate(ctx, w, "tag", "literal template"); }
      void k(String script) throws Exception { ScriptEngine se = mgr.getEngineByName("js"); se.eval(script); }
      void l(String expr) { ExpressionParser parser = new SpelExpressionParser(); parser.parseExpression(expr); }
      void m() { ExpressionParser parser = new SpelExpressionParser(); parser.parseExpression("1+1"); }
    }""",
 "a/Xss1.java": """
    public class Xss1 {
      void l(HttpServletRequest rq, HttpServletResponse resp) throws IOException { String name = rq.getParameter("n");
         resp.getWriter().println("<b>" + name + "</b>"); }
      void m(PrintWriter out, String name) { out.println(HtmlUtils.htmlEscape(name)); }
      void n(PrintWriter out) { out.println("<b>static</b>"); }
      String o(String x) { return "<li>" + x + "</li>"; }
      String p(int n) { return "<li>" + n + "</li>".length(); }
    }""",
 "web/page.gsp": "<html><body>${person.name} <b>${ui.encodeHtml(x)}</b> ${ui.message('a.b')}</body></html>",
 "web/safe.gsp": "<html><body>${ui.encodeHtml(x)} ${ui.message('a.b')} ${1}</body></html>",
 "a/Val1.java": """
    public class Val1 {
      void h(HttpServletRequest r) { Integer.parseInt(r.getParameter("a")); }
      void i(HttpServletRequest r) { validate(r); Integer.parseInt(r.getParameter("a")); }
      void j(String s) { Integer.parseInt(s); }
    }""",
 "a/Graph1.java": """
    public class Graph1 {
      void entry(HttpServletRequest r) { helper(r.getParameter("x")); }
      void helper(String s) { new File(s); }
      void lonely(String s) { new File(s); }
      void guardedCaller(HttpServletRequest r) { validate(r); other(r.getParameter("x")); }
      void other(String s) { Integer.parseInt(s); }
      static void ov(int a) {} static void ov(int a, int b) {}
      void callsOv() { ov(1); ov(1, 2); }
    }""",
 "t/src/test/java/FooTest.java": "public class FooTest { void t(){ new File(x); } }",
}

# (file, unit-name prefix, cwe, expected s1, expected s2)
CASES = [
 ("a/Paths1.java", "Paths1.a(", "CWE-22", 1, 1), ("a/Paths1.java", "Paths1.b(", "CWE-22", 1, 0), ("a/Paths1.java", "Paths1.c(", "CWE-22", 1, 1),
 ("a/Paths1.java", "Paths1.d(", "CWE-22", 1, 0), ("a/Paths1.java", "Paths1.e(", "CWE-22", 1, 0), ("a/Paths1.java", "Paths1.f(", "CWE-22", 1, 1),
 ("a/Paths1.java", "Paths1.g(", "CWE-22", 1, 1),
 ("a/Xml1.java", "Xml1.e(", "CWE-611", 1, 1), ("a/Xml1.java", "Xml1.f(", "CWE-611", 1, 0), ("a/Xml1.java", "Xml1.g(", "CWE-611", 0, 0),
 ("a/Xml1.java", "Xml1.h(", "CWE-611", 1, 1), ("a/Xml1.java", "Xml1.i(", "CWE-611", 1, 0),
 ("a/Code1.java", "Code1.i(", "CWE-94", 1, 1), ("a/Code1.java", "Code1.j(", "CWE-94", 1, 1), ("a/Code1.java", "Code1.k(", "CWE-94", 1, 1),
 ("a/Code1.java", "Code1.l(", "CWE-94", 1, 1), ("a/Code1.java", "Code1.m(", "CWE-94", 1, 0),
 ("a/Xss1.java", "Xss1.l(", "CWE-79", 1, 1), ("a/Xss1.java", "Xss1.m(", "CWE-79", 1, 0), ("a/Xss1.java", "Xss1.n(", "CWE-79", 1, 0),
 ("a/Xss1.java", "Xss1.o(", "CWE-79", 1, 1),
 ("web/page.gsp", "(file scope)", "CWE-79", 1, 1), ("web/safe.gsp", "(file scope)", "CWE-79", 1, 0),
 ("a/Val1.java", "Val1.h(", "CWE-20", 1, 1), ("a/Val1.java", "Val1.i(", "CWE-20", 1, 0), ("a/Val1.java", "Val1.j(", "CWE-20", 0, 0),
]


def main():
    P = plugins.get("java")
    with tempfile.TemporaryDirectory() as root:
        for rel, body in SRC.items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write(textwrap.dedent(body))
        files = U.list_files(root)
        per_file = [U.extract_file((root, f)) for f in files]
        cb = U.assemble(per_file, "synthetic", "synthetic")
        # unit names/spans == the scorer's plugin output
        for ff in per_file:
            if ff["file"].endswith(".java"):
                want = [("(file scope)", 1)] + [(q, s) for q, s, e in P.functions(os.path.join(root, ff["file"]))]
                got = [(u["name"], u["start"]) for u in ff["units"]]
                assert got == want, (ff["file"], got, want)
        cg = callgraph.build(cb, log=lambda s: None)
        fails, byname = [], {(u["file"], u["name"]): u for u in cb["units"]}
        res = {}
        for cwe in ("CWE-22", "CWE-611", "CWE-94", "CWE-79", "CWE-20"):
            recs, _ = s123.run(cb, cg, cwe)
            res[cwe] = {(r["file"], r["function"]): r for r in recs}
        for rel, pref, cwe, e1, e2 in CASES:
            hit = [k for k in byname if k[0] == rel and k[1].startswith(pref)]
            assert hit, (rel, pref)
            r = res[cwe].get(hit[0])
            g1, g2 = int(bool(r and r["s1"])), int(bool(r and r["s2"]))
            if (g1, g2) != (e1, e2):
                fails.append(f"{cwe} {rel}::{hit[0][1]}: expected S1,S2={e1},{e2} got {g1},{g2}")
        # call graph + S3: helper is reachable from a source unit; ov(1)/ov(1,2) resolve by arity; test-path flag
        rg = res["CWE-22"]
        h = rg.get(("a/Graph1.java", "Graph1.helper(String)"))
        lonely = rg.get(("a/Graph1.java", "Graph1.lonely(String)"))
        if not (h and h["s2"] and h["s3"] and h["callers"] == 1):
            fails.append(f"helper S3/callers: {h and (h['s2'], h['s3'], h['callers'])}")
        if not (lonely and lonely["s3"] and lonely["via"] == "no-caller"):
            fails.append(f"lonely (externally callable) should be S3 via no-caller: {lonely}")
        ids = {u["name"]: u["id"] for u in cb["units"] if u["file"] == "a/Graph1.java"}
        if cg["callees"][ids["Graph1.callsOv()"]] != {ids["Graph1.ov(int)"], ids["Graph1.ov(int,int)"]}:
            fails.append("arity resolution of ov(..) failed")
        # CWE-20 guard propagation: other() is only called from guardedCaller (guarded) -> not S2
        o = res["CWE-20"].get(("a/Graph1.java", "Graph1.other(String)"))
        if o and o["s2"]:
            fails.append("CWE-20 guard did not propagate to a callee whose only caller is guarded")
        t = res["CWE-22"].get(("t/src/test/java/FooTest.java", "FooTest.t()"))
        if not (t and t["test"]):
            fails.append("test-path unit not flagged test")
    if fails:
        print("SELFTEST FAILED"); [print("  -", f) for f in fails]; sys.exit(1)
    print(f"pipeline selftest OK ({len(CASES)} rule cases + parity + call graph + S3 + guard propagation)")


if __name__ == "__main__":
    main()
