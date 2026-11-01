"""Stage 5 (LLM Assessment) for Java units (BLIND side).  WRITTEN, NOT RUN: no function here contacts a model unless the caller
sets MEDICALJAVA_ALLOW_LLM=1 (to be done only after the user approves) -- `dry_run`, `build_prompt` and `selftest` are offline.

Two-phase design (research -> binary verdict; same system roles, temperatures, token caps, "when uncertain default to
EXPLOITABLE" rule as the C/C++ pipeline's Stage 4) with a Java fence, Java wording and per-CWE factors for CWE-22/94/611/79/20
written from the generic CWE definitions.

Prompt content  = generic CWE description + unit code (Java comments blanked, line numbers kept) + deterministic call-graph/static
                  notes.  NEVER: file path, repo/ref, slice label, CVE id, sheet text.  Method/class names appear only as they occur in
                  the code and in the caller/callee lists.  Package-qualified names inside code can remain; dry-run counts them.
Output          = predictions JSONL {file, function, line_start, line_end, cwe, slice, verdict, confidence, ...}.  `slice` is the opaque
                  label given on the command line, copied verbatim.  Failures / unparseable verdicts fail OPEN to EXPLOITABLE (as in the
                  C/C++ pipeline) and are flagged `fallback`.
Cache           = every LLM response is stored under pipeline/cache/llm/<sha256(model+phase+system+prompt+sampling params)>.json; re-runs never
                  re-bill an identical request.  The key covers model, phase, system, prompt, max_tokens, temperature, reasoning_effort, seed
                  and NOT the arm (S1/S2/S3), the slice label or the unit id: a unit has one key whichever arm selects it.
Model           = openai/gpt-oss-20b (reasoning model: max_tokens covers reasoning + answer; completion_tokens in the usage block includes both).
                  Parameters live in PARAMS and are frozen by sha256 in notes/stage5_freeze.json (scripts/stage5_freeze.py).
"""
import hashlib, json, os, re, subprocess, sys, threading, time, urllib.request

# Real-cost tracking (mirrors the equivalent hook added to IRIS's GPTModel): every live, non-cached
# API call's usage is appended here as one JSON line. Set REPAIR_USAGE_LOG to enable.
USAGE_LOG = os.environ.get("REPAIR_USAGE_LOG")
_usage_lock = threading.Lock()


def _log_usage(model, usage):
    if not USAGE_LOG or not usage:
        return
    rec = dict(model=model, prompt_tokens=usage.get("prompt_tokens"), completion_tokens=usage.get("completion_tokens"))
    with _usage_lock:
        with open(USAGE_LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from pipeline import units as U                       # noqa: E402
from pipeline import param_tracer as PT                # noqa: E402

FILE_SCOPE = "(file scope)"
LLM_CACHE = os.path.join(HERE, "cache", "llm")
CHARS_PER_TOKEN = 3.5            # ESTIMATE only; exact counts via --tok-python/--tokenizer (count exactly before a real run; estimates can mislead)
OVERHEAD_TOKENS = 1500           # scaffolding + factors + system prompt, upper estimate
# Sampling parameters (frozen).  max_tokens INCLUDES the model's reasoning tokens.  Temperatures: research 0.2, verdict 0.0.
PARAMS = dict(model="openai/gpt-oss-20b", reasoning_effort="medium", temperature_p1=0.2, temperature_p2=0.0,
              max_tokens_p1=6000, max_tokens_p2=3000, seed=1234)
OUT1, OUT2 = PARAMS["max_tokens_p1"], PARAMS["max_tokens_p2"]
TEMP1, TEMP2 = PARAMS["temperature_p1"], PARAMS["temperature_p2"]
HARMONY_OVERHEAD = 200           # fallback ESTIMATE of chat-template framing tokens when no tokenizer directory is given (exact count: --tokenizer DIR)
SYSTEM_1 = ("You are a security researcher performing static vulnerability analysis. "
            "Analyze the provided Java code and answer all questions precisely and concisely.")
SYSTEM_2 = ("You are a security expert. Give a definitive verdict on vulnerability exploitability. "
            "Follow the exact output format requested.")

CWE_INFO = {
    "CWE-22": dict(name="Path Traversal", harm="read, write, create or delete files outside the directory the code means to confine file access to",
        description="A file or path is built from externally influenced data (request parameters, archive entry names, stored values) without making sure the resulting location stays inside the intended directory.",
        factors=["Where does each component of the path come from (request, archive entry name, stored value, configuration, constant)?",
                 "Are '..' segments, absolute paths, drive letters, encoded separators and symbolic links rejected or resolved?",
                 "Is containment verified AFTER normalization on the same value that is passed to the file operation (e.g. normalized/canonical path starts with the base directory)? A check on a different string, or a check of only the first path segment, does not count.",
                 "For archive extraction: is every entry's resolved destination checked, and is the check applied to the final path that is written?",
                 "What does the file operation do (read, write, delete, list) and what is exposed or changed?"]),
    "CWE-94": dict(name="Code Injection (expression, script or template evaluation)", harm="make the application evaluate attacker-chosen code, expressions or template directives (for example reflective Java method calls or command execution)",
        description="Data from outside the trusted code base becomes part of a script, expression or template that the application then evaluates.",
        factors=["What exactly is evaluated (script, SpEL/OGNL/MVEL/JEXL expression, Velocity/FreeMarker template text)? Is any part of that text built from non-constant data?",
                 "Who controls that data (unauthenticated user, any logged-in user, a privileged user, an administrator, a value read from the database that a user can edit)?",
                 "Is the data passed as a variable/binding (safe) or concatenated into the template or expression text (unsafe)?",
                 "Is the engine restricted (secure uberspector / restricted introspector, SimpleEvaluationContext, class allow-list, sandbox)? If it is not, what can evaluated text reach (Class, reflection, Runtime)?",
                 "What privilege is needed to supply the data, and is that a realistic attacker?"]),
    "CWE-611": dict(name="XML External Entity (XXE) Reference", harm="make the XML processor read local files, issue network requests on the server's behalf, or exhaust resources through entity expansion",
        description="An XML parser, transformer or schema/validator processes XML or XSLT with external entity or DTD resolution left enabled.",
        factors=["Which parser/factory/transformer is used and is it configured before it processes input: DOCTYPE disallowed, external general/parameter entities off, external DTD / stylesheet / schema access off, secure-processing on, XInclude off?",
                 "Is the configuration applied to the SAME factory/object that parses (not to a different instance)? Is a hardened helper used?",
                 "Where does the XML or XSLT come from (upload, request body, network, a file the user chooses, internal resource)?",
                 "Is there an entity resolver or URI resolver that blocks or replaces external access?",
                 "What can an attacker read or reach if entity resolution works (local files, internal URLs)?"]),
    "CWE-79": dict(name="Cross-site Scripting", harm="run attacker-controlled script in another user's browser session",
        description="Data that an attacker can influence (request input, stored values) is written into a page or a response that browsers render as HTML/script without neutralization suitable for the output context.",
        factors=["What is the output sink (response writer, HTML string, template expression, JSON embedded in a page) and in which context does the value land (HTML body, attribute, JavaScript, URL, CSS)?",
                 "Where does each dynamic value come from (request, stored data, other user's data, constant)?",
                 "Is a context-appropriate encoder applied? A JavaScript-string escaper does not protect an HTML context or a </script> sequence; HTML escaping does not protect a JavaScript or unquoted-attribute context.",
                 "Is the content type HTML (or sniffable) so a browser would execute it?",
                 "Who sees the output (the attacker themself only, other users, administrators)?"]),
    "CWE-20": dict(name="Improper Input Validation", harm="make the application process input that violates its assumptions (malformed, out of range, unauthorized or unexpectedly typed) with a security-relevant effect",
        description="The code receives input and uses it for a sensitive operation without validating the properties that operation requires (format, range, length, type, allowed values, caller authorization).",
        factors=["What input does this code take and from whom (anonymous, authenticated, privileged)?",
                 "What properties must that input have for the sensitive operation to be safe (format, range, allowed values, path confinement, caller permission)?",
                 "Is each property checked before the operation on every path? Are checks bypassable (checking a different value, partial checks, checks after use)?",
                 "What is the worst effect if the input is hostile (file access, data change, resource exhaustion, privilege misuse)?",
                 "Is there a caller in the code base that already validates for this unit?"]),
}
DEFAULT_INFO = dict(name="Potential weakness", harm="misuse the operation", description="A potentially dangerous operation.", factors=["Can attacker-controlled data reach the dangerous operation unchecked?"])


# ----------------------------------------------------------------------------- code rendering (comments blanked, line numbers kept)
def masked_lines(root, rel):
    path = os.path.join(root, rel)
    src = open(path, "rb").read()
    buf = bytearray(src)
    if rel.endswith(".java"):
        stack = [U.parser().parse(src).root_node]
        while stack:
            n = stack.pop()
            if n.type in ("line_comment", "block_comment"):
                U._blank(buf, n.start_byte, n.end_byte)
            else:
                stack.extend(n.children)
    else:
        for m in re.finditer(rb"<%--.*?--%>", src, re.S):
            U._blank(buf, m.start(), m.end())
    return [l.rstrip() for l in buf.decode("utf-8", "replace").split("\n")]


def render(root, u, cb, focus, budget_tokens):
    """-> (code text with line-number prefixes, meta).  File scope elides method bodies; over-budget units are windowed around focus lines."""
    lines = masked_lines(root, u["file"])
    s, e = u["start"], min(u["end"], len(lines))
    elide = {}
    if u["name"] == FILE_SCOPE and u["file"].endswith(".java"):
        top = [x for x in cb["units"] if x["file"] == u["file"] and x["name"] != FILE_SCOPE]
        for x in top:
            if x["start"] not in elide or x["end"] > elide[x["start"]][0]:
                elide[x["start"]] = (x["end"], x["name"])
    items, i = [], s
    while i <= e:
        if i in elide:
            b, nm = elide[i]
            items.append((i, b, f"    // [body of {nm.rsplit('.', 1)[-1]} omitted: {b - i + 1} lines, analyzed as a separate unit]"))
            i = b + 1
        else:
            items.append((i, i, lines[i - 1])); i += 1
    # collapse runs of blank/comment-only lines
    out, k = [], 0
    while k < len(items):
        a, b, t = items[k]
        if t.strip() == "":
            j = k
            while j + 1 < len(items) and items[j + 1][2].strip() == "":
                j += 1
            out.append((a, items[j][1], f"[{items[j][1] - a + 1} blank or comment-only lines]") if j > k else (a, b, t))
            k = j + 1
        else:
            out.append((a, b, t)); k += 1
    full = [f"{a:5d} | {t}" for a, b, t in out]
    cap = int(budget_tokens * CHARS_PER_TOKEN)
    est = sum(len(x) + 1 for x in full) / CHARS_PER_TOKEN
    kept = sum(b - a + 1 for a, b, _ in out)
    if est > budget_tokens:                                   # window around focus lines (+ the signature), then enforce the cap
        want = set(range(s, min(e, s + 12) + 1))
        for f in focus:
            want.update(range(max(s, f - 40), min(e, f + 40) + 1))
        sel, last, size, kept = [], None, 0, 0
        for (a, b, t), txt in zip(out, full):
            if not any(x in want for x in range(a, b + 1)):
                continue
            if size + len(txt) + 1 > cap:
                break
            if last is not None and a > last + 1:
                sel.append(f"      | [{a - last - 1} lines omitted]")
            sel.append(txt); last = b; size += len(txt) + 1; kept += b - a + 1
        if last is not None and last < e:
            sel.append(f"      | [{e - last} lines omitted]")
        full = sel
    omitted = (e - s + 1) - kept if est > budget_tokens else 0
    return "\n".join(full), dict(unit_lines=e - s + 1, truncated=est > budget_tokens, omitted_lines=omitted)


# ----------------------------------------------------------------------------- prompts
def build_phase1(cwe, kind, code, meta, notes, traced_evidence=None):
    info = CWE_INFO.get(cwe, DEFAULT_INFO)
    factors = "\n".join(f"  - {f}" for f in info["factors"])
    trunc = (f"\nNOTE: this unit is large ({meta['unit_lines']} lines); some lines were omitted and are marked. Do not assume omitted code is safe "
             f"or unsafe; say what you could not determine.\n") if meta["truncated"] else ""
    lang = "Java (web application; the unit may be a servlet filter, MVC controller, utility or Grails/GSP template)"
    fence = "gsp" if kind.startswith("template") else "java"
    traced_section = ""
    if traced_evidence:
        traced_section = f"""
## Traced Parameter Origin (deterministic, mechanical trace — not a verdict)
The following was produced by a mechanical, non-LLM trace of where each flagged sink argument's value
textually originates: local reassignments inside this unit, and, when a variable turns out to be this
unit's own parameter, the matching argument passed at each call site found in the codebase's call graph.
It reports facts only (what reassigns what, which caller passes what); it does not judge whether any of
it is attacker-controlled, sanitized, or exploitable — that judgment is yours to make from the evidence.
{traced_evidence}
"""
    return f"""# Vulnerability Analysis — Research Phase

## Vulnerability Type
**{cwe}: {info['name']}**
{info['description']}

## Code Under Analysis
- **Language:** {lang}
- **Unit:** {kind}
{trunc}
## Static Notes (deterministic, produced by a non-LLM analysis; not a verdict)
{notes}
{traced_section}
## Code (line numbers on the left)
```{fence}
{code}
```

## Factors to Investigate
{factors}

## Your Task
Carefully analyze whether this code contains an exploitable instance of {cwe}.

Specifically answer:
1. **What is security-relevant here** (the sink, path, evaluated text, parser, output or sensitive operation), and where does its data come from?
2. **What protection exists** (validation, normalization and containment check, hardening of the parser/engine, encoding, authorization) and does it cover the dangerous use on every path you can see?
3. **Who can reach this code** (unauthenticated, any logged-in user, privileged user), considering the callers listed in the notes?
4. **What is your preliminary verdict?** (exploitable / not exploitable / uncertain)

Be concrete. Quote specific variable names and line numbers from the code.
"""


def build_phase2(cwe, report):
    info = CWE_INFO.get(cwe, DEFAULT_INFO)
    return f"""# Exploitability Assessment — Decision Phase

## Issue
- **{cwe}: {info['name']}**

## Research Findings
{report}

## Final Decision

Based on the research above, make a definitive binary classification.

Rules:
- Mark **UNEXPLOITABLE** only if you have concrete evidence that the issue cannot occur: for example, every dynamic value is a constant or is
  neutralized correctly for its context, the parser/engine is hardened, an effective validation/containment/authorization check applies on every path
  that reaches the sensitive operation, or the code is unreachable.
- Mark **EXPLOITABLE** if there is any realistic way an attacker with the access level needed to reach this code can {info['harm']}.
- When uncertain, default to **EXPLOITABLE** (conservative).

Respond in EXACTLY this format (no other text):

VERDICT: <EXPLOITABLE or UNEXPLOITABLE>
CONFIDENCE: <HIGH or MEDIUM or LOW>
REASONING: <one paragraph, max 150 words>
"""


def unit_kind(u):
    if u["name"] == FILE_SCOPE:
        return "template / view file (top-level markup)" if not u["file"].endswith(".java") else "top-level code of a class (fields, initializers)"
    b = u["bare"]
    return "constructor" if b == "<init>" else ("static initializer" if b == "<clinit>" else ("initializer block" if b == "<init-block>" else "method"))


def short(name):
    return name if name == FILE_SCOPE else re.sub(r"^.*?([A-Za-z_$][\w$]*\.[^.()]*(?:\(.*)?)$", r"\1", name)


def notes_for(cwe, u, rec, cb, cg):
    cs = sorted({("top-level code of a class/template" if cb["units"][c]["name"] == FILE_SCOPE else short(cb["units"][c]["name"])) for c in cg["callers"][u["id"]]})
    ce = sorted({short(cb["units"][c]["name"]) for c in cg["callees"][u["id"]] if cb["units"][c]["name"] != FILE_SCOPE})
    f = lambda xs: (", ".join(xs[:8]) + (f" (+{len(xs) - 8} more)" if len(xs) > 8 else "")) if xs else None
    lines = [f"- Callers found in the analyzed codebase (name+arity static call graph, may be incomplete): {f(cs) or 'none (entry point, or invoked from outside the analyzed code / by reflection or a framework)'}.",
             f"- Callees resolved inside the analyzed codebase: {f(ce) or 'none'}.",
             f"- Request or data-source API read directly in this unit: {'yes' if rec['own_source'] else 'no'}.",
             f"- Statically detected relevant sinks in this unit: {rec['sinks']}; of these, with a dynamic (non-constant, non-neutralized) argument or without hardening: {rec['bad']}.",
             f"- Protective vocabulary (validation / containment / encoding / hardening) present in this unit: {'yes' if rec['guarded'] else 'no'}."]
    return "\n".join(lines)


def build_prompt(root, cb, cg, rec, cwe, window_tokens):
    u = cb["units"][rec["id"]]
    focus = [d["line"] for d in rec.get("desc", []) if "line" in d] + ([u["start"]] if not rec.get("desc") else [])
    code, meta = render(root, u, cb, focus, max(1000, window_tokens - OVERHEAD_TOKENS - OUT1))
    kind = unit_kind(u)
    traced = PT.trace_unit_sinks(cb, cg, u, rec.get("desc"))
    p1 = build_phase1(cwe, kind, code, meta, notes_for(cwe, u, rec, cb, cg), traced_evidence=traced)
    return dict(id=rec["id"], system1=SYSTEM_1, prompt1=p1, meta=meta, kind=kind)


# ----------------------------------------------------------------------------- token counting
def count_tokens(texts, tok_python=None, tokenizer=None):
    """texts = list of user-prompt strings, or of (system, prompt) pairs.
    exact via a subprocess in an env that has `tokenizers`/`transformers`:
      --tokenizer DIR          a HF model dir: counts the CHAT-TEMPLATED request (harmony framing + system + user + generation prompt,
                               reasoning_effort from PARAMS)  -> what the server actually tokenizes
      --tokenizer tokenizer.json   raw text only (no template)
    else the chars/3.5 ESTIMATE (+ HARMONY_OVERHEAD per request)"""
    pairs = [t if isinstance(t, (tuple, list)) else ("", t) for t in texts]
    if tok_python and tokenizer and os.path.isdir(tokenizer):
        code = ("import json,sys\nfrom transformers import AutoTokenizer\ntk=AutoTokenizer.from_pretrained(sys.argv[1])\n"
                "eff=sys.argv[2]\n"
                "for l in sys.stdin:\n out=[]\n for s,u in json.loads(l):\n  m=([{'role':'system','content':s}] if s else [])+[{'role':'user','content':u}]\n"
                "  r=tk.apply_chat_template(m,tokenize=True,add_generation_prompt=True,reasoning_effort=eff)\n  out.append(len(r['input_ids'] if hasattr(r,'keys') else r))\n print(json.dumps(out),flush=True)\n")
        argv = [tok_python, "-c", code, tokenizer, PARAMS["reasoning_effort"]]
        how = "exact (chat template)"
    elif tok_python and tokenizer:
        code = ("import json,sys\nfrom tokenizers import Tokenizer\ntk=Tokenizer.from_file(sys.argv[1])\n"
                "for l in sys.stdin:\n print(json.dumps([len(e.ids) for e in tk.encode_batch([s+'\\n'+u if s else u for s,u in json.loads(l)], add_special_tokens=False)]),flush=True)\n")
        argv = [tok_python, "-c", code, tokenizer]
        how = "exact (raw text, no template framing)"
    else:
        return [int(len(s + u) / CHARS_PER_TOKEN) + 1 + HARMONY_OVERHEAD for s, u in pairs], "ESTIMATE (chars/3.5 + %d framing)" % HARMONY_OVERHEAD
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    out = []
    for i in range(0, len(pairs), 64):
        p.stdin.write(json.dumps(pairs[i:i + 64]) + "\n"); p.stdin.flush()
        out.extend(json.loads(p.stdout.readline()))
    p.stdin.close(); p.wait()
    return out, how


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))] if xs else 0


def request_key(model, phase, system, prompt, max_tokens, temperature, reasoning_effort, seed):
    return hashlib.sha256(json.dumps([model, phase, system, prompt, max_tokens, temperature, reasoning_effort, seed], sort_keys=True).encode()).hexdigest()


def keyed(variant, model, phase, system, prompt, max_tokens, temperature, reasoning_effort, seed):
    """cache key including the ablation variant.  variant "main" reproduces request_key exactly (the frozen main-run keys); every other variant
    appends 'variant:<name>' to the hashed list, so variants can never collide with the main run or with each other (seed alone also separates seeds)."""
    k = [model, phase, system, prompt, max_tokens, temperature, reasoning_effort, seed]
    if variant == "main":
        return request_key(*k)
    return hashlib.sha256(json.dumps(k + ["variant:" + variant], sort_keys=True).encode()).hexdigest()


def phase1_key(p):
    """cache key of a unit's phase-1 request (arm-independent: a function of the prompt and PARAMS only)"""
    return request_key(PARAMS["model"], "p1", p["system1"], p["prompt1"], OUT1, TEMP1, PARAMS["reasoning_effort"], PARAMS["seed"])


def dry_run(root, cb, cg, recs, cwe, label, arm, window_tokens, tok_python=None, tokenizer=None, out_prompts=None, log=print):
    """prints calls and token counts for one slice; makes NO LLM call.
    input tokens  phase 1: exact (chat-templated request).  phase 2 UPPER bound: scaffold + a phase-1 answer of OUT1 tokens (the answer cannot
                  exceed max_tokens, which also pays for reasoning).
    output tokens UPPER bound: OUT1 + OUT2 per candidate, i.e. max_tokens INCLUDING reasoning tokens (what a reasoning model may spend)."""
    sel = [r for r in recs if r[arm]]
    prompts = [build_prompt(root, cb, cg, r, cwe, window_tokens) for r in sel]
    toks, how = count_tokens([(p["system1"], p["prompt1"]) for p in prompts], tok_python, tokenizer)
    for p, t in zip(prompts, toks):
        p["tok1"] = t
        p["key1"] = phase1_key(p)
    unitkeys = {f"{r['file']}::{r['function']}": p["key1"] for r, p in zip(sel, prompts)}
    scaffold = count_tokens([(SYSTEM_2, build_phase2(cwe, ""))], tok_python, tokenizer)[0][0]
    fq = re.compile(r"\b(?:org|com|net|io)\.[a-z][\w]*\.[a-z][\w.]*")
    n_fqn = sum(bool(fq.search(p["prompt1"])) for p in prompts)
    n_path = sum(bool(re.search(r"[\w/.-]+\.(?:java|gsp)\b", p["prompt1"])) for p in prompts)
    t1 = [p["tok1"] for p in prompts]
    p2 = scaffold + OUT1
    res = dict(slice=label, cwe=cwe, arm=arm, candidates=len(sel), calls=2 * len(sel), tokens=how,
               in_tokens_phase1=sum(t1), in_tokens_phase2_upper=p2 * len(sel), out_tokens_upper=(OUT1 + OUT2) * len(sel),
               p50=pct(t1, 50), p95=pct(t1, 95), max=max(t1) if t1 else 0,
               over={str(w): sum(x + OUT1 > w for x in t1) for w in (8192, 16384, 32768, 131072)},
               truncated=sum(p["meta"]["truncated"] for p in prompts), prompts_with_fqn=n_fqn, prompts_with_file_name=n_path,
               params=PARAMS, unitkeys=unitkeys)
    log(json.dumps({k: v for k, v in res.items() if k != "unitkeys"}))
    if out_prompts:
        with open(out_prompts, "w") as fh:
            for p in prompts:
                fh.write(json.dumps(p) + "\n")
    return res


# ----------------------------------------------------------------------------- freeze (prompts + parameters)
def _sha(x):
    return hashlib.sha256(x if isinstance(x, bytes) else json.dumps(x, sort_keys=True).encode()).hexdigest()


def freeze_components():
    """sha256 of everything that defines a Stage-5 request: prompts' fixed text, builders' source, sampling parameters.
    (Client plumbing -- retries, concurrency, usage capture -- is deliberately not hashed: it cannot change a request.)"""
    import inspect
    fn = [masked_lines, render, build_phase1, build_phase2, unit_kind, short, notes_for, build_prompt, request_key, phase1_key, parse_verdict]
    return dict(params=PARAMS, params_sha=_sha(PARAMS), system1_sha=_sha(SYSTEM_1), system2_sha=_sha(SYSTEM_2), cwe_info_sha=_sha(CWE_INFO),
                default_info_sha=_sha(DEFAULT_INFO), constants_sha=_sha([CHARS_PER_TOKEN, OVERHEAD_TOKENS, FILE_SCOPE]),
                phase2_template_sha={c: _sha(build_phase2(c, "{REPORT}")) for c in sorted(CWE_INFO)},
                builders_sha={f.__name__: _sha(inspect.getsource(f).encode()) for f in fn})


def verify_freeze(path, slice_name, unitkeys, root_dir):
    """abort unless the prompt/parameter definition, the model snapshot template and this slice's per-unit phase-1 keys equal the frozen ones"""
    fz = json.load(open(path))
    bad = []
    cur = freeze_components()
    for k, v in cur.items():
        if fz["components"].get(k) != v:
            bad.append(f"component {k} differs from the freeze")
    pk = os.path.join(root_dir, fz["prompt_keys_file"])
    if _sha(open(pk, "rb").read()) != fz["prompt_keys_sha256"]:
        bad.append("notes prompt-keys file was modified after the freeze")
    frozen = json.load(open(pk)).get(slice_name, {})
    for u, k in unitkeys.items():
        if frozen.get(u) != k:
            bad.append(f"unit {u}: phase-1 key differs from the frozen prompt" if u in frozen else f"unit {u}: not in the frozen prompt set")
    if bad:
        raise SystemExit("Stage-5 freeze violated (this would be a TUNED run):\n  " + "\n  ".join(bad[:10]))


# ----------------------------------------------------------------------------- LLM (gated) + cache
class CacheMiss(RuntimeError):
    pass


_REASONING_MODEL_PREFIXES = ("gpt-5", "o1", "o3", "o4", "claude-opus-5", "claude-sonnet-5")


class LLMClient:
    """OpenAI-compatible chat client (vLLM).  Cache hit -> no network.  `cache_only` turns any miss into a hard CacheMiss (never fail-open)."""
    def __init__(self, endpoint, model=None, api_key="dummy", timeout=900, cache_only=False, retries=3, variant="main", seed=None):
        self.endpoint, self.model, self.key, self.timeout = endpoint.rstrip("/"), model or PARAMS["model"], api_key, timeout
        self.cache_only, self.retries = cache_only, retries
        self.variant, self.seed = variant, PARAMS["seed"] if seed is None else seed
        os.makedirs(LLM_CACHE, exist_ok=True)

    def chat(self, phase, system, prompt, max_tokens, temperature):
        """-> dict(content, cached, finish, usage={prompt_tokens, completion_tokens}, reasoning_chars)"""
        k = keyed(self.variant, self.model, phase, system, prompt, max_tokens, temperature, PARAMS["reasoning_effort"], self.seed)
        cp = os.path.join(LLM_CACHE, k + ".json")
        if os.path.exists(cp):
            d = json.load(open(cp))
            return dict(content=d["content"], cached=True, finish=d.get("finish"), usage=d.get("usage") or {}, reasoning_chars=d.get("reasoning_chars", 0))
        if self.cache_only:
            raise CacheMiss(f"{phase} request {k[:12]} not in cache")
        if os.environ.get("MEDICALJAVA_ALLOW_LLM") != "1":
            raise RuntimeError("LLM calls are disabled: set MEDICALJAVA_ALLOW_LLM=1 to allow live model calls (they cost tokens and send source code to the endpoint)")
        is_reasoning = self.model.startswith(_REASONING_MODEL_PREFIXES)
        if is_reasoning:
            # gpt-5 (and o1/o3/o4) reject the classic params this pipeline was built around:
            # no custom temperature, no seed, no reasoning_effort at the top level, and the token
            # budget field is renamed -- and it must cover hidden reasoning tokens too, which can
            # silently eat the whole budget and leave zero tokens for the actual answer (empty
            # content, not an error). Same fix already applied and verified on the IRIS side.
            params = dict(model=self.model, messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                          max_completion_tokens=max(max_tokens, 16000))
        else:
            params = dict(model=self.model, messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                          max_tokens=max_tokens, temperature=temperature, seed=self.seed, reasoning_effort=PARAMS["reasoning_effort"])
        body = json.dumps(params).encode()
        last = None
        for attempt in range(self.retries + 1):                # transport / 5xx (vLLM harmony header errors are transient): same request again
            try:
                req = urllib.request.Request(self.endpoint + "/chat/completions", body, {"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    d = json.loads(r.read())
                break
            except Exception as ex:
                last = ex
                time.sleep(2 * (attempt + 1))
        else:
            raise RuntimeError(f"request failed after {self.retries + 1} tries: {last}")
        m = d["choices"][0]["message"]
        content = m.get("content") or ""
        reasoning = m.get("reasoning_content") or m.get("reasoning") or ""
        u = d.get("usage") or {}
        rec = dict(model=self.model, phase=phase, content=content, finish=d["choices"][0].get("finish_reason"),
                   usage=dict(prompt_tokens=u.get("prompt_tokens"), completion_tokens=u.get("completion_tokens")),
                   reasoning=reasoning, reasoning_chars=len(reasoning))
        tmp = cp + f".{os.getpid()}.tmp"
        json.dump(rec, open(tmp, "w")); os.replace(tmp, cp)
        _log_usage(self.model, rec["usage"])
        return dict(content=content, cached=False, finish=rec["finish"], usage=rec["usage"], reasoning_chars=len(reasoning))


def parse_verdict(text):
    m = re.search(r"VERDICT:\s*\**\s*(UNEXPLOITABLE|EXPLOITABLE)", text or "", re.I)
    c = re.search(r"CONFIDENCE:\s*\**\s*(HIGH|MEDIUM|LOW)", text or "", re.I)
    if not m:
        return None, (c.group(1).upper() if c else None)
    return m.group(1).upper() == "UNEXPLOITABLE", (c.group(1).upper() if c else None)


def parse_reasoning(text):
    """Extract the free-text justification for a verdict (evidence trace).
    Mirrors the C/C++ pipeline's parse_assessment(): pulls the REASONING:
    paragraph the prompt asks for, truncated to 500 chars; if that line is
    missing (garbled/unparseable answer), falls back to the full raw
    response instead of discarding it, so a reader can always see what the
    model actually said."""
    m = re.search(r"REASONING:\s*(.+)", text or "", re.I | re.S)
    if m:
        return m.group(1).strip()[:500]
    return (text or "").strip()[:500]


def _tok(*rs):
    return dict(tok_in=sum((r["usage"].get("prompt_tokens") or 0) for r in rs), tok_out=sum((r["usage"].get("completion_tokens") or 0) for r in rs))


def assess(client, p, cwe):
    """two-phase verdict.  Failure classes (all fail OPEN to exploitable, flagged `fallback`, reason in `error`):
       transport (request failed), p1_empty (no phase-1 answer: truncated inside reasoning or empty), unparseable (no VERDICT line in phase 2)"""
    r1 = r2 = None
    try:
        r1 = client.chat("p1", p["system1"], p["prompt1"], OUT1, TEMP1)
        if not r1["content"].strip():
            return dict(verdict="exploitable", confidence="LOW", fallback=True, error="p1_empty", fail="p1_empty", cached=r1["cached"],
                        reasoning="(no phase-1 research report: truncated inside reasoning or empty)",
                        finish1=r1["finish"], **_tok(r1))
        r2 = client.chat("p2", SYSTEM_2, build_phase2(cwe, r1["content"]), OUT2, TEMP2)
    except CacheMiss:
        raise
    except Exception as ex:
        return dict(verdict="exploitable", confidence="LOW", fallback=True, error=str(ex)[:200], fail="transport", cached=False,
                    reasoning=f"(transport failure before a verdict could be produced: {str(ex)[:200]})",
                    **(_tok(r1) if r1 else dict(tok_in=0, tok_out=0)))
    un, conf = parse_verdict(r2["content"])
    reasoning = parse_reasoning(r2["content"])
    base = dict(cached=r1["cached"] and r2["cached"], finish1=r1["finish"], finish2=r2["finish"], reasoning=reasoning, **_tok(r1, r2))
    if un is None:
        return dict(verdict="exploitable", confidence="LOW", fallback=True, error="unparseable verdict", fail="unparseable", **base)
    return dict(verdict="unexploitable" if un else "exploitable", confidence=conf or "LOW", fallback=False, fail=None, **base)


def run_stage5(root, cb, cg, recs, cwe, label, arm, window_tokens, client, out_path, log=print, workers=8):
    """writes predictions JSONL (with `slice`) in candidate order; refuses to contact a model unless MEDICALJAVA_ALLOW_LLM=1 (cache hits are free)"""
    from concurrent.futures import ThreadPoolExecutor
    sel = [x for x in recs if x[arm]]
    prompts = [build_prompt(root, cb, cg, r, cwe, window_tokens) for r in sel]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        res = list(ex.map(lambda p: assess(client, p, cwe), prompts))
    with open(out_path, "w") as fh:
        for r, a in zip(sel, res):
            fh.write(json.dumps(dict(file=r["file"], function=r["function"], line_start=r["line_start"], line_end=r["line_end"], cwe=cwe,
                                     slice=label, **a)) + "\n")
    log(f"[stage5] {len(sel)} predictions -> {out_path}")


def selftest():
    """offline checks: verdict parsing, the LLM gate, cache_only, cache-key properties, and the client against a FAKE local server
    (payload fields, reasoning/usage capture, retry on 5xx, failure classes).  No model is contacted."""
    import http.server, tempfile, threading
    global LLM_CACHE
    assert parse_verdict("VERDICT: EXPLOITABLE\nCONFIDENCE: HIGH\nREASONING: x") == (False, "HIGH")
    assert parse_verdict("VERDICT: **UNEXPLOITABLE**\nCONFIDENCE: low") == (True, "LOW")
    assert parse_verdict("no verdict here")[0] is None
    assert parse_reasoning("VERDICT: EXPLOITABLE\nCONFIDENCE: HIGH\nREASONING: the sink is reachable from an unauthenticated endpoint") == \
        "the sink is reachable from an unauthenticated endpoint"
    assert parse_reasoning("no reasoning line here, just garbled text") == "no reasoning line here, just garbled text"  # fail-open: keep the raw text
    assert len(parse_reasoning("REASONING: " + "x" * 600)) == 500  # truncated, never silently dropped
    LLM_CACHE = tempfile.mkdtemp(prefix="m4cache")
    c = LLMClient("http://127.0.0.1:1")
    os.environ.pop("MEDICALJAVA_ALLOW_LLM", None)
    try:
        c.chat("p1", "s", "definitely-not-cached-" + os.urandom(4).hex(), 10, 0.0)
        raise SystemExit("GATE FAILED: contacted a model without MEDICALJAVA_ALLOW_LLM")
    except RuntimeError:
        pass
    a = assess(c, dict(system1="s", prompt1="p-" + os.urandom(4).hex()), "CWE-22")
    assert a["fallback"] and a["fail"] == "transport" and a["verdict"] == "exploitable", a
    try:
        assess(LLMClient("http://127.0.0.1:1", cache_only=True), dict(system1="s", prompt1="x-" + os.urandom(4).hex()), "CWE-22")
        raise SystemExit("cache_only must raise CacheMiss")
    except CacheMiss:
        pass
    # cache key: depends on every sampling parameter, not on anything else
    base = request_key(PARAMS["model"], "p1", "s", "p", 1, 0.2, "medium", 1)
    assert len({base, request_key("m2", "p1", "s", "p", 1, 0.2, "medium", 1), request_key(PARAMS["model"], "p1", "s", "p", 1, 0.2, "high", 1),
                request_key(PARAMS["model"], "p1", "s", "p", 1, 0.2, "medium", 2), request_key(PARAMS["model"], "p1", "s", "p", 2, 0.2, "medium", 1),
                request_key(PARAMS["model"], "p1", "s", "p", 1, 0.0, "medium", 1)}) == 6
    # fake server
    seen, state = [], dict(fail_first=True)
    def reply(content, reasoning="thinking", finish="stop"):
        return dict(choices=[dict(message=dict(content=content, reasoning_content=reasoning), finish_reason=finish)], usage=dict(prompt_tokens=11, completion_tokens=22))
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(body)
            if state["fail_first"]:
                state["fail_first"] = False
                self.send_response(500); self.end_headers(); return
            usr = body["messages"][1]["content"]
            out = reply("") if "EMPTYCASE" in usr else (reply("report text") if body["max_tokens"] == OUT1 else reply("VERDICT: UNEXPLOITABLE\nCONFIDENCE: HIGH\nREASONING: ok" if "report text" in usr else "garbled"))
            raw = json.dumps(out).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    os.environ["MEDICALJAVA_ALLOW_LLM"] = "1"
    try:
        fc = LLMClient(f"http://127.0.0.1:{srv.server_port}", retries=2)
        r = assess(fc, dict(system1="s", prompt1="hello"), "CWE-22")
        assert r["verdict"] == "unexploitable" and not r["fallback"] and r["tok_in"] == 22 and r["tok_out"] == 44, r      # one 5xx retried, usage summed over 2 calls
        assert r["reasoning"] == "ok", r      # evidence trace captured, not just a bare verdict
        b = seen[-1]
        assert b["reasoning_effort"] == PARAMS["reasoning_effort"] and b["seed"] == PARAMS["seed"] and b["max_tokens"] == OUT2 and b["temperature"] == TEMP2, b
        r2 = assess(fc, dict(system1="s", prompt1="hello"), "CWE-22")                         # second time: all from cache, no new request
        n = len(seen)
        assert r2["cached"] and len(seen) == n
        empty_res = assess(fc, dict(system1="s", prompt1="EMPTYCASE"), "CWE-22")
        assert empty_res["fail"] == "p1_empty" and empty_res["reasoning"], empty_res   # fail-open still explains itself
        state["fail_first"] = False
    finally:
        os.environ.pop("MEDICALJAVA_ALLOW_LLM", None); srv.shutdown()
    print("stage5 selftest OK (parse, gate, cache_only, cache-key, fake-server payload/retry/usage/failure classes)")


if __name__ == "__main__":
    selftest()
