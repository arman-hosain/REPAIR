#!/usr/bin/env python3
"""
llm_agent.py — Stage 4 (Evidence Tracing, via param_tracer.py) + Stage 5 (two-phase LLM Assessment)

Implements the paper's LLM-based exploitability agent:
  Phase 1 (Research): LLM explores the code context and builds a findings report.
  Phase 2 (Assessment): LLM reads the report and makes a binary decision.

Uses the OpenAI-compatible API (vLLM, OpenAI, etc.) via plain requests.
No LangChain/LangGraph dependency required.
"""

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))      # cpp_pipeline/ on sys.path, so `sinkpipe` resolves whether
                                                # this module is run standalone or imported as a package member
from sinkpipe import param_tracer as PT         # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CWE-specific exploitability factors (from assessor_prompt.py in atlantis-java)
# Adapted for C
# ---------------------------------------------------------------------------

CWE_INFO: dict[str, dict] = {
    "CWE-121": {
        "name": "Stack Buffer Overflow",
        "description": (
            "The program copies data into a buffer without verifying the size, "
            "potentially overwriting adjacent stack memory."
        ),
        "factors": [
            "Is the destination buffer a fixed-size array on the stack?",
            "Is the size argument derived from user-controlled data (e.g., strlen of input)?",
            "Is there any bounds check before the copy?",
            "Can an attacker provide input longer than the buffer?",
            "Static/compile-time size limits are generally safe.",
            "If the source is a constant literal string, it is likely safe.",
        ],
    },
    "CWE-122": {
        "name": "Heap Buffer Overflow",
        "description": (
            "The program copies data into a heap-allocated buffer without "
            "verifying the size, potentially overwriting adjacent heap memory."
        ),
        "factors": [
            "Is the destination buffer heap-allocated with a fixed/bounded size?",
            "Is the size argument derived from user-controlled data (e.g., a length read straight off the input)?",
            "Is there any bounds check or clamp before the copy?",
            "Can an attacker provide input longer than the buffer's allocated size?",
            "Static/compile-time size limits are generally safe.",
            "If the source is a constant literal string, it is likely safe.",
        ],
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "description": (
            "The program dereferences a pointer that may be NULL, "
            "causing a crash or unexpected behavior."
        ),
        "factors": [
            "Is there a NULL check before the dereference?",
            "Can the pointer be NULL based on server/input data?",
            "Is this in an error handling path that is rarely reached?",
            "A cast of an integer error code to a pointer and then dereferencing it is always exploitable.",
            "Pointer-to-function dereferences without NULL checks are dangerous.",
        ],
    },
    "CWE-078": {
        "name": "OS Command Injection",
        "description": "User-controlled input reaches an OS command execution function.",
        "factors": [
            "Is any argument to system()/popen()/exec*() user-controlled?",
            "Are all arguments hard-coded constants? If so, likely safe.",
            "Is there shell meta-character filtering?",
        ],
    },
    "CWE-022": {
        "name": "Path Traversal",
        "description": "User-controlled input is used as a file path without sanitization.",
        "factors": [
            "Is the path argument derived from user/network input?",
            "Is there a '../' or absolute-path check?",
            "Is the file operation restricted to a chroot or specific directory?",
        ],
    },
    "CWE-787": {
        "name": "Out-of-Bounds Write",
        "description": (
            "The program writes data past the end, or before the beginning, "
            "of the intended buffer."
        ),
        "factors": [
            "Is the write index/length derived from user-controlled data?",
            "Is the index/length clamped or bounds-checked against the destination's real size before the write?",
            "If the write is a terminator (e.g. NUL byte) at a computed index, does that index use the SAME bound that constrained an earlier copy into the same buffer, or a different, unclamped one?",
            "Static/compile-time bounds are generally safe.",
        ],
    },
    "CWE-126": {
        "name": "Buffer Over-read",
        "description": (
            "The program reads past the end of the intended buffer, typically "
            "because a loop or index advances without being checked against "
            "the buffer's real length."
        ),
        "factors": [
            "Is the read index advanced (incremented) based on a fixed iteration count rather than the actual remaining buffer length?",
            "Is the index ever compared against the buffer's real length/size anywhere before the read?",
            "Can the buffer be shorter than the number of reads the code assumes it can perform?",
        ],
    },
    "CWE-129": {
        "name": "Improper Validation of Array Index",
        "description": (
            "An index derived from user-controlled data is used to access an "
            "array (including an array of function pointers) without first "
            "verifying it falls within the array's bounds."
        ),
        "factors": [
            "Is the index attacker-controlled (e.g. a raw byte/field read from network input)?",
            "Is there a check (e.g. against the array's length/size, or a switch/case covering only valid values) before the index is used?",
            "Is the array used as a jump/dispatch table (function pointers), making an out-of-bounds access a control-flow hijack rather than just a bad read?",
        ],
    },
}

DEFAULT_CWE_INFO = {
    "name": "Unknown",
    "description": "A potentially dangerous operation.",
    "factors": ["Is any argument user-controlled?"],
}



# ---------------------------------------------------------------------------
# Optional extended CWE context (MITRE CWE data), gated by --cwe-context
# ---------------------------------------------------------------------------

CWE_CONTEXT_MODES = ("hardcoded", "extended", "none", "bare", "nohint", "mitre")
_CWE_EXTENDED_FILE = Path(__file__).resolve().parent / "cwe_extended_info.json"
_cwe_extended_cache: Optional[dict] = None


def _load_cwe_extended() -> dict:
    global _cwe_extended_cache
    if _cwe_extended_cache is None:
        _cwe_extended_cache = json.loads(_CWE_EXTENDED_FILE.read_text())
    return _cwe_extended_cache


def _clip(text: str, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " ..."


def build_extended_cwe_context(cwe: str, include_examples: bool = False) -> str:
    """Render MITRE's description/consequences/detection/mitigation text for one CWE.

    DemonstrativeExamples are excluded by default: for CWE-121 and CWE-134 they are
    close to the curl-003/curl-001 ground-truth shapes (64-byte stack buffer + strcpy
    of a network-derived string; attacker string in the format-string position), so
    including them would hand the model a near-answer.
    """
    entry = _load_cwe_extended().get(cwe)
    if not entry:
        return ""
    parts = [f"{entry['Description']}"]
    if entry.get("ExtendedDescription"):
        parts.append(_clip(entry["ExtendedDescription"], 900))
    cons = entry.get("CommonConsequences") or []
    if cons:
        lines = [f"  - {'/'.join(c.get('Scope', []))}: {'/'.join(c.get('Impact', []))}"
                 + (f" -- {_clip(c['Note'], 200)}" if c.get("Note") else "") for c in cons]
        parts.append("Common consequences:\n" + "\n".join(lines))
    mit = entry.get("PotentialMitigations") or []
    if mit:
        lines = [f"  - {_clip(m.get('Description', ''), 300)}" for m in mit[:6]]
        parts.append("Mitigations (what an effective guard looks like):\n" + "\n".join(lines))
    if include_examples:
        for ex in (entry.get("DemonstrativeExamples") or [])[:2]:
            parts.append("Example: " + _clip(json.dumps(ex.get("Entries", [])), 1200))
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------

class LLMClient:
    """Thin wrapper around the OpenAI-compatible chat completions endpoint."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "dummy",
        timeout: int = 120,
        max_retries: int = 3,
    ):
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

    def chat(
        self,
        messages: list[dict],
        max_tokens: int = 1024,
        temperature: float = 0.1,
        stop: list[str] = None,
        extra: dict = None,
    ) -> str:
        """Send a chat completion request and return the assistant's text.

        `extra` is merged into the request payload as-is (e.g. vLLM's
        `chat_template_kwargs` to toggle a model's thinking mode, or
        `reasoning_effort` for gpt-oss-style models). Opt-in only -- omitting
        it reproduces the exact payload this client has always sent.
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if stop:
            payload["stop"] = stop
        if extra:
            payload.update(extra)

        last_error = None
        for attempt in range(self.max_retries):
            try:
                resp = self.session.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                choice = data["choices"][0]
                content = choice["message"]["content"]
                if content is None:
                    # reasoning models (gpt-oss) can spend the whole max_tokens budget on
                    # reasoning and return no answer. With temperature > 0 a fresh sample
                    # usually answers, so resample (only non-answers are retried); at
                    # temperature 0 a retry would loop identically, so surface the error.
                    if temperature > 0 and attempt < self.max_retries - 1:
                        logger.warning(f"empty content (finish_reason={choice.get('finish_reason')}); "
                                       f"resampling (attempt {attempt+1}/{self.max_retries})")
                        continue
                    raise RuntimeError(
                        f"empty content (finish_reason={choice.get('finish_reason')}, "
                        f"max_tokens={max_tokens}) -- reasoning consumed the token budget")
                return content.strip()
            except requests.exceptions.RequestException as e:
                last_error = e
                wait = 2 ** attempt
                body = getattr(getattr(e, "response", None), "text", "") or ""
                logger.warning(f"LLM request failed (attempt {attempt+1}/{self.max_retries}): {e}"
                               + (f" | body: {body[:300]}" if body else "") + f". Retrying in {wait}s...")
                time.sleep(wait)
            except (KeyError, IndexError, json.JSONDecodeError) as e:
                last_error = e
                logger.error(f"Unexpected LLM response format: {e}")
                break

        raise RuntimeError(f"LLM call failed after {self.max_retries} attempts: {last_error}")


# ---------------------------------------------------------------------------
# Code context reader
# ---------------------------------------------------------------------------

def read_code_context(root: Path, file_name: str, line_num: int, ctx: int = 20) -> str:
    """Read ±ctx lines around line_num from file_name."""
    candidates = [
        root / file_name,
        *root.rglob(Path(file_name).name),
    ]
    for path in candidates:
        if path.exists():
            try:
                lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
                start = max(0, line_num - 1 - ctx)
                end = min(len(lines), line_num + ctx)
                result = []
                for i in range(start, end):
                    marker = " >>> " if i == line_num - 1 else "     "
                    result.append(f"{marker}{i+1:5d} | {lines[i]}")
                return "\n".join(result)
            except Exception as e:
                logger.warning(f"Could not read {path}: {e}")
    return f"(file not found: {file_name})"


def read_function_body(root: Path, file_name: str, func_name: str) -> str:
    """Try to extract a function body from a C file by name."""
    if not func_name:
        return ""
    candidates = [root / file_name, *root.rglob(Path(file_name).name)]
    for path in candidates:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
            # Find function definition
            pattern = re.compile(
                rf'\b{re.escape(func_name)}\s*\([^;]*\)\s*\{{',
                re.DOTALL
            )
            m = pattern.search(text)
            if not m:
                continue
            # Extract up to 80 lines
            start = text[:m.start()].count('\n')
            lines = text.splitlines()
            body_lines = lines[start:start+80]
            return "\n".join(body_lines)
        except Exception:
            continue
    return ""


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

def build_research_prompt(sink: dict, root: Path, harness: str, traced_evidence: str = None,
                          cwe_context: Optional[str] = None) -> str:
    """Build the Phase 1 research prompt."""
    coord = sink['coord']
    cwe = sink.get('cwe', 'unknown')
    info = CWE_INFO.get(cwe, DEFAULT_CWE_INFO)

    file_name = coord['file_name']
    line_num = coord['line_num']
    func_name = coord.get('func_name', '')
    containing = sink.get('containing_function', '')
    call_text = sink.get('call_text', '')

    # Get wider code context
    code_ctx = read_code_context(root, file_name, line_num, ctx=25)

    # Get the containing function body
    func_body = ""
    if containing and containing != func_name:
        func_body = read_function_body(root, file_name, containing)

    factors_text = "\n".join(f"  - {f}" for f in info['factors'])
    # None -> SINKPIPE_CWE_CONTEXT env var (lets the param_trace/ diagnostic scripts,
    # which call this builder directly, run an arm without per-script edits)
    cwe_context = cwe_context or os.environ.get("SINKPIPE_CWE_CONTEXT", "hardcoded")
    if cwe_context not in CWE_CONTEXT_MODES:
        raise ValueError(f"cwe_context must be one of {CWE_CONTEXT_MODES}, got {cwe_context!r}")
    if cwe_context == "nohint":
        # hardcoded minus the one CWE-476 factor that describes the curl-005..008 bug shape
        # (integer error code cast to a pointer); identical to hardcoded for every other CWE
        factors_text = "\n".join(f"  - {f}" for f in info['factors']
                                 if "cast of an integer error code" not in f)
    elif cwe_context == "mitre":
        # MITRE text INSTEAD of the hand-written description/factors (header keeps CWE ID + name)
        factors_text = build_extended_cwe_context(cwe) or "  (no MITRE data for this CWE)"
    elif cwe_context == "none":
        factors_text = "  (none provided -- use your own judgment)"
    elif cwe_context == "extended":
        ext = build_extended_cwe_context(cwe)
        if ext:
            factors_text = factors_text + "\n\n### MITRE CWE reference\n" + ext

    func_body_section = ""
    if func_body:
        func_body_section = f"""
### Containing Function: `{containing}`
```c
{func_body[:3000]}
```
"""

    traced_evidence_section = ""
    if traced_evidence:
        traced_evidence_section = f"""
## Traced Parameter Origin (deterministic, mechanical trace -- not a verdict)

The lines below were produced by a separate, non-LLM static tracer. It walks
backward from the sink argument(s) through local assignments and, where a
variable is a function parameter, up through the parameter's real callers
(from the call graph), up to 5 hops. It does NOT judge exploitability or
taint -- it only reports where each value's code comes from, and where the
trace mechanically stops (a literal/macro, a struct/array field access, a
depth limit, or no further assignment/caller found). Use this as additional
ground truth about the code's actual data flow, on top of your own reading
of the code above -- it may reveal call paths outside the ±25-line window
shown above.

```
{traced_evidence}
```
"""

    # "bare" drops the whole factors section; every other mode renders it exactly as before
    if cwe_context == "bare":
        factors_section = ""
    elif cwe_context == "mitre":
        factors_section = f"## CWE Reference (MITRE)\n{factors_text}\n\n"
    else:
        factors_section = f"## Exploitability Factors to Investigate\n{factors_text}\n\n"

    # Harness-specific wording
    if harness == "none":
        harness_line = "- **Analysis mode:** General security review (no fuzzer harness)"
        q3 = (
            "3. **Can an external caller or attacker** reach this code path "
            "with attacker-controlled data via the public API or network input?"
        )
        trigger_note = (
            "Consider whether any publicly accessible function, network socket, "
            "or file input could supply attacker-controlled data to this sink."
        )
    else:
        harness_line = f"- **Fuzzer harness:** `{harness}`"
        q3 = (
            f"3. **Can the fuzzer harness `{harness}`** realistically trigger "
            "this path with attacker-controlled data?"
        )
        trigger_note = (
            f"The harness `{harness}` is the entry point — check whether "
            "it feeds data that flows to this sink."
        )

    return f"""# Vulnerability Sink Analysis — Research Phase

## Vulnerability Type
**{cwe}: {info['name']}**
{'' if cwe_context in ('bare', 'mitre') else info['description']}

## Sink Location
- **File:** `{file_name}`
- **Line:** {line_num}
- **Sink call:** `{call_text}`
- **Containing function:** `{containing or '(unknown)'}`
{harness_line}

## Code Context (±25 lines, sink marked with >>>)
```c
{code_ctx}
```
{func_body_section}
{traced_evidence_section}
{factors_section}## Your Task
Carefully analyze whether this sink is exploitable.

Specifically answer:
1. **What is the source of the data** reaching the sink? (network/user input vs. compile-time constant?)
2. **Are there bounds checks** or NULL checks before the sink?
{q3}
4. **What is your preliminary verdict?** (exploitable / not exploitable / uncertain)

{trigger_note}
Be concrete. Quote specific variable names and line numbers from the code.
"""


def build_assessment_prompt(sink: dict, research_report: str) -> str:
    """Build the Phase 2 structured assessment prompt."""
    cwe = sink.get('cwe', 'unknown')
    info = CWE_INFO.get(cwe, DEFAULT_CWE_INFO)
    coord = sink['coord']

    return f"""# Exploitability Assessment — Decision Phase

## Sink
- **{cwe}: {info['name']}**
- File: `{coord['file_name']}` line {coord['line_num']}
- Call: `{sink.get('call_text', '')}`

## Research Findings
{research_report}

## Final Decision

Based on the research above, make a definitive binary classification.

Rules:
- Mark **UNEXPLOITABLE** only if you have concrete evidence that attacker-controlled
  data cannot reach the sink (e.g., all size/pointer arguments are compile-time constants,
  or there is an effective bounds check, or the path is dead code).
- Mark **EXPLOITABLE** if there is any realistic way attacker-controlled input can trigger
  this sink with an out-of-bounds write, NULL dereference, or other harmful effect.
- When uncertain, default to **EXPLOITABLE** (conservative).

Respond in EXACTLY this format (no other text):

VERDICT: <EXPLOITABLE or UNEXPLOITABLE>
CONFIDENCE: <HIGH or MEDIUM or LOW>
REASONING: <one paragraph, max 150 words>
"""


# ---------------------------------------------------------------------------
# Assessment parser
# ---------------------------------------------------------------------------

def parse_assessment(response: str) -> dict:
    """Parse the structured assessment response from the LLM."""
    result = {
        "unexploitable": False,
        "confidence": "LOW",
        "reasoning": response,
    }

    # Extract VERDICT
    verdict_m = re.search(r'VERDICT\s*:\s*(EXPLOITABLE|UNEXPLOITABLE)', response, re.IGNORECASE)
    if verdict_m:
        verdict = verdict_m.group(1).upper()
        result["unexploitable"] = (verdict == "UNEXPLOITABLE")
    else:
        # Fallback: look for keywords
        text_lower = response.lower()
        if "unexploitable" in text_lower and "exploitable" not in text_lower[:text_lower.index("unexploitable")]:
            result["unexploitable"] = True

    # Extract CONFIDENCE
    conf_m = re.search(r'CONFIDENCE\s*:\s*(HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    if conf_m:
        result["confidence"] = conf_m.group(1).upper()

    # Extract REASONING
    reason_m = re.search(r'REASONING\s*:\s*(.+)', response, re.IGNORECASE | re.DOTALL)
    if reason_m:
        result["reasoning"] = reason_m.group(1).strip()[:500]

    return result


# ---------------------------------------------------------------------------
# Main assessor
# ---------------------------------------------------------------------------

class ExploitabilityAssessor:
    """Two-phase LLM exploitability assessor."""

    def __init__(
        self,
        llm: LLMClient,
        root: Path,
        harness: str,
        verbose: bool = False,
        cwe_context: str = "hardcoded",
        graph: Optional[dict] = None,
    ):
        self.cwe_context = cwe_context
        self.llm = llm
        self.root = root
        self.harness = harness
        self.verbose = verbose
        self.graph = graph  # Stage 4 (Evidence Tracing): call graph for param_tracer; None -> no trace

    def assess(self, sink: dict) -> dict:
        """
        Run two-phase assessment on a single sink.

        Returns dict with:
          unexploitable: bool
          confidence: str
          reasoning: str
          research_report: str
          error: str (if failed)
        """
        sink_id = sink.get('id', '?')
        coord = sink.get('coord', {})
        logger.info(f"Assessing {sink_id} [{sink.get('cwe')}] "
                    f"{coord.get('file_name')}:{coord.get('line_num')}")

        try:
            # ---- Stage 4: Evidence Tracing (deterministic, non-LLM) ----
            traced_evidence = PT.trace_sink_arg(self.root, self.graph, sink) if self.graph else None

            # ---- Stage 5, Phase 1: Research ----
            research_prompt = build_research_prompt(sink, self.root, self.harness, traced_evidence=traced_evidence,
                                                    cwe_context=self.cwe_context)
            if self.verbose:
                print(f"\n{'='*60}\n[Phase 1 Prompt]\n{research_prompt[:500]}...\n{'='*60}")

            research_report = self.llm.chat(
                messages=[
                    {"role": "system", "content":
                     "You are a security researcher performing static vulnerability analysis. "
                     "Analyze the provided C code and answer all questions precisely and concisely."},
                    {"role": "user", "content": research_prompt},
                ],
                max_tokens=1200,
                temperature=0.05,
            )
            if self.verbose:
                print(f"[Phase 1 Response]\n{research_report}\n{'='*60}")

            # ---- Phase 2: Assessment ----
            assessment_prompt = build_assessment_prompt(sink, research_report)
            if self.verbose:
                print(f"[Phase 2 Prompt]\n{assessment_prompt}\n{'='*60}")

            assessment_response = self.llm.chat(
                messages=[
                    {"role": "system", "content":
                     "You are a security expert. Give a definitive verdict on vulnerability exploitability. "
                     "Follow the exact output format requested."},
                    {"role": "user", "content": assessment_prompt},
                ],
                max_tokens=400,
                temperature=0.0,
            )
            if self.verbose:
                print(f"[Phase 2 Response]\n{assessment_response}\n{'='*60}")

            result = parse_assessment(assessment_response)
            result["research_report"] = research_report
            result["raw_assessment"] = assessment_response
            return result

        except Exception as e:
            logger.error(f"Assessment failed for {sink_id}: {e}")
            return {
                "unexploitable": False,  # conservative: keep as potentially exploitable
                "confidence": "LOW",
                "reasoning": f"Assessment failed: {e}",
                "research_report": "",
                "raw_assessment": "",
                "error": str(e),
            }


def run_exploitability_filter(
    sinks: list[dict],
    llm: LLMClient,
    root: Path,
    harness: str,
    threshold: int = 10,
    force: bool = False,
    verbose: bool = False,
    cwe_context: str = "hardcoded",
    graph: Optional[dict] = None,
) -> list[dict]:
    """
    Apply Stage 4 (Evidence Tracing, if `graph` is given) + Stage 5 (LLM Assessment) to sinks.

    Matching the paper's logic:
    - If candidate count ≤ threshold, skip LLM analysis (all pass through)
    - Otherwise, run LLM on each and filter out unexploitable ones

    Returns updated sinks list with 'unexploitable', 'reasoning',
    'in_final_result' fields added.
    """
    # Candidates = passed stages 1 and 2
    candidates = [s for s in sinks
                  if not s.get('filtered_out_flow')
                  and not s.get('filtered_out_test')
                  and s.get('reachable', True)]

    print(f"\n[llm_agent] Stage 4/5 input: {len(candidates)} candidate sinks")

    if len(candidates) <= threshold and not force:
        print(f"[llm_agent] ≤{threshold} candidates → skipping LLM analysis (all pass through)")
        for s in sinks:
            if s in candidates:
                s['in_final_result'] = True
                s['unexploitable'] = False
                s['reasoning'] = "Not analyzed (below threshold)"
                s['confidence'] = "N/A"
        return sinks

    assessor = ExploitabilityAssessor(llm, root, harness, verbose=verbose, cwe_context=cwe_context, graph=graph)
    total = len(candidates)

    for i, sink in enumerate(candidates, 1):
        print(f"[llm_agent] [{i}/{total}] {sink['coord']['file_name']}:{sink['coord']['line_num']} [{sink['cwe']}]")
        result = assessor.assess(sink)

        sink['unexploitable'] = result['unexploitable']
        sink['confidence'] = result.get('confidence', 'LOW')
        sink['reasoning'] = result.get('reasoning', '')
        sink['research_report'] = result.get('research_report', '')
        sink['in_final_result'] = not result['unexploitable']

        status = "NOT exploitable ✗" if result['unexploitable'] else "EXPLOITABLE ✓"
        print(f"          → {status} [{result.get('confidence','?')}]")
        print(f"          {result.get('reasoning','')[:120]}")

    return sinks


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="LLM-based exploitability filter")
    parser.add_argument("root", help="Repository root path")
    parser.add_argument("sinks", help="Input sinks JSON (with reachability)")
    parser.add_argument("--endpoint", default="http://129.108.156.67:8001/v1",
                        help="vLLM / OpenAI-compatible base URL")
    parser.add_argument("--model", default="meta-llama/Llama-3.1-8B-Instruct",
                        help="Model name")
    parser.add_argument("--harness", default="curl_fuzzer_http")
    parser.add_argument("--threshold", type=int, default=10,
                        help="Skip LLM if candidate count ≤ this. Default: 10")
    parser.add_argument("--force", action="store_true",
                        help="Run LLM even if below threshold")
    parser.add_argument("--output", "-o", default="sinks_filtered.json")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")

    root = Path(args.root).resolve()
    sinks = json.loads(Path(args.sinks).read_text())

    llm = LLMClient(base_url=args.endpoint, model=args.model)
    updated = run_exploitability_filter(
        sinks, llm, root, args.harness,
        threshold=args.threshold,
        force=args.force,
        verbose=args.verbose,
    )

    out = Path(args.output)
    out.write_text(json.dumps(updated, indent=2))

    final = [s for s in updated if s.get('in_final_result')]
    print(f"\n[llm_agent] Final actionable sinks: {len(final)}")
    for s in final:
        print(f"  [{s['cwe']}] {s['coord']['file_name']}:{s['coord']['line_num']}  "
              f"conf={s.get('confidence','?')}  ({s['message']})")
    print(f"\n[llm_agent] Written to {out}")


if __name__ == "__main__":
    raise SystemExit(main())
