#!/usr/bin/env python3
"""
sink_finder.py — Pattern-based C sink scanner (§3.1.1 analog for C)

Scans a C codebase for dangerous function call sites by CWE type
(Stage 1: Sink Identification), then applies candidate-validation
filters (constant args, test files) (Stage 2: Candidate Validation).

Output JSON format matches the pipeline's internal schema.
"""

import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Sink patterns per CWE
# Each entry: (regex_pattern, description)
# The pattern must capture the full call expression for context extraction.
# ---------------------------------------------------------------------------

CWE_SINK_PATTERNS: dict[str, list[tuple[str, str]]] = {
    # Stack/heap buffer overflows — only the highest-signal dangerous operations
    "CWE-121": [
        # memcpy with strlen-derived size is the #1 pattern for this CWE in C
        (r'\bmemcpy\s*\([^;]*strlen\s*\(', "memcpy with strlen size — classic OOB"),
        # Unconditionally unsafe functions
        (r'\bstrcpy\s*\(', "strcpy — no bounds check"),
        (r'\bstrcat\s*\(', "strcat — no bounds check"),
        (r'\bgets\s*\(', "gets — inherently unbounded"),
        (r'\bvsprintf\s*\(', "vsprintf — unbounded format write"),
        # sprintf only where format string uses %s or has user-controlled args
        (r'\bsprintf\s*\([^;]*%s', "sprintf with %%s — potential overflow"),
        # Broad net: any call whose name CONTAINS "memcpy" as a substring, not
        # just the exact libc name. Real codebases wrap memcpy in their own
        # bounds-adjacent helpers (wireshark's tvb_memcpy(tvb, dst, offset,
        # length), glib's g_memcpy, wmem_memcpy, ...) that the exact-name
        # patterns above silently miss entirely. Confirmed against
        # afc-wireshark ws-delta-02's ground truth (packet-icmp.c:927):
        # `tvb_memcpy(tvb, ident_name, offset, obj_length - 4)` where
        # obj_length is read straight off the packet via tvb_get_ntohs() two
        # lines earlier, into a fixed ICMP_MAX_IDENT_NAME_LENGTH stack array
        # with no bounds check — this exact sink is invisible to every other
        # pattern in this list since the function name is "tvb_memcpy", not
        # "memcpy". Deliberately broad (and therefore noisier) by design;
        # Stage 2's tvb_memcpy-specific arg-index check below and Stage 5
        # narrow the false-positive volume this introduces.
        (r'\b\w*memcpy\w*\s*\(', "call to a *memcpy* family function — check the length argument for attacker control"),
    ],
    # Heap-buffer-overflow — mechanically the same detection shape as
    # CWE-121 above (any *memcpy* family call with an unbounded/attacker-
    # derived length argument); the stack-vs-heap distinction is a runtime
    # property of the destination's storage class that a static regex can't
    # determine, so this is a literal alias of the CWE-121 pattern list under
    # its own key (kept as a real, separate CWE entry rather than just
    # reusing "CWE-121" so results/config stay correctly labeled downstream).
    # Confirmed against afc-wireshark ws-delta-03's ground truth
    # (dissect_irc_names / dissect_irc_request_command, packet-irc.c:563):
    # `tvb_memcpy(tvb, channel_name, start_offset, length)` where `length`
    # is `end_offset - start_offset` with no clamp against `CHANNELLEN`,
    # copied into a `channel_name` buffer allocated exactly CHANNELLEN+1
    # bytes — same tvb_memcpy-unbounded-length shape as CWE-121's ws-02
    # ground truth, just a heap-allocated (not fixed stack array) destination.
    "CWE-122": [
        (r'\bmemcpy\s*\([^;]*strlen\s*\(', "memcpy with strlen size — classic OOB"),
        (r'\bstrcpy\s*\(', "strcpy — no bounds check"),
        (r'\bstrcat\s*\(', "strcat — no bounds check"),
        (r'\bgets\s*\(', "gets — inherently unbounded"),
        (r'\bvsprintf\s*\(', "vsprintf — unbounded format write"),
        (r'\bsprintf\s*\([^;]*%s', "sprintf with %%s — potential overflow"),
        (r'\b\w*memcpy\w*\s*\(', "call to a *memcpy* family function — check the length argument for attacker control"),
    ],
    # NULL pointer dereference — only cast-then-dereference, which is specific and rare
    "CWE-476": [
        # *(type *)var = value  — dereferencing an integer as a pointer (the curl-008 pattern)
        (r'\*\s*\(\s*(?:unsigned\s+)?(?:int|long|short|char)\s*\*\s*\)\s*\w+\s*=',
         "integer cast to pointer then dereferenced — guaranteed NULL deref if 0"),
        # *(type *)expr where expr is a function return value
        (r'\*\s*\(\s*\w[\w\s]*\s*\*\s*\)\s*\w+\s*[=;]',
         "cast to pointer + deref — check if source can be NULL/0"),
        # NULL pointer passed to function that dereferences it (returned ptr not checked)
        (r'\bCurl_\w+\s*\([^;]*\)\s*;\s*\n\s*\w+\s*->', "unchecked Curl_ return then ->"),
    ],
    # OS command injection
    "CWE-078": [
        (r'\bsystem\s*\(', "system() — shell command execution"),
        (r'\bpopen\s*\(', "popen() — shell command execution"),
        (r'\bexecv[pe]?\s*\(', "execv*() — process execution"),
        (r'\bexecl[pe]?\s*\(', "execl*() — process execution"),
    ],
    # Path traversal
    "CWE-022": [
        (r'\bfopen\s*\(', "fopen — file open with user-controlled path"),
        (r'\bopen\s*\(', "open — file open with user-controlled path"),
        (r'\bunlink\s*\(', "unlink — file delete with user-controlled path"),
        (r'\brename\s*\(', "rename — file rename with user-controlled path"),
    ],
    # Use of uninitialized value (treat like CWE-457)
    "CWE-457": [
        (r'\bstrcmp\s*\(', "strcmp with potentially uninit pointer"),
        (r'\bmemcmp\s*\(', "memcmp with potentially uninit pointer"),
        # Raw printf() left in dissector code. Confirmed against afc-wireshark's
        # vuln_012 ground truth (dissect_zbee_zdp_req_mgmt_nwk_disc,
        # packet-zbee-zdp-management.c:243-246): a leftover debug printf loops
        # `for (i=0; i <= channels; i++)` and prints `channels_arr[i]->text`
        # with %s -- but `->text` is only ever assigned inside the EARLIER,
        # differently-scoped bit-scan loop (`if (channels & (1<<i))`), so for
        # any i where that bit wasn't set, `->text` is read straight off the
        # malloc'd-but-never-written struct field -- a classic
        # vestigial-debug-code CWE-457. Real dissector code never calls raw
        # printf() (it uses proto_tree_add_*/expert-info APIs instead), so a
        # bare printf() in dissector source is itself a strong, narrow signal
        # for exactly this "accidentally shipped debug code" bug class --
        # confirmed low-volume and high-signal: only ~13 real (non-commented)
        # hits across the entire epan/dissectors tree, one of which is the
        # ground truth itself.
        (r'(?<!f)(?<!s)(?<!sn)(?<!v)(?<!g_)\bprintf\s*\(', "raw printf() in dissector code — likely vestigial debug code reading unset struct fields"),
    ],
    # Integer-overflow-to-buffer-overflow. Narrow, high-signal shape: a size
    # variable assigned from one of Wireshark's tvb_get_*() packet-buffer
    # accessors (the standard "read N bytes/bits from the raw packet" API --
    # tvb_get_ntohs, tvb_get_guint8, tvb_get_letohl, etc. -- all directly
    # attacker-controlled) is then used, unchecked, as a memcpy()/g_memmove()
    # length. Confirmed against afc-wireshark's vuln_011 ground truth
    # (aim_get_buddyname, packet-aim.c:588-591): `buddyname_length =
    # tvb_get_ntohs(tvb, offset);` immediately followed by `memcpy(*name,
    # tvb_get_ptr(tvb,offset,1), buddyname_length);` into a fixed 256-byte
    # `wmem_alloc(pool, 256)` buffer, with no bounds check on
    # buddyname_length in between -- a 16-bit attacker-controlled length
    # (up to 65535) copied into a 256-byte destination. Only 1 match across
    # the entire epan/dissectors tree (the ground truth itself) -- see
    # _scan_memcpy_tvb_length below for the flow-sensitive (split-statement)
    # pass; the base pattern here also covers the same-line inline form
    # `memcpy(dst, src, tvb_get_ntohs(...))`, which doesn't occur in this
    # codebase today but is the same bug shape one statement more compact.
    "CWE-680": [
        (r'\b(?:memcpy|g_memmove)\s*\([^;]*,\s*tvb_get_\w+\s*\(',
         "memcpy/g_memmove length argument is an inline tvb_get_*() packet read — attacker-controlled, unbounded"),
    ],
    # Out-of-bounds write. Narrow, high-signal shape: memcpy() whose
    # DESTINATION is pointer arithmetic (buf +/- some variable) rather than a
    # bare buffer name. Confirmed against afc-systemd's systemd-001 ground
    # truth (udev_rule_parse_value, udev-rules.c:1220): the function tracks
    # the "start of value" offset two different ways -- a raw per-character
    # counter (`pos`, incremented once per flag char including duplicates)
    # and a deduped boolean sum (`m = str + is_escaped + is_case_insensitive
    # + is_prefix_match`) -- and the vulnerable branch's sink,
    # `memcpy(str + pos - 1, unescaped, l + 1)`, uses the raw counter, which
    # desyncs from the buffer's real layout whenever a flag character repeats
    # (e.g. "pp"). Any memcpy whose destination is computed via pointer
    # arithmetic carries the same class of risk -- the offset expression may
    # not agree with whatever tracking actually bounds the buffer -- so this
    # generalizes to a real, if noisy, Stage 1 filter rather than a literal
    # match on the one ground-truth line (59 hits across the whole systemd
    # source tree, most unrelated append-into-presized-buffer idioms that
    # Stage 2's constant-size-arg filter and Stage 5's LLM triage narrow
    # down from there).
    "CWE-787": [
        (r'\bmemcpy(?=\s*\(\s*\w+\s*[+\-]\s*\w+)\s*\(',
         "memcpy with pointer-arithmetic destination — offset may not track the buffer's real bounds"),
    ],
    # Format-string vulnerabilities. Narrow, high-signal shape: curl's own
    # printf-style helpers (`sendf(data, fmt, ...)`, `failf`, `infof`, the
    # pingpong-protocol `Curl_pp_sendf`/`Curl_pp_vsendf`) all take the format
    # string as their 2nd argument. Confirmed against curl-001's ground truth
    # (lib/dict.c:230, `sendf(data, user_start)` — the DICT protocol's parsed
    # username passed directly as the format argument, no `%s` wrapper): a
    # bare identifier (or any non-literal expression) in that position is the
    # textbook CWE-134 shape. `_is_filtered_out_flow` below does the real
    # literal-vs-non-literal decision (mirrors the existing sprintf/vsprintf
    # branch) — this pattern just finds every call site to check.
    "CWE-134": [
        (r'\b(?:sendf|failf|infof|Curl_pp_sendf|Curl_pp_vsendf)\s*\(',
         "printf-style curl helper — check whether the format argument is a literal"),
    ],
    # Use-after-free — no single-line regex pattern for this class (see
    # _scan_ungated_free_after_state_check below); handled flow-sensitively.
    "CWE-416": [],
    # Double-free — two distinct bug shapes, both flow-sensitive (see
    # _scan_list_free_without_unlink / _scan_free_wrapper_missing_null_reset
    # below); no single-line regex pattern for either.
    "CWE-415": [],
    # Buffer over-read via an unbound-checked loop-advanced index — no
    # single-line regex pattern (see _scan_unchecked_loop_index_read below);
    # handled flow-sensitively.
    "CWE-126": [],
    # Improper array index validation before a function-pointer-table
    # dispatch — no single-line regex pattern (see
    # _scan_unchecked_array_dispatch below); handled flow-sensitively.
    "CWE-129": [],
}

# ---------------------------------------------------------------------------
# Constant-argument detection
# If ALL size/length arguments look constant → not exploitable via fuzzing
# ---------------------------------------------------------------------------

# Patterns that indicate a CONSTANT value (safe)
CONST_PATTERNS = [
    re.compile(r'^\s*\d+\s*$'),                          # plain integer literal
    re.compile(r'^\s*sizeof\s*\('),                       # sizeof(...)
    re.compile(r'^\s*[A-Z_][A-Z0-9_]*\s*$'),             # ALL_CAPS macro constant
    re.compile(r'^\s*[A-Z_][A-Z0-9_]*\s*[\+\-\*]\s*\d'), # MACRO +/- literal
    re.compile(r'^\s*\d+\s*[\+\-\*]\s*\d+\s*$'),         # literal arithmetic
]

# For memcpy / string funcs: the SIZE argument (3rd arg for memcpy, N/A for strcpy)
# We check if the size arg is strlen(something) -- that's user-controlled!
STRLEN_PATTERN = re.compile(r'\bstrlen\s*\(')


# A bare return-type token with nothing else -- `static CURLcode`, `CURLcode`,
# `static char *` -- used to recognize a function definition/prototype's
# signature line for CWE-134's definition-vs-call disambiguation above.
_TYPE_ONLY_RE = re.compile(r'^\s*(?:static\s+)?[A-Za-z_]\w*(?:\s*\*+)?\s*$')


def _extract_full_call_text(lines_nc: list[str], line_idx: int, start_col: int,
                             max_lines: int = 10) -> str:
    """
    Starting at (line_idx, start_col) -- the start of a function-call match --
    concatenate lines until the call's parentheses balance (or max_lines is
    hit), so downstream argument parsing sees the real, full argument list
    even when a call wraps across multiple lines.
    """
    parts = [lines_nc[line_idx][start_col:]]
    depth = parts[0].count('(') - parts[0].count(')')
    i = line_idx
    while depth > 0 and i + 1 < len(lines_nc) and (i - line_idx) < max_lines:
        i += 1
        parts.append(lines_nc[i])
        depth += lines_nc[i].count('(') - lines_nc[i].count(')')
    return '\n'.join(parts)


def _is_constant_expr(expr: str) -> bool:
    """Return True if expr looks like a compile-time constant."""
    expr = expr.strip()
    return any(p.match(expr) for p in CONST_PATTERNS)


def _extract_args(call_text: str) -> list[str]:
    """
    Naive argument splitter for a function call.
    Handles one level of nested parens.
    Returns list of arg strings (may be incomplete for complex exprs).
    """
    # Find opening paren
    start = call_text.find('(')
    if start == -1:
        return []
    depth = 0
    args = []
    current = []
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
            else:
                current.append(ch)
        elif ch == ',' and depth == 1:
            args.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    return args


def _is_filtered_out_flow(func_name: str, call_line: str) -> bool:
    """
    Stage 2 candidate-validation filter: return True if the sink is clearly non-exploitable
    because all security-relevant arguments are compile-time constants.
    """
    args = _extract_args(call_line)
    if not args:
        return False

    # For memcpy: check 3rd arg (size). If it's strlen(...) → user-controlled = NOT filtered
    if func_name in ('memcpy',):
        if len(args) >= 3:
            size_arg = args[2]
            if STRLEN_PATTERN.search(size_arg):
                return False  # strlen of user data → exploitable, keep
            if _is_constant_expr(size_arg):
                return True   # constant size → filtered out

    # wireshark's tvb_memcpy(tvb, dst, offset, length) — 4 args, length is
    # the 4th (index 3), not the 3rd like plain memcpy. Any other *memcpy*
    # variant caught by the broad substring pattern above falls through to
    # the default `return False` (kept, unfiltered) below, since we don't
    # know its argument shape — conservative by construction.
    if func_name in ('tvb_memcpy',):
        if len(args) >= 4:
            size_arg = args[3]
            if _is_constant_expr(size_arg):
                return True   # constant length → filtered out
            return False      # variable/derived length → keep, potentially exploitable

    # For strcpy / strcat / gets: always potentially exploitable
    if func_name in ('strcpy', 'strcat', 'gets', 'wcscpy', 'wcscat'):
        return False

    # For sprintf/vsprintf: if format string is a literal → likely safe
    if func_name in ('sprintf', 'vsprintf'):
        if len(args) >= 2:
            fmt = args[1].strip()
            if fmt.startswith('"'):
                # Check for %s with user data — hard to know statically, keep
                return False
            if _is_constant_expr(fmt):
                return True

    # For snprintf: if size arg is sizeof(...) or a literal → keep (format may still be bad)
    if func_name in ('snprintf',):
        return False

    # For curl's printf-style helpers: `sendf`/`failf`/`infof` take the
    # format string as their 2nd argument (`fn(data, fmt, ...)`), but
    # `Curl_pp_sendf`/`Curl_pp_vsendf` take an extra `struct pingpong *pp`
    # argument first, pushing fmt to the 3rd position (`fn(data, pp, fmt,
    # ...)` — confirmed against their real declarations in pingpong.h). A
    # literal (or literal concatenation, e.g. `"CLIENT " LIBCURL_NAME " " ...`,
    # which still starts with `"`) is safe by construction; anything else — a
    # bare identifier, a struct-field access, a ternary — is a real
    # format-string candidate and must not be filtered out.
    if func_name in ('sendf', 'failf', 'infof', 'Curl_pp_sendf', 'Curl_pp_vsendf'):
        fmt_idx = 2 if func_name in ('Curl_pp_sendf', 'Curl_pp_vsendf') else 1
        if len(args) > fmt_idx:
            fmt = args[fmt_idx].strip()
            if fmt.startswith('"'):
                return True
            if _is_constant_expr(fmt):
                return True
        return False

    # For strncpy/strncat: if the N arg is a sizeof → borderline safe
    if func_name in ('strncpy', 'strncat'):
        if len(args) >= 3:
            n_arg = args[2]
            if _is_constant_expr(n_arg) and not STRLEN_PATTERN.search(n_arg):
                return True

    return False


# ---------------------------------------------------------------------------
# CWE-476 flow-sensitive detector: missing NULL guard after a pointer-chase
# reassignment (e.g. `mpe = mpe->Next;` then using `mpe` with no NULL check).
#
# This catches a DIFFERENT bug shape than the CWE_SINK_PATTERNS entries above.
# Those are single-line, syntax-only patterns (cast-then-deref, unchecked
# Curl_* return). This one is genuinely flow-sensitive: it finds the
# reassignment, then looks forward across lines for the next use of that
# variable, and only flags it if no `if (...)` guard mentioning the variable
# appears in between. It is the generalized fix for the class of bug found in
# lcms-001 (`mpe = mpe->Next;` then `cmsStageType(mpe)` with no NULL check) —
# a "missing condition" bug with no dangerous function call for a plain regex
# to match, which is why the original CWE-476 patterns (built around curl's
# specific bug shape) never covered it.
# ---------------------------------------------------------------------------

_SELF_ADVANCE_RE = re.compile(r'\b(\w+)\s*=\s*\1\s*->\s*\w+\s*;')
_LOOKAHEAD_WINDOW = 15  # lines to scan forward for a use / guard


def _scan_missing_null_guard(text: str, lines: list[str]):
    """
    Yields (line_idx, start_col, end_col, var_name, use_line_text) for each
    pointer-chase reassignment (`var = var->field;`) whose first subsequent
    use of `var` is not preceded by a NULL guard (`if (...var...)`).
    """
    for m in _SELF_ADVANCE_RE.finditer(text):
        var = m.group(1)
        v = re.escape(var)
        assign_line_idx = text[:m.start()].count('\n')
        # A "guard" must be an actual NULL/truthiness test on the variable —
        # NOT just any if(...) that happens to mention it (e.g. `if
        # (cmsStageType(mpe) == X)` uses mpe but does not check it for NULL).
        guard_re = re.compile(
            rf'(?:\bif\s*\(\s*!?\s*{v}\s*\))'        # if (var) / if (!var)
            rf'|(?:\b{v}\s*(?:==|!=)\s*(?:NULL|0)\b)'  # var == NULL / var != 0
            rf'|(?:!\s*{v}\b)'                          # !var  (in a && chain)
            rf'|(?:\b{v}\s*&&)'                          # var &&
            rf'|(?:&&\s*{v}\b)'                          # && var
        )
        reassign_re = re.compile(rf'^\s*{v}\s*=\s*{v}\s*->')
        use_re = re.compile(rf'\b{v}\b')
        # Column-0 `}` marks the end of a top-level function in K&R-style C
        # (confirmed true for both curl and lcms). Use it as the scope
        # boundary instead of a fixed line count — a fixed window crosses
        # into the next function and false-positives on unrelated same-named
        # variables (e.g. `cf`, `addr`, `chunk` reused across functions).
        func_end_re = re.compile(r'^\}\s*$')

        window_end = min(len(lines), assign_line_idx + 1 + _LOOKAHEAD_WINDOW)
        for i in range(assign_line_idx + 1, window_end):
            line = lines[i]
            if func_end_re.match(line):
                break  # end of the enclosing function — stop, nothing to flag
            if guard_re.search(line):
                break  # guarded — not a sink
            if reassign_re.match(line):
                continue  # just another chase step, keep scanning
            u = use_re.search(line)
            if u:
                yield (i, u.start(), u.end(), var, line.strip())
                break


# ---------------------------------------------------------------------------
# CWE-787 detector: snprintf/msnprintf bounded by the WRONG variable's
# sizeof(). Narrow, high-signal shape: `(m)snprintf(dst, sizeof(other), ...)`
# where `other` is textually different from `dst`. Confirmed against
# curl-004's ground truth (lib/file.c:495):
#   msnprintf(header, sizeof(no_body), "%s (%ld bytes) \r\n", no_body, ...)
# -- writes into `header` but is bounded by `sizeof(no_body)` (a short local
# constant string), not `sizeof(header)` (the real destination's declared
# size) -- an out-of-bounds write whenever the formatted output exceeds
# no_body's size but fits header's. `sink_finder`'s existing CWE-787 pattern
# (memcpy w/ pointer-arithmetic destination, built for a systemd bug) cannot
# see this at all: it isn't a memcpy, and the destination is a bare buffer
# name, not pointer arithmetic. Deliberately conservative: only plain
# identifiers on both sides (no member access / array subscript, which would
# need real type info this scanner doesn't have), and only fires when the two
# names are textually different -- `sizeof(dst)` matching the destination
# exactly is correct usage by construction and is never flagged.
# ---------------------------------------------------------------------------

_SIZEOF_MISMATCH_RE = re.compile(
    r'\b(m?snprintf)\s*\(\s*(\w+)\s*,\s*sizeof\s*\(\s*(\w+)\s*\)'
)


def _scan_sizeof_mismatch(text: str, lines: list[str]):
    """
    Yields (line_idx, start_col, end_col, func_name, dest_var, sizeof_var)
    for every (m)snprintf call whose declared bound (sizeof(X)) names a
    different variable than the buffer it actually writes into.
    """
    for m in _SIZEOF_MISMATCH_RE.finditer(text):
        func, dest, sizeof_var = m.group(1), m.group(2), m.group(3)
        if dest == sizeof_var:
            continue  # sizeof matches the real destination -- correct usage
        line_idx = text[:m.start()].count('\n')
        line_start = text.rfind('\n', 0, m.start()) + 1
        start_col = m.start() - line_start
        end_col = m.end() - line_start
        yield (line_idx, start_col, end_col, func, dest, sizeof_var)


# ---------------------------------------------------------------------------
# CWE-787 detector #2: NUL-terminator array write at a raw, unclamped index
# that disagrees with the length actually used to bound a preceding copy
# into the same buffer. A different bug shape from the sizeof-mismatch
# detector above (this one is a bare `dst[idx] = '\0';`, no snprintf/
# msnprintf involved at all). Confirmed against afc-wireshark
# ws-delta-01's ground truth (dissect_ber_GeneralString, packet-ber.c:3194):
#     if ((unsigned)tvb_len >= name_len) {
#         tvb_memcpy(out_tvb, (uint8_t*)name_string, 0, name_len-1);
#     } else {
#         tvb_memcpy(out_tvb, (uint8_t*)name_string, 0, tvb_len);
#     }
#     name_string[tvb_len] = '\0';
# Both copy branches bound the actual write to whichever of `name_len-1` /
# `tvb_len` is smaller, but the terminator write always uses the raw
# `tvb_len` regardless of which branch ran -- an out-of-bounds write
# whenever the first branch (tvb_len >= name_len) is the one that executed.
# Deliberately narrow: only fires when a memcpy/tvb_memcpy call into the
# SAME destination buffer is found in the lookback window AND its length
# argument is textually different from the terminator's index -- a
# terminator that reuses the exact same length expression as the copy is
# correct usage by construction and is never flagged.
# ---------------------------------------------------------------------------

_TERMINATOR_WRITE_RE = re.compile(r"\b(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*(?:'\\0'|0)\s*;")
_TERMINATOR_LOOKBACK_WINDOW = 8


def _scan_unclamped_terminator_write(text: str, lines: list[str]):
    """
    Yields (line_idx, start_col, end_col, dest_var, idx_var, copy_len_expr)
    for each `dest[idx] = '\\0';` (or `= 0;`) NUL-termination write where ANY
    memcpy/tvb_memcpy call into the same `dest` buffer in the lookback
    window used a textually different length expression than `idx` --
    checks every candidate copy in the window, not just the nearest one,
    since the real bug shape (ws-delta-01) is exactly two conditional
    branches each copying with a different length, where only the branch
    matching the terminator's own index looks consistent if you only check
    the closest preceding call.
    """
    for m in _TERMINATOR_WRITE_RE.finditer(text):
        dest, idx = m.group(1), m.group(2)
        line_idx = text[:m.start()].count('\n')
        d = re.escape(dest)
        memcpy_re = re.compile(rf'\b(?:tvb_)?memcpy\s*\(\s*(?:\w+\s*,\s*)?(?:\([^)]*\)\s*)?{d}\b')
        window_start = max(0, line_idx - _TERMINATOR_LOOKBACK_WINDOW)
        mismatched_expr = None
        for i in range(window_start, line_idx):
            cm = memcpy_re.search(lines[i])
            if not cm:
                continue
            call_text = _extract_full_call_text(lines, i, cm.start())
            args = _extract_args(call_text)
            if not args:
                continue
            copy_len_expr = args[-1].strip()
            if copy_len_expr != idx:
                mismatched_expr = copy_len_expr
        if mismatched_expr is not None:
            line_start = text.rfind('\n', 0, m.start()) + 1
            yield (line_idx, m.start() - line_start, m.end() - line_start, dest, idx, mismatched_expr)


# ---------------------------------------------------------------------------
# CWE-126 detector: buffer over-read via a loop-advanced index that is never
# compared against any bound within the loop body. Purely flow-sensitive --
# no single-line regex shape exists for "a loop that forgets to check its
# own advancing index" -- same "missing condition" family as
# _scan_missing_null_guard/_scan_ungated_free_after_state_check above.
# Confirmed against afc-wireshark ws-delta-04's ground truth
# (json_string_unescape, packet-json.c:361), a \uXXXX/surrogate-pair
# hex-decode loop:
#     for (int i = 0; i < 8; i++)
#     {
#         current_character = string[read_index];
#         read_index++;
#         ...
#     }
# `read_index` advances every iteration but is never compared against
# `string_length` (the string's real bound) anywhere in the loop body --
# the fixed 8-iteration loop reads past the end of `string` whenever fewer
# than 8 bytes remain. Deliberately requires the index to actually be
# incremented IN THE BODY (not just be the loop's own header counter, e.g.
# ordinary `for(i=0;i<len;i++) arr[i]=...` where the bound is the header
# itself) -- this excludes the overwhelmingly common safe pattern by
# construction rather than by trying to parse the header.
# ---------------------------------------------------------------------------

_FOR_LOOP_RE = re.compile(r'\bfor\s*\(')
_ARRAY_READ_ASSIGN_RE = re.compile(r'\b(\w+)\s*=\s*(\w+)\s*\[\s*(\w+)\s*\]\s*;')
_LOOP_BODY_MAX_LINES = 40


def _scan_unchecked_loop_index_read(text: str, lines: list[str]):
    """
    Yields (line_idx, start_col, end_col, arr_var, idx_var, read_line_text)
    for each `for(...)` loop whose body reads `arr[idx]` (via a plain
    `x = arr[idx];` assignment), where `idx` is incremented somewhere in the
    same loop body but never compared against any other identifier anywhere
    in that body.
    """
    for m in _FOR_LOOP_RE.finditer(text):
        header_line_idx = text[:m.start()].count('\n')
        depth = 0
        started = False
        body_start_idx = None
        body_end_idx = None
        for i in range(header_line_idx, min(len(lines), header_line_idx + _LOOP_BODY_MAX_LINES)):
            for ch in lines[i]:
                if ch == '{':
                    if not started:
                        body_start_idx = i
                    depth += 1
                    started = True
                elif ch == '}':
                    depth -= 1
                    if started and depth == 0:
                        body_end_idx = i
                        break
            if body_end_idx is not None:
                break
        if body_start_idx is None or body_end_idx is None:
            continue

        body_lines = lines[body_start_idx:body_end_idx + 1]
        body_text = '\n'.join(body_lines)

        for rm in _ARRAY_READ_ASSIGN_RE.finditer(body_text):
            arr, idx = rm.group(2), rm.group(3)
            i_esc = re.escape(idx)
            incr_re = re.compile(rf'\b{i_esc}\s*(?:\+\+|\+=)')
            bound_re = re.compile(
                rf'\b{i_esc}\s*(?:<|<=|>=|>)\s*\w+|\w+\s*(?:<|<=|>=|>)\s*\b{i_esc}\b'
            )
            if not incr_re.search(body_text):
                continue  # idx not advanced in the body -- likely the loop's own bounded counter
            if bound_re.search(body_text):
                continue  # a comparison on idx exists somewhere in the body -- guarded
            read_line_offset = body_text[:rm.start()].count('\n')
            read_line_idx = body_start_idx + read_line_offset
            line = lines[read_line_idx]
            col_m = re.search(rf'\b{re.escape(arr)}\s*\[\s*{i_esc}\s*\]', line)
            if not col_m:
                continue
            yield (read_line_idx, col_m.start(), col_m.end(), arr, idx, line.strip())


# ---------------------------------------------------------------------------
# CWE-129 detector: array-indexed function-pointer dispatch, `(arr[idx])(`,
# where `idx` is not range-checked against the array anywhere in the
# preceding lookback window. Confirmed against afc-wireshark ws-delta-05's
# ground truth (dissect_netbios, packet-netbios.c:1144):
#     session_id = (dissect_netb[ command])( tvb, pinfo, offset, netb_tree);
# `command` is a raw attacker-controlled byte from the packet with no
# preceding check against `array_length(dissect_netb)` (or any bound) --
# AIxCC's own fix adds exactly that check right before this line. Excludes
# a `switch (idx)` appearing in the lookback window too, since dispatch
# gated by a switch on the same index is itself a (different, safe) form of
# validated dispatch elsewhere in this codebase's style.
# ---------------------------------------------------------------------------

_ARRAY_CALL_DISPATCH_RE = re.compile(r'\(\s*(\w+)\s*\[\s*(\w+)\s*\]\s*\)[ \t]*\(')
_DISPATCH_LOOKBACK_WINDOW = 15


def _scan_unchecked_array_dispatch(text: str, lines: list[str]):
    """
    Yields (line_idx, start_col, end_col, arr_var, idx_var, call_line_text)
    for each `(arr[idx])(...)` function-pointer-table dispatch whose index
    is not range-checked against the array anywhere in the lookback window.
    """
    for m in _ARRAY_CALL_DISPATCH_RE.finditer(text):
        arr, idx = m.group(1), m.group(2)
        line_idx = text[:m.start()].count('\n')
        i_esc = re.escape(idx)
        a_esc = re.escape(arr)
        bound_re = re.compile(
            rf'\b{i_esc}\s*(?:<|<=|>=|>)\s*(?:array_length\s*\(\s*{a_esc}\s*\)|sizeof\s*\(\s*{a_esc}\s*\)|\w+)'
            rf'|\bswitch\s*\(\s*{i_esc}\s*\)'
        )
        window_start = max(0, line_idx - _DISPATCH_LOOKBACK_WINDOW)
        guarded = any(bound_re.search(lines[i]) for i in range(window_start, line_idx + 1))
        if guarded:
            continue
        line_start = text.rfind('\n', 0, m.start()) + 1
        yield (line_idx, m.start() - line_start, m.end() - line_start, arr, idx, lines[line_idx].strip())


# ---------------------------------------------------------------------------
# CWE-416 flow-sensitive detector: free() that isn't gated by the same
# state/ownership check that determines whether this code path is the one
# that "owns" the object. Targets the xz-001 bug shape: a graph/tree node
# (not a strict tree — cyclic backlinks exist) is guarded on entry by
# `if (node->state == STATE_CLEAR) { ...process...; node->state = STATE_HASHED; }`,
# but the `free(node->edges); free(node);` calls sit AFTER that block instead
# of inside it — so a call that reaches the same node via a backlink while an
# ancestor call is still mid-traversal (state STATE_VISITED, not yet CLEAR)
# falls through the guard, does nothing to children, and then frees the node
# out from under the still-running ancestor call: a use-after-free /
# double-free. The fix (confirmed via good_patch.diff) is simply moving the
# two free() calls inside the closing brace of the state-check block.
#
# This is the same "missing condition" bug family as CWE-476's
# _scan_missing_null_guard above and the CWE-611/918 XXE-hardening detector —
# the vulnerability is an absence (the free isn't wrapped in the guard that
# should own it), not a call to an inherently dangerous function.
# ---------------------------------------------------------------------------

_STATE_GUARD_RE = re.compile(
    r'\bif\s*\(\s*(\w+)\s*(?:->|\.)\s*\w*state\w*\s*(?:==|!=)\s*\w+\s*\)', re.IGNORECASE
)
_FREE_LOOKAHEAD_WINDOW = 10  # lines after the guard block ends to look for an ungated free()


def _scan_ungated_free_after_state_check(text: str, lines: list[str]):
    """
    Yields (line_idx, start_col, end_col, var_name, free_line_text) for each
    `if (var->state ...) { ... }` ownership/state-check block whose object is
    freed (`free(var)` or `free(var->field)`) shortly AFTER the block instead
    of inside it, with no intervening guard re-checking that same variable.
    """
    func_end_re = re.compile(r'^\}\s*$')

    for m in _STATE_GUARD_RE.finditer(text):
        var = m.group(1)
        v = re.escape(var)
        guard_line_idx = text[:m.start()].count('\n')

        # Brace-match forward from the guard to find where its block closes.
        depth = 0
        started = False
        end_idx = None
        for i in range(guard_line_idx, min(len(lines), guard_line_idx + 60)):
            for ch in lines[i]:
                if ch == '{':
                    depth += 1
                    started = True
                elif ch == '}':
                    depth -= 1
                    if started and depth == 0:
                        end_idx = i
                        break
            if end_idx is not None:
                break
        if end_idx is None:
            continue  # unbalanced / couldn't resolve — skip rather than guess

        free_re = re.compile(rf'\bfree\s*\(\s*{v}(?:\s*->\s*\w+)?\s*\)')
        reguard_re = re.compile(rf'\bif\s*\([^)]*\b{v}\b')

        window_end = min(len(lines), end_idx + 1 + _FREE_LOOKAHEAD_WINDOW)
        for i in range(end_idx + 1, window_end):
            line = lines[i]
            if func_end_re.match(line):
                break  # end of enclosing function — nothing to flag
            if reguard_re.search(line):
                break  # a new guard on the same var appears first — not ungated
            fm = free_re.search(line)
            if fm:
                yield (i, fm.start(), fm.end(), var, line.strip())
                break


# ---------------------------------------------------------------------------
# CWE-415 flow-sensitive detectors: double-free. Two distinct bug shapes,
# both confirmed against real afc-systemd ground truth, both "missing
# condition" bugs in the same family as CWE-476/CWE-416 above:
#
# (1) List-node freed without first unlinking it (systemd-004,
#     condition_free_list_type() in condition.c): `LIST_FOREACH(name, var,
#     head)` walks a linked list, and the loop body frees `var` (e.g.
#     `condition_free(var)`) without a preceding `LIST_REMOVE(name, head,
#     var)` in the same iteration. The freed node's neighbors still point to
#     it -- any later walk of the list dereferences/re-frees freed memory.
#     Confirmed: good_patch.diff adds exactly one `LIST_REMOVE(...)` call
#     right before the existing `condition_free(c);`.
#
# (2) A trivial pointer-freeing "destructor" helper that frees but never
#     nulls the pointer afterward (systemd-005, freep() in alloc-util.h):
#     `static inline void NAME(void *p) { free(*(void**) p); }` -- the whole
#     function body is just the bare free call, no NULL-reset. Compare to
#     the very similar unsetp() a few lines above it in the same file, which
#     DOES reset (`*(void**)p = NULL;`) and is the obvious template this
#     function should have followed. Confirmed: good_patch.diff replaces
#     `free(*(void**) p);` with `*(void**)p = mfree(*(void**) p);` -- same
#     free, now paired with a reset.
# ---------------------------------------------------------------------------

_LIST_FOREACH_RE = re.compile(
    r'\bLIST_FOREACH\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)'
)
_LIST_FOREACH_LOOKAHEAD_WINDOW = 15  # lines to scan into the loop body for a free call


def _scan_list_free_without_unlink(text: str, lines: list[str]):
    """
    Yields (line_idx, start_col, end_col, iter_var, free_line_text) for each
    LIST_FOREACH loop whose body frees the iteration variable (a call whose
    name contains "free", with the iter var as an argument) without a
    LIST_REMOVE(...) on that same list/var appearing first in the loop body.

    Only fires when the free is CONDITIONAL (guarded by an `if (...)` inside
    the loop) -- i.e. only some iterated items get freed, the systemd-004
    shape (`if (type < 0 || c->type == type) { condition_free(c); }`), where
    the list must remain valid/walkable afterward for the un-freed items.
    Excludes the extremely common, structurally different "free every item,
    unconditionally, while tearing the whole list down" idiom (e.g.
    `LIST_FOREACH(items, i, first) free(i); return NULL;` -- systemd's own
    `dns_txt_item_free_all()`), which never needs LIST_REMOVE because nothing
    is left referencing the list afterward. Confirmed via real regression
    check: without this condition, 3 of systemd's own `*_free_all()`-style
    functions false-positived; with it, all 3 go silent and systemd-004
    still fires (its free sits inside exactly this kind of if-block).
    """
    if_re = re.compile(r'\bif\s*\(')
    for m in _LIST_FOREACH_RE.finditer(text):
        list_name, iter_var = m.group(1), m.group(2)
        lv, iv = re.escape(list_name), re.escape(iter_var)
        foreach_line_idx = text[:m.start()].count('\n')

        free_call_re = re.compile(rf'\b\w*free\w*\s*\(\s*{iv}\s*[,)]')
        remove_re = re.compile(rf'\bLIST_REMOVE\s*\(\s*{lv}\s*,\s*\w+\s*,\s*{iv}\s*\)')

        window_end = min(len(lines), foreach_line_idx + 1 + _LIST_FOREACH_LOOKAHEAD_WINDOW)
        removed = False
        saw_if = False
        for i in range(foreach_line_idx + 1, window_end):
            line = lines[i]
            if remove_re.search(line):
                removed = True
            if if_re.search(line):
                saw_if = True
            fm = free_call_re.search(line)
            if fm:
                if not removed and saw_if:
                    yield (i, fm.start(), fm.end(), iter_var, line.strip())
                break


_FREE_WRAPPER_FUNC_RE = re.compile(
    r'\bstatic\s+inline\s+void\s+\w+\s*\(\s*void\s*\*\s*\w+\s*\)\s*'
    r'\{\s*free\s*\(\s*[^;]*\)\s*;\s*\}',
    re.MULTILINE,
)


def _scan_free_wrapper_missing_null_reset(text: str, lines: list[str]):
    """
    Yields (line_idx, start_col, end_col, func_name, free_line_text) for each
    `static inline void NAME(void *p) { free(...); }` one-line pointer
    destructor whose entire body is a bare free call with no NULL-reset
    assignment anywhere in it.
    """
    func_name_re = re.compile(r'\bstatic\s+inline\s+void\s+(\w+)\s*\(')
    for m in _FREE_WRAPPER_FUNC_RE.finditer(text):
        name_m = func_name_re.search(m.group())
        func_name = name_m.group(1) if name_m else "?"
        free_line_idx = text[:m.start()].count('\n')
        # The whole match is 1-2 lines (signature + brace, then the free
        # statement, possibly all on one line); find the actual line
        # containing "free(" to report a precise location.
        match_text = m.group()
        offset_to_free = match_text.index('free(')
        free_line_idx = text[:m.start() + offset_to_free].count('\n')
        line = lines[free_line_idx]
        fcol = line.index('free(')
        yield (free_line_idx, fcol, fcol + len('free'), func_name, line.strip())


_STRLEN_ASSIGN_RE = re.compile(r'\b(\w+)\s*=\s*strlen\s*\(')
_STRLEN_MEMCPY_LOOKAHEAD_WINDOW = 5  # lines after the strlen assignment to look for its use


def _scan_memcpy_indirect_strlen(text: str, lines: list[str]):
    """
    Flow-sensitive CWE-121 detector: catches `memcpy(dst, src, strlen(src))`
    when a decompiler has split it into two statements --
    `tmp = strlen(src); memcpy(dst, src, tmp);` -- which the strict
    same-expression static pattern (`memcpy(...strlen(...))`) cannot match,
    since the literal text "strlen(" never appears inside the memcpy call's
    own parentheses once it's been hoisted into a separate assignment.

    Confirmed this is exactly how Ghidra represents curl-003's ground-truth
    line even under full analysis with every symbol resolved by name:
        __n = strlen(xpoweredby);
        memcpy((data->req).xpoweredby,xpoweredby,__n);
    The compiler evaluates strlen(src) into a register/stack temp before the
    memcpy call at the machine-code level, and Ghidra reconstructs that as
    two separate C statements rather than re-nesting it into one expression
    -- so a literal-adjacency pattern misses real strlen-derived overflows
    on decompiled code, which is why the earlier decompiled-curl run had to
    fall back to matching *every* memcpy( call regardless of its size
    argument (98 matches, almost all not actually strlen-derived, e.g.
    weak_random's `memcpy(entropy, &r, length)` where length is sizeof(int)).
    This detector recovers precision: it only fires when the length
    argument is provably assigned from strlen(...) a few lines earlier.
    """
    for m in _STRLEN_ASSIGN_RE.finditer(text):
        var = m.group(1)
        assign_line_idx = text[:m.start()].count('\n')
        memcpy_re = re.compile(
            rf'\bmemcpy\s*\([^;]*,\s*{re.escape(var)}\s*\)'
        )
        window_end = min(len(lines), assign_line_idx + 1 + _STRLEN_MEMCPY_LOOKAHEAD_WINDOW)
        for i in range(assign_line_idx + 1, window_end):
            mm = memcpy_re.search(lines[i])
            if mm:
                yield (i, mm.start(), mm.end(), var, lines[i].strip())
                break


_TVB_GET_ASSIGN_RE = re.compile(r'\b(\w+)\s*=\s*tvb_get_\w+\s*\(')
_TVB_GET_MEMCPY_LOOKAHEAD_WINDOW = 6  # lines after the tvb_get_* assignment to look for its use


def _scan_memcpy_tvb_length(text: str, lines: list[str]):
    """
    Flow-sensitive CWE-680 detector: catches `memcpy(dst, src, tvb_get_X(...))`
    when the length has been hoisted into its own assignment first --
    `len = tvb_get_ntohs(tvb, offset); ...; memcpy(dst, src, len);` -- which
    the same-line static pattern in CWE_SINK_PATTERNS["CWE-680"] can't match,
    same rationale as _scan_memcpy_indirect_strlen above for CWE-121's
    strlen-split shape.

    Confirmed against afc-wireshark's vuln_011 ground truth
    (aim_get_buddyname, packet-aim.c:588+591):
        buddyname_length = tvb_get_ntohs(tvb, offset);
        if (pool)
                memcpy(*name, tvb_get_ptr(tvb,offset,1), buddyname_length);
    buddyname_length is a raw attacker-controlled 16-bit packet field (up to
    65535) copied straight into a fixed 256-byte wmem_alloc'd buffer with no
    bounds check anywhere in between -- the canonical Wireshark
    dissector-heap-overflow shape. Only 1 match across the entire
    epan/dissectors tree in this codebase (the ground truth itself).
    """
    for m in _TVB_GET_ASSIGN_RE.finditer(text):
        var = m.group(1)
        assign_line_idx = text[:m.start()].count('\n')
        memcpy_re = re.compile(
            rf'\b(?:memcpy|g_memmove)\s*\([^;]*,\s*{re.escape(var)}\s*\)'
        )
        window_end = min(len(lines), assign_line_idx + 1 + _TVB_GET_MEMCPY_LOOKAHEAD_WINDOW)
        for i in range(assign_line_idx + 1, window_end):
            mm = memcpy_re.search(lines[i])
            if mm:
                yield (i, mm.start(), mm.end(), var, lines[i].strip())
                break


def _is_test_file(file_path: str) -> bool:
    """Return True if the file appears to be test code."""
    lower = file_path.lower()
    return (
        '/test/' in lower or
        '/tests/' in lower or
        '_test.' in lower or
        'test_' in Path(file_path).name.lower() or
        Path(file_path).name.lower().startswith('test')
    )


def _get_context(lines: list[str], line_idx: int, ctx: int = 5) -> str:
    """Return ±ctx lines around line_idx as a formatted string."""
    start = max(0, line_idx - ctx)
    end = min(len(lines), line_idx + ctx + 1)
    result = []
    for i in range(start, end):
        marker = " > " if i == line_idx else "   "
        result.append(f"{marker}{i+1:5d} | {lines[i].rstrip()}")
    return "\n".join(result)


@dataclass
class Sink:
    """A single detected sink location."""
    id: str
    cwe: str
    coord: dict          # file_name, line_num, start_column, end_column, func_name
    message: str
    filtered_out_flow: bool   # True → constant args, not exploitable
    filtered_out_test: bool   # True → in test code
    context: str              # ±5 lines of code for display/LLM
    call_text: str            # The actual call expression


def scan_file(
    file_path: Path,
    cwe: str,
    repo_root: Path,
) -> list[Sink]:
    """Scan one file for sinks matching the given CWE."""
    # NOTE: check dict membership, not truthiness — CWE-416/CWE-476's
    # flow-sensitive detectors are registered with an empty pattern LIST
    # (they have no single-line regex patterns), and `if not patterns`
    # would incorrectly early-return before the flow-sensitive block below
    # ever runs. Only bail out for CWEs with no registration at all.
    if cwe not in CWE_SINK_PATTERNS:
        return []
    patterns = CWE_SINK_PATTERNS[cwe]

    # CWE-134's patterns match curl's OWN helper function names (sendf,
    # failf, ...), which -- unlike memcpy/strcpy -- also have real
    # declarations and definitions in this codebase, not just call sites.
    # Header (.h) files contain only declarations (no exploitable logic by
    # definition), so skip them entirely for this CWE rather than trying to
    # regex-distinguish a prototype from a call.
    if cwe == "CWE-134" and file_path.suffix == '.h':
        return []

    try:
        text = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    lines = text.splitlines()
    rel_path = str(file_path.relative_to(repo_root)).replace('\\', '/')
    is_test = _is_test_file(rel_path)

    # Strip comments from the WHOLE file text before matching, not per-line.
    # The previous per-line `re.sub(r'/\*.*?\*/', ...)` only erases a block
    # comment when its opening AND closing markers are on the same line --
    # multi-line block comments (extremely common for file-header/doc
    # comments, e.g. "Requires double parentheses because of variable
    # arguments of printf().") were left completely unstripped, so any sink
    # pattern whose keyword also shows up in prose inside one of those
    # comments (confirmed for the new CWE-457 printf() detector against
    # wireshark: file-jpeg.c:39, packet-mmse.c:44, packet-wbxml.c:48, etc.
    # all false-positived on a shared boilerplate comment) would incorrectly
    # match. Same technique as call_graph.py's extract_functions_from_file:
    # replace comment bodies with newlines/spaces so line numbers and single-
    # line column offsets are preserved exactly.
    text_nc = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group()), text)
    text_nc = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group().count('\n'), text_nc, flags=re.DOTALL)
    lines_nc = text_nc.splitlines()

    sinks: list[Sink] = []

    for pattern_str, description in patterns:
        pat = re.compile(pattern_str)
        for line_idx in range(len(lines_nc)):
            stripped = lines_nc[line_idx]

            m = pat.search(stripped)
            if not m:
                continue

            # CWE-134's function names (sendf/failf/infof/...) are also
            # defined, not just called, in this codebase -- unlike memcpy/
            # strcpy, which are never redefined. A definition/prototype has
            # only a bare return type before the name (same line, e.g.
            # `static CURLcode sendf(`, or the line above, for a
            # split-across-lines signature like `static CURLcode\nsendf(`).
            # Confirmed necessary against dict.c's own local `static CURLcode
            # sendf(...)` -- without this, its forward declaration and
            # definition both show up as false "calls" with the wrong-typed
            # `const char *fmt` param read as a non-literal format string.
            if cwe == "CWE-134":
                same_line_prefix = stripped[:m.start()]
                prev_line = lines_nc[line_idx - 1] if line_idx > 0 else ""
                if _TYPE_ONLY_RE.match(same_line_prefix) or \
                        (not same_line_prefix.strip() and _TYPE_ONLY_RE.match(prev_line)):
                    continue

            line_num = line_idx + 1
            start_col = m.start() + 1
            end_col = m.end() + 1

            # Extract function name from the pattern match
            func_name = m.group().strip().rstrip('(').strip()

            # Grab enough text for arg analysis -- the call's parens must
            # balance, not just "up to end of line". A single-line window
            # silently truncates every multi-line call before its later
            # arguments (e.g. curl's very common wrapped-format-string style,
            # `failf(data, "text..."\n  "more text", var)`), so
            # _is_filtered_out_flow never even sees arg 2+ and defaults to
            # "not filtered" -- confirmed to make the CWE-134 detector
            # unusably noisy (342/2195 false "valid" sinks, nearly all
            # multi-line failf/infof calls with an entirely literal format
            # string that was simply never seen) before this fix.
            call_text = _extract_full_call_text(lines_nc, line_idx, m.start()).split(';')[0]

            # Validity filter
            f_flow = _is_filtered_out_flow(func_name, call_text)

            sink_id = f"{rel_path}:{line_num}:{start_col}:{line_num}:{end_col}"
            context = _get_context(lines, line_idx)

            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start_col,
                    "end_column": end_col,
                    "func_name": func_name,
                },
                message=description,
                filtered_out_flow=f_flow,
                filtered_out_test=is_test,
                context=context,
                call_text=call_text.strip(),
            ))

    # Flow-sensitive CWE-476 pass: missing NULL guard after pointer-chase
    # reassignment. Separate from the regex loop above since it needs
    # multi-line lookahead, not a single-line match.
    if cwe == "CWE-476":
        seen_lines = {s.coord["line_num"] for s in sinks}
        for line_idx, start, end, var, use_line in _scan_missing_null_guard(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue  # already flagged by a regular pattern
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": var,
                },
                message=f"'{var}' reassigned via pointer-chase (X = X->field) "
                        f"and used again with no NULL guard in between — "
                        f"missing-condition NULL deref",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=use_line,
            ))

    # Flow-sensitive CWE-787 pass: (m)snprintf bounded by the wrong
    # variable's sizeof(). See detector docstring above.
    if cwe == "CWE-787":
        seen_lines = {s.coord["line_num"] for s in sinks}
        for line_idx, start, end, func, dest, sizeof_var in _scan_sizeof_mismatch(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": func,
                },
                message=f"{func} writes into '{dest}' but is bounded by "
                        f"sizeof({sizeof_var}), a different variable — "
                        f"wrong-variable sizeof, a classic CWE-787 shape",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=lines[line_idx].strip(),
            ))

        # Second CWE-787 pass: unclamped NUL-terminator array write whose
        # index disagrees with the length that bounded a preceding copy
        # into the same buffer. See detector docstring above.
        seen_lines = {s.coord["line_num"] for s in sinks}
        for line_idx, start, end, dest, idx, copy_len_expr in _scan_unclamped_terminator_write(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue
            seen_lines.add(line_num)
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": dest,
                },
                message=f"'{dest}[{idx}]' NUL-terminator write uses a raw index that "
                        f"disagrees with '{copy_len_expr}', the length that actually "
                        f"bounded a preceding copy into '{dest}' — unclamped "
                        f"terminator write, a CWE-787 shape",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=lines[line_idx].strip(),
            ))

    # Flow-sensitive CWE-126 pass: buffer over-read via a loop-advanced
    # index never compared against any bound in the loop body. See
    # detector docstring above.
    if cwe == "CWE-126":
        seen_lines = {s.coord["line_num"] for s in sinks}
        for line_idx, start, end, arr, idx, read_line in _scan_unchecked_loop_index_read(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue
            seen_lines.add(line_num)
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": arr,
                },
                message=f"'{arr}[{idx}]' read inside a loop that advances '{idx}' "
                        f"but never compares it against any bound in the loop body — "
                        f"missing-condition buffer over-read",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=read_line,
            ))

    # Flow-sensitive CWE-129 pass: array-indexed function-pointer dispatch
    # with no range check on the index. See detector docstring above.
    if cwe == "CWE-129":
        seen_lines = {s.coord["line_num"] for s in sinks}
        for line_idx, start, end, arr, idx, call_line in _scan_unchecked_array_dispatch(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue
            seen_lines.add(line_num)
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": arr,
                },
                message=f"'({arr}[{idx}])(...)' function-pointer dispatch with no "
                        f"range check on '{idx}' against '{arr}' anywhere nearby — "
                        f"improper array index validation",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=call_line,
            ))

    # Flow-sensitive CWE-416 pass: free() not gated by the state-check block
    # that determines ownership (xz-001 bug shape). See detector docstring above.
    if cwe == "CWE-416":
        seen_lines = {s.coord["line_num"] for s in sinks}
        for line_idx, start, end, var, free_line in _scan_ungated_free_after_state_check(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": var,
                },
                message=f"free({var}...) not gated by the same 'if ({var}->state ...)' "
                        f"ownership check just above it — a call reaching this node via a "
                        f"cycle/shared pointer while an ancestor call is still active could "
                        f"free it out from under that call — missing-condition use-after-free",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=free_line,
            ))

    # Flow-sensitive CWE-415 pass: double-free via list-unlink-before-free
    # (systemd-004 shape) and missing-null-reset-after-free (systemd-005
    # shape). See detector docstrings above.
    if cwe == "CWE-415":
        seen_lines = {s.coord["line_num"] for s in sinks}

        for line_idx, start, end, iter_var, free_line in _scan_list_free_without_unlink(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue
            seen_lines.add(line_num)
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": iter_var,
                },
                message=f"'{iter_var}' freed inside a LIST_FOREACH loop with no LIST_REMOVE "
                        f"on it first — the freed node stays linked, so a later walk of the "
                        f"list dereferences/re-frees freed memory — missing-condition double-free",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=free_line,
            ))

        for line_idx, start, end, func_name, free_line in _scan_free_wrapper_missing_null_reset(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue
            seen_lines.add(line_num)
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": func_name,
                },
                message=f"'{func_name}' frees its pointer argument but never resets it to "
                        f"NULL/mfree() afterward — any later free of the same variable through "
                        f"this destructor is a double-free — missing-condition double-free",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=free_line,
            ))

    # Flow-sensitive CWE-121 pass: memcpy whose length argument was assigned
    # from strlen(...) a few lines earlier, rather than inline in the same
    # call expression. See detector docstring above.
    if cwe == "CWE-121":
        seen_lines = {s.coord["line_num"] for s in sinks}
        for line_idx, start, end, var, memcpy_line in _scan_memcpy_indirect_strlen(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue
            seen_lines.add(line_num)
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": var,
                },
                message=f"memcpy length argument '{var}' was assigned from strlen(...) a few "
                        f"lines above rather than inline in the call — same OOB shape as "
                        f"memcpy(...strlen(...)), just split across two statements "
                        f"(the common decompiler idiom)",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=memcpy_line,
            ))

    # Flow-sensitive CWE-680 pass: memcpy/g_memmove whose length argument was
    # assigned from tvb_get_*(...) a few lines earlier, rather than inline in
    # the same call expression. See detector docstring above.
    if cwe == "CWE-680":
        seen_lines = {s.coord["line_num"] for s in sinks}
        for line_idx, start, end, var, memcpy_line in _scan_memcpy_tvb_length(text, lines):
            line_num = line_idx + 1
            if line_num in seen_lines:
                continue
            seen_lines.add(line_num)
            sink_id = f"{rel_path}:{line_num}:{start+1}:{line_num}:{end+1}"
            sinks.append(Sink(
                id=sink_id,
                cwe=cwe,
                coord={
                    "file_name": rel_path,
                    "line_num": line_num,
                    "start_column": start + 1,
                    "end_column": end + 1,
                    "func_name": var,
                },
                message=f"memcpy/g_memmove length argument '{var}' was assigned from "
                        f"tvb_get_*(...) a few lines above — an attacker-controlled packet "
                        f"field used as a copy length with no bounds check in between — "
                        f"integer-overflow/unbounded-length-to-buffer-overflow",
                filtered_out_flow=False,
                filtered_out_test=is_test,
                context=_get_context(lines, line_idx),
                call_text=memcpy_line,
            ))

    return sinks


def scan_codebase(
    root: Path,
    cwes: list[str],
    include_dirs: list[str] = None,
    exclude_dirs: list[str] = None,
) -> list[Sink]:
    """
    Scan entire codebase for sinks matching any of the given CWEs.

    Args:
        root: Repository root path
        cwes: List of CWE identifiers e.g. ["CWE-121", "CWE-476"]
        include_dirs: Only scan these subdirs (relative to root). None = scan all.
        exclude_dirs: Skip these subdirs.
    """
    exclude_dirs = set(exclude_dirs or ['docs', 'doc', '.git', 'cmake', 'CMake',
                                         'appveyor', 'm4', 'aclocal'])
    all_sinks: list[Sink] = []

    # Also scan .h -- some real, freestanding function bodies live in headers
    # (e.g. systemd's many `static inline` helpers like alloc-util.h's
    # freep(), the systemd-005 bug's containing function). Same rationale as
    # call_graph.py's build_call_graph(): this only adds files, and
    # CWE_SINK_PATTERNS/the flow-sensitive detectors only match real function
    # bodies/call sites, not declarations, so this doesn't introduce
    # header-declaration noise.
    c_files = []
    for f in list(root.rglob('*.c')) + list(root.rglob('*.h')):
        rel = f.relative_to(root)
        parts = rel.parts
        if any(p in exclude_dirs for p in parts):
            continue
        if include_dirs:
            if not any(str(rel).startswith(d) for d in include_dirs):
                continue
        c_files.append(f)

    print(f"[sink_finder] Scanning {len(c_files)} .c/.h files for {cwes}...")

    seen_ids: set[str] = set()
    for f in c_files:
        for cwe in cwes:
            for sink in scan_file(f, cwe, root):
                if sink.id not in seen_ids:
                    seen_ids.add(sink.id)
                    all_sinks.append(sink)

    return all_sinks


def sinks_to_json(sinks: list[Sink]) -> list[dict]:
    """Convert sinks to JSON-serializable dicts (GONDAR format)."""
    result = []
    for s in sinks:
        d = {
            "id": s.id,
            "cwe": s.cwe,
            "coord": s.coord,
            "message": s.message,
            "filtered_out_flow": s.filtered_out_flow,
            "filtered_out_test": s.filtered_out_test,
            "context": s.context,
            "call_text": s.call_text,
        }
        result.append(d)
    return result


def main():
    parser = argparse.ArgumentParser(description="Scan C codebase for vulnerability sinks")
    parser.add_argument("root", help="Repository root path")
    parser.add_argument("--cwe", action="append", default=[], dest="cwes",
                        help="CWE to scan for (repeat for multiple). Default: CWE-121 CWE-476")
    parser.add_argument("--include-dir", action="append", default=[], dest="include_dirs",
                        help="Only scan files under these subdirs (relative to root)")
    parser.add_argument("--output", "-o", default="sinks.json",
                        help="Output JSON file path")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary table after scanning")
    args = parser.parse_args()

    cwes = args.cwes or ["CWE-121", "CWE-476"]
    root = Path(args.root).resolve()
    if not root.exists():
        print(f"ERROR: {root} does not exist")
        return 1

    sinks = scan_codebase(root, cwes, include_dirs=args.include_dirs or None)

    valid = [s for s in sinks if not s.filtered_out_flow and not s.filtered_out_test]
    print(f"\n[sink_finder] Found {len(sinks)} total sinks")
    print(f"  Filtered (constant args):  {sum(1 for s in sinks if s.filtered_out_flow)}")
    print(f"  Filtered (test code):      {sum(1 for s in sinks if s.filtered_out_test)}")
    print(f"  Valid sinks remaining:     {len(valid)}")

    data = sinks_to_json(sinks)
    out = Path(args.output)
    out.write_text(json.dumps(data, indent=2))
    print(f"  Written to: {out}")

    if args.summary:
        print("\n--- Valid Sinks ---")
        for s in valid:
            print(f"  [{s.cwe}] {s.coord['file_name']}:{s.coord['line_num']}  ({s.message})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
