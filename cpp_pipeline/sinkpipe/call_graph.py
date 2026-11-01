#!/usr/bin/env python3
"""
call_graph.py -- Regex-based C function call graph + reachability BFS
"""

import re
import json
import argparse
import signal
from pathlib import Path
from collections import deque

FUNC_DEF_SIMPLE = re.compile(
    r'^(?:static\s+)?(?:inline\s+)?(?:const\s+)?(?:\w+\s+)+(\w+)\s*\([^;{]*\)\s*\n?\s*\{',
    re.MULTILINE
)
FUNC_DEF_PATTERN = re.compile(
    # The separator right before the captured name must be one-or-more of
    # (whitespace OR '*'), not just whitespace -- otherwise this only
    # matches "Type* name(" (star glued to the type) and silently misses
    # "Type *name(" (star glued to the name, no space before the
    # identifier), which is an equally common, arbitrary C style choice.
    # Found via curl's lib/hostip.c: static struct Curl_addrinfo
    # *get_localhost6(...) and *get_localhost(...) were both missing from
    # the graph entirely under the old pattern, silently merging their
    # bodies into the *previous* correctly-detected function's span
    # (Curl_cache_addr) -- so find_containing_function() misattributed
    # sinks inside get_localhost/get_localhost6 to Curl_cache_addr instead.
    r'^[\w\s]+[\s\*]+(\w+)\s*\([^)]*\)\s*(?:__\w+\s*)*\{',
    re.MULTILINE
)
# Matches xz/liblzma's public-API idiom:
#   extern LZMA_API(lzma_ret)
#   lzma_stream_encoder(lzma_stream *strm, ...)
#   {
# FUNC_DEF_SIMPLE alone mis-parses this: its `(?:\w+\s+)+(\w+)\s*\(` greedily
# stops at "LZMA_API(" (the macro-wrapped return type), capturing "LZMA_API"
# as the function name and swallowing the *real* name + real params into the
# "arguments" — so every public liblzma function (lzma_stream_encoder,
# lzma_code, lzma_tree, ...) silently disappeared from the call graph. This
# pattern explicitly requires a `RETTYPE_MACRO(...)` line followed by
# `real_name(...)  {` on the next line, and captures the real name.
FUNC_DEF_MACRO_RET = re.compile(
    r'^(?:extern\s+)?\w+\s*\([^()]*\)\s*\n\s*(\w+)\s*\([^;{]*\)\s*\n?\s*\{',
    re.MULTILINE
)
FUNC_CALL_PATTERN = re.compile(r'\b(\w+)\s*\(')
C_KEYWORDS = frozenset({
    'if','else','for','while','do','switch','case','return','sizeof','typeof',
    'alignof','offsetof','__typeof__','__alignof__','goto','break','continue',
    'typedef','struct','union','enum','static','extern','inline','const',
    'volatile','register','auto','signed','unsigned','int','char','long',
    'short','float','double','void','bool','_Bool',
})

_MAX_FILE_SIZE_FOR_GRAPH = 300_000  # bytes; guards against pathological regex cost

# The size guard above doesn't catch everything -- confirmed on Wireshark's
# epan/dissectors (2026-09-22): packet-bluetooth.c (259KB) and packet-dns.c
# (299KB), both under the 300KB cutoff, still hang FUNC_DEF_SIMPLE/
# FUNC_CALL_PATTERN's regex backtracking for minutes (open-endedly -- never
# measured to completion, just confirmed >5s each via this same alarm while
# every other ~2200 files in the same tree took a combined ~23s). Root cause
# is presumably these files' specific structure (heavily nested #if/#ifdef,
# many small functions with complex signatures), not raw size, so a size
# threshold alone can't be tuned to catch it without also dropping real
# files. A hard per-file wall-clock timeout, skip-and-warn on expiry, is the
# actual fix. SIGALRM-based -- Unix only, and only safe from the main thread
# of the main process (true for every caller in this codebase).
_EXTRACT_TIMEOUT_SECONDS = 8


class _ExtractTimeout(Exception):
    pass


def _extract_timeout_handler(signum, frame):
    raise _ExtractTimeout()


def extract_functions_from_file(file_path):
    try:
        # Vendored kernel/system UAPI headers (e.g. systemd's src/basic/linux/*.h,
        # a straight copy of Linux kernel headers like bpf.h at 7500+ lines of
        # dense nested struct/union/macro definitions) can make FUNC_DEF_SIMPLE's
        # `(?:\w+\s+)+` and the per-function-body FUNC_CALL_PATTERN pass take
        # catastrophically long -- confirmed hanging the systemd call-graph build
        # on exactly such a file. These files never contain real function bodies
        # worth graphing anyway (they're vendored constant/struct definitions),
        # so skip anything implausibly large rather than trying to parse it.
        if file_path.stat().st_size > _MAX_FILE_SIZE_FOR_GRAPH:
            return {}
        text = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return {}
    text_stripped = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group()), text)
    text_stripped = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group().count('\n'),
                           text_stripped, flags=re.DOTALL)
    lines = text_stripped.splitlines()
    funcs = {}

    # Macro-wrapped-return-type definitions first (see FUNC_DEF_MACRO_RET) —
    # these take priority at their start line since FUNC_DEF_SIMPLE gets the
    # name wrong for this exact shape.
    starts_by_line: dict[int, str] = {}
    for m in FUNC_DEF_MACRO_RET.finditer(text_stripped):
        name = m.group(1)
        if name in C_KEYWORDS: continue
        line_idx = text_stripped[:m.start()].count('\n')
        starts_by_line[line_idx] = name

    for m in FUNC_DEF_SIMPLE.finditer(text_stripped):
        name = m.group(1)
        if name in C_KEYWORDS: continue
        line_idx = text_stripped[:m.start()].count('\n')
        if line_idx in starts_by_line:
            continue  # already correctly named by the macro-ret pattern
        starts_by_line[line_idx] = name

    # FUNC_DEF_PATTERN as a per-line gap-filler, not a whole-file fallback.
    # FUNC_DEF_SIMPLE's `(?:\w+\s+)+(\w+)\s*\(` requires the return type and
    # name to be separated by plain whitespace -- it cannot match ANY pointer
    # return type, since a `*` between the type and name (in either style,
    # `Type* name(` or `Type *name(`) isn't whitespace or \w, so the
    # `(?:\w+\s+)+` chain can't reach the name. FUNC_DEF_PATTERN's
    # `[\w\s\*]+` class does include `*`, so it correctly matches pointer
    # returns via backtracking -- but it was previously only tried when
    # FUNC_DEF_SIMPLE found ZERO functions in the entire file, which almost
    # never happens in a real file that mixes pointer- and value-returning
    # functions (i.e. nearly every real C file). This silently dropped every
    # pointer-returning function from the graph project-wide until now --
    # confirmed on systemd's `Condition* condition_free_list_type(...)`,
    # the systemd-004 bug's own containing function, which was invisible to
    # Stage 3 (Path Analysis) reachability as a result. Now always run both and merge,
    # filling in any line FUNC_DEF_SIMPLE missed.
    for m in FUNC_DEF_PATTERN.finditer(text_stripped):
        name = m.group(1)
        if name in C_KEYWORDS: continue
        line_idx = text_stripped[:m.start()].count('\n')
        if line_idx in starts_by_line:
            continue
        starts_by_line[line_idx] = name

    func_starts = sorted(starts_by_line.items(), key=lambda x: x[0])
    for i, (start_line, name) in enumerate(func_starts):
        end_line = func_starts[i+1][0] if i+1 < len(func_starts) else len(lines)-1
        body = '\n'.join(lines[start_line:end_line])
        calls = {m.group(1) for m in FUNC_CALL_PATTERN.finditer(body)
                 if m.group(1) not in C_KEYWORDS and m.group(1) != name}
        if name in funcs:
            funcs[name]['calls'].update(calls)
            funcs[name]['end_line'] = max(funcs[name]['end_line'], end_line)
        else:
            funcs[name] = {"file": str(file_path), "start_line": start_line+1,
                           "end_line": end_line+1, "calls": calls}
    return funcs

def build_call_graph(root, source_dirs=None):
    # Also scan .h files, not just .c -- some real function BODIES (not just
    # prototypes) live in headers, e.g. `static` fuzz-harness helpers like
    # xz's fuzz_code() in tests/ossfuzz/fuzz_common.h. extract_functions_from_file's
    # regexes only match a `{` immediately after the parameter list (an actual
    # body), so plain `;`-terminated prototype declarations are still ignored --
    # this only adds real definitions, so it's a strict improvement to graph
    # completeness, not a source of prototype-noise.
    source_dirs = source_dirs or ['lib', 'src']
    c_files = []
    for sd in source_dirs:
        sd_path = root / sd
        if sd_path.exists():
            c_files.extend(sd_path.rglob('*.c'))
            c_files.extend(sd_path.rglob('*.h'))
    if not c_files:
        c_files = list(root.rglob('*.c')) + list(root.rglob('*.h'))
    print(f"[call_graph] Building call graph from {len(c_files)} files...")

    # NOTE: tried a multiprocessing.Pool here under the assumption that
    # Wireshark's ~2200-file epan/dissectors (vs. curl's few-hundred-file
    # lib/) was genuinely slow single-threaded -- it wasn't. Direct
    # profiling (per-file timing, unbuffered output written straight to a
    # file rather than through a `| tail` pipe) showed the real serial cost
    # is ~24s for the whole tree, a handful of ~0.5-0.6s outliers aside. The
    # apparent "10+ minute hang" was `tail`'s buffering: `cmd | tail -N`
    # shows nothing until the pipe closes, which reads exactly like a hang
    # if you kill the command before it finishes. The 128-worker pool was
    # then measured to be SLOWER than serial (fork + pickle overhead per
    # task dominates at ~10ms/file average work) -- reverted. Moral: profile
    # before parallelizing, and never judge "is this hung" from output
    # piped through `tail` without `-f`.
    old_handler = signal.signal(signal.SIGALRM, _extract_timeout_handler)
    per_file_results = []
    skipped_timeout = []
    try:
        for f in c_files:
            signal.alarm(_EXTRACT_TIMEOUT_SECONDS)
            try:
                per_file_results.append(extract_functions_from_file(f))
            except _ExtractTimeout:
                per_file_results.append({})
                skipped_timeout.append(f)
            finally:
                signal.alarm(0)
    finally:
        signal.signal(signal.SIGALRM, old_handler)
    if skipped_timeout:
        print(f"[call_graph] WARNING: {len(skipped_timeout)} file(s) exceeded "
              f"{_EXTRACT_TIMEOUT_SECONDS}s regex-extraction timeout, skipped "
              f"(no functions from these files are in the graph): "
              f"{', '.join(str(p.relative_to(root)) for p in skipped_timeout)}")

    graph = {}
    for f, file_funcs in zip(c_files, per_file_results):
        for name, data in file_funcs.items():
            if name in graph:
                graph[name]['calls'] = list(set(graph[name]['calls']) | data['calls'])
            else:
                graph[name] = {
                    "file": str(f.relative_to(root)).replace('\\', '/'),
                    "start_line": data['start_line'], "end_line": data['end_line'],
                    "calls": list(data['calls']),
                }
    print(f"[call_graph] Extracted {len(graph)} functions")
    return graph

def find_containing_function(graph, file_name, line_num):
    candidates = [(n, info['start_line']) for n, info in graph.items()
                  if (info['file'].endswith(file_name) or file_name.endswith(info['file']))
                  and info['start_line'] <= line_num <= info['end_line']]
    return max(candidates, key=lambda x: x[1])[0] if candidates else None

def bfs_reachable(graph, entry_points):
    reachable = set(entry_points)
    queue = deque(entry_points)
    while queue:
        current = queue.popleft()
        for callee in graph.get(current, {}).get('calls', []):
            if callee not in reachable:
                reachable.add(callee)
                queue.append(callee)
    return reachable

# ---------------------------------------------------------------------------
# Harness-free mode
# ---------------------------------------------------------------------------

TAINT_SOURCE_FUNCTIONS = frozenset({
    'recv','recvfrom','recvmsg','accept','read',
    'fread','fgets','fgetc','getchar','gets',
    'fscanf','scanf','sscanf','vsscanf','getline','getdelim',
    'getenv','getopt','getopt_long',
    'strtol','strtoul','strtoll','strtoull','strtod','atoi','atol','atof',
    'http_parser_execute','llhttp_execute','nghttp2_session_recv',
})

_HEADER_DECL_RE = re.compile(
    r'^(?!.*\b(?:static|typedef|#define|#)\b)'
    r'(?:extern\s+)?[\w\s\*\[\]]+\s+(\w{3,})\s*\([^;{#\n]*\)\s*;',
    re.MULTILINE,
)
# Same macro-wrapped-return-type idiom as FUNC_DEF_MACRO_RET above, but for
# header DECLARATIONS: `extern LZMA_API(lzma_ret) lzma_stream_encoder(lzma_stream *strm,`
# -- name and macro are on the same line here (unlike the .c definitions, where
# they're on separate lines), but the parameter list still often continues onto
# following lines before the closing `;`. _HEADER_DECL_RE requires the whole
# declaration on one line and can't match through `MACRO(...)` either way, so
# every public liblzma function silently vanished from detect_public_api_functions
# too. This only needs to find `MACRO(...) name(` -- it doesn't need to consume
# through the closing `;`, so multi-line parameter lists don't matter here.
_HEADER_DECL_MACRO_RET_RE = re.compile(
    r'^(?:extern\s+)?\w+\s*\([^()]*\)\s*(\w{3,})\s*\(',
    re.MULTILINE,
)

def detect_public_api_functions(root, header_dirs=None):
    """Scan .h files for non-static declared function names (public API)."""
    headers = []
    if header_dirs:
        for d in header_dirs:
            p = root / d
            if p.exists():
                headers.extend(p.rglob('*.h'))
    if not headers:
        headers = list(root.rglob('*.h'))
    headers.sort(key=lambda p: (0 if 'include' in p.parts else 1, len(p.parts)))
    found = set()
    for h in headers:
        try:
            text = h.read_text(encoding='utf-8', errors='replace')
            for m in _HEADER_DECL_RE.finditer(text):
                name = m.group(1)
                if name and not name.isupper() and len(name) >= 3:
                    found.add(name)
            for m in _HEADER_DECL_MACRO_RET_RE.finditer(text):
                name = m.group(1)
                if name and not name.isupper() and len(name) >= 3:
                    found.add(name)
        except Exception:
            continue
    return sorted(found)

def detect_taint_entry_points(graph):
    """Functions that directly call a taint source -- where external data enters."""
    return [n for n, info in graph.items()
            if set(info.get('calls', [])) & TAINT_SOURCE_FUNCTIONS]

def get_entry_points_for_no_harness(root, graph):
    """
    Entry points for a codebase without a fuzzer harness.

    Taint-source callers (recv/read/fgets/getenv/...) and public API functions
    are UNIONED, not tried as a priority fallback chain. For a library
    codebase (lcms, libpng, zlib, ...) the real attack surface is
    overwhelmingly the public API -- callers pass attacker-controlled bytes
    in as function parameters (e.g. an ICC profile buffer), not via recv/
    fgets/etc. Only a narrow slice of a library's own internal code (text-
    format parsers that call fscanf/fgets on embedded sub-streams) shows up
    as a taint-source caller. Using taint-source callers ALONE (the previous
    behavior) undercounts reachability badly for libraries: it found only 9
    reachable candidates out of 258 valid sinks in lcms2, missing the real
    lcms-001 bug entirely because its containing function (EmitCIEBasedDEF)
    is only reachable via the public API entry point cmsGetPostScriptCSA,
    which never calls a taint-source function itself -- it receives the
    profile as a memory buffer parameter instead.

    Falls back to "all graph functions" only if neither set is non-empty.
    """
    taint_eps = detect_taint_entry_points(graph)
    api_in_graph = [f for f in detect_public_api_functions(root) if f in graph]

    entry_points = sorted(set(taint_eps) | set(api_in_graph))
    if entry_points:
        print(f"[call_graph] No-harness: {len(taint_eps)} taint-source callers "
              f"+ {len(api_in_graph)} public API functions "
              f"= {len(entry_points)} entry points (union)")
        return entry_points

    print("[call_graph] No-harness: using all graph functions as entry points")
    return list(graph.keys())

# ---------------------------------------------------------------------------
# Named fuzzer harnesses (curl OSS-Fuzz)
# ---------------------------------------------------------------------------
#
# curl_fuzzer's own harness source (curl_fuzzer_*.c) lives in a separate
# oss-fuzz-aixcc repo, not vendored into this challenge repo, so
# LLVMFuzzerTestOneInput itself is never in the graph for a source-only run --
# curl's own public API entry points (curl_easy_perform et al.) are used as
# the practical root instead, same as any embedder driving the library.
#
# Curl_http_write_resp is a hand-traced supplemental entry, needed because
# curl dispatches response-header writing through a function pointer:
# struct Curl_handler.write_resp, invoked at lib/transfer.c:877
# (`data->conn->handler->write_resp(...)` inside Curl_xfer_write_resp) --
# never called by literal name anywhere. Confirmed by hand: lib/http.c
# assigns Curl_http_write_resp to that field for both the HTTP and HTTPS
# handler structs (lines 125, 154). Without this seed, curl-003's real chain
# (Curl_http_write_resp -> Curl_http_write_resp_hds -> http_parse_headers ->
# http_rw_hd -> Curl_http_header, the CWE-121 sink at lib/http.c:3017) is
# invisible to BFS even though curl_easy_perform is reachable and the whole
# rest of the chain is wired up correctly in the graph. Same class of
# invisible dynamic dispatch as xz's block_encode and systemd's
# config_parse_net_condition/freep.
CURL_HARNESS_ENTRY_POINTS = {
    "curl_fuzzer_http": [
        "LLVMFuzzerTestOneInput", "curl_easy_perform", "curl_easy_setopt",
        "Curl_do", "Curl_connect", "Curl_http", "Curl_http_write_resp",
    ],
    "curl_fuzzer_ws": [
        "LLVMFuzzerTestOneInput","extremelygoodprtcl_doing",
        "Curl_extremelygoodprtcl_doing","extremelygoodprtcl_statemach",
    ],
    "curl_fuzzer": ["LLVMFuzzerTestOneInput","Curl_read","Curl_write"],
    "_default": [
        "LLVMFuzzerTestOneInput","curl_easy_perform",
        "curl_easy_setopt","Curl_do","Curl_connect","Curl_http_write_resp",
    ],
}

# xz (afc-xz-challenges-xz-full-01) OSS-Fuzz harnesses -- these live under
# tests/ossfuzz/, not lib/ or src/, so build_call_graph() must be called with
# source_dirs including that directory for LLVMFuzzerTestOneInput to actually
# appear in the graph. Each harness's real entry function is always just
# LLVMFuzzerTestOneInput -- BFS from there naturally reaches the rest of the
# real call chain (e.g. fuzz_encode_stream -> lzma_stream_encoder/lzma_code ->
# lzma_check_update -> lzma_tree -> create_tree/compute_tree_checksum for the
# xz-001 CWE-416 bug), so no need to hand-list intermediate functions.
XZ_HARNESS_ENTRY_POINTS = {
    # fuzz_encode_stream also seeds `block_encode` (src/liblzma/common/block_encoder.c):
    # liblzma dispatches its actual per-block encode step through a function
    # pointer (`coder->next.code(...)`, wired up during lzma_stream_encoder's
    # init chain) that the regex call graph can't trace through. Confirmed by
    # hand that block_encode is the real callback lzma_code() invokes, and
    # that it's the function that calls lzma_check_update() -> lzma_tree() ->
    # compute_tree_checksum()/create_tree() -- i.e. this is filling in a real
    # dynamic-dispatch edge the static graph misses, the same reason curl's
    # harness entries needed hand-added intermediate functions, not a
    # hand-picked shortcut to the bug itself.
    "fuzz_encode_stream": ["LLVMFuzzerTestOneInput", "block_encode"],
    "fuzz_decode_stream": ["LLVMFuzzerTestOneInput"],
    "fuzz_decode_stream_mt": ["LLVMFuzzerTestOneInput"],
    "fuzz_decode_alone": ["LLVMFuzzerTestOneInput"],
}

# afc-systemd harnesses. LLVMFuzzerTestOneInput's name collides across all 46
# systemd fuzz harnesses in one shared graph (every harness .c file defines a
# function with this exact name), so each entry seeds the harness's real,
# uniquely-named next-hop function directly instead.
SYSTEMD_HARNESS_ENTRY_POINTS = {
    # fuzz-link-parser -> link_load_one -> config_parse_many() -> (function-
    # pointer dispatch through a .gperf-generated config-item table, for the
    # "[Match]" section) -> config_parse_net_condition -> condition_free_list_type
    # (systemd-004's bug). Confirmed by hand: link_load_one calls
    # config_parse_many() (src/udev/net/link-config.c:273), which is
    # systemd's generic declarative config-file parser -- it looks up each
    # "[Section] Key=Value" line in a static table and invokes the matching
    # config_parse_* callback through a function pointer, never as a literal
    # `config_parse_net_condition(...)` call anywhere in the source. Same
    # class of invisible dynamic dispatch as xz's block_encode.
    "fuzz-link-parser": ["link_load_one", "config_parse_net_condition"],
    # fuzz-systemctl-parse-argv -> systemctl_dispatch_parse_argv -> (dozens of
    # systemctl-*.c command handlers) -> freep (systemd-005's bug, in
    # alloc-util.h). freep() is never called by name anywhere -- it's wired
    # up as the GCC __attribute__((cleanup(freep))) destructor for every
    # `_cleanup_free_`-annotated local variable, invoked implicitly by
    # compiler-generated code whenever such a variable goes out of scope.
    # Confirmed by hand: `_cleanup_free_` is used directly in systemctl.c
    # itself (5 occurrences) and in the large majority of the systemctl-*.c
    # command handler files systemctl_dispatch_parse_argv dispatches to
    # (grep count: 0-31 occurrences per file, only a handful of files have
    # zero). No static call graph can see a compiler-attribute-triggered
    # call, so freep is seeded directly as reachable.
    "fuzz-systemctl-parse-argv": ["systemctl_dispatch_parse_argv", "freep"],
    # fuzz-udev-rule-parse-value -> udev_rule_parse_value (systemd-001's bug,
    # CWE-787, udev-rules.c:1220). Confirmed by reading the harness directly
    # (src/udev/fuzz-udev-rule-parse-value.c): LLVMFuzzerTestOneInput calls
    # udev_rule_parse_value() straight on the raw fuzz input with no
    # indirection -- the entry point IS the vulnerable function itself.
    "fuzz-udev-rule-parse-value": ["udev_rule_parse_value"],
}

# afc-wireshark's harness (fuzz/fuzzshark.c) is a single shared
# LLVMFuzzerTestOneInput that dynamically selects a target dissector at
# runtime via an env var (FUZZSHARK_TARGET) and dispatches to it through a
# registered dissector_handle_t (get_dissector_handle -> call_dissector_*) --
# never a literal `dissect_aim(...)` / `dissect_zbee_zdp(...)` call anywhere
# in the harness source. Same invisible function-pointer-dispatch class as
# xz's block_encode and systemd's config_parse_net_condition above. Seed each
# vuln's own top-level per-protocol dissect_* function directly as the entry
# point instead -- confirmed by reading each dissector file directly.
WIRESHARK_HARNESS_ENTRY_POINTS = {
    "handler_aim": ["dissect_aim"],            # packet-aim.c:1639
    "handler_zbee_zdp": ["dissect_zbee_zdp"],  # packet-zbee-zdp.c:1052
    # afc-wireshark ws-delta-02, vuln_004 (CWE-121, packet-icmp.c:927): the
    # crash trace in the vuln README confirms handler_icmp -> dissect_icmp ->
    # dissect_icmp_extension -> tvb_memcpy sink.
    "handler_icmp": ["dissect_icmp"],          # packet-icmp.c:1494
}

def get_entry_points_for_harness(harness):
    """Returns [] for harness='none' (caller must use get_entry_points_for_no_harness)."""
    if harness == "none":
        return []
    if harness in XZ_HARNESS_ENTRY_POINTS:
        return XZ_HARNESS_ENTRY_POINTS[harness]
    if harness in SYSTEMD_HARNESS_ENTRY_POINTS:
        return SYSTEMD_HARNESS_ENTRY_POINTS[harness]
    if harness in WIRESHARK_HARNESS_ENTRY_POINTS:
        return WIRESHARK_HARNESS_ENTRY_POINTS[harness]
    return CURL_HARNESS_ENTRY_POINTS.get(harness, CURL_HARNESS_ENTRY_POINTS["_default"])

def mark_reachability(sinks, graph, harness, root=None):
    """
    Add 'reachable' and 'containing_function' to each sink.
    Conservative fallback: if all sinks are unreachable, mark all as reachable.
    """
    candidates = [s for s in sinks
                  if not s.get('filtered_out_flow') and not s.get('filtered_out_test')]
    if not candidates:
        return sinks

    if harness == "none":
        entry_points = get_entry_points_for_no_harness(root or Path('.'), graph)
    else:
        entry_points = list(set(
            get_entry_points_for_harness(harness) +
            [n for n in graph if 'LLVMFuzzerTestOneInput' in n or 'fuzzer' in n.lower()]
        ))

    reachable_funcs = bfs_reachable(graph, entry_points)
    print(f"[call_graph] Entry points: {entry_points[:5]}... "
          f"-> {len(reachable_funcs)} reachable functions")

    updated = []
    for sink in sinks:
        s = dict(sink)
        if s.get('filtered_out_flow') or s.get('filtered_out_test'):
            s['reachable'] = False
            updated.append(s)
            continue
        coord = s.get('coord', {})
        containing = find_containing_function(graph, coord.get('file_name',''), coord.get('line_num',0))
        s['containing_function'] = containing
        if containing and containing in reachable_funcs:
            s['reachable'] = True
        else:
            file_name = coord.get('file_name', '')
            file_funcs = {n for n, info in graph.items()
                          if info['file'].endswith(file_name) or file_name.endswith(info['file'])}
            s['reachable'] = bool(file_funcs & reachable_funcs)
        updated.append(s)

    reachable_candidates = [s for s in updated if s.get('reachable')
                            and not s.get('filtered_out_flow') and not s.get('filtered_out_test')]
    if not reachable_candidates and candidates:
        print("[call_graph] WARNING: All candidates unreachable -- applying conservative fallback.")
        for s in updated:
            if not s.get('filtered_out_flow') and not s.get('filtered_out_test'):
                s['reachable'] = True
    return updated

def main():
    parser = argparse.ArgumentParser(description="Build call graph and mark sink reachability")
    parser.add_argument("root", help="Repository root path")
    parser.add_argument("sinks", help="Input sinks JSON")
    parser.add_argument("--harness", default="none",
                        help="Fuzzer harness name, or 'none' for no-harness mode")
    parser.add_argument("--output", "-o", default="sinks_reachable.json")
    parser.add_argument("--save-graph", help="Save call graph JSON")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    graph = build_call_graph(root)
    if args.save_graph:
        with open(args.save_graph, 'w') as f:
            json.dump({k: {**v, 'calls': list(v.get('calls',[]))} for k, v in graph.items()}, f, indent=2)
        print(f"[call_graph] Saved graph to {args.save_graph}")

    sinks = json.loads(Path(args.sinks).read_text())
    updated = mark_reachability(sinks, graph, args.harness, root=root)

    reachable = [s for s in updated if s.get('reachable')
                 and not s.get('filtered_out_flow') and not s.get('filtered_out_test')]
    print(f"[call_graph] Reachable candidate sinks: {len(reachable)}")
    for s in reachable:
        print(f"  [{s['cwe']}] {s['coord']['file_name']}:{s['coord']['line_num']}"
              f"  fn={s.get('containing_function','?')}  ({s['message']})")

    Path(args.output).write_text(json.dumps(updated, indent=2))
    print(f"[call_graph] Written to {args.output}")

if __name__ == "__main__":
    raise SystemExit(main())
