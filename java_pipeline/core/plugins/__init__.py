"""Language plugins for the shared scorer.

A plugin supplies everything language-specific; core/scorer.py is language-neutral.

    name            "php" | "java"
    extensions      file suffixes that are scorable (each such file contributes one "(file scope)" unit)
    case_sensitive  False => unit names compare case-insensitively (PHP), True => exactly (Java)
    functions(path) -> [(qualified_name, start_line1, end_line1)]   (files with no function notion return [])
    norm_name(fn)   normalise a name given in a key or prediction
    candidates(n, names) -> (set_of_candidate_names, accept_single)  loose resolution when `n` is not an exact name;
                    accept_single=True lets a single candidate stand for `n`
"""


def get(name):
    if name == "php":
        from . import php
        return php.PLUGIN
    if name == "java":
        from . import java
        return java.PLUGIN
    raise SystemExit(f"unknown language plugin {name!r} (have: php, java)")
