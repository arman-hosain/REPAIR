#!/usr/bin/env python3
"""Thin CLI entry point for cpp_pipeline.

The actual implementation (sink scanning, call graph, param tracer, LLM assessment, argument
parsing) lives in the `sinkpipe` package (sinkpipe/sink_finder.py, call_graph.py, param_tracer.py,
llm_agent.py, run.py) -- mirroring java_pipeline's `pipeline/` package layout. This file is kept
at the top level, unchanged in behavior, purely so the documented public CLI invocation
(`python pipeline.py run ...`) keeps working after that internal reorganization.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sinkpipe.run import main

if __name__ == "__main__":
    raise SystemExit(main())
