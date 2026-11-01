"""sinkpipe -- the C/C++ sink-detection engine (sink_finder, call_graph, param_tracer, llm_agent, run).

Mirrors java_pipeline's `pipeline/` package layout: a plain top-level `pipeline.py` script in
cpp_pipeline/ is kept as a thin CLI wrapper around sinkpipe.run.main, so `python pipeline.py run ...`
keeps working unchanged.
"""
