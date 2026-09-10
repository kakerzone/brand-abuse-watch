# Local operations

`run_pipeline.py` performs only local discovery, parsing, scoring, tracking, indexing, case sync, graph generation, and optional Lark preview. It does not call CT/RDAP/DNS/web collectors; add their normalized evidence files with repeated `--evidence` arguments after separately authorized collection. Its case threshold defaults to 70 so generated candidates do not overwhelm analysts; lower it only after reviewing queue volume.

Run `health_check.py` after every scheduled local run. A healthy local run is not proof that external sources were available or that global domain coverage was complete.
