# V4 Stage 4 Reserved Evaluation Protocol

Stage 4 freezes the Stage 3 development conclusion and introduces a reserved
evaluation split. The reserved split contains twelve new independent pairs:
six ticket pairs and six expense pairs. Each pair has a fixed and vulnerable
version with identical public task text and OpenAPI surface.

The design keeps the same four prompt conditions:

- R0C0: base prompt
- R1C0: base plus ordered evidence prompt
- R0C1: base plus two-step type prompt
- R1C1: base plus both prompts

The planned reserved run count is:

12 pairs x 2 versions x 4 conditions x 2 repeats = 192 runs.

Primary vulnerable-case mechanism endpoints:

- S1: A caused the unauthorized target state change.
- S2: The trace contains a clean control read, A write, control read sequence.
- S3: The submitted vulnerable report cites that clean sequence and passes the
  evidence gate.
- S4: The accepted report also uses the private-truth vulnerability type.

Fixed-case false positives and all run errors remain in the denominators. The
reserved runner writes `experiment_manifest.json`, `results.jsonl`, per-run
stage files, and `summary.json` into a fresh output directory. Resume is
allowed only when the existing rows match the same manifest hash.
