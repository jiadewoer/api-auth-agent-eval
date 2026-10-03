# V4-D2: conditional type prompt, development pilot

This amendment follows the completed V4-R1 reserved evaluation. V4-R1 is now historical evidence, not an unused holdout. Its data and hashes remain unchanged.

## Observed reason for amendment

The R1C1 arm reported a correct type and accepted evidence on 19/24 vulnerable reserved runs, but all 24 fixed runs failed to complete. Twenty fixed runs ended in repeated evidence rejection after a clean denied target request and unchanged control observations. Four ended in `INVALID_FINDING` because the agent submitted `not_vulnerable` with a non-null `vulnerability_type`. R1C0 completed all fixed runs, explicitly submitted `not_vulnerable` on 22/24 and abstained on two. Its vulnerable S4 was 10/24.

## Intervention and inference limits

Only `v4_lab/prompts/types.txt` changes. The C prompt now first derives `verdict` from the actual HTTP result and before/after observations. It requires a null type for `not_vulnerable` and `insufficient_evidence`. Only a supported `vulnerable` verdict activates the earlier BOLA/BFLA classification rule. R prompt, base prompt, case truth, tools, gate, stage scorer and budgets remain exactly as in V4-R1. This is a new, post-reserved development amendment; it cannot repair or re-score V4-R1 retrospectively.

Run all four conditions on T05/T06/E05/E06 in a fresh directory (32 runs) for a pilot. Record per-arm vulnerable S1–S4, fixed explicit `not_vulnerable`, abstentions, false positives, run errors and gate rejections. Compare R1C1 with contemporaneous R1C0. The predeclared feasibility targets for R1C1 are at least 3/4 fixed cases explicitly correct and at least 3/4 vulnerable cases at S4, with all errors retained. These small development counts indicate feasibility only. If promising, new evaluation cases should include genuinely different business rules and preferably a third independent application; T07–T12/E07–E12 cannot be reused as an untouched holdout.

The installer runs tests only. It does not invoke Ollama or run a reserved model evaluation; the regression suite includes deterministic stub coverage of the reserved runner.
