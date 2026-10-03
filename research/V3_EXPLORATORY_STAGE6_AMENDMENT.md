# V3-E1: exploratory evaluation amendment

Date: 2026-09-29. This amendment is recorded **after** examining the T01/E01 development runs and **before** any V3 reserved-case Agent run.

## Why the original freeze failed

The original `v3_agent.freeze_dev` requires at least one submitted finding in each condition. In the complete `qwen3:8b` development run, baseline A submitted 0/4 and evidence-order B submitted 4/4. A's four failures (one `NO_CONCLUSION` and three repeated evidence rejections) are observable Agent outcomes, not model-service or lab setup failures. B's two vulnerable-case reports cited valid evidence, but used the wrong `vulnerability_type`; under the unchanged grader, their correct-detection count is 0/2. The original freeze remains failed. Its code and output are retained.

## Revised exploratory eligibility, fixed before reserved runs

Create a **separate** `exploratory_dev_lock.json` from the existing eight development records. Require: the exact eight planned keys; a current matching development manifest and source hashes; one consistent actual model digest matching the configured prefix; no model service, timeout or lab setup failure; and at least one actual API request in each condition. Keep **all** Agent failures, including zero submissions in a condition, in the result set. This changes only the feasibility gate for a new exploratory study. It does not alter prompts, model, tools, limits, evidence gate, grader, case truth or any past result.

## Reserved evaluation plan

Six independent pairs (`T02`–`T04`, `E02`–`E04`), each with fixed and vulnerable versions, two conditions (A/B), two repeats: **48 planned runs**. Run serially, alternating condition order by case/repeat. Each run receives a fresh database and has its own trace, finding or explicit failure, and grade. Commit each row immediately; resume skips completed **and failed** rows. An interrupted, uncommitted attempt stops automatic continuation for manual inspection. Preserve the development and reserved directories separately.

Report both conditions against all **24 planned runs per condition**, with six independent pairs as the unit of case diversity. Show vulnerability detection with correct type, false positives on fixed cases, valid evidence, paired correctness, classification errors, abstentions, Agent run errors, API request cost, and write-state contamination. Never convert a failure into a correct negative or exclude it from a denominator. Repeats do not create new independent cases. Analyze effects descriptively; the development-driven amendment makes this an **exploratory**, not a confirmatory, evaluation.

Do not change configuration after looking at reserved results. A setup failure should remain in the record; pause and report it rather than selectively rerunning. No earlier Qwen 4B results are combined with this configuration.
