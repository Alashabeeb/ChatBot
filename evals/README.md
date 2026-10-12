# Evals

Measures answer quality against [`STANDARD.md`](STANDARD.md). Nothing here calls a model, OpenSearch
or Wazuh.

| Path | What it is |
|---|---|
| `STANDARD.md` | What a good answer looks like: the hard checks and the 0–100 quality score |
| `check.py` | The checker. Python 3 standard library only |
| `synthetic/` | **SYNTHETIC** cases: invented telemetry plus hand-written answers that validate the checker. Generated, not edited by hand |
| `../baseline/` | Real captured answers replayed for scoring. Gitignored: real telemetry |

## Running it

Score the baseline (after a capture and `replayFixtures.js --out ../baseline`, see `docs/CAPTURE_RUNBOOK.md`):
```bash
python3 evals/check.py baseline --json baseline/scores.json
```
Check the checker:
```bash
python3 evals/check.py evals/synthetic --expect
```
`--strict` exits 1 when any hard check fails; Phase 8 uses it as the release gate.

The input is the capture fixture format (`backend/src/recording/capture.js`): the answer is
`result.report` and the evidence is the recorded OpenSearch and Wazuh responses in `calls`, plus
`result.tools` for tools that were unavailable.

## Synthetic cases

Every case is a capture of an invented scenario, made by running the real capture code with every
HTTP call stubbed, then paired with an answer and an `expect` block (the hard checks it must fail,
and optionally a score range or specific grades). Each file is named `SYNTHETIC-…`, carries
`"synthetic": true`, and lives here, never in `fixtures/`. Replay refuses to load one.

To add a case, for example when the checker misjudges a real answer:
1. Add the answer (and, if needed, a scenario) to `backend/scripts/makeSyntheticEvalCases.js`, with
   the `expect` block describing the correct verdict.
2. Regenerate: `cd backend && node scripts/makeSyntheticEvalCases.js`.
3. Run the self-test and watch the new case fail.
4. Fix `check.py` until every case passes, and update `STANDARD.md` if the rule changed.

`backend/test/evals.test.js` runs the self-test as part of `npm test`. It also regenerates the cases
and fails if the committed files differ, so they can't drift from the capture format.

## Known limits

The checker only flags what it can identify unambiguously, so passing a hard check means nothing
detectably wrong, not proven correct.

- **Rule IDs** are recognised only after the word "rule" or in a "Rule" table column. A bare number
  isn't treated as a rule ID.
- **Counts** are checked only when unambiguously tied to one rule. "6 of 14 alerts were rule 60122"
  is not checked.
- **Host names** are recognised by shape (`web-01`, `DC01`). A host named with an ordinary word
  (`mailserver`) isn't detected, so a fabricated one wouldn't be caught.
- **IP addresses:** IPv4 only.
- **Sampled evidence:** each search returns at most 200 hits with an exact total. When the total is
  larger, a rule's true count is only known to lie between its count in the sample and the search
  total, so counts are checked against that range.
- **Recommendations** are found only under a recognisable heading or label (`Next steps`,
  `Recommendations`, …). Advice buried in prose isn't graded.
- **Paraphrased fabrications:** `H7` catches the known mock-tool outputs and a few paraphrases, not
  every possible wording.
- **Source names:** the sources criterion looks for the words "alerts", "firewall", "agent",
  "threat intel" and "process". An answer that names a source differently gets no credit for it.
