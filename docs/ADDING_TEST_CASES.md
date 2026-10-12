# Turning a bad answer into a permanent test

When an analyst gets a bad answer, the goal is a test that fails today and passes once it's fixed,
so the same mistake can never come back unnoticed. Everything below runs on the Mac with stubs:
no model, OpenSearch or Wazuh is called.

## 1. Find the run

Every answer has a run record. On the backend host, from `backend/`:

```bash
node scripts/findRun.js --search "failed logons"
```
Lists the latest runs whose question contains the text, newest first, with their `request_id`.

```bash
node scripts/findRun.js --request-id <request_id>
```
Shows that run in full:
- the question, the planner source and the models used;
- each search, with its window and hit count, or the failure;
- **every statement verification removed, and why**;
- the answer as shown.

Both open the database read-only, so they're safe while the backend runs. The output contains the
question, the answer and the model's claims; handle it like the answers themselves.

## 2. Decide what went wrong

| What you see | Kind | Where the test goes |
|---|---|---|
| A wrong fact, or something not in the data, was **shown** | Verification missed it (should be impossible) | `backend/test/groundedReport.test.js` (or `aggregation.test.js` for counts) |
| The checker passed a bad answer, or failed a good one | Checker bug | a SYNTHETIC case in `backend/scripts/makeSyntheticEvalCases.js` |
| Honest but poor: missed the obvious outlier, vague next steps, wrong window stated | Quality | a SYNTHETIC case with a score limit, then measure fixes with the gate and `compare_models.py` |
| Searched the wrong thing, answered from chat instead of searching, asked a needless question, or reused old evidence for a new question | Routing or planning | the unit tests for that rule: `routing.test.js`, `clarify.test.js`, `followUp.test.js`, `aggregation.test.js` (severity floor) |
| Only reproducible with that day's real data | Needs a capture | a fixture on the host, then an invented copy of its shape (step 4) |

## 3. Write the test, and watch it fail

**Always write the test first and run it before changing any code.** A test that passes before the
fix tests nothing.

**Verification missed something.** Copy the evidence and the model's claim into a test. The claim
is in the run record's `grounding.rawOutput`, which `findRun.js` summarises. Use invented values with
the same shape, as `groundedReport.test.js` does with its `FABRICATED` list:
```js
{ marker: '10.9.9.9', claim: { text: 'Traffic also came from 10.9.9.9.', cite: [cite('rule', '5710')] } }
```
Assert the marker never appears in the response. Then fix `backend/src/agent/grounding.js`. If the
mistake is a kind a model could make again, also add it to `FABRICATIONS` in
`backend/scripts/evalSyntheticPipeline.js`, so the gate keeps trying it.

**Checker bug.** Add the answer, with the verdict it should get, to `ANSWERS` in
`backend/scripts/makeSyntheticEvalCases.js`:
```js
'my-new-case': { answer: '...', expect: { hard_fail: ['H5_ips_grounded'] } }
```
Then regenerate the cases and run the self-test:
```bash
cd backend && node scripts/makeSyntheticEvalCases.js
```
```bash
python3 evals/check.py evals/synthetic --expect
```
The new case shows `MISMATCH`. Fix `evals/check.py` until every case behaves, and update
`evals/STANDARD.md` if the rule itself changed.

**Quality.** Add a SYNTHETIC case that pins the standard, for example
`expect: { hard_fail: [], score_max: 40 }` for a vague answer. Improve the prompt or the evidence,
then show the improvement:
- on synthetic scenarios: `python3 evals/gate.py`;
- on real fixtures: `python3 evals/compare_models.py`, with an approved model.

**Routing or planning.** Add the question to the matching rule's test, with the expected route,
alongside the existing examples (for instance the list of clear questions in `clarify.test.js`).

## 4. When it only happens with real data

Real telemetry never goes into the repository. `fixtures/`, `baseline/` and `quarantine/` are
gitignored everywhere.

1. **Capture the question on the host** (see `docs/CAPTURE_RUNBOOK.md`, "Re-running one question"):
   ```powershell
   node scripts\captureFixtures.js --questions-file .\question.txt --out .\fixtures\case
   ```
2. **Replay it on the Mac** and score the answer:
   ```bash
   cd backend && node scripts/replayFixtures.js --dir fixtures/case --out ../baseline/case
   ```
   ```bash
   python3 evals/check.py baseline/case
   ```
3. **For a permanent test, rebuild its shape with invented data:** add a scenario to
   `backend/scripts/lib/evalScenarios.js` with the same rules, counts and structure, but made-up IPs,
   hosts and users. Never copy a real value.

## 5. Before merging

- [ ] The new test failed before the fix and passes after it.
- [ ] No existing test was weakened to make room for the fix.
- [ ] `cd backend && npm test`, `npm test` and `npm run gate` all pass.
- [ ] If scores went up, `python3 evals/gate.py --update` was run and the `evals/gate_baseline.json`
      diff is part of the change. A score may only go down with the reason written in
      `docs/MERGE_DECISIONS.md`.
- [ ] A new finding gets the next F-number in `docs/FINDINGS.md`, and a behaviour change gets an
      entry in `docs/MERGE_DECISIONS.md`.
- [ ] Nothing real was committed: no fixture, baseline record, `.env`, database or log output.
