# Working together

How changes get from an idea to production without surprises.

## One repository

- **The only copy is `github.com/Alashabeeb/ChatBot`** (private). On the Mac it's
  `/Users/solomonalor/Documents/ChatBot`.
- **The old `ChatBot-main` folder is retired.** Its work was merged into `main` on 2026-10-07; don't
  edit it or copy from it.
- **Production pulls `main`.** Whatever is on `main` is what the Windows host deploys next
  (`docs/DEPLOY.md`).

## Every session

1. **Pull before you start:** `git pull` on `main`, then branch from it.
2. **Read `docs/STATUS.md`** to see where things stand and what is waiting on whom.
3. **Update `docs/STATUS.md` before you finish:** what changed, what's next, what's blocked. Even when
   the session produced no code, if something was decided or learned.

## Branches for work, `main` for production

- **Each piece of work gets a branch:** `fix/<topic>`, `feat/<topic>` or `docs/<topic>`.
- **Merge into `main` through a pull request,** once the release gate is green.
- **Nobody pushes work-in-progress to `main`,** because production pulls it.
- **Exception:** the October 2026 consolidation (Phases 0 to 8) was done directly on `main` at the
  owner's explicit request. From now on, use branches.

## Tests before merge

The **release gate** (`.github/workflows/release-gate.yml`) runs on every push and pull request to
`main`:
- backend tests;
- frontend tests;
- the frontend build;
- `evals/gate.py`, which fails if any fabricated claim reaches an answer or any answer-quality score
  drops below `evals/gate_baseline.json`.

Run the same locally with `npm run release`, which runs the tests, the gate and the build.

Rules that come with it:
- **Write the test first and watch it fail** (`docs/ADDING_TEST_CASES.md`).
- **For anything security-critical, also break the code on purpose** and check that a test catches it.
- **Never weaken a test to make a change pass.** If a test's expectation must change, say why in the
  pull request and in `docs/MERGE_DECISIONS.md`.
- **Scores only go up through `python3 evals/gate.py --update`,** with the baseline diff in the pull
  request.

## Data and secrets

- **Never commit real telemetry or credentials:** fixtures, baseline records, quarantine files, `.env`,
  databases or logs. The `.gitignore` covers the usual names; a test fails if a source directory is
  named `fixtures`, `quarantine` or `baseline`.
- **Tests never call the live model, OpenSearch or Wazuh.** They use stubs and local stand-in servers;
  replays use captured fixtures.
- **A model endpoint is only called once someone has approved it,** by name, in `evals/models.json`
  (`approved_by`). Keys live in the environment, never in files.

## Keeping the record

| File | Keep current when |
|---|---|
| `docs/STATUS.md` | every session |
| `docs/FINDINGS.md` | a problem is found (next F-number) or fixed (mark it with the commit) |
| `docs/MERGE_DECISIONS.md` | a judgement call is made; mark the ones the owner should review with ⚠ |
| `docs/DEPLOY.md` | anything changes how production is deployed or configured |
| `evals/STANDARD.md` | the definition of a good answer changes |
