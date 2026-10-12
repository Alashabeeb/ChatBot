# Status

**Updated:** 2026-10-12, end of the October consolidation plan (Phases 0–8).
**Update this file every session** (`docs/WORKING_TOGETHER.md`).

## Where things stand

| | |
|---|---|
| **Production** (Windows host) | `c0e2010` ("Push 26"). None of the work below is deployed yet. |
| **`main`** | Phases 0–8 complete. All tests and the release gate pass. |
| **Baseline capture** | **Not done yet.** Waiting on the Windows trip (bundle built from `b346a38`). |
| **Model comparison** | Tooling ready; **no endpoint approved yet**. |
| **CI** | Workflow added (`.github/workflows/release-gate.yml`); **its first run happens on the next push**. |

**Tests on `main`:** backend 171, frontend 17, checker self-test 33/33. The release gate passes against
`evals/gate_baseline.json`.

## What each phase delivered

| Phase | What | Key commits |
|---|---|---|
| 0 | Hotfix: fabricating tools unregistered; read-only audit | `8fef3d9`, `13f741d` |
| 1 | `ChatBot-main` hardening merged into `main`; ChatGPT-style chat with streaming | `ea2299f`, `dd1603c` |
| 2 | Every known defect closed: honest action tools, model timeouts, DB-backed auth, forced admin password change, strong JWT secret, no fake status | `afec39c` … `3707ce3` |
| 3 | Measurement: `evals/STANDARD.md`, `evals/check.py`, synthetic cases, baseline replay, capture bundle | `266b952` … `d7ec1f4` |
| 4 | Grounded answers: every claim cited and verified in code; sources and window in every answer | `bdd5a5e`, `294138f` |
| 5 | Exact counts by aggregation, week-on-week comparison, severity floor for "right now", stage timings | `6a92cbc`, `3993137` |
| 6 | Planner and report models configurable separately; `evals/compare_models.py` | `7e5413d`, `e2aa177` |
| 7 | Streamed search answers (verified text only), follow-ups on previous evidence, one clarifying question | `9f53a74`, `c7e0cab` |
| 8 | Release gate (CI and `npm run gate`), `findRun.js`, these docs | see `git log` |

Details: `docs/MERGE_DECISIONS.md` (decisions per phase) and `docs/FINDINGS.md` (every finding, fixed or open).

## Waiting on

| # | What | Who | How |
|---|---|---|---|
| 1 | Windows capture of the four questions | Owner | `docs/CAPTURE_RUNBOOK.md`, using the bundle from `b346a38` |
| 2 | Baseline replay and score per question | Claude, once the fixtures are back | `replayFixtures.js --out ../baseline`, then `check.py baseline` |
| 3 | An approved model endpoint, to test whether the production model follows the cited-claims format (G11) and to compare models | Owner | `evals/models.json` with `approved_by`, then `compare_models.py` |
| 4 | Deploying `main` | Abdulhakeem | `docs/DEPLOY.md`: database backup, `JWT_SECRET`, `npm ci` in both folders, smoke tests 0–9 |
| 5 | First CI run, and deciding whether `npm run build` should also run the gate | Owner | push `main`, check the Actions tab |

## Decisions waiting for review (⚠ in MERGE_DECISIONS)

- **P4:** model time limits (planner 45 s, report 120 s, memory 45 s, conversation 60 s).
- **P9:** password policy (12+ characters, not containing the username, 6+ distinct characters).
- **P10:** a weak `JWT_SECRET` now stops the backend starting.
- **P14:** `npm audit fix` also updated `axios` and `proxy-addr`.
- **M9:** checker score weights.
- **G11:** cited-claims format not yet tried on the production model.
- **A6:** severity floor level 7 and its trigger phrases.
- **A8 / F-64:** aggregations assume the standard Wazuh field mapping.
- **C4 / C6:** when a follow-up reuses evidence, and when to ask a clarifying question.
- **E1 / E2:** the gate runs in CI and `npm run release`, not in `npm run build`; CI uses Node 22, not the Mac's Node 26.

## Open findings worth acting on next

- **Security:**
  - F-55: a password change doesn't sign out other sessions.
  - F-56: admin-created users aren't forced to change their initial password.
  - F-57: no login rate limit.
  - F-10: plain HTTP between browser and backend.
  - F-09: wide-open server settings.
- **Operations:**
  - F-26: no retention for run records.
  - F-50: no limit on concurrent model streams.
  - F-61: re-running one capture question replaces the manifest.
- **Product:**
  - F-21b: provenance (the footer) is not shown in the UI.
  - F-49: no regenerate or edit.
  - F-51: answer flags aren't saved.
  - F-58: there's no way to grant an approval, so blocking stays impossible.
- **Housekeeping:**
  - F-18: stale README.
  - F-52: 885 kB bundle.
  - F-53 / F-60: frontend audit (build-time only).
  - F-59: leftover CSS.

## Health check

```bash
cd backend && npm test
```
```bash
npm test && npm run gate
```
```bash
cd backend && node scripts/findRun.js --search "<words from a question>"
```
