# Merge Decisions

Every judgement call made while bringing Solomon's hardening work (Sep 16–18, done outside this repository and imported once on 2026-10-07) together with Abdulhakeem's Push 25/26 (Sep 22). **This repository on `main` is the only working copy; the folder the earlier work came from is not part of the project.** The plan's own instructions are not repeated here; this file records what the plan left open, and why each choice was made. Items marked **⚠ Review** are the ones most worth a second opinion.

---

## Phase 0: Hotfix on `main` (`8fef3d9`, `13f741d`)

| # | Decision | Why |
|---|---|---|
| 0.1 | Unregister the two tools only. The tool files and the now-unreachable references to them in `runtime.js` stay until Phase 2. | Smallest possible production change. Phase 2.1 replaces them properly. |
| 0.2 | The hotfix commit includes test infrastructure (`backend/test/`, `npm test`). | `main` had no tests, and the ground rules require a test for every fix. |
| 0.3 | `toolRegistry.test.js` imports a temporary copy of `src/`. | On `main`, importing `runtime.js` opens `backend/data/soc_chatbot.db` at a fixed path; a copy keeps tests from creating a database in the repo. Still valid after the merge; left as is. |
| 0.4 | The audit searches `messages.text`, `summary` and `raw_logs`, and (after review) `memories.content` in a second commit. | All text columns that can carry a report; memories because they're fed back to the planner. |
| 0.5 | `"blocklist"` is a search term even though it also matches legitimate advice. | Requested. The output warns that those matches need reading by hand; the other three signatures are definite. |
| 0.6 | Deploy backup is a plain file copy with the backend stopped. | `backupDb.js` isn't on `main`, and the backend has to be stopped to deploy anyway. |
| 0.7 | Smoke-test questions contain no IP address. | The threat-intel mock is still live on `main`; an IP in the question would create new contaminated messages. |
| 0.8 | The memories audit is a separate commit, not an amended `8fef3d9`. | `8fef3d9` may already have been pushed; amending would rewrite published history. |

---

## Phase 1: Merge onto `merge-hardening`

### Method

| # | Decision | Why |
|---|---|---|
| 1.1 | The work was imported as a real commit (`7519cf0`, branch `import/chatbot-main`) on top of `72e249e`, the commit `ChatBot-main` was downloaded from, and then merged with `git merge --no-ff`. | Git then applies the 18 files only one side changed without manual copying, and marks exactly the files both sides changed. History shows where each line came from. 70 of the 96 base files were verified byte-identical in `ChatBot-main`, confirming `72e249e` as the base. |
| 1.2 | `backend/package-lock.json` was not imported. | The only difference was one npm metadata line (`"hasInstallScript": true`) added by an install. No dependency changed. |
| 1.3 | Before merging, the import branch alone was tested: 38/38 pass. | Proves the import is faithful, so any later failure comes from the merge. |

### The conflicted files

| File | Resolution |
|---|---|
| `backend/package.json` | Ours: a superset of the hotfix's `test` script plus the capture/replay/report/backup scripts. |
| `backend/src/llm/foundation.js` | His `options` argument (`maxTokens`, `timeout`) and request body, using our `MODEL_NAME` constant. In the error handler, **his wording** ("request failed") over ours ("Falling back to rule-based logic", which wasn't true on every path), with our request-ID tagging and `recordRunError`. The timeout default stays `0`; Phase 2.2 wires real timeouts. |
| `backend/src/controllers/chat.controller.js` | Our history sanitizer and request-ID logging. **His** status code (`error.statusCode \|\| 500`) and `{ type: 'error', error }` body, because his frontend error handling reads `data.error`. Plus our `request_id`. |
| `backend/src/services/chat.service.js` | **⚠ Review.** His conversational path (model-backed, not canned) and empty-message handling are kept. **The routing condition is changed**: his rule sent every message without a security keyword to the chat-only path, which sent all four capture questions there (F-43). Now only clearly conversational messages go there, using `isConversational()` (greeting or chat phrase, and no security keyword); everything else goes to the runtime. His 503 on model failure stays until Phase 2.3. |
| `backend/src/integrations/opensearch.integration.js` | Both return fields: his `sourceScope` and our `query`. His `size: 200`, firewall signals and `sourceScope` param; our replay hook. |
| `backend/src/llm/prompts.js` | His rewritten reasoning prompt as the base, our "unavailableSources" rule inserted as rule 3, his rules renumbered 4–8. **⚠ Review:** his rule 6 is reworded from "without identifying it as **malicious**" to "**unless the evidence shows it is hostile**". The F-00 regression test treats the word "malicious" anywhere in a model message as leaked mock data; rewording the rule keeps that test strict instead of loosening it. The meaning is the same. |
| `src/pages/ChatPage.jsx` | Only a blank-line conflict: both sides removed the same selector block. Both sides' other changes auto-merged and were verified: his welcome text and error handling, our `flattenRawLogs` and `requestId`. |
| `backend/src/agent/runtime.js` | Started from ours (run scope, run records, attribution, threat-intel handling, keyed `raw_logs`, replay provenance), then his changes re-applied one by one. See below. |
| `src/pages/ChatPage.css` | No conflict: both removed the same rules. |

### `runtime.js` in detail

| # | His change | How it was kept |
|---|---|---|
| R1 | Firewall fan-out | Kept, as a separate `executionPlan`, so `run.planner.tools` still records exactly what the model planned and `run.tools` records what ran. `summary.toolsExecuted` counts executed calls. |
| R2 | Joined source labels, `sourceTotals`, `summary.totalMatches` | Kept as written. This also replaces our URL-based `source`, which removes the `undefined/agents` header in replay mode (F-41). |
| R3 | Evidence keyed `firewallLogs` / `searchSecurityLogs`, with `sampleSize` | Kept as written. A second planned search still overwrites the first in the evidence (F-29), due in Phase 2.4. |
| R4 | Concatenated `rawLogsToReturn` | Replaced by our per-invocation keys, extended with a `:firewall` suffix (`searchSecurityLogs`, `searchSecurityLogs:firewall`, `searchSecurityLogs#2`, …). **⚠ Review:** empty result sets are no longer listed as empty arrays; their counts remain in the run record. This keeps "View Full Details" free of empty groups now that every search has two halves. |
| R5 | `blockIpAction` / `checkProcessList` registration and evidence handling | Dropped (unregistered by the hotfix). |
| R6 | His zero-results wording ("I searched the database and intelligence sources…") | Ours kept. His version claims intelligence sources were searched, which F-00 removed. |

### Test changes needed by the merge

The fan-out turns each planned search into two OpenSearch calls. Five existing tests assumed one. **No assertion was removed or loosened.**

| # | Change | Why it's not a weakening |
|---|---|---|
| T1 | The OpenSearch stub in `test/helpers.js` is now scope-aware: the firewall-scoped query returns `firewallLogs` (default none), the other returns `logs`. | The real queries are mutually exclusive (`must` vs `must_not` on the same clause). The old stub returned the same records to both halves, which can't happen. |
| T2 | `runRecord`, `fixtures`, `chatRequest` and `multiToolRawLogs` expect two calls per planned search. | Each now asserts **both** halves: each recorded query equals exactly one sent body, with the scope in its parameters. That is stricter than the original single-call check. |

### Tests added in Phase 1

| File | What it pins |
|---|---|
| `test/routing.test.js` (5) | The four capture questions and other keyword-less security questions go to the runtime; greetings go to conversation; a greeting makes no run and no search; model down on the conversational path gives the kept 503 error shape. |
| `test/firewallFanout.test.js` (1) | One firewall and one non-firewall query per search; both results kept and labelled; totals summed once; `sourceTotals`, `firewallLogs` evidence; planned vs executed tools recorded separately. |
| `test/startupConfig.test.js` (+1) | F-44: no JWT fallback value for any importer, and the old literal appears nowhere in `src/`. |

### Mutation checks run on the merged code

| Mutation | Result |
|---|---|
| Routing reverted to keyword-only | Caught (2 tests) |
| Fan-out removed | Caught (1) |
| History sanitizer bypassed in the controller (F-06) | Caught (1) |
| Threat-intel mock restored (F-00) | Caught (3) |
| Fallback report credited to the model (F-01) | Caught (2) |
| `blockIpAction` re-registered (hotfix) | Caught (2) |
| JWT fallback restored (F-08a) | **Missed at first** → F-44 test added → now caught |

### Assistant chat (branch `assistant-chat`, requested before Phase 2)

The request: *"talk to the LLM directly from the frontend … like ChatGPT, Gemini … able to do our day to day task"*, with latitude to decide the details.

| # | Decision | Why |
|---|---|---|
| A1 | **The browser talks to the backend, which talks to the model.** It does not call the model directly. | The model endpoint has no authentication, and every safeguard (login, history sanitizer, honest prompt, timeouts, run records) lives in the backend. This is how ChatGPT and the others work too. |
| A2 | **Two explicit modes:** Chat (default) and a **Search Wazuh** toggle, instead of guessing per message. | An 8B model can't reliably decide when to search, and F-43 showed what happens when routing guesses wrong: security questions answered with no data. An explicit toggle is predictable and honest. In Chat mode, likely data questions get a one-click "Search Wazuh for this". **⚠ Review:** the default could be Search Wazuh instead if analysts mostly ask about data. |
| A3 | **The toggle is remembered per browser** (`localStorage`), not per account. | Simple, and a per-device habit. Easy to move server-side later. |
| A4 | **New endpoint `POST /api/chat/stream`** (server-sent events); `/api/chat` is untouched. | The investigation pipeline and its fixture replay stay exactly as they were; chat gets streaming without changing them. |
| A5 | **Streaming uses Node's `fetch`, not axios.** | Native streaming with `AbortSignal`, which makes Stop cancel the model request. Consequence: fixture replay (`FIXTURES=1`) doesn't cover Chat mode. It isn't meant to; replay is for Search Wazuh. |
| A6 | **Defaults:** max tokens 1024, temperature 0.5, first-token timeout 60 s, idle timeout 30 s, history budget 24,000 characters. | Middle-of-the-road values for an 8B model on shared hardware. All configurable (`docs/ASSISTANT_CHAT.md`). **⚠ Review** once real latency is known. |
| A7 | **Markdown via `react-markdown` + `remark-gfm`**, with images disallowed and raw HTML off. | Needed for code, lists and tables. Both are widely used and safe by default; the image block stops model output from making the browser fetch arbitrary URLs. |
| A8 | **The welcome message was rewritten.** Phase 1 kept Abdulhakeem's text, but it described a data-only bot. | The product changed: it now explains both modes. |
| A9 | **Error notices aren't saved as messages.** | Saved, they'd return as assistant history the model never wrote. The run record still has the error. |
| A10 | **History sent to the model excludes the welcome text, errors and unfinished answers** (both modes). | Same reason as A9. This also fixes the welcome message being sent as history on every Search Wazuh request before. |
| A11 | **The fake typewriter and rotating status text are gone.** "Thinking…" until the first real token; "Searching Wazuh and firewall data…" during a search. | They simulated activity that wasn't happening. Part of Phase 2.14 done early; the login page's fake terminal feed is still there. |
| A12 | **The fake model used for the UI check lives only in the session scratchpad.** It isn't committed. | After `blockIpAction`, no new fake-data generators go into the codebase. Tests use their own in-test fake server. |
| A13 | **Quick queries use the current mode.** | They're user-defined prompts; in Chat mode a data query gets the Search Wazuh button. **⚠ Review:** they could always search instead. |

### Working on `main` only (2026-10-07)

| # | Decision | Why |
|---|---|---|
| W1 | **All work happens on `main`.** `merge-hardening` and `assistant-chat` were fast-forwarded into it (no merge commit; `main` was their ancestor) and the extra branches retired. | Requested. One branch, one source of truth. |
| W2 | **Production deploys from `main`, which now carries every change, not just the hotfix.** `docs/DEPLOY.md` replaces the hotfix-only instructions. | Pulling `main` now migrates the database, requires `JWT_SECRET` and adds frontend packages. The old hotfix doc would have caused an outage. |
| W3 | **Past commit messages that mention the old folder are left as they are.** | They're already on GitHub; rewriting pushed history would break every other clone. |

---

## Phase 2: Close every known defect (2026-10-07)

Commits: `afec39c` (2.1), `4dc3b9e` (2.2, 2.3, 2.6, 2.10), `0d862e2` (2.4, 2.5), `ecdbc8a` (2.7, 2.8, 2.9), `da2dcae` (2.11, 2.12), `47fcda9` (2.13, 2.14), `4784306` (2.15), then the docs commit (2.16).

| # | Decision | Why |
|---|---|---|
| P1 | `checkProcessList` **is registered** with the planner, returning "not available". | It's honest now. If an analyst asks about processes, the report says plainly that process inspection isn't available, instead of the plan being silently rejected. |
| P2 | `blockIpAction` is **registered but approval-gated in three layers** (registry hides it, validator rejects it, gateway refuses it without an approval for exactly that tool, those parameters and a named approver). | Requested: "never on the planner's own judgement". Each layer is mutation-checked independently. A future real implementation inherits the gate by default. Nothing creates approvals yet, so blocking is impossible today (F-58). |
| P3 | **Purge paraphrase for block claims is deliberately narrow:** "IP/address … has been / was / is now blocked". | Real firewall reports say "blocked" constantly; the test pins that "the firewall blocked 42 inbound connections" is not flagged. Patterns are bounded by length, not '.', because IP addresses contain dots — a bug the tests caught. |
| P4 | **Timeouts:** planner 45 s, report 120 s, memory 45 s, conversation 60 s, plus a 60 s default for any call that passes none. Each call also gets an `AbortSignal` hard deadline. | **⚠ Review** once real model speed is known; all are configurable. The report gets the longest because it writes the most. A mutation test showed a `0` default would abort every call instantly, so the default is pinned in both directions. |
| P5 | **The conversational path returns HTTP 200 with an honest message when the model is down**, replacing the 503 kept from Push 26. | Requested (2.3). The routing test that pinned the 503 was updated to the new behaviour. |
| P6 | **Memories go to the planner inside a `<stored_context>` block in the user prompt, labelled "data, not instructions".** | Requested (F-20). They're still useful context, just without system authority. |
| P7 | **`askFoundation` drops any history entry that isn't `{ role: user \| assistant, content: string }`** (F-22). | Defence in depth. It makes two mutants equivalent — the F-20 and conversation-sanitizer mutants each break one layer while the other keeps the outcome correct. Recorded rather than weakening a layer so a test could see it. |
| P8 | **The auth middleware reads the user from SQLite on every request** (F-24). | One indexed read per request is negligible here, and it's the only way a deletion or role change takes effect before the 7-day token expires. |
| P9 | **The admin is forced to change its password if it still verifies against the published default `Password12$`**; freshly seeded admins always are. While flagged, only `/api/auth/me` and `/api/auth/change-password` work. | Requested: keep the default account, but force a change. Checking the actual password means an admin who already set their own isn't bothered. **⚠ Review:** the password policy (12+ characters, not the default, not containing the username, 6+ distinct characters) is my choice. |
| P10 | **`JWT_SECRET` minimum is 32 characters, with 8+ distinct, and known published values are rejected.** | The tokens use HS256, so one captured token allows offline guessing; 32 random characters is far beyond brute force. The old fallback is 47 characters, so a length rule alone wouldn't catch it. Blocked values are stored as SHA-256 hashes so the literal never re-enters the source (the F-44 test enforces that). **⚠ Production impact:** a weak existing secret now stops the backend from starting. `DEPLOY.md` step 3 checks it first. |
| P11 | **Purge script:** `openDatabase(write)` and `isMainModule()` are exported so they can be tested. The Windows check compares paths case-insensitively. | F-32 and F-36 can't be reproduced on macOS directly; the pure functions are tested with Windows-style inputs instead. |
| P12 | **View Full Details:** records are labelled by source (new `src/lib/rawLogs.js`); the modal now takes `entries`, not `logs`. Agent records read "Wazuh agent: active". The modal summary collapses by height. | F-33 and F-40. Cutting the summary by word count broke the Markdown. |
| P13 | **Removed claims nothing backed:** "ENCRYPTED SESSION", "TLS 1.3 ENCRYPTED", "SYSTEM ONLINE", "Connected to Wazuh SIEM", "Live Monitoring Active" and "v2.0.0". **Kept** "Verifying SOC Credentials…", which is true at that moment. A guard test fails if any of these claims returns. | Requested (2.14: "never simulate activity"). The app talks to the backend over plain HTTP (F-10), so the encryption claims were false; nothing checked "online" status. |
| P14 | **⚠ `npm audit fix` updated `axios` (high) and `proxy-addr` (critical) as well as the named `qs` / `express` / `body-parser`.** | The same non-breaking command fixes all five, all within declared ranges. Leaving a critical and a high open seemed wrong. If you wanted only the three, it's one commit (`4784306`) to revisit. |
| P15 | **The F-31 single-process rule is documented with a check** in `DEPLOY.md` and the runbook; behaviour is unchanged. | Requested (2.16). A real fix (a lock or heartbeat) would be a design change. |

**Tests changed in Phase 2** (none loosened):
- `toolRegistry` now describes the new rule (checkProcessList offered, blockIpAction never).
- The routing 503 test now expects the requested 200 fallback.
- `multiToolRawLogs` expects 3 OpenSearch calls (its CVE search is no longer split).
- `assistantStream` and `serverRestart` start past the admin's first login and use 32+ character secrets.
- The stream test's read loop can no longer spin forever.

### Left for later phases on purpose

- ~~**The conversational path still returns HTTP 503 when the model is down**~~ — fixed in Phase 2.3.
- ~~**`docs/PIPELINE_MAP.md` and `docs/CAPTURE_RUNBOOK.md` predate the consolidation** (F-47)~~ — runbook rebuilt in Phase 3; the map's F-14 figure corrected. The map is otherwise a September snapshot and is marked as such.
- **The local branch `import/chatbot-main` is kept.** Its commit is a parent of the merge either way; you can delete the branch name before pushing if you don't want it on the remote.

## Phase 3: The measurement harness (2026-10-12)

| # | Decision | Why |
|---|---|---|
| M1 | **`check.py` reads the capture fixture format directly.** The answer is `result.report`; the evidence is the recorded OpenSearch and Wazuh responses in `calls`, plus `result.tools` for unavailable tools. | No conversion step that could drift. A capture from Windows, a replay record and a synthetic case are the same shape. |
| M2 | **The baseline scores the answer production gave at capture**, not an answer produced during replay. Replay re-runs the pipeline to prove today's code rebuilds the same queries and gets the same evidence, and records that verdict beside the captured answer. | Replay can't call the model (ground rule), so a replayed answer would only be the "model unavailable" notice. The captured answer is the real production behaviour being measured. Later phases change the answer, so scoring them will need a model endpoint you approve (Phase 6). |
| M3 | **Replay disables the model by default**, even if `backend/.env` points at the live one: it sets `LLM_API_URL` to an unreachable `.invalid` address before `.env` loads. `--allow-model` opts in. | Found while building this: `dotenv` loads `.env` from the working directory, so on the Windows host a "replay" would quietly have called the live model. A test runs a real local model server and asserts it gets zero requests; mutation-checked. |
| M4 | **Synthetic cases are generated by the real capture code** with every HTTP call stubbed in-process (`backend/scripts/makeSyntheticEvalCases.js`), committed under `evals/synthetic/`, and checked by a test that regenerates them and fails on any difference. | They have exactly the shape a real capture has, and can't drift from it. They add 1.7 MB (29 cases, mostly the recorded prompts). |
| M5 | **Synthetic cases can't become fixtures or baselines:** each is named `SYNTHETIC-…` and marked `"synthetic": true`, replay refuses to load one (mutation-checked), and `baseline/` is gitignored like `fixtures/`. A guard test now also forbids a source directory named `baseline`. | Requested: "marked SYNTHETIC, kept out of fixtures/". `baseline/` holds real telemetry and production answers. |
| M6 | **The checker is conservative.** It only flags rule IDs, counts, hosts and IPs it can identify unambiguously; anything ambiguous goes unchecked. Known gaps are in `evals/README.md`. | A false fabrication alarm would make the release gate (Phase 8) untrustworthy. Missing an ambiguous case is the lesser harm, and every missed case found later becomes a synthetic case. |
| M7 | **Counts against sampled evidence are bounded, not exact.** Each search returns at most 200 hits with an exact total, so a rule's true count is known only to lie between its count in the sample and the search total. | Exact matching would flag correct answers as fabricated whenever more than 200 events matched. |
| M8 | **Scoring:** a criterion that can't apply is dropped and the rest rescaled (no hits → no rule, outlier or recommendation criteria). No recommendations → that criterion is dropped rather than awarded. An empty answer scores 0. | Otherwise an honest "nothing found" answer couldn't reach 100, and an answer could earn the recommendations points by giving none. |
| M9 | **⚠ Review the weights:** time window 10, rule IDs with counts 20, outlier 15, MITRE 10, recommendations 20, sources 15, evidence honesty 10. | They are my judgement of the standard's emphasis. Changing them later changes every score, so it's better settled before the baseline. |
| M10 | **Answers the system writes itself are scored too.** With zero hits the runtime writes the answer without the model (`model_generated=false`); that is production behaviour, so it's scored. For questions with hits, the runbook asks for a re-capture if `model_generated=false`. | The baseline should measure what analysts actually see. |
| M11 | **The checker runs inside `npm test`** (`backend/test/evals.test.js`); that one test is skipped if Python isn't installed. | Keeps the checker green with every change, without making Python a requirement on the Windows host, which never runs it. |
| M12 | **The capture bundle includes `makeSyntheticEvalCases.js`** (it's under `scripts/`). | Harmless (it only writes invented data, and only to `../evals/synthetic`), and keeping the bundle recipe unchanged avoids a new step on the trip. |
| M13 | **Replay's verdict compares failed searches by count, successful ones query by query.** | Found in the bundle smoke test: a search that failed at capture made replay report `DIVERGED` although it had rebuilt the exact query (a recorded failure is only served for an exact match; anything else is a fixture miss and still flagged). A real capture with one failed firewall search would have hit this. Test-first and mutation-checked; the count comparison itself is defence in depth. |

**Mutation checks on the checker:** each of the ten hard checks, forced to always pass, makes the self-test fail; so do collapsing the sampled-count bounds, ignoring scoped "no alerts on X" phrasing, ignoring the time-window tolerance, constant recommendation and rule-count grades, not treating a failed firewall search as unavailable, and both parts of the labelled-bullet reader. Two mutants initially survived (an empty answer, a rule named without a count); synthetic cases were added for both.

**Also corrected:** F-14 said 10,000 hits per search. The code has returned 200 (plus the exact total) since `c0e2010`, which is already in production.

## Phase 4: Grounded answers (2026-10-12)

Started before the Windows capture, at your request, so there is no real baseline to compare against yet (see "Checker run" below).

| # | Decision | Why |
|---|---|---|
| G1 | **The report model returns JSON:** `answer`, `findings`, `assessment`, `next_steps`, each a list of `{text, cite: [...]}`, plus `insufficient_evidence`. A citation is a rule ID, agent, IP, user, MITRE technique, CVE, a search total, a past investigation, or a field path in the evidence. | Requested (4.1). Statements are short and individually checkable, so one bad statement can be removed without losing the rest. |
| G2 | **Every claim is verified in code** (`backend/src/agent/grounding.js`) and dropped if any citation fails to resolve, a cited count is outside what the evidence supports, its text names an IP, rule, technique, CVE or host not in the evidence, it contains a number no citation backs, or it gives a score or claims an action. | Requested (4.2, 4.3, 4.6). Checking the text as well as the citations matters: a model can cite something real while writing something invented. Each rule is mutation-checked on its own (22 mutants, all killed). |
| G3 | **Dropped claims are logged in the run record** (new column `runs.grounding_json`, with the reason for each) and as `[Grounding]` warnings, **never sent to the client**. The client gets counts only, and the footer says "N unsupported statements removed". | "Dropped and logged, never shown". The text stays out of the browser payload too, not just out of the display. **Database migration** on first start. |
| G4 | **The code writes the opening lines:** sources searched with their totals and time window, then anything not available and why. | Requested (4.4), and it can't be left to the model. It also fixes F-62: a failed search is now named as failed, never shown as "0 records". |
| G5 | **When the model's output isn't the required JSON, or no claim survives,** nothing it wrote is shown. The analyst gets the header and a code-written count of what was retrieved (top rules, agents and source IPs), marked "couldn't be verified". `model_generated` is false. | Unverifiable text is exactly what this phase exists to stop. The counts are still useful, and computed rather than generated. |
| G6 | **`insufficient_evidence: true` produces "Not enough evidence"** plus the code-written counts; any claims sent alongside it are ignored. Zero hits and all-searches-failed never call the model and get plain code-written answers. | Requested (4.5): never a guess. |
| G7 | **The evidence the model sees changed shape:** a list of searches, each with a `key`, `totalMatches` and samples now carrying `ruleId` and `mitre`; `counts.byRule/byAgent/bySourceIp` (from the up-to-200 records returned, with `{atLeast, atMost}` when sampled); `mitreTechniques`; agents; past investigations. | The model can only cite what it's shown. The counts are computed in code from the records returned; Phase 5 replaces them with real aggregations. |
| G8 | **Claims citing only past investigations are labelled** "(from a past investigation)". | They're memory, not current telemetry, and the analyst should be able to tell. |
| G9 | **Numbers inside a rule description quoted verbatim from the evidence don't need a citation** ("…web server 400 error codes…"). | Found by the pipeline evaluation: otherwise a correct statement quoting the rule's own name was dropped. Test-first. |
| G10 | **⚠ With sampled evidence, a count within the possible range is accepted** even if wrong: with 1,500 matches and 200 returned, "rule 5710 fired 53 times" can't be refuted when the sample shows 3 (F-63). | Exact counts need aggregation over all matches, which is Phase 5. |
| G11 | **⚠ Not tried with the production model.** The prompt contains a worked example, and the parser tolerates code fences and text around the JSON, but whether an 8B model follows the contract reliably is unknown. | Ground rule: no live model calls. If it doesn't follow the format, every answer becomes the code-written summary; safe, but much less useful. To check before deploying: replay the captured fixtures with `--allow-model` against an endpoint you approve, or wait for Phase 6. |
| G12 | **Not checked in code:** numbers written as words ("twelve"), and host names that are ordinary words. | Same limits as the checker (`evals/README.md`); the number rule covers digits, which is how counts are written in practice. |

**Checker run (synthetic, no baseline yet).** `backend/scripts/evalSyntheticPipeline.js` runs the four invented scenarios through the real pipeline with a stub model, then scores the reports with `evals/check.py`. It also runs inside `npm test`, which fails if any fabrication reaches the analyst.

| Model output | Mean score | Failing a hard check | Fabrications reaching the analyst |
|---|---|---|---|
| Faithful claims, through Phase 4 | 100.0 | 0 / 4 | 0 |
| Same claims plus 8 fabrications each, through Phase 4 | 100.0 | 0 / 4 | 0 |
| The adversarial output shown verbatim, as before Phase 4 | 76.6 | 3 / 4 | 17 |

These are synthetic: a stub model that follows the format perfectly scores 100, which shows the plumbing and the safeguards work, not that a real model will. One of the eight fabrications survives in the sampled scenario (an inflated count inside the possible range, G10); it isn't one the checker can see either. The real comparison needs the captured baseline and a model endpoint you approve: replay with `--allow-model`, then `python3 evals/check.py`.

**Checker changes this phase:** a count is now read up to about 110 characters after the rule ID, so a long rule description in parentheses no longer hides it (two synthetic cases added first, which failed).

**Tests changed in Phase 4** (behaviour change requested, none loosened):
- The stub report in `attribution` and `runRecord` is now a cited JSON claim.
- Tests that inspected the old evidence shape (`evidenceKeys`, `firewallFanout`, `actionTools`, `threatIntel`) read the new one and keep their guarantees.
- The hung-model test now gives the search a working stub, so the report stage is still reached and still times out; before, the search failure masked it.
- The threat-intel guard caught the words "threat scores" in the new prompt; the prompt was reworded, the guard kept.

## Phase 5: Better evidence, faster (2026-10-12)

| # | Decision | Why |
|---|---|---|
| A1 | **Aggregations go in a separate size-0 request per search**, not into the record search. One request covers this window and the same window a week earlier (two `filter` aggregations over `terms` by rule, agent, source IP, level and technique). | The record search stays byte-identical, so fixtures captured before Phase 5, including the baseline you're about to capture, still replay; they simply have no aggregation, and the answer says its counts are from the records retrieved. One request instead of two halves the extra load. |
| A2 | **An aggregation failure never fails the search.** The answer falls back to sample counts and says so; the run record shows `aggregations.available: false` and the error. | Exact counts are an improvement, not a dependency. In replay, a missing aggregation is the same fallback, never a live call and never invented. |
| A3 | **Counts are held as bounds everywhere** (`{min, max}`): exact from the aggregation (widened by OpenSearch's own `doc_count_error_upper_bound` if it reports one), or the sample bounds as before. The checker does the same. | One code path for exact and approximate counts, and an honest one when OpenSearch's terms counts are approximate across shards. |
| A4 | **The model now gets aggregated counts, `bySeverity`, `countsExact`, the comparison, and at most 10 example records per search** (30 when counts aren't exact). | Requested (5.1: "not raw events"). Fewer raw records means a smaller prompt on real data (below). |
| A5 | **"Previous" = the same window shifted 7 days** (`now-24h` → `now-192h..now-168h`; ISO ranges shifted by 7 days; months and years in date maths taken as 30 and 365 days). New citation kind `previous` for last week's totals and rule counts, checked like the others. The header states the comparison in code. | Requested (5.2). For windows longer than a week the two windows overlap; that's what "the same window seven days earlier" means, and the header names the window, so it's visible. |
| A6 | **⚠ Severity floor: level 7 for questions containing "right now", "currently", "at the moment" and similar**, only when the planner set no level, never for vulnerability searches. `RIGHT_NOW_MIN_SEVERITY` adjusts it; `0` turns it off. The header says "at level 7 and above"; the run record notes it. | Requested (5.3). **Review the default and the trigger phrases.** Wazuh level 7 is a common "worth a look" threshold, but it's a judgement. It changes the record search for those questions, so the baseline's "what is going on right now" replays as diverged with today's code (runbook explains; `RIGHT_NOW_MIN_SEVERITY=0` avoids it). |
| A7 | **Per-stage timings in every run record:** memory retrieval, planning, execution (and each tool, with its scope), aggregation, the model call alone (`reasoningDuration`), verification and rendering (`verificationDuration`), total, and the report prompt's size. A stage not reached is `null`, not 0. | Requested (5.4). Separating the model call from the code around it is what shows where time goes. |
| A8 | **⚠ Field mapping assumed** (F-64). | Matches the standard Wazuh template; the first Phase 5 capture will confirm it. |

**Checker run (synthetic; same scenarios, same stub models, same scorer, Phase 4 code vs Phase 5 code).** The sampled scenario now has a realistic page (200 records returned of 1,500 matches).

| | Phase 4 | Phase 5 |
|---|---|---|
| Mean score, faithful / adversarial stub model | 100 / 100 | 100 / 100 |
| Fabrications reaching the analyst (checker-visible) | 0 | 0 |
| Inflated count shown, sampled scenario with aggregations | yes (F-63) | **no** |
| Inflated count shown, sampled scenario without aggregations (pre-Phase-5 fixture) | yes | yes (same fallback, and the answer now says counts are sampled) |
| Report prompt, realistic 200-record search | 15,150 chars | **8,877 chars (−41%)** |
| Report prompt, small scenarios (≤ 13 records) | 6,100–9,678 | 7,152–10,459 (+~1,000: comparison data and longer instructions) |
| OpenSearch requests per planned search | 2 | 4 (each half adds one aggregation request) |

The checker can't see the inflated count in the Phase 4 run (its capture has no aggregation either), which is why it's listed separately. Speed here means prompt size: model latency grows with input, and the stub model has none. Real speed needs the capture and an approved model, and every run record now has the per-stage timings to measure it.

**Checker changes this phase:** reads aggregation requests (exact counts, not counted as searches) and keeps the sample bounds when there are none. New synthetic cases: exact count right and wrong, and the sampled scenario as captured before Phase 5. 12 Phase 5 mutants, all killed, including "checker ignores aggregations".

**Tests changed in Phase 5:** fixture tests distinguish searches from aggregation requests (a capture now records both); the failed-search replay test removes the aggregation request a failed search would never have sent. Test helpers answer aggregation requests from `scripts/lib/fakeAggregations.js`, shared with the eval scenarios.

## Phase 6: Model flexibility (2026-10-12)

| # | Decision | Why |
|---|---|---|
| F1 | **Per-role settings** (`src/llm/models.js`): `PLANNER_LLM_*` and `REPORT_LLM_*` override URL, model name and key field by field; everything else (memory, conversation, chat) uses the default. With none set, every call goes to `LLM_API_URL` as `foundation-sec-8b-instruct`, as before. | Requested: separately configurable, current model as default, no production change. A test pins the unchanged defaults. |
| F2 | **A key goes only to its own endpoint:** a role with its own URL uses its own key or none, never the default's. Keys are sent as a bearer header and never written to run records, fixtures or comparison output. | Otherwise pointing the report at another provider would quietly forward the production key to it. Mutation-checked. |
| F3 | **Run records and responses name the models** (`generation.models: {planner, report}`; `model` stays the report model). The footer says "Planned by …" when the planner differs. Names only, never URLs. | Provenance for each answer once more than one model is in play. |
| F4 | **`replayFixtures.js` disables every model URL by default,** not just `LLM_API_URL`. | Found while adding the roles: a `REPORT_LLM_API_URL` in `.env` would have got past the Phase 3 guard. Test-first. |
| F5 | **`--live-planner` replay:** the configured planner is asked for the plan, while searches still come from the fixture; a different plan shows as `DIVERGED`, never as a live search. | Lets planners be compared without touching the SIEM. "Matched" then means the planner reproduced the captured searches. |
| F6 | **`evals/compare_models.py`** replays every fixture per model (`--allow-model`) and scores each model's own answer (`check.py --answer replay`). Reported side by side: score, hard-check failures, fabrications shown, claims dropped and drop rate, format failures, model unavailable, model-call time (mean and max), prompt size, and planning time with `--live-planner`. | Requested. "Claims dropped" is the best fabrication signal for a model: with verification on, fabrications shown should always be 0, so what differs between models is how much they try to say without support. |
| F7 | **Guards:** every model needs `approved_by` (the example's candidate is blank, so the example is refused as it stands); credentials can't be written into the config, only referenced by environment-variable name; synthetic cases are refused; `--dry-run` calls nothing; results go under gitignored `baseline/`. `evals/models.json` is gitignored. | "Don't call any external model until I supply an approved endpoint." All guards mutation-checked (11 mutants, all killed after two tests were added). |
| F8 | **⚠ OpenAI-compatible endpoints only** (F-65). | That's the current model's API. Another API needs a small adapter or a gateway. |
| F9 | **Not run against any real model.** | Ground rule. The tests use a local stand-in server only. The first real comparison needs the captured fixtures and an endpoint you approve. |

**Tests changed in Phase 6:** `attribution` and `runRecord` expect the added `generation.models`; the replay no-model test now sets the per-role URLs too. New: `modelConfig.test.js` (5), `compareModels.test.js` (7), and the live-planner replay test.

## Phase 7: Professional conversation (2026-10-12)

| # | Decision | Why |
|---|---|---|
| C1 | **Search answers stream only what is true when shown** (`POST /api/chat/search/stream`): stage events as each stage actually starts, the code-written header as soon as the searches finish, and each statement only after it passes verification. The model's raw tokens are never shown. | Requested (7.1), within Phase 4's rule that unverified text never reaches the analyst, and Phase 2's "never simulate activity". The fixed "Searching Wazuh and firewall data…" placeholder is gone, replaced by the real stage. |
| C2 | **Statements are verified as the model streams** (`claimStream.js` reads its JSON and hands over each claim object as soon as it is complete), but **the final answer is always rebuilt from the complete output.** A test pins that the streamed answer equals the non-streamed `/api/chat` answer for the same model output. | Early display without a second, weaker code path. A scanner fault can only delay a statement, never show an unchecked one. |
| C3 | **`insufficient_evidence: true` stops streaming statements**, and **Stop cancels the model request** (run recorded as `stopped`, nothing the model wrote shown). The streamed report uses the configured report model (Phase 6). | Each is pinned by a test that was first seen to fail as a surviving mutant. |
| C4 | **Follow-ups reuse the previous search's evidence** when they refer back ("that IP", "tell me more", "which one") or name a rule, agent, IP or user in it. Anything asking for new data or naming a time window searches again. The answer opens with "Answered from the evidence of your previous search (…)", is badged "From previous search", and offers **Search again**. | Requested (7.2). Conservative on purpose: reusing stale evidence for a question about a different window would be wrong, while an unnecessary fresh search only costs time. |
| C5 | **Follow-up evidence is kept in memory, per user, for 2 hours, at most 50 searches** (F-66). Another user's evidence is never reused. | Avoids a second on-disk copy of raw records. A restart means the next follow-up searches again; nothing is lost from the record. |
| C6 | **One clarifying question, only when genuinely needed:** rules catch a specific thing that's referred to but never named ("that IP", "the user", "the server", singular only) and requests with nothing to search for ("check", "investigate this"). The planner may also ask, only with no searches planned and only one short question (≤ 200 characters, one "?"). | Requested (7.3). Rules handle the clear cases without a model call; plurals ("the servers") and anything naming an IP, host, rule, user or quoted name are not ambiguous. A missing time window is never a reason to ask (default 24 hours). |
| C7 | **Never asked twice:** a clarification starts with "Quick question before I search:"; if the previous assistant turn is one, the reply is combined with the original question ("is that IP malicious? (185.220.101.7)") and goes straight to planning, even if still vague, and is not routed to small talk ("yes"). Decided on the server from the history, not by a client flag. | "One short question rather than guessing", without loops. |
| C8 | **With previous evidence, "that IP" is a follow-up, not a question back.** The follow-up check runs first. | The reference has something to point at. |

**Checker run:** synthetic self-test 33/33; pipeline evaluation identical to Phase 5 (faithful and adversarial stub models 100, no fabrication reaching the analyst; legacy pass-through 76.3 with 23 fabrications; report prompt 10,563 characters). Nothing regressed.

**Browser check** (fixture replay, a local stand-in model streaming slowly): the header appeared within 150 ms, three verified statements then arrived one by one over about 2 s, a fabricated statement the stand-in included never appeared, the follow-up reused the evidence with **Search again**, and the clarification asked once and proceeded with the combined question. Found and fixed during it: follow-up answers still carried the "Searched Wazuh" badge, including after reloading the conversation.

**Mutation checks:** 14 Phase 7 mutants, all killed (two needed new tests: insufficient evidence while streaming, and the report model on the streamed path).

