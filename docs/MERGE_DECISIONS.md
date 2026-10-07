# Merge Decisions

Every judgement call made while consolidating `ChatBot-main` (Solomon's hardening work, Sep 16–18) with `ChatBot/` `main` (Abdulhakeem's Push 25/26, Sep 22). The plan's own instructions are not repeated here; this file records what the plan left open, and why each choice was made. Items marked **⚠ Review** are the ones most worth a second opinion.

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

### Left for later phases on purpose

- **The conversational path still returns HTTP 503 when the model is down** — Phase 2.3.
- **`docs/PIPELINE_MAP.md` and `docs/CAPTURE_RUNBOOK.md` still describe `ChatBot-main`** (F-47) — the runbook in Phase 3, the map after Phase 2.
- **The local branch `import/chatbot-main` is kept.** Its commit is a parent of the merge either way; you can delete the branch name before pushing if you don't want it on the remote.
