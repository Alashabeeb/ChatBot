# Findings

Issues found while working on the codebase. **None of these are fixed** unless marked. They are logged here on purpose, so fixes can be scoped and scheduled separately.

Opened 2026-09-16; all fixes and findings live in this repository on `main` since 2026-10-07 (history in `docs/MERGE_DECISIONS.md`). Paths are relative to the repo root.

**Status by phase of the October consolidation plan:**
- **Phase 0 (hotfix on `main`):** F-42 mitigated.
- **Phase 1 (merge):** everything under "Fixed" below. F-43 and F-44 fixed.
- **Phase 2 (2026-10-07):** F-03, F-08b, F-11, F-12, F-16, F-20, F-22, F-23, F-24, F-29, F-32, F-33, F-35, F-36, F-40, F-42, F-46 fixed; F-31 documented. New: F-55 to F-60.
- **Phase 3 (2026-10-12):** measurement harness (`evals/`). F-14 corrected (200 hits per search, not 10,000). F-47 closed (runbook rebuilt). Replay no longer reports a false divergence when a search failed at capture. New: F-61, F-62.
- **Assistant chat (before Phase 2, by request):** general ChatGPT-style chat with streaming. F-03 fixed on the chat path; F-14 still open for searches. See `docs/ASSISTANT_CHAT.md`.
- **All of the above is on `main`** (2026-10-07). Production still runs `c0e2010` until `main` is deployed with `docs/DEPLOY.md`; until then it still has F-00, F-01, F-06, F-08a, F-42 and F-43.

---

## On the record: which model `askFoundation` calls

Source: `backend/src/llm/foundation.js`, `askFoundation`, lines 7–29.

| Question | Answer from the code |
|---|---|
| Model string | `'foundation-sec-8b-instruct'`, hard-coded as `MODEL_NAME` in `foundation.js` (moved to a constant during the F-01 fix). It is not configurable. |
| Endpoint | `LLM_API_URL` from the environment (`backend/src/config/env.js:10`). It is **not set anywhere in the repo**: there is no `.env` file or default value, and the README only has a placeholder `https://<llm-api-endpoint>`. |
| Provider | **Can't be determined from the repo.** The code sends a single `POST {model, messages}` to whatever `LLM_API_URL` points at, and reads `response.data.choices[0].message.content`. That is the **OpenAI-compatible Chat Completions format**, which many servers accept (vLLM, Ollama's `/v1`, TGI, LiteLLM and others). |
| Authentication | **None.** No `Authorization` header or API key is sent. So the endpoint is either unauthenticated (typically self-hosted) or protected only by the network. A hosted commercial API that requires a key would reject these calls. |
| Timeout | `timeout: 0`, meaning no timeout (`foundation.js:22`). |
| Identity claims elsewhere | The greeting says "powered by Cisco Foundation Sec 8B" (`backend/src/services/chat.service.js:17`). The report footer said "Analyzed by foundation-sec-8b" unconditionally until F-01 was fixed. It now reads "Analyzed by foundation-sec-8b-instruct" only when the model wrote the report. `foundation-sec-8b-instruct` matches the name of Cisco Foundation AI's open-weights model (Foundation-Sec-8B-Instruct). **The code does not verify** that the server behind `LLM_API_URL` actually runs that model. The `model` field is only a request parameter, and many OpenAI-compatible servers ignore it or map it to whatever model they serve. |

**To confirm the real provider:** check `LLM_API_URL` in the deployed `backend/.env`, then query that server's `/v1/models` (or equivalent) to see what it serves.

---

## Fixed

### F-00: `lookupThreatIntel` mock fed fake data into reports. **FIXED 2026-09-16**
- The tool returned `{ malicious: false, threatScore: 10, tags: ['scanner'], message: 'Mock threat intelligence response…' }`. That reached the report prompt, the report, long-term memory (read back by the planner and `searchMemory`) and chat history.
- **Fix:** the tool returns `{ available: false, reason }`. The runtime puts it under `unavailableSources`, never under `evidence`, and the runtime itself appends `THREAT_INTEL_ABSENT_NOTE` to the report. Report prompt rule 3 forbids describing unavailable sources.
- **Tests:** `backend/test/threatIntel.test.js`, 3 tests. They pass on the fix and fail on the original code.
- **Existing data:** `backend/scripts/purgeMockThreatIntel.js` quarantines contaminated `messages` and `memories` rows. Tests: `backend/test/purgeMockThreatIntel.test.js`.
- **Remaining risk:** the real model can still make up a reputation claim unprompted. The tests use a stubbed model, so they can't catch that.

### F-08a: Hard-coded JWT fallback secret. **FIXED 2026-09-16** (admin password default still open, see F-08b)
- Was: `JWT_SECRET` fell back to a fixed string in `backend/src/config/env.js`, so anyone with the repo could forge tokens if the variable was unset.
- **Fix:** the fallback is removed. `findFatalConfigErrors` in `env.js` and `backend/src/config/startupCheck.js` (the first import in `server.js`) make the process exit with code 1 and a `FATAL CONFIG ERROR` message when `JWT_SECRET` is unset, empty or whitespace. This happens before the database is created or the port is opened.
- **Tests:** `backend/test/startupConfig.test.js`. It checks the unset, empty and whitespace cases, plus a control run that confirms the server starts when the secret is set. All three refusal tests fail on the original code, where the server started.
- **Not addressed:** already-issued tokens (see the incident note below), and secret strength (F-23).

### F-06: A client could inject `system` and other roles into model calls. **FIXED 2026-09-16**
- Was: `req.body.history` went unchecked from `chat.controller.js` into `askFoundation`, which copied `msg.role` verbatim.
- **Fix:** `sanitizeChatHistory` (`backend/src/utils/history.util.js`) runs in `handleChat` on the server. It keeps only `{role, content}` entries whose role is exactly `user` or `assistant` and whose content is a string. Everything else is dropped, and the number dropped is logged.
- **Tests:** `backend/test/historyRoles.test.js` sends `system`, `System`, ` system`, `developer`, `tool`, object content and missing-role entries through `handleChat`. It rebuilds the arguments of every `askFoundation` call and checks that none of the injected text is present and that legitimate turns still arrive. On the original controller, the injected system text reached the model and the test failed.
- **Related, still open:** F-20.

### F-01: The footer credited the model when the model never ran. **FIXED 2026-09-16**
- Was: when the model was down, the report was the canned "Successfully retrieved records…" and the footer still said "Analyzed by foundation-sec-8b". Canned zero-result replies were credited to the model too.
- **Fix** (`backend/src/agent/runtime.js`):
  - When the model call fails, the summary now starts with `MODEL_UNAVAILABLE_NOTICE`: "⚠️ **Model unavailable: this response was not generated by a model.**…"
  - Every response carries `model_generated` (true only when the model wrote the report) and `generation: { planner: 'model'|'fallback_rules', report: 'model'|'fallback_model_unavailable'|'template_no_results', model }`.
  - The footer is built from those values, and the `[Runtime Complete]` log line includes them.
  - `generateLLMPlan` now returns `{ tools, source }`.
  - The model string lives in one place, `MODEL_NAME` in `foundation.js`.
- **Tests:** `backend/test/attribution.test.js` covers model down, model up, planner fallback with a model-written report, and no results. All four fail on the original code. For "model up", that's only because the flags didn't exist yet.
- **Limit:** the flags exist only in the API response and server log. They are not stored and not shown in the UI (F-21).

### F-15 / F-21: Runs weren't traceable, and provenance flags weren't stored. **FIXED 2026-09-16** (UI display still open, see F-21b)
- Was: `requestId`, the plan and timings only reached the console. The F-01 flags weren't saved, and nothing tied a saved report to its run.
- **Fix:** run logging to a SQLite `runs` table. See "Run logging" below.

### F-25: A `running` run left by a restart looked the same as a live hang. **FIXED 2026-09-16**
- **Fix:**
  - Each server process gets a `SERVER_INSTANCE_ID` (`backend/src/observability/instance.js`), and every run row stores it in `runs.instance_id`.
  - At startup, `server.js` calls `RunModel.markInterruptedRuns(currentInstanceId)`. Any `running` row from a different instance, or with no instance, becomes `interrupted`, and an error with `stage: 'server'` naming both instance IDs is added. `completed_at` stays `NULL`.
  - `running` now means "in progress or hung in the live process".
  - `initDatabase` rebuilds a `runs` table created before `instance_id` existed, keeping its rows (SQLite can't alter the status CHECK constraint).
- **Tests:** `backend/test/serverRestart.test.js` uses real server processes, a real login and a model server that accepts connections and never answers.
  - A genuine hang stays `running` while its instance is alive.
  - After a `SIGKILL` restart, the old run is `interrupted` while the new instance's hang is still `running`.
  - The migration test covers a pre-`instance_id` table.
  - Mutation check: disabling the startup sweep makes the test fail.
- **Limit:** assumes one backend process per database (F-31).

### F-13 (blocker 3): Multiple tools overwrote each other's `raw_logs`. **FIXED 2026-09-16**
- **Fix:**
  - `response.raw_logs` is now an object keyed per tool invocation, in plan order: `searchSecurityLogs`, `getEndpointStatus`, and `searchSecurityLogs#2` for a second call to the same tool.
  - `executePlan` records `planIndex`, so the order doesn't depend on which tool finishes first.
  - No log is duplicated or dropped, so the payload size is unchanged (F-14 is still open).
  - The frontend (`ChatPage.jsx`, `flattenRawLogs`) accepts both the keyed object and the plain arrays in messages saved earlier.
- **Tests:** `backend/test/multiToolRawLogs.test.js` runs two OpenSearch searches plus a Wazuh call, and checks that all three result sets survive, including when tools finish out of order. Both tests failed before the fix. Mutation check: removing the plan-order sort makes them fail.
- **Not verified:** the frontend change hasn't been built or run here (frontend dependencies not installed).

### F-42: Two "action" tools returned fabricated results to analysts. **MITIGATED 2026-10-07 (Phase 0, `8fef3d9`); FIXED (Phase 2, `afec39c`)**
- **Was:** `blockIpAction` (added in Push 25) blocked nothing but returned `IP_BLOCKED` / "Successfully added … to the firewall blocklist." `checkProcessList` returned the same hard-coded list for every endpoint, including a root `unknown_miner` at 98.5% CPU. Both were registered with the planner, so their output reached reports as evidence, and the planner could "block" on its own judgement.
- **Mitigation:** both unregistered. A model plan naming either one is rejected by `validateExecutionPlan`. Tests: `backend/test/toolRegistry.test.js`. `backend/scripts/auditFabricatedActions.js` (`8fef3d9`, `13f741d`) lists saved messages and memories containing the fabricated text. Deploy steps: `docs/HOTFIX_DEPLOY.md`.
- **Fixed (Phase 2.1, `afec39c`):** `checkProcessList` returns an explicit "not available" result, handled like threat intel: never evidence, and a runtime-written note in the report. `blockIpAction` is approval-gated in three layers: the registry never offers it to the planner, the plan validator rejects it, and the gateway refuses it without an approval for exactly that tool, those parameters and a named approver. Nothing in the planner path supplies one, and even an approved call blocks nothing until a firewall integration exists. The purge script now catches `IP_BLOCKED`, "added … to the firewall blocklist" and `unknown_miner`. Tests: `backend/test/actionTools.test.js`.

### F-43: Security questions were answered without searching any data. **FIXED on `main` 2026-10-07 (Phase 1)**; live in production until `main` is deployed
- **Was (Push 25/26 on `main`):** `processChatQuery` sent every message *without* a security keyword to the chat-only model path, which never searches. `hasSecurityKeyword` matches whole words only, so `alerts`, `failed`, `logons`, `vulnerabilities`, `unusual` and `suspicious` carry no keyword. All four capture questions — "what is going on right now", "anything unusual on the AD servers", "show me failed logons today", "what are the top alerts this week" — plus questions like "how many vulnerabilities on web-01" were answered by the model with no data at all.
- **Fix:** `isConversational()` in `backend/src/services/chat.service.js`. Only clearly conversational messages (greetings and chat phrases with no security keyword) go to the conversational path; everything else goes to the data-searching runtime. Tests: `backend/test/routing.test.js`; mutation-checked against the keyword-only rule.
- **Remaining:** the whole-word keyword matching itself is still weak (see F-45). It now only decides whether a chat-phrase message is excluded from conversation, so a miss errs toward searching, not toward answering blind.

### F-44: The F-08a test didn't pin the fix itself. **FIXED 2026-10-07 (Phase 1)**
- **Was:** `startupConfig.test.js` only proved the *server* refuses to start without `JWT_SECRET`. Restoring the hard-coded fallback in `env.js` passed every test: the startup check reads `process.env` directly, so the server stayed safe, but the literal secret was back in a repo that pushes to GitHub, and any other importer of `env.js` (scripts) would get it. Found by mutation-checking the merge.
- **Fix:** a new test asserts `JWT_SECRET` is `undefined` for any importer when unset, and that the old literal appears nowhere in `src/`.

---

## Open

### Model output integrity

**F-02: Model failures are silent to the analyst.**
- **Where:** `backend/src/llm/foundation.js:25–28`, `backend/src/agent/planner.js:38–41`.
- **Problem:** every error becomes `null` or a quiet switch to the legacy planner, with only a `console.warn`.
- **Partly addressed by F-01:** the response now flags a rule-based plan and a report the model didn't write. The actual error (timeout, HTTP status, bad JSON) still isn't passed on or recorded anywhere except the console.

**F-03: No timeout on model calls. Likely cause of slow and stalled runs.** **FIXED 2026-10-07 (Phase 2, `4dc3b9e`)**: every model call now has a time limit; also covers Search Wazuh.
- **Where:** `backend/src/llm/foundation.js`, the `axios.post` in `askFoundation` passes `{ timeout: 0 }`, which in axios means no timeout.
- **Refused vs. hung:** if the model server *refuses* the connection (down, wrong port), axios rejects straight away, the `catch` fires, and the run falls back to rule-based logic. If the server *hangs* (accepts the connection but never answers, for example stuck on load or an overloaded GPU), nothing ever throws. The promise stays pending forever, so the `catch` that would trigger the fallback never runs.
- **Effect on a run:**
  - The planner call happens first, so a hang stops the run before any tool executes.
  - There's no error, no fallback report and no `[Runtime Complete]` log line.
  - The HTTP request to `/api/chat` stays open until the client gives up (the UI's Cancel button aborts only the browser side). Until run logging was added, no record existed either.
  - Up to 3 model calls are made per run (planner, report, background memory summary), and each can hang.
  - A slow but responsive model has no upper limit either, so runs can take arbitrarily long.
- **Likely cause of:** runs that are slow for no visible reason, and runs that stall without a clean error.
- **Not fixed** (as instructed). Runs logged as `running` that never complete are the observable symptom; see the run logging section.

**F-04: Model plan parameters aren't checked against the tool schemas.**
- **Where:** `backend/src/schemas/ExecutionPlan.schema.js:38–63` checks only the shape and tool names.
- **Example:** if `minSeverity` is omitted, then `undefined !== null` is true at `backend/src/integrations/opensearch.integration.js:29`, which adds `rule.level >= undefined` to the query.

**F-05: `extractJSON` grabs everything from the first `{` to the last `}`.**
- **Where:** `backend/src/llm/foundation.js:34–55`.
- **Problem:** if the model writes any text containing braces after the JSON, parsing fails, and it silently falls back to the legacy planner (see F-02).

### Security

**F-07: User text goes into prompts unescaped.**
- **Where:** `backend/src/agent/planner.js:22`, `backend/src/agent/runtime.js` (reasoning prompt), `backend/src/memory/summarizer.js:8`.

**F-08b: Default admin password.** **FIXED 2026-10-07 (Phase 2, `ecdbc8a`)**: admin must change the published default password on first login.
- **Where:** `backend/src/config/env.js`, `ADMIN_INITIAL_PASSWORD`.
- **Problem:** it defaults to `Password12$` when unset. The seeded admin account (`initDatabase`) gets that password.

**F-09: Wide-open server settings.**
- **Where:** `backend/src/server.js:16–18`.
- **Problem:** `cors()` allows any origin, and JSON and form bodies can be up to `500mb` (easy denial of service).

**F-10: The frontend talks to the backend over plain `http://`.**
- **Where:** `src/pages/ChatPage.jsx:131–133`, 180–182 and more.
- **Problem:** JWTs and SIEM data travel unencrypted to port 3002.

**F-11: `npm audit` reports 3 moderate vulnerabilities in backend dependencies.** Reviewed 2026-09-16; nothing applied. **FIXED 2026-10-07 (Phase 2, `4784306`)**: `npm audit fix`: 0 issues, plus new axios and proxy-addr advisories.
- The three entries are really **one vulnerable package, `qs@6.15.3`**, counted three times: directly, through `body-parser@1.20.6`, and through `express@4.22.2`.
  - **GHSA-4mjr-xmp4-gh2g** (CVSS 5.3): denial of service through an attacker-controlled `isBuffer`. Affects `qs` >=2.2.5 <6.16.0.
  - **GHSA-x5fp-wj9c-mxmx** (CVSS 3.7): array-limit bypass through bracket-key comma parsing. Affects `qs` >=6.14.2 <=6.15.3.
- **Reachable:** Express 4 parses every request's query string with `qs`, and `server.js:20` uses `express.urlencoded({ extended: true })`, which also uses `qs`. That includes unauthenticated routes such as `/api/auth/login`. Whether these specific advisories can be exploited through that path was not tested.
- **Fix (dry run only):** `npm audit fix` would change `qs` 6.15.3 → 6.16.0, `express` 4.22.2 → 4.22.3 and `body-parser` 1.20.6 → 1.20.8. All are patch or minor bumps inside the ranges already declared (`express: ^4.19.2`), so it is a lockfile-only change and not a breaking one under semver. `--force` is not needed.

### Reliability

**F-12: Unhandled promise rejection in the memory write.** **FIXED 2026-10-07 (Phase 2, `4dc3b9e`)**
- **Where:** `backend/src/agent/runtime.js:186`.
- **Problem:** `memoryManager.write(...)` in the no-results branch is neither awaited nor given a `.catch`. If the write fails (for example a foreign-key error for an unknown user), Node's default unhandled-rejection behavior crashes the process.

**F-14: Up to 10,000 raw logs per reply are sent to the browser and saved to SQLite.** **CORRECTED 2026-10-12 (Phase 3):** the code has returned `size: 200` per search, with an exact `track_total_hits` total, since `c0e2010` ("Push 26", already in production). The 10,000 figure came from an older copy. What remains: up to 200 records per search (two searches per question with the firewall fan-out) are still sent to the browser and saved, while the model sees 30 of them. Phase 5 (aggregation) replaces this.
- **Where:** `backend/src/integrations/opensearch.integration.js:29`, `src/pages/ChatPage.jsx`.
- **Problem:** the model only sees 30 of them.

### Observability

**F-16: Fake activity text in the UI.** **FIXED 2026-10-07 (Phase 2, `47fcda9`)**: fake typewriter, rotating status, TerminalFeed and false status claims removed.
- **Where:** `src/components/TerminalFeed.jsx:6` and `src/components/ChatMessage.jsx` (`TypingDots` phases).
- **Problem:** `TerminalFeed` is a hard-coded script that looks like a live log. The loading phrases ("Correlating security events…" and others) don't reflect what the backend is doing. The "Fetching threat intelligence…" phrase was removed as part of F-00; the rest are unchanged.

### Hygiene

**F-17: Dead system prompts.**
- **Where:** `backend/src/llm/prompts.js`.
- **Problem:** `WAZUH_SERVER_API` and `STRICT_FACTUAL_RAG` are never used, and `STRICT_FACTUAL_RAG` has an unfilled `{TIME_LABEL}` placeholder.

**F-18: The README is stale.** It describes a `server/server.js` backend. The real code is in `backend/src/`, which also adds an agent, memory and login.

**F-19: No test infrastructure existed before 2026-09-16.** The backend now has `npm test` (`node --test`). The frontend still has no tests.

---

### Found 2026-09-16 (second pass)

**F-20: Stored user text is sent to the planner as a `system` message.** **FIXED 2026-10-07 (Phase 2, `4dc3b9e`)**: memories passed as delimited data in the user prompt.
- **Where:** `backend/src/agent/runtime.js`, step 0/1. `preContextStr` embeds short-term memories (which contain raw user text and prior report text) and is added to the planner history with `role: "system"`.
- **Problem:** text a user typed in an earlier turn comes back to the model with system authority. This is a server-side path around the F-06 fix.

**F-21b: Provenance is stored but not shown.**
- **Where:** `src/pages/ChatPage.jsx`.
- **Problem:** the frontend still doesn't render `footer` or `model_generated` for `agent_response`. A fallback is visible to the analyst only through the prose notice.

**F-22: `askFoundation` assumes well-formed history.** **FIXED 2026-10-07 (Phase 2, `4dc3b9e`)**
- **Where:** `backend/src/llm/foundation.js:14`.
- **Problem:** before the F-06 fix, a single `null` history entry made every model call throw inside its `try`, return `null` and silently fall back. The chat endpoint now filters these out, but `askFoundation` itself still has no guard for internal callers.

**F-23: No strength check on `JWT_SECRET`.** Any non-blank value (for example `secret`) is accepted. **FIXED 2026-10-07 (Phase 2, `ecdbc8a`)**: 32+ characters, 8+ distinct, not a known published value.

**F-24: The token middleware doesn't check that the user still exists.** **FIXED 2026-10-07 (Phase 2, `ecdbc8a`)**: user looked up on every request; role from the database.
- **Where:** `backend/src/middleware/auth.middleware.js:15–22`.
- **Problem:** it trusts `id` and `role` from the token without a database lookup, and tokens last 7 days (`auth.controller.js:39`) with no revocation. Deleted users keep access until their token expires. A forged token can name any user id or `role: 'admin'`.

**F-26: The `runs` table has no retention policy.** One row is added per question and never removed. Rows are small (metadata, not raw logs), but they hold user questions, report text and query bodies indefinitely.

**F-27: Run-record write failures don't fail the request.**
- **Where:** `backend/src/agent/runtime.js`, `startRunRecord` / `finishRunRecord`.
- **Behavior:** by design, a database error while writing the run record is logged loudly (`[req:<id>] [Run Record] …`) and the analyst still gets the response. So a run can exist without a record. Revisit this if the run log must be a complete audit trail.

**F-28: Some errors after the run completes aren't recorded.** The background memory summary and write happen after the record is finalized. Their errors and model calls show up in the console (tagged with the request ID) but not in `runs.errors_json`.

### Found 2026-09-16 (third pass)

**F-29: Model evidence is still keyed by tool name, so repeated tool calls overwrite each other.** **FIXED 2026-10-07 (Phase 2, `0d862e2`)**
- **Where:** `backend/src/agent/runtime.js`, evidence aggregation (`structuredEvidence.evidence[result.tool] = …`).
- **Problem:** the blocker-3 fix keyed `raw_logs` per invocation, but the evidence sent to the reasoning model is still keyed by tool name. If a plan calls `searchSecurityLogs` twice, the model sees only one search's `totalMatches` and sample logs, while `total_hits` counts both.

**F-30: `response.source` shows one tool only.**
- **Where:** `backend/src/agent/runtime.js`, `sourceLabel` (last one wins).
- **Problem:** in a multi-tool run it names one index or URL.

**F-31: The interrupted-run sweep assumes one backend process per database.** **DOCUMENTED 2026-10-07 (Phase 2, docs)**: documented in DEPLOY.md and CAPTURE_RUNBOOK.md with a check; behaviour unchanged.
- **Where:** `RunModel.markInterruptedRuns`.
- **Problem:** if two backend processes share one SQLite file (a cluster, or an accidental second start), a starting process marks the other *live* process's running runs as `interrupted`.

**F-32: The purge script's dry run opens the database read-write.** **FIXED 2026-10-07 (Phase 2, `da2dcae`)**
- **Where:** `backend/scripts/purgeMockThreatIntel.js`, `main`.
- **Problem:** it writes nothing, but it doesn't use the read-only flag the way `scripts/dbReport.js` does.

**F-33: "View Full Details" mixes every tool's records in one list.** **FIXED 2026-10-07 (Phase 2, `47fcda9`)**: Source column in View Full Details.
- **Where:** `src/pages/ChatPage.jsx`, `LogDetailsModal`.
- **Problem:** since F-13, all tools' records are kept but flattened into one list. The modal doesn't say which tool a record came from, and Wazuh agent-inventory entries appear alongside alerts, with most alert fields showing N/A.

**F-34: Capture timeouts don't cancel the hung run.**
- **Where:** `backend/src/fixtures/capture.js`.
- **Problem:** when a question hits `--timeout-ms`, its run keeps its pending model call (F-03) while capture moves on, so later questions run alongside it. The timed-out fixture is still written, with `status: 'timeout'` and whatever calls completed.

**F-35: The server logs its OpenSearch URL at startup.** **FIXED 2026-10-07 (Phase 2, `da2dcae`)**
- **Where:** `backend/src/server.js`, the `app.listen` callback.
- **Problem:** the internal indexer host and port go into every startup log.

**F-36: On Windows, the purge script may silently do nothing.** **FIXED 2026-10-07 (Phase 2, `da2dcae`)**
- **Where:** `backend/scripts/purgeMockThreatIntel.js`, the last lines.
- **Problem:** `main()` runs only if `path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)`. On Windows, a drive-letter case difference (`c:\` vs `C:\`) makes that false, so the script exits 0 with no output. The capture, replay, backup and report scripts call `main()` unconditionally and aren't affected. `docs/CAPTURE_RUNBOOK.md` step 5 warns about this.

**F-37 (fixed on the spot, recorded for history): the `fixtures/` gitignore pattern matched a code directory.**
- **Problem:** the unanchored `fixtures/` pattern, added to keep telemetry out of git, also matched the new code directory `backend/src/fixtures/`, so that source would never have been committed.
- **Fix:** the code moved to `backend/src/recording/`. The broad pattern stays, and `test/fixtures.test.js` now fails if any source, script or test directory is named `fixtures` or `quarantine`.

**F-38: Capture reports success when every backend is unreachable.**
- **Where:** `backend/src/recording/capture.js`, `captureOne` / `captureFixtures`.
- **Problem:** a fixture's `status` is `completed` whenever the pipeline returns a run, including runs where the model was unreachable (rule-based plan, fallback report) and every OpenSearch and Wazuh call failed. Verified 2026-09-16 with all endpoints unreachable: `Done: 4/4 completed`, exit code 0, `failedCalls=3 hits=0 model_generated=false` on every question. The exit code and the "completed" count alone don't show whether any real data was captured. `docs/CAPTURE_RUNBOOK.md` step 7 says to check the per-question fields.

### Found 2026-09-18

**F-39: The data-source selector was inert. Traced 2026-09-18, then removed.**

The composer dropdown offered three sources — Wazuh (SIEM), HiSec (Threat), Honeypot — and sent the selection to the backend on every request. Full trace before removal:

| Where | What it did |
|---|---|
| `src/pages/ChatPage.jsx:58` | `useState(['wazuh'])` |
| `src/pages/ChatPage.jsx:566` | Button label (display) |
| `src/pages/ChatPage.jsx:577, 581, 585` | One checkbox per source (display + toggle) |
| `src/pages/ChatPage.jsx:154` | Sent as `sources` in the POST body |
| `backend/src/controllers/chat.controller.js:5` | Destructured from the body |
| **`backend/src/controllers/chat.controller.js:8`** | **The only functional read:** refused the request unless the selection contained `wazuh` or `all` |
| `backend/src/controllers/chat.controller.js:23` | Passed to `processChatQuery` |
| `backend/src/services/chat.service.js:8` | Declared as a parameter and never read; `runAgentWorkflow(text, history, userId)` was called without it |

- **Never reached:** the planner, any prompt, the tool registry, tool selection, the OpenSearch query builder, the Wazuh client, the `messages` table or the `runs` table. Outside that controller line, `hisec` and `honeypot` appeared nowhere in the backend.
- **Actual behaviour:** selecting all three ran exactly the same pipeline as Wazuh alone. Selecting HiSec and/or Honeypot *without* Wazuh refused the request ("Please select Wazuh from the Agents dropdown to query security data") with no run, no run record and no model call. The `'all'` branch was unreachable: the UI could only produce `wazuh`, `hisec` and `honeypot`.
- **No backing implementation:** there is no HiSec or Honeypot integration, tool or index. The nearest thing, `lookupThreatIntel`, is the stub that reports itself unavailable (F-00).
- **Not recorded:** the selection was never persisted, so for any saved report there is no way to tell what had been selected.
- **Decision (2026-09-18):** removed rather than made real. HiSec and Honeypot are not being built. The selector, the request field, the controller gate (including the dead `'all'` branch) and the unused service parameter are gone; every request now runs. Regression tests: `backend/test/chatRequest.test.js` (3 tests) assert that a body with no `sources` field, a body with only `text`, and a stray `sources: ['hisec']` from an older client all run normally instead of being refused. The selector's CSS was removed too (`.composer-toolbar`, `.agent-dropdown-*`, `.dropdown-item` in `src/pages/ChatPage.css`).

**F-40: The log-details modal shows raw markdown in its summary line.** **FIXED 2026-10-07 (Phase 2, `47fcda9`)**
- **Where:** `src/pages/ChatPage.jsx`, `TruncatedSummary` inside the modal header, which renders `m.summary` as plain text while the chat bubble renders it through `parseToTokens`.
- **Problem:** asterisks show literally, e.g. `**Model unavailable: this response was not generated by a model.**`. Pre-existing for any bold in a report; now guaranteed visible, because the F-01 fallback notice is bold. Observed in the UI smoke test on 2026-09-18.

**F-41: In replay mode the source label reads `undefined/...`.** **FIXED on `main` (Phase 1):** `source` is now the joined source names ("Wazuh", "Firewall (Wazuh)", "Wazuh Agents"), not a URL. See MERGE_DECISIONS R2.
- **Where:** `backend/src/integrations/wazuh.integration.js` builds `apiUrl` from `WAZUH_SERVER_API_URL`, which is unset when running against fixtures; the modal header then shows `undefined/agents`.
- **Problem:** cosmetic and replay-only (a real deployment has the URLs set), but it surfaces the string `undefined` to the analyst. Same root as F-30.

### Found 2026-10-07 (consolidation, Phases 0–1)

**F-45: `hasSecurityKeyword` matches whole words only.**
- **Where:** `backend/src/utils/parser.util.js`.
- **Problem:** `\b(alert|fail|log|…)\b` misses plurals and inflections (`alerts`, `failed`, `logons`, `logs`), and `vulnerab` can never match because it's always followed by more letters. After F-43 this only affects which chat-phrase messages are kept away from the conversational path; it's no longer a routing hole.

**F-46: The firewall fan-out also runs on vulnerability searches.** Due in Phase 2.5. A firewall-scoped query against the vulnerability index costs a request and returns nothing useful. **FIXED 2026-10-07 (Phase 2, `0d862e2`)**

**F-47: `docs/PIPELINE_MAP.md` and `docs/CAPTURE_RUNBOOK.md` predate the 2026-10-07 consolidation.** **CLOSED 2026-10-12 (Phase 3):** the runbook is rebuilt for the current code (baseline replay, scoring, `model_generated` check, re-running one question); the pipeline map's header already says its line numbers are a September snapshot, and its F-14 figure is corrected. *Original text:* Paths, line numbers and the bundle contents predate the merge. The runbook is rebuilt in Phase 3; the pipeline map needs a refresh after Phase 2.

**F-48: Two capture questions route by phrase, not by data need.** *Since assistant chat (2026-10-07) this only affects Search Wazuh mode, where the user has explicitly asked to search; the fix there is to route only bare greetings to conversation.*
- **Where:** `isConversational()`.
- **Problem:** "what is going on right now" and similar contain no chat phrase, so they go to the runtime (correct). But a security question that *contains* a chat phrase and no keyword — "can you check for anything unusual" (`can you`) — still goes to the conversational path. Rarer than F-43 and fails safer (the conversational prompt forbids claiming a search), but not fixed.

### Found 2026-10-07 (assistant chat)

**F-49: No regenerate or edit for answers.** Expected in a ChatGPT-style UI. Not built yet: regenerating needs a way to replace the saved answer in `messages`, otherwise both versions come back on reload.

**F-50: No rate limit or concurrency cap on the model.** Any logged-in user can start many long streams at once and tie up a shared 8B model. Worth a per-user limit (for example 2 concurrent streams) before wide rollout.

**F-51: Answer flags aren't saved.** "Stopped", "cut off" and "Search Wazuh for this" exist only until the page reloads; the `messages` table has no column for them. The run record does keep `report` (`stopped`, `model_truncated`, …).

**F-52: Frontend bundle is 885 kB** after adding the Markdown renderer (the previous size wasn't measured). Vite warns above 500 kB. Code-splitting the log modal and charts would recover most of it.

**F-53: Frontend `npm audit`: 3 issues, all build-time only.** `nanoid` (high), `source-map-js` (high) and `postcss` (moderate) sit under Vite's build toolchain, not in the browser bundle. None come from `react-markdown`. Fix with the Phase 2.15 audit step.

**F-54: The "data question" detector is a heuristic.** `looksLikeDataQuestion()` (`backend/src/services/assistant.service.js`) needs a security-data term plus a "live" cue ("show", "today", "our", …) or an IP address. It only decides whether to *offer* the Search Wazuh button, never what the model is asked, so a miss costs a click, not an invented answer.

### Found 2026-10-07 (Phase 2)

**F-55: Changing a password doesn't sign out other sessions.** Tokens last 7 days and there is no token versioning, so a session opened before a password change keeps working until it expires. F-24's per-request lookup does lock out *deleted* accounts at once. Fix: a `token_version` column checked by the middleware and bumped on password change.

**F-56: Only the default admin is forced to change its password.** Accounts an admin creates keep the initial password the admin chose, with a 6-character minimum (`UserModel.create`). Consider flagging new accounts with `must_change_password` too, and raising the minimum to 12 to match the change-password policy.

**F-57: Login has no rate limit or lockout.** `POST /api/auth/login` can be tried indefinitely, so passwords can be brute-forced over the network. Add a per-account and per-IP limit.

**F-58: The approval mechanism has no way to grant approval.** `blockIpAction` runs only with `context.approval` for exactly that tool and those parameters, and nothing in the product creates one, so blocking is impossible by design today. Building the human-approval step (UI, endpoint, audit record) is the prerequisite for any real firewall integration.

**F-59: Leftover CSS for removed status claims.** `.lp-secure-badge`, `.lp-status-bar` and `.status-indicator` rules remain in the stylesheets, unused. Harmless; delete during the next UI pass.

**F-60: Frontend `npm audit` (F-53) still shows the three build-time issues.** Phase 2.15 covered the backend only, as specified. They're in Vite's toolchain, not the browser bundle.

**F-61: A capture run's `manifest.json` lists only that run's questions.** Found in Phase 3.
- **Where:** `backend/src/recording/capture.js` (`captureFixtures` writes the manifest from this run's summaries).
- **Problem:** re-running one question into the same folder replaces the manifest, so it no longer describes the other fixtures. The fixture files themselves are unaffected, and replay doesn't read the manifest.
- **Workaround (in the runbook):** re-run into a sub-folder (`--out .\fixtures\rerun`) and move the new file up.

**F-62: When every search fails and the model is down, the answer says "0 matching record(s) were retrieved".** Found in Phase 3 (bundle smoke test, endpoints refusing connections).
- **Where:** the "model unavailable" fallback report in `backend/src/agent/runtime.js`.
- **Problem:** a failed search is presented as an empty result, and the answer names neither the time window nor the sources that failed. An analyst could read it as "nothing happened". `evals/check.py` flags it (`H8`, `H10`).
- **Plan:** Phase 4.4 ("every report opens with the sources and time window actually searched") covers it.

## Run logging (added 2026-09-16)

**Storage: SQLite `runs` table, not `runs/` on disk.** Why:
- **Same store as the reports it describes.** `messages.request_id` joins a saved report to its run in one query, and flags plus report text can be checked with SQL. Files on disk can't be joined or indexed, and would need a separate backup and retention story.
- **Stalled runs show up.** The row is inserted as `running` before any work and updated at the end. A crash or hang can't leave a half-written file; it leaves a row stuck at `running` (F-03, F-25).
- **Concurrency is already handled.** The database runs in WAL mode with transactional writes. `runs/` would need atomic-rename handling for the two-phase write.
- **Trade-off:** individual runs are less convenient to diff or copy as fixtures than JSON files. `SELECT … FROM runs WHERE request_id = ?` (or `RunModel.findById`) returns everything as JSON-parsed columns.

**One row per `runAgentWorkflow` execution** (`backend/src/models/Run.js`, schema in `backend/src/config/db.js`):

| Column | Content |
|---|---|
| `request_id` (PK) | Same ID as the `[req:<id>]` tag on **every** console line of the run, the `request_id` in the API response (including 500 errors), and `messages.request_id` |
| `user_id`, `question` | Who asked what |
| `instance_id` | The server process that ran it (F-25) |
| `status` | `running` → `completed` or `failed`. `interrupted` if the process stopped before the run finished, set by the next instance at startup |
| `planner_json` | `{ source, thought, rawOutput, error, tools }`: the model's raw reply, the parsed plan, and why it was rejected if the rule-based fallback was used |
| `tools_json` | Per tool: parameters, success, time, error, and metadata. `raw_logs` in the API response is keyed the same way (F-13). `searchSecurityLogs` records `query` (the exact OpenSearch body sent), `targetIndex`, `totalHits` and `returnedCount`. `getEndpointStatus` records the Wazuh API `url`, `query`, `total` and `returnedCount`. **No raw logs.** |
| `report_text` | The final report exactly as returned |
| `timings_json` | Planning, execution, aggregation, reasoning and total, in ms |
| `errors_json` | `[{ stage: 'llm'\|'planner'\|'tool'\|'runtime', message, tool?, at }]` |
| `model_generated`, `generation_json` | The F-01 flags |
| `started_at`, `completed_at` | ISO timestamps |

- **No foreign key to `users`,** so the audit trail survives a user being deleted.
- **Linking saved reports:** the frontend sends back `request_id` when saving a message. The server links it only if that run belongs to the same user; otherwise it stores `NULL` and logs a warning.
- **Schema change on startup:** `initDatabase` adds a nullable `messages.request_id` column and an index to existing databases, and creates `runs`. Existing rows are unaffected (tested against a copy of the old schema).
- **Tests:** `backend/test/runRecord.test.js` covers:
  - a completed run, including the recorded query exactly matching what was sent to OpenSearch, no raw logs in the record, and every console line tagged
  - model down
  - a failed run
  - a hung model call still visible as `running`
  - linking only to the saving user's own runs
  - migrating a database with the old schema

  A mutation check confirmed it: making one executor log line untagged fails the test.
- **Purge script:** `backend/scripts/purgeMockThreatIntel.js` doesn't scan `runs`. The table didn't exist while the mock was live, so it can't contain mock output.

## Incident note: JWT fallback exposure (F-08a)

- **Scope:** if any deployment ran with `JWT_SECRET` unset, it signed and verified tokens with a secret published in this repo. Every token it issued is forgeable, and anyone with the repo could mint new ones for any user id with `role: 'admin'` (see F-24). The code can't tell whether this happened; it depends on the deployed environment.
- **Check:** take a token issued by that deployment (browser `localStorage` key `soc_auth_token`) and verify it against the old fallback string with `jwt.verify`. If verification succeeds, the deployment was using the fallback.
- **What rotating the secret does and doesn't do:** setting a real secret and restarting invalidates all existing and forged tokens at once. It does **not** undo anything done with forged tokens during the exposure:
  - admin accounts created via `POST /api/auth/users`
  - users deleted
  - sessions, messages and SIEM results read for any user
- **Visibility gap:** there is no request or audit log (F-15), so reads can't be reconstructed. The `users` table (`created_at`) is the only place to look for accounts that shouldn't exist.

## Environment notes (2026-09-16)

- Node was installed with Homebrew as **node 26.8.2** (npm 11.19.1). With its dependencies (`lz4`, `xz`, `zstd` and others) it took more space than the ~30–40 MB estimated beforehand; the node package alone is 70.4 MB.
- `backend/node_modules` is 42 MB. npm 11 warned that `better-sqlite3`'s install script is not in `allowScripts`. The prebuilt binary loaded anyway, and all tests pass.
- There is no `backend/data/soc_chatbot.db` on this machine, so the purge script has not been run against real data here.

## Purge script limits

- The paraphrase patterns in `backend/scripts/purgeMockThreatIntel.js` (`PATTERNS`, tier `paraphrase`) cover common restatements of the mock verdict. A model could phrase it in ways they miss. **Review the dry-run output by hand before capturing fixtures.**
- The script covers `messages` and `memories`, the only stores fed back to the model. Session titles and quick queries hold user-written text only, so they aren't scanned.
- Removing a contaminated assistant message leaves its user question in the session without an answer.
