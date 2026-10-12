# Pipeline Map

How one chat question flows through the SOC assistant, and where each stage lives.
All paths are relative to the repo root. Line numbers reflect the code as first mapped on 2026-09-16. Later fixes (run logging, per-tool `raw_logs`, fixture replay hooks and others) have shifted many of them. `docs/FINDINGS.md` describes each change.

> Note: the README describes a `server/server.js` backend. The real backend is `backend/src/`.

## End-to-end flow

```
ChatPage.handleSend                         src/pages/ChatPage.jsx:203
  └─ getBackendReply  → POST /api/chat      src/pages/ChatPage.jsx:129
       └─ handleChat                        backend/src/controllers/chat.controller.js:3
            └─ processChatQuery             backend/src/services/chat.service.js:8   (greeting fast-path, no LLM)
                 └─ runAgentWorkflow        backend/src/agent/runtime.js:27
                      0. memoryManager.retrieve              (memory context)
                      1. generateLLMPlan    → LLM call #1    (planner prompt → JSON plan)
                      2. executePlan        → tools          (Wazuh API / OpenSearch queries)
                      3. evidence aggregation                (build structuredEvidence)
                      4. askFoundation      → LLM call #2    (reasoning prompt → markdown report)
                      5. memory write       → LLM call #3    (background summary, fire-and-forget)
                      6. console telemetry + return response object
  └─ saveMessageToDB  → POST /api/sessions/:id/messages   (frontend persists the reply)
```

---

## 1. Where the Wazuh query is built

There are two query paths. Security alerts and CVEs go to the **OpenSearch indexer** (`wazuh-alerts-*`). Agent and manager status goes to the **Wazuh Manager REST API** (port 55000).

### 1a. Alert/vulnerability search: OpenSearch DSL (main path)

| What | File | Function | Lines |
|---|---|---|---|
| **Builds the query DSL and sends it** | `backend/src/integrations/opensearch.integration.js` | `searchSecurityLogs(params)` | 9–85 |
| Time filter (`@timestamp` range, `gte`/`lte`) | same | same | 12–13, 20 |
| Base query: `bool`, sort desc, `size: 200` (was 10000 in an older copy; see F-14), `track_total_hits` | same | same | 15–27 |
| Severity filter (`rule.level >= minSeverity`) | same | same | 29–31 |
| IP filter (`multi_match` on `*ip*`, `full_log`, …) | same | same | 33–35 |
| Intent clauses (`brute_force` / `vulnerabilities` / free text) | same | same | 37–63 |
| Index choice (`wazuh-alerts-*` vs `wazuh-states-vulnerabilities-*`) | same | same | 67–70 |
| HTTP POST + hit extraction (`_source`, `hits.total.value`) | same | same | 72–84 |
| Tool wrapper and parameter schema shown to the LLM | `backend/src/tools/searchSecurityLogs.js` | `searchSecurityLogsTool.execute` | 3–48 |

**Where the query parameters come from** (`timeRange`, `intent`, `extractedIPs`, …):

- **Main path:** the LLM planner writes them as JSON. See `generateLLMPlan` in `backend/src/agent/planner.js:17`.
- **Fallback path** (the LLM is down or returns bad JSON): `fallbackLegacyPlanner` in `backend/src/agent/planner.js:47` fills them with regex and chrono helpers from `backend/src/utils/parser.util.js`:
  - `extractLegacyIntent` (:25)
  - `extractIPs` (:36)
  - `extractSeverity` (:44)
  - `extractTimeRange` (:61)
  - `cleanSearchQuery` (:105)

### 1b. Agent/manager status: Wazuh Manager API

| What | File | Function | Lines |
|---|---|---|---|
| Maps `status` param → WQL string (`status=active` / `status=disconnected`) | `backend/src/tools/getEndpointStatus.js` | `getEndpointStatusTool.execute` | 24–36 |
| Builds `GET /agents` query (`limit`, `select`, `q=<WQL>`) and calls it | `backend/src/integrations/wazuh.integration.js` | `getEndpointStatus(wqlStatus)` | 37–57 |
| `GET /manager/status` | same | `getManagerStatus()` | 63–80 |
| JWT auth token (cached 14 min) | same | `getWazuhToken()` | 11–31 |

Tool dispatch goes through `executePlan` (`backend/src/agent/executor.js:7`), which runs every tool in parallel, and then `executeTool` (`backend/src/tools/gateway.js:9`). Tools are registered at `backend/src/agent/runtime.js:18–21`.

---

## 2. Where the prompt sent to the model lives

### System prompts

The system prompts are string constants in **`backend/src/llm/prompts.js`**, exported as `SYSTEM_PROMPTS`:

| Key | Lines | Used by |
|---|---|---|
| `AGENT_PLANNER_PROMPT` | 17–37 | `generateLLMPlan` (planner.js:24) |
| `AGENT_REASONING_PROMPT` | 39–54 | `runAgentWorkflow` (runtime.js:137). **This prompt produces the final report.** |
| `MEMORY_SUMMARIZATION_PROMPT` | 56–66 | `summarizeInvestigation` (memory/summarizer.js:11) |
| `WAZUH_SERVER_API` | 2–5 | **Unused** (no references) |
| `STRICT_FACTUAL_RAG` | 7–15 | **Unused**. Its `{TIME_LABEL}` placeholder is never filled in. |

### User-turn prompts

Each call site builds its user-turn prompt inline:

| Call | File | Function | Line | Content |
|---|---|---|---|---|
| Planning | `backend/src/agent/planner.js` | `generateLLMPlan` | 22 | User request + `registry.listTools()` JSON |
| Reasoning (report) | `backend/src/agent/runtime.js` | `runAgentWorkflow` | 135 | User request + `structuredEvidence` JSON |
| Memory summary | `backend/src/memory/summarizer.js` | `summarizeInvestigation` | 8 | Request + final report + evidence counts |

Extra context sent with the prompts:

- `runtime.js:43` builds memory context (`preContextStr`), and `runtime.js:50` appends it as a `system` message. It reaches the **planner only**.
- The frontend sends conversation history (`ChatPage.jsx:135–142`). It reaches both the planner and the reasoner.

### Transport

The model call itself is `askFoundation(prompt, systemInstruction, conversationHistory)` in **`backend/src/llm/foundation.js:7`**.

- It builds the OpenAI-style `messages` array (system → history → user) at lines 9–17.
- It POSTs `{ model: 'foundation-sec-8b-instruct', messages }` to `LLM_API_URL` with no timeout, at lines 19–22.
- If the call fails, it returns `null`.

---

## 3. Where the model response is parsed and assembled into the final report

| Step | File | Function | Lines |
|---|---|---|---|
| Raw text extraction: `response.data.choices[0].message.content.trim()` | `backend/src/llm/foundation.js` | `askFoundation` | 24 |
| **Planner response → JSON** (slices first `{` to last `}`, else `[`…`]`) | `backend/src/llm/foundation.js` | `extractJSON(text)` | 34–55 |
| Plan validation (shape + tool names only, **no parameter schema check**) | `backend/src/schemas/ExecutionPlan.schema.js` | `validateExecutionPlan(plan, registry)` | 38–63 |
| Parse/validate failure → legacy plan | `backend/src/agent/planner.js` | `generateLLMPlan` catch → `fallbackLegacyPlanner` | 38–41 |
| **Evidence aggregation**: `structuredEvidence`, `totalHits`, `rawLogsToReturn`, `sourceLabel`; log minification (first 30 logs → `time/level/desc/srcip/user/agent/cve`) | `backend/src/agent/runtime.js` | `runAgentWorkflow` (step 3) | 71–124 |
| **Report generation**: reasoning LLM call. The markdown text is used **as-is, with no parsing**. There is a zero-hits canned message and a fallback string if the LLM returns `null`. | `backend/src/agent/runtime.js` | `runAgentWorkflow` (step 4) | 129–140 |
| **Final response object**: `{ type: 'agent_response', source, summary, raw_logs, total_hits, footer }` | `backend/src/agent/runtime.js` | `runAgentWorkflow` (step 6) | 170–177 |
| Memory-summary response `JSON.parse` (falls back to raw string) | `backend/src/agent/runtime.js` | `runAgentWorkflow` (step 5) | 147–156 |

### Frontend rendering of the report

| What | File | Function / location |
|---|---|---|
| Reply merged into the message list | `src/pages/ChatPage.jsx` | `handleSend`, lines 256–266 |
| `agent_response` → report text | `src/pages/ChatPage.jsx` | JSX, lines 500–502 |
| Markdown-ish tokenizer (only `**bold**`, `*italic*`, newlines) | `src/components/ChatMessage.jsx` | `parseToTokens` (:6), `MarkdownRenderer` (:31), `Typewriter` (:44) |
| "View Full Details" raw-log view (field extraction, severity bands, top IPs/users/hosts) | `src/components/LogDetailsModal.jsx` | `extractFields` (:6), `LogDetailsModal` (:65) |

---

## 4. Where runs are logged

**There is no dedicated run log, audit table or log file.** Run information goes to three places:

### 4a. Console (stdout/stderr of the backend process only)

| Log line | File | Function | Line |
|---|---|---|---|
| `[Context Initialized] RequestID: …` | `backend/src/agent/context.js` | `AgentContext` constructor | 17 |
| `[Planner LLM Success] … Thought: "…"` / `[Planner LLM Failure] …` | `backend/src/agent/planner.js` | `generateLLMPlan` | 35 / 39 |
| `[Executor] Executing plan…` / `…complete` | `backend/src/agent/executor.js` | `executePlan` | 8 / 19 |
| `[Gateway Executing] Tool: … Params: …` / Success / Failure / not-found | `backend/src/tools/gateway.js` | `executeTool` | 30 / 38 / 41 / 23 |
| `Foundation-sec-8B Unreachable…` | `backend/src/llm/foundation.js` | `askFoundation` | 26 |
| **`[Runtime Complete] RequestID`** + **`[Telemetry] Plan/Exec/Agg/Reason/Total ms`** | `backend/src/agent/runtime.js` | `runAgentWorkflow` (step 6) | 165–168 |
| `[Memory Writer] Saved …` | `backend/src/memory/writer.js` | `writeMemory` | 16 |
| `Controller Error: …` | `backend/src/controllers/chat.controller.js` | `handleChat` | 19 |

### 4b. SQLite `messages` table (`backend/data/soc_chatbot.db`)

The backend does **not** save the chat reply itself. The **frontend** saves it after it receives the reply:

1. `saveMessageToDB` in `src/pages/ChatPage.jsx:178` (called at :255 for the user message and :269 for the reply)
2. `POST /api/sessions/:id/messages` (`backend/src/routes/session.routes.js:23`)
3. `saveSessionMessage` in `backend/src/controllers/session.controller.js:37`
4. `MessageModel.create` in `backend/src/models/Message.js:5`

The table schema is in `initDatabase` (`backend/src/config/db.js:52–68`).

- **Saved:** `role, type, text, summary, raw_logs, total_hits`
- **Not saved:**
  - `source`
  - `footer` (which contains the runtime ms)
  - `requestId`
  - the plan / planner "thought"
  - the prompts sent
  - per-stage telemetry
  - tool errors

### 4c. SQLite `memories` table

`runAgentWorkflow` step 5 (`runtime.js:146–160`) writes to this table through `writeMemory` (`memory/writer.js:7`), then `SqliteMemoryProvider.saveMemory` (`memory/providers/SqliteMemoryProvider.js:51`).

- Runs with results: an LLM-compressed investigation summary is saved as long-term memory.
- Runs without results: a `{user, bot}` exchange is saved as short-term memory.

This table is agent memory, not an audit log.

> `src/components/TerminalFeed.jsx` looks like a live run log in the UI but is a **hard-coded script** (`SCRIPT`, line 6). It is not connected to real runs.

---

## Observations (noted while mapping; no code changed)

1. **Runs can't be traced end-to-end.** The `requestId` appears only in the console. It isn't returned to the client or stored with the message, so a saved report can't be matched to its console telemetry or plan.
2. **LLM plan parameters aren't checked against the tool schema.** For example, if the planner leaves out `minSeverity`, then `undefined !== null` is true (`opensearch.integration.js:29`), and a `rule.level` range with `gte: undefined` gets added to the query.
3. **Multiple tools overwrite each other's `raw_logs`.** `rawLogsToReturn` is reassigned for each tool (`runtime.js:93, 102`), so the "View Full Details" logs come from whichever tool finished last in the loop.
4. **Up to 200 raw logs per search are sent to the browser and stored in SQLite for every reply** (`size: 200`; F-14 originally said 10,000). The LLM only sees 30 of them.
5. **User text goes into the prompts unescaped** (`planner.js:22`, `runtime.js:135`), which is a prompt-injection surface.
6. **Two system prompts (`WAZUH_SERVER_API`, `STRICT_FACTUAL_RAG`) are dead code.**
7. ~~`lookupThreatIntel` returns mock data that feeds into the report.~~ **Fixed 2026-09-16.** The tool now returns `{ available: false, reason }`. The runtime lists it under `structuredEvidence.unavailableSources` (never under `evidence`) and appends `THREAT_INTEL_ABSENT_NOTE` to the report. Regression test: `backend/test/threatIntel.test.js`. Line numbers in `runtime.js` above shifted by about 20 lines after step 3.
