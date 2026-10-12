# Assistant Chat

How SOC Assistant's general chat works: a ChatGPT-style conversation with the model, alongside the existing Search Wazuh investigations. Added 2026-10-07.

## The two modes

| | **Chat** (default) | **Search Wazuh** (toggle in the composer) |
|---|---|---|
| For | Everyday work: writing and editing, explaining concepts or log lines, scripts and code, tables, planning, general security questions | Questions about *your* live data: alerts, failed logons, agents, firewall activity, CVEs |
| What happens | The message goes to the model, and the answer streams back token by token | The agent pipeline plans a search, queries OpenSearch and Wazuh (with the firewall split), and the model writes a report from the evidence |
| Endpoint | `POST /api/chat/stream` (server-sent events) | `POST /api/chat` (JSON) |
| Can see security data | **No.** The model is told so and must say so. | Yes: the evidence from the search |
| Answer label | none | "Searched Wazuh" badge, plus View Full Details |

**Choosing the mode:** the toggle is remembered per browser. In Chat mode, a question that looks like it needs live data ("show me failed logons today", anything with an IP address) gets an honest answer plus a **Search Wazuh for this** button, which re-asks the same question as a search.

## Why the browser doesn't call the model directly

The browser talks to the backend, and the backend talks to the model — the same architecture as ChatGPT, Gemini and Claude:
- **The model endpoint has no authentication** (see FINDINGS, "which model `askFoundation` calls"). Exposing it to browsers would let anyone on the network use it.
- **The safeguards live in the backend:** login check, history sanitizer (F-06), honest system prompt, timeouts, run records and request-ID logging.

## What the model is sent

1. **A system prompt** (`GENERAL_ASSISTANT_PROMPT` in `backend/src/llm/prompts.js`) with **today's date**, since models have no clock. It tells the model to answer directly, use Markdown, admit uncertainty, and never invent facts. It also says plainly that the model **cannot see** Wazuh, OpenSearch, firewall data or any live system, must never invent alerts, counts, IPs, hostnames, usernames or log entries, and must suggest "Search Wazuh" for live-data questions.
2. **Recent conversation**, newest first until the history budget is used up. Only real user and assistant turns are included: never the welcome message, error notices, unfinished answers, or `system` / `developer` / `tool` roles from the client.
3. **The new message**, always (up to 40,000 characters; longer is rejected with HTTP 413).

## Streaming protocol (`POST /api/chat/stream`)

**Request:** `{ "text": "...", "history": [{ "role": "user" | "assistant", "content": "..." }] }`, with an `Authorization: Bearer <token>` header.

**Response:** `text/event-stream`:

| Event | Data | When |
|---|---|---|
| `meta` | `{ request_id, mode: "chat" }` | First, always |
| `token` | `{ text }` | Each piece of the answer as the model generates it |
| `error` | `{ code, message }` | `model_unavailable` (refused, reset, HTTP error) or `model_timeout`. `message` is user-facing and honest. |
| `done` | `{ request_id, mode, model_generated, truncated, finish_reason, suggest_search }` | Last, always |

**Failures:**
- **Model down:** an `error` event over HTTP 200, never a 503, and nothing invented.
- **Model hangs:** gives up after `LLM_STREAM_FIRST_TOKEN_TIMEOUT_MS` (F-03 on this path).
- **Model stalls mid-answer:** gives up after `LLM_STREAM_IDLE_TIMEOUT_MS`, keeping the partial text, which is marked as incomplete.
- **Stop in the UI:** cancels the request to the model as well.
- **Servers that ignore `stream: true`** and return plain JSON work too.

## Search Wazuh, streamed (`POST /api/chat/search/stream`, Phase 7)

Search answers are verified before anyone sees them, so the model's raw tokens are never streamed.
What streams is true at the moment it is shown:

| Event | Data | When |
|---|---|---|
| `meta` | `{ request_id, mode: 'search' }` | the run starts |
| `stage` | `{ stage, label }` | `planning`, `reading` (follow-up), `searching`, `analysing`, `verifying`, as each actually starts |
| `report` | `{ markdown }` | the answer so far: the code-written header as soon as the searches finish, then again each time a statement passes verification |
| `error` | `{ message }` | the run failed |
| `done` | `{ response }` | last: exactly what `POST /api/chat` returns |

The final answer is always rebuilt from the model's complete output, and a test pins that it matches
the non-streamed answer. Stop cancels the model request; the run is recorded as `stopped`.

**Follow-ups.** The browser sends `follow_up_of` (the latest search answer's `request_id`). If the
question refers back ("that IP", "tell me more", "which one") or names a rule, agent, IP or user from
that evidence, it is answered from it without planning or searching, opens with "Answered from the
evidence of your previous search", and offers **Search again**. A time window or "search again / latest"
always searches. The evidence is kept in memory per user for `FOLLOW_UP_TTL_MS` (2 hours).

**Clarifying questions.** A request that can't be answered without guessing a key detail ("is that IP
malicious?" with no IP and no previous search, or just "check") gets one short question starting
"Quick question before I search:". The planner may also ask, only with no searches planned and only one
short question. The reply is combined with the original question and is never asked about again.

## Settings (all optional, in `backend/.env`)

| Variable | Default | Meaning |
|---|---|---|
| `LLM_CHAT_MAX_TOKENS` | `1024` | Longest answer, in tokens. When reached, the answer is marked "cut off"; the user can ask "continue". |
| `LLM_CHAT_TEMPERATURE` | `0.5` | Randomness. Lower is more consistent; higher is more varied. |
| `LLM_STREAM_FIRST_TOKEN_TIMEOUT_MS` | `60000` | Wait for the first token before giving up |
| `LLM_STREAM_IDLE_TIMEOUT_MS` | `30000` | Wait between tokens before giving up |
| `LLM_CHAT_HISTORY_CHAR_BUDGET` | `24000` | Conversation history sent per message, in characters (≈ 6,000 tokens). Lower it if the model's context window is small. |

## In the UI

- **Live rendering:** answers stream in with a cursor, as Markdown — headings, lists, tables, and code blocks with a Copy button.
- **Honest status:** "Thinking…" until the first token arrives; "Searching Wazuh and firewall data…" during a search. No simulated activity.
- **Stop:** keeps the partial answer, marked "Stopped. This answer is incomplete."
- **Copy:** under every answer. A fallback makes it work on plain-HTTP pages too.
- **Safety:** **images in model output are not rendered** (a model-written image URL would be fetched automatically by the browser, which can leak conversation content), raw HTML is not rendered, and links open in a new tab with `noopener noreferrer`.
- **Auto-scroll:** follows new output only while you're at the bottom; scroll up to read and it stops following.
- **Keyboard:** Enter sends, Shift+Enter adds a new line.

## Observability

Every chat is a row in `runs`, under the same request ID that tags its console lines (`[req:<id>]`):
- `generation_json.mode = "chat"`
- `report`: `model`, `model_truncated`, `stopped` or `fallback_model_unavailable`
- `timings_json.firstTokenMs` and `totalDuration`
- `errors_json`, with stage `llm` or `client`

Saved answers link to their run through `messages.request_id`. Error notices are not saved as messages, so they can't come back later as history the model never wrote.

## Tests

- `backend/test/assistantStream.test.js` (14 tests) runs against a local fake model server. It covers token streaming, what the model receives, auth, model down, hang, stall, length limit, HTTP 500, non-streaming servers, Stop cancelling upstream (and the run record), history trimming, the search suggestion, the run record, and input limits.
- `src/lib/chatStream.test.js` (5 tests, `npm test` at the repo root) covers the browser's SSE parser (every chunk split, CRLF), the stream client, and which turns go into history.
- Mutation-checked: skipping the history sanitizer, removing the honesty rule, disabling timeouts, Stop not cancelling, and reporting an outage as success are each caught.

## Not done yet

See FINDINGS F-49 to F-53: no regenerate or edit, no per-user rate limit, flags like "stopped" or "cut off" aren't saved with the message, the large frontend bundle, and the Search Wazuh routing nuance (F-48).
