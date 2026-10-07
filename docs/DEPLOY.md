# Deploying `main`

**For:** Abdulhakeem, on the Windows production host.
**Production today:** `c0e2010` ("Push 26"). **Deploying:** current `main`.
**Time needed:** about 30 minutes, including a short backend restart.

All work now happens on `main`, so pulling it brings **everything** below, not just the earlier hotfix. **Do not skip steps 2 and 3:** the new backend refuses to start without `JWT_SECRET`, and it changes the database on its first start.

## What changes

| Area | Change | Effect on deploy |
|---|---|---|
| **Fabricated tools** | `blockIpAction` and `checkProcessList` (fake "IP blocked" and fake `unknown_miner`) can no longer be used | none |
| **Routing** | Security questions like "show me failed logons today" now search Wazuh instead of being answered with no data (F-43) | none |
| **Threat intel** | The mock "not malicious, threat score 10" no longer reaches reports (F-00) | none |
| **Login security** | No hard-coded JWT fallback secret (F-08a) | **`JWT_SECRET` must be set, or the backend won't start.** Setting a new one logs every user out once. |
| **Chat history** | Clients can no longer inject system instructions (F-06) | none |
| **Honesty** | Fallback answers are labelled as not model-generated (F-01) | none |
| **Run logging** | Every question gets a run record and a request ID | **Database migration on first start** (adds `messages.request_id` and the `runs` table) |
| **Assistant chat** | ChatGPT-style chat with streaming, plus a **Search Wazuh** toggle | **Frontend needs `npm ci`** (two new packages) |
| **Scripts** | Backup, read-only DB report, audit, purge, capture/replay | none |

Backend dependencies are unchanged, so the backend needs no `npm install`.

---

## Steps (PowerShell)

```powershell
$REPO = 'C:\path\to\ChatBot'
```
Use the folder that contains `backend\` and `src\`.

### 1. Check what's running now

```powershell
cd $REPO; git status; git log -1 --oneline
```
Expected: a clean working tree at `c0e2010 Push 26`. If there are local changes, stop and report them; don't overwrite them.

### 2. Back up the database (backend can stay running)

Pull first, so the backup script exists, but **don't restart anything yet**:
```powershell
cd $REPO; git pull; git log -1 --oneline
```
```powershell
cd $REPO\backend; node scripts\backupDb.js
```
Expected: `Backup OK: …\data\soc_chatbot.backup-<timestamp>.db`, followed by `integrity_check: ok` and a row count per table. **Anything else: stop.**

Pulling doesn't affect the running backend. Node already has the old code loaded until the restart.

### 3. Set `JWT_SECRET`

```powershell
if (Select-String -Path "$REPO\backend\.env" -Pattern '^JWT_SECRET=\S' -Quiet) { 'JWT_SECRET: already set' } else { 'JWT_SECRET: NOT set' }
```
If it's not set, generate one and add it. This prints nothing secret to the screen:
```powershell
$secret = node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"; Add-Content -Path "$REPO\backend\.env" -Value "JWT_SECRET=$secret"; Remove-Variable secret; 'JWT_SECRET added'
```
**If it was *not* set before,** production has been signing login tokens with the old secret that was published in the source code, so tokens could have been forged. Setting a real secret invalidates them all. See the incident note in `docs/FINDINGS.md`, and check the user list in step 6 for accounts nobody recognises.

### 4. Frontend packages

```powershell
cd $REPO; npm ci
```
Then rebuild and restart the frontend **the way it's normally run** (for example `npm run build` and serving `dist\`, or restarting `npm run dev`).

### 5. Restart the backend

Stop it and start it the normal way. Expected startup lines:
```
[Database] All tables and indexes verified.
[Server] Instance ID: …
🚀 AI SOC Proxy Server running on port 3002
```
If you instead see `❌ FATAL CONFIG ERROR: JWT_SECRET is not set`, step 3 didn't take effect: check `backend\.env`, or wherever the service reads its environment.

### 6. Confirm the migration and the users (read-only)

```powershell
cd $REPO\backend; node scripts\dbReport.js
```
Expected last line: `run-logging migration applied: messages.request_id=yes, runs table=yes (…)`. Check the **usernames** list for anyone who shouldn't be there.

### 7. Audit for fabricated results (read-only)

```powershell
cd $REPO\backend; node scripts\auditFabricatedActions.js; $LASTEXITCODE
```
This lists saved messages and memories containing `IP_BLOCKED`, `unknown_miner`, `blocklist` or the old threat-intel mock text, with date, user and snippet. **Exit codes:** `0` none found, `2` matches listed, `1` error.
- **`IP_BLOCKED` and `unknown_miner` are definite:** someone was shown a fake block or a fake miner. Each needs a human follow-up.
- **`blocklist`** also matches legitimate advice, so read those snippets.
- **Memory matches** keep influencing the planner. Report them; don't delete anything by hand.

### 8. Smoke test in the browser

Log in again (everyone is logged out if the secret changed), then:

1. **Chat mode** (Search Wazuh off): ask `Write a two-line status update for the team`.
   - **Pass:** the answer streams in word by word; it has a Copy button and no "Searched Wazuh" badge.
2. **Chat mode, data question:** ask `show me failed logons today`.
   - **Pass:** the answer says it hasn't searched your data and offers **Search Wazuh for this**. It must not invent numbers.
3. Click **Search Wazuh for this**.
   - **Pass:** an answer marked **Searched Wazuh**, with **View Full Details**.
4. **Stop:** ask for something long and press the red stop button mid-answer.
   - **Pass:** the partial answer stays, marked "Stopped".
5. Ask `Block the IP that attacked us most today`, with Search Wazuh **on**.
   - **Pass:** nothing claims an IP was blocked or added to a blocklist.

### 9. Send back

1. The output of steps 2, 6 and 7.
2. `git log -1 --oneline` after the pull.
3. Whether `JWT_SECRET` was already set (yes/no only, never the value).
4. Smoke-test results, and the text of any answer that looked wrong.

The audit and DB report outputs contain usernames and fragments of security reports, so use the usual internal channel.

---

## Rollback

1. Stop the backend.
2. Restore the database from the step 2 backup (copy it over `data\soc_chatbot.db`), and delete `soc_chatbot.db-wal` and `soc_chatbot.db-shm` if present.
3. Go back to the previous code, then reinstall frontend packages and restart both:
```powershell
cd $REPO; git checkout c0e2010; npm ci
```
**Rolling back re-enables the fabricated tools, the JWT fallback and the misrouting.** Report straight away if you have to.

## New optional settings (`backend\.env`)

`LLM_CHAT_MAX_TOKENS` (1024), `LLM_CHAT_TEMPERATURE` (0.5), `LLM_STREAM_FIRST_TOKEN_TIMEOUT_MS` (60000), `LLM_STREAM_IDLE_TIMEOUT_MS` (30000), `LLM_CHAT_HISTORY_CHAR_BUDGET` (24000). Defaults in brackets; see `docs/ASSISTANT_CHAT.md`.

**One backend process per database file:** a second process starting would mark the first one's in-flight requests as interrupted (F-31).
