# Capture Runbook: Windows Backend Host

Instructions for one trip to the Windows machine that runs the backend. By the end you will have:

1. **A verified backup** of the live database.
2. **A read-only database report:** row counts for `messages`, `memories` and `users`, the message date range, the usernames, plus `LLM_API_URL` and whether `JWT_SECRET` is set.
3. **Four fixture files,** one per question, for replay on the Mac:
   - "what is going on right now"
   - "anything unusual on the AD servers"
   - "show me failed logons today"
   - "what are the top alerts this week"

These four fixtures become the **baseline**. Back on the Mac they're replayed and scored with `evals/check.py` against `evals/STANDARD.md`, and every later change is measured against that score. The score is of the answer the live model gave during capture, so **the model must be working during capture** (step 7 says how to check).

## Read this first

- **The live backend is not touched.** You'll run the updated code from a *separate* folder (`C:\soc-capture`). The live backend folder, its running process and its database stay as they are. The only things run against the live database are the backup (read-only source) and the report (read-only).
- **Capture never opens the live database.** It creates a scratch SQLite database in the Windows temp folder and deletes it at the end. So capture can't migrate the live database, and memories or chat history in the live database (including any old mock threat-intel contamination) can't influence the captured planner output.
- **The updated backend auto-migrates on startup.** The first time `src\server.js` from the updated code starts against a database, it:
  - adds a `messages.request_id` column and an index
  - creates the `runs` table
  - rebuilds `runs` if an earlier version of it exists

  That's why **step 3 (backup) comes before anything else touches the database** (step 2 only unpacks files), and why you must **not** start `server.js` from `C:\soc-capture` pointed at the live data. Deploying the updated backend is a separate change, covered at the end.
- **The updated backend also refuses to start without a strong `JWT_SECRET`** (F-08a, F-23): at least 32 random characters, and not the old published value. This doesn't affect capture, but step 4 checks for it so you know before any deployment.
- **One backend process per database file (F-31).** On startup the backend marks every request still recorded as "running" by a *different* process as **interrupted**, because a single backend can't have two lives. Starting a second backend against the same database — for example `server.js` from `C:\soc-capture` while the live one runs — would wrongly mark the live backend's in-flight requests as interrupted. Capture itself doesn't start a backend and uses its own scratch database, so it's safe. To see whether a backend is already listening, run `Get-NetTCPConnection -LocalPort 3002 -State Listen -ErrorAction SilentlyContinue`.
- **Fixtures contain real security telemetry, unredacted.** That includes internal IPs, hostnames, usernames and raw alert and agent data. Handle them like the SIEM data they are: never commit them, email them, paste them into chat, or put them in synced or cloud folders. `fixtures/` and `quarantine/` are gitignored.
- **Never recorded, with or without redaction:** request headers (which carry the Wazuh/OpenSearch credentials), the Wazuh API token, and the OpenSearch, Wazuh and model base URLs (replaced with `<OPENSEARCH_URL>` and similar).

**Time needed:** about 15 minutes of setup, plus capture time. Capture is dominated by model latency: each question makes up to 3 model calls, and each question gives up after 10 minutes (hangs are F-03).

---

## 0. On the Mac, before the trip

Run the tests and the checker's self-test; all must pass:
```bash
cd /Users/solomonalor/Documents/ChatBot/backend && npm test
```
```bash
cd /Users/solomonalor/Documents/ChatBot && python3 evals/check.py evals/synthetic --expect
```
The self-test ends with `Checker self-test: N/N synthetic case(s) behaved as expected`.

**For the baseline capture, use the bundle already built from `b346a38` (Phase 3) and don't rebuild it from a later commit.** The baseline must measure the answers production gives today; Phase 4 changed how answers are written. If the bundle has to be rebuilt, check out `b346a38` first (`git checkout b346a38`, build, then `git checkout main`).

Build the bundle. It contains only `package.json`, `package-lock.json`, `.gitignore`, `src/` and `scripts/`, with no `.env`, `node_modules`, `data`, `fixtures`, `quarantine` or tests:
```bash
cd /Users/solomonalor/Documents/ChatBot && zip -r ~/Desktop/soc-capture-bundle.zip backend/package.json backend/package-lock.json backend/.gitignore backend/src backend/scripts -x '*.DS_Store'
```

Expected: `adding: …` lines. The file `~/Desktop/soc-capture-bundle.zip` is about 110 KB (about 270 KB unpacked, 80 files).

Transfer the zip to the Windows machine by your approved method. It contains code only, no secrets.

---

## On the Windows machine (PowerShell)

Open **PowerShell** (not cmd). Replace the path in step 1 with the real location of the live backend folder: the one containing `.env`, `data\soc_chatbot.db` and `node_modules`.

### 1. Locate the live backend and check Node

```powershell
$LIVE = 'C:\path\to\ChatBot\backend'
```
```powershell
Test-Path "$LIVE\data\soc_chatbot.db"; Test-Path "$LIVE\.env"; Test-Path "$LIVE\node_modules\better-sqlite3"
```
Expected: `True` three times. If `.env` is `False`, the backend gets its settings some other way (system environment variables or a service manager). See Troubleshooting.

```powershell
node --version
```
Expected: `v18` or newer. On anything older, stop here: the scripts need Node 18+.

### 2. Set up the capture folder beside the live backend

```powershell
Expand-Archive -Path "$HOME\Downloads\soc-capture-bundle.zip" -DestinationPath 'C:\soc-capture'
```
Adjust the zip path if you saved it somewhere else. Expected result: `C:\soc-capture\backend\` containing `package.json`, `package-lock.json`, `src\` and `scripts\`.

Copy the live settings and installed packages. Dependencies are unchanged, and the live `node_modules` already has `better-sqlite3` built for this machine, so nothing needs installing:
```powershell
Copy-Item "$LIVE\.env" 'C:\soc-capture\backend\.env'
```
```powershell
Copy-Item "$LIVE\node_modules" 'C:\soc-capture\backend\node_modules' -Recurse
```
```powershell
cd C:\soc-capture\backend
```

**Do not** copy `data\`. Capture doesn't use it.

### 3. Back up the live database (mandatory, before anything else)

This is safe while the backend is running. It uses SQLite's online backup through a read-only connection, includes changes still in the WAL file, and verifies the copy:
```powershell
node scripts\backupDb.js --db "$LIVE\data\soc_chatbot.db"
```
Expected output:
```
Backup OK: C:\path\to\ChatBot\backend\data\soc_chatbot.backup-20260917-101500.db
  size: 1234567 bytes, integrity_check: ok
  memories: 42 rows
  messages: 310 rows
  quick_queries: 3 rows
  sessions: 57 rows
  users: 4 rows
```
Anything other than `Backup OK` (for example `BACKUP FAILED: …`) means **stop**: don't continue without a verified backup. The backup contains all chat history and SIEM results, so keep it where the live database lives, under your retention policy.

### 4. Database report and settings check (read-only)

```powershell
node scripts\dbReport.js --db "$LIVE\data\soc_chatbot.db"
```
Expected output shape:
```
Database: C:\path\to\ChatBot\backend\data\soc_chatbot.db (opened read-only)
messages: 310
memories: 42
users:    4
message date range: 2026-03-01T10:00:00.000Z -> 2026-09-16T18:30:00.000Z
usernames:
  admin (admin, created 2026-03-01T09:58:12.000Z)
  analyst1 (user, created 2026-03-02T11:20:40.000Z)
run-logging migration applied: messages.request_id=no, runs table=no
```
The last line should say `no` / `no`, which confirms the live database hasn't been migrated. The report uses SQLite's read-only flag; it can't change or create anything.

**For reference, the equivalent SQL** (all read-only):
```sql
SELECT COUNT(*) FROM messages;
SELECT COUNT(*) FROM memories;
SELECT COUNT(*) FROM users;
SELECT MIN(created_at), MAX(created_at) FROM messages;
SELECT username, role, created_at FROM users ORDER BY created_at;
```

**Settings check.** This prints the model endpoint and only *whether* the JWT secret is set, never its value:
```powershell
Select-String -Path "$LIVE\.env" -Pattern '^LLM_API_URL='
```
```powershell
if (Select-String -Path "$LIVE\.env" -Pattern '^JWT_SECRET=\S' -Quiet) { 'JWT_SECRET: set in .env' } else { 'JWT_SECRET: NOT set in .env' }
```
If `JWT_SECRET` isn't in `.env`, the live backend may still get it from the service or system environment. Check how the backend process is launched (for example its service definition). If it's truly unset, the live backend has been signing tokens with the old fallback secret (see the incident note in `docs/FINDINGS.md`), and the updated backend will refuse to start until it's set.

**Save the output of this whole step** (copy the PowerShell text into a local file). It comes back with you.

### 5. Optional: purge dry run on the live database

This checks the live database for old mock threat-intel contamination. It **doesn't change anything** without `--apply`, and capture doesn't depend on it, because capture never reads the live database. Run `--apply` only as a deliberate decision, with the step 3 backup in place.
```powershell
node scripts\purgeMockThreatIntel.js --db "$LIVE\data\soc_chatbot.db"
```
Expected: `Clean: no mock threat intel found.` (exit code 0), or a list of matches ending in `Dry run. Re-run with --apply to quarantine these records.` (exit code 2). Include the output with the step 4 notes.

**If it prints nothing at all,** the script didn't run (known Windows issue F-36: drive-letter case). That's a no-op, not a clean result. Skip this optional step and note it.

### 6. Pre-flight check (no network, writes nothing)

```powershell
node scripts\captureFixtures.js --check
```
Expected:
```
Settings (values not shown): OPENSEARCH_URL=set WAZUH_SERVER_API_URL=set WAZUH_USER=set WAZUH_PASSWORD=set LLM_API_URL=set
Output directory: C:\soc-capture\backend\fixtures
Questions (4): "what is going on right now", "anything unusual on the AD servers", "show me failed logons today", "what are the top alerts this week"
Redaction: off
READY
```
If it says `NOT READY: missing …`, see Troubleshooting. Don't continue until it says `READY`.

### 7. Capture

```powershell
node scripts\captureFixtures.js
```
```powershell
$LASTEXITCODE
```
Expected output: backend log lines tagged `[req:<id>]`, and for each question a summary line like:
```
[Capture] (2/4) "anything unusual on the AD servers"
...
[Capture]   -> anything-unusual-on-the-ad-servers.json: status=completed planner=model opensearch=2 wazuh=1 llm=3 failedCalls=0 hits=4210 model_generated=true errors=0 size=0.61MB
...
[Capture] Done: 4/4 completed. Manifest: C:\soc-capture\backend\fixtures\manifest.json
```

**Exit code 0 and `4/4 completed` do NOT prove data was captured** (F-38). `completed` only means the pipeline returned. If the model, OpenSearch or Wazuh were unreachable, capture still reports `completed`, with fallback plans and failed calls. Always check the per-question fields below.

**`$LASTEXITCODE`:**
- **`0`:** all four completed.
- **`2`:** at least one didn't complete (`timeout`, `failed` or `no_run`). **Still copy everything back:** a `timeout` fixture is direct evidence of the F-03 model hang.
- **`1`:** a setup error; the message says what.

**What to look for in each summary line:**
- **`planner=model`:** the model produced the plan. `planner=fallback_rules` means the model couldn't be reached or returned unusable output, and the rule-based planner ran instead. The fixture is still valid, but it doesn't capture the model's plan. Note it.
- **`opensearch=`:** should be at least 1 for all four questions.
- **`failedCalls=`:** should be 0. If not, an OpenSearch, Wazuh or model call returned an error, which is recorded in the fixture.
- **`model_generated=true`:** needed for every question. It means the live model wrote the captured answer, which is what the baseline scores. `model_generated=false` means the captured answer is a fallback notice (model unreachable, or no hits at all, where the system writes the answer itself). For a question with hits, that fixture can't serve as a baseline: note it and re-run just that question once the model responds (see Troubleshooting for `--questions-file`).
- **`size=`:** each search returns up to 200 hits plus the exact total, so files are usually well under 5 MB.

**If a question seems stuck:** wait. It gives up after 10 minutes, then moves on. Press Ctrl+C only if the whole run is stuck well beyond that; files already written are kept.

**Redaction (off by default, as agreed).** If you're required to redact, use `--redact`, and add each AD or internal domain name with `--redact-term`:
```powershell
node scripts\captureFixtures.js --redact --redact-term CORP --redact-term corp.example.com
```
See "What `--redact` masks" below before relying on it.

### 8. Verify the output

```powershell
Get-ChildItem .\fixtures | Select-Object Name, Length
```
Expected: five files:
- `anything-unusual-on-the-ad-servers.json`
- `manifest.json`
- `show-me-failed-logons-today.json`
- `what-are-the-top-alerts-this-week.json`
- `what-is-going-on-right-now.json`

```powershell
Get-Content .\fixtures\manifest.json
```
Check each entry's `status` (ideally `completed`) and `plannerSource`.

### 9. Copy back to the Mac

**Bring back:**
1. `C:\soc-capture\backend\fixtures\`, all five files.
2. The saved text output from steps 3, 4 and 5.

**Do not bring back:**
- `.env`, which holds credentials
- `node_modules`
- the database backup, which stays on the host

Use your approved secure transfer. Not git, email, chat or cloud-synced folders.

### 10. Clean up on Windows (after the transfer is confirmed)

```powershell
cd $HOME; Remove-Item -Recurse -Force 'C:\soc-capture'
```
This removes the copied `.env` (credentials) and the local copy of the fixtures. Also delete the downloaded `soc-capture-bundle.zip`. The scratch capture database was already deleted by the script. Keep the step 3 backup.

The live backend was never modified. Only the backup file was added next to its database.

---

## Back on the Mac: replay and baseline

Put the five files into `backend/fixtures/`. That folder is gitignored; create it if it doesn't exist.

```bash
cd /Users/solomonalor/Documents/ChatBot/backend && node scripts/replayFixtures.js --out ../baseline
```
Expected:
```
[Replay] 4 fixture(s) from /Users/solomonalor/Documents/ChatBot/backend/fixtures (model calls disabled)
[Replay] OK       anything-unusual-on-the-ad-servers.json request_id=… hits=4210 report=fallback_model_unavailable
...
[Replay] Baseline records written to /Users/solomonalor/Documents/ChatBot/baseline. Score them with: python3 ../evals/check.py …
[Replay] 4/4 matched the capture.
```
Then score the baseline:
```bash
cd /Users/solomonalor/Documents/ChatBot && python3 evals/check.py baseline --json baseline/scores.json
```
This prints one line per question (`PASS`/`FAIL`, score, fabrication count), the hard checks each answer failed, and the mean. `baseline/scores.json` has the details. `baseline/` holds real telemetry and production answers, so it's gitignored like `fixtures/`.

**How replay works:**
- With `FIXTURES=1` (which the script sets), `generateLLMPlan` returns the captured plan, and the OpenSearch and Wazuh clients return the captured responses.
- A request that doesn't exactly match the recording fails loudly (`Fixture miss …`) instead of calling anything live.
- **No model is called.** The script replaces `LLM_API_URL` with an unreachable address, even if `backend/.env` points at the live model, so the replayed report is the "model unavailable" notice and `report=fallback_model_unavailable` is expected. `--allow-model` turns this off; don't use it without an approved model endpoint.
- **What the baseline scores:** each record in `baseline/` is the fixture (captured evidence and the answer production gave, under `result.report`) plus the replay verdict under `replay`. A record whose replay `DIVERGED` still scores, but the divergence means today's code no longer builds the same queries; report it.
- **Synthetic cases are refused.** Replay rejects any file marked `synthetic` (the checker's invented test cases in `evals/synthetic/`), so they can never end up in a baseline.
- To use replay through the app instead, start the backend with `FIXTURES=1`. Only the four fixture questions will work; any other question fails the run with "no fixture for the question".

---

## What `--redact` masks (and doesn't)

Redaction is **off by default**. When on:

**Masked**, consistently within each fixture (the same value always becomes the same token; the mapping isn't saved):
- **Internal IPv4 addresses** (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `100.64/10`) anywhere in the file, as `INTERNAL_IP_n`.
- **Hostnames and domains taken from recognized fields,** as `HOST_n`:
  - `agent.name`, `manager.name`, `cluster.name`, `host.name`, `predecoder.hostname`
  - any field named `hostname`, `host`, `computer`, `workstationName`, `srchost`, `dsthost`, `targetServerName`, `fqdn`, `domain`, `targetDomainName`, `subjectDomainName` (case-insensitive)
  - `DC01$` machine accounts are treated as the host `DC01`
- **Usernames taken from recognized fields,** as `USER_n`: `user`, `username`, `srcuser`, `dstuser`, `targetUserName`, `subjectUserName`, `accountName`, `samAccountName`, `userPrincipalName`, `logonUser`, `owner` and similar. `DOMAIN\user` and `user@domain` are split into a host and a user.
- **Every occurrence of those collected values anywhere else:** `full_log`, rule descriptions, model prompts and responses, the report, error messages.
- **Anything passed with `--redact-term`,** as `REDACTED_TERM_n`.

**Not masked:**
- **Public IP addresses:** kept on purpose, since attacker sources are the point of the data.
- **IPv6 addresses,** including internal ones (`fd00::/8`, `fe80::`).
- **Names that appear only in free text** and never in a recognized field. For example, a username that exists only inside a Windows event message, or a server named only in `full_log`.
- **Internal or AD domain names,** unless they're in a recognized field or passed with `--redact-term`.
- **Other identifiers:** email addresses (outside user fields), SIDs (`S-1-5-21-…`, which identify the domain), MAC addresses, GUIDs, Wazuh agent IDs, file and registry paths, command lines and URLs. A path like `C:\Users\jdoe` is masked only if `jdoe` was also collected from a user field.
- **Values shorter than 3 characters,** purely numeric values, and generic accounts (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`).
- **The question text** (it's the replay lookup key), timestamps, rule IDs and levels, alert counts, OS and software versions, and CVE inventory. The vulnerability data reveals what's unpatched.

**Caveats:**
- **Still sensitive:** a redacted fixture still contains security telemetry. Handle it the same way.
- **Replay may break:** if a masked value also appears as a literal inside a query the code builds (for example a username that matches a query constant such as `sshd`), the rebuilt query won't match the recording and replay reports a fixture miss. Unredacted capture, the default, doesn't have this problem.

---

## Troubleshooting

**`--check` says `NOT READY: missing …`.** The live backend gets settings from somewhere other than `.env`. Set them for this PowerShell session only, using the same values the live backend uses, then re-run `--check`:
```powershell
$env:OPENSEARCH_URL = 'https://…:9200'; $env:WAZUH_SERVER_API_URL = 'https://…:55000'; $env:WAZUH_USER = '…'; $env:WAZUH_PASSWORD = '…'; $env:LLM_API_URL = 'http://…'
```
These disappear when the window closes.

**`Cannot find module 'better-sqlite3'` or `was compiled against a different Node.js version`.** `node_modules` wasn't copied, or the `node` on your PATH differs from the one the live backend uses. Check `node --version` against the live service's Node. If internet access is available, `npm ci` in `C:\soc-capture\backend` is the alternative.

**Every question shows `planner=fallback_rules` and `model_generated=false`.** The model endpoint wasn't reachable from this machine, or it hung and the time limits stopped waiting (F-03 is fixed: every model call now gives up instead of hanging). The fixtures still capture OpenSearch and Wazuh faithfully, but neither the model's plan nor its answer, so they can't serve as the baseline. Bring them back anyway, and if the model comes back, re-run as below.

**Re-running one question.** Put the question in a text file and capture into a sub-folder, so the existing fixtures and manifest aren't overwritten:
```powershell
Set-Content -Path .\rerun.txt -Value 'what are the top alerts this week'
node scripts\captureFixtures.js --questions-file .\rerun.txt --out .\fixtures\rerun
```
Then move the new `.json` up into `.\fixtures\`, replacing the old file for that question, and bring back both manifests (`fixtures\manifest.json` and `fixtures\rerun\manifest.json`).

**A question ends `status=timeout`.** The whole run took longer than 10 minutes. Bring back the fixtures and the step 4 output: the recorded calls show exactly where the run stopped.

---

## Deploying the updated backend (not part of this trip)

When the updated code is later installed in `$LIVE` and started:
Follow **`docs/DEPLOY.md`**: it's the full procedure. In short:
1. **Take a fresh backup** with `scripts\backupDb.js` right before. The one from this trip won't include later changes.
2. **Make sure `JWT_SECRET` is set and strong** (32+ random characters), or the server refuses to start with `FATAL CONFIG ERROR: JWT_SECRET …`.
3. **On first start it migrates the database:**
   - adds `messages.request_id` with an index
   - creates `runs`
   - marks any `running` runs left by a previous process as `interrupted`

   Afterwards, `dbReport.js` shows `messages.request_id=yes, runs table=yes`.
4. **Run a single backend process per database file** (F-31).
5. **To roll back:** stop the backend, restore the backup over `data\soc_chatbot.db`, delete `soc_chatbot.db-wal` and `soc_chatbot.db-shm` if present, and start the previous code.
