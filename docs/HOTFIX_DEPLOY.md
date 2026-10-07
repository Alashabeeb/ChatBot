# Hotfix Deploy: Unregister Fabricating Tools

**For:** Abdulhakeem, on the Windows production host running `ChatBot/` `main`.
**Commit:** `hotfix: unregister fabricating tools and add read-only audit` (the commit directly after `c0e2010 Push 26`).
**Time needed:** about 15 minutes, including one short backend restart.

## What this fixes, and why it's urgent

Two tools added in "Push 25" return **fabricated results** that the model then reports to analysts as fact:

| Tool | What it actually does | What the analyst is told |
|---|---|---|
| `blockIpAction` | Nothing. Waits 1.5 s. | "Successfully added *IP* to the firewall blocklist." (`IP_BLOCKED`) |
| `checkProcessList` | Returns the same hard-coded list for every endpoint | A root process `unknown_miner` at 98.5% CPU — a fake cryptominer on every host checked |

An analyst could believe an attacker was contained when nothing was blocked, or chase a compromise that doesn't exist. The planner could also call `blockIpAction` on its own judgement.

**The fix:** both tools are removed from the tool registry, so the planner can no longer select them. If a model plan names either one, it's rejected before anything runs and the rule-based fallback plan is used instead. The tool files stay in the repo, unused.

**The change:**
- `backend/src/agent/runtime.js`: the two registrations and their imports removed (4 lines in, 11 out)
- `backend/scripts/auditFabricatedActions.js`: new read-only audit script
- `backend/test/` and the `test` script in `backend/package.json`: tests only, not needed in production
- **No dependency changes, no database changes.** No `npm install` or migration is needed.

**Not fixed by this hotfix** (they arrive in the upcoming merge): the threat-intel mock (`lookupThreatIntel` still returns fake "not malicious, threat score 10" data), the hard-coded JWT fallback secret, and unfiltered chat history. The audit below will keep finding threat-intel mock matches until that merge ships. That's expected.

---

## Steps (PowerShell)

Set the backend path once (the folder containing `src\`, `data\` and `.env`):
```powershell
$BACKEND = 'C:\path\to\ChatBot\backend'
```

### 1. Stop the backend

Stop it the way it's normally run (service, pm2, or close its terminal). Confirm it's down:
```powershell
Test-NetConnection localhost -Port 3002 | Select-Object TcpTestSucceeded
```
Expected: `False`.

### 2. Back up the database (backend stopped, so a file copy is safe)

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'; Get-ChildItem "$BACKEND\data\soc_chatbot.db*" | ForEach-Object { Copy-Item $_.FullName "$($_.FullName).pre-hotfix-$stamp" }
```
```powershell
Get-ChildItem "$BACKEND\data" | Select-Object Name, Length
```
Expected: a `.pre-hotfix-<stamp>` copy next to `soc_chatbot.db`, the same size. Also next to `-wal` / `-shm` if those exist. This hotfix doesn't touch the database; the backup is a precaution.

### 3. Update the code

**If production is a git clone** (once the commit has been pushed):
```powershell
cd $BACKEND\..; git pull; git log -1 --oneline
```
Expected: the last line starts with the hotfix commit, message `hotfix: unregister fabricating tools and add read-only audit`.

**If production is a copied folder:** copy these two files from the hotfix commit, keeping their paths:
- `backend\src\agent\runtime.js` (replaces the existing file)
- `backend\scripts\auditFabricatedActions.js` (new)

### 4. Verify the tools are unregistered (before starting)

```powershell
Select-String -Path "$BACKEND\src\agent\runtime.js" -Pattern 'registry.registerTool\('
```
Expected: **exactly four** lines, for `searchSecurityLogsTool`, `getEndpointStatusTool`, `lookupThreatIntelTool` and `searchMemoryTool`. If `blockIpAction` or `checkProcessList` appears, stop: the wrong file was deployed.

### 5. Start the backend and check the log

Start it the normal way. Expected in the startup output:
```
[Database] All tables and indexes verified.
🚀 AI SOC Proxy Server running on port 3002
```
If it doesn't start, see Rollback.

### 6. Run the audit (read-only; safe while the backend runs)

```powershell
cd $BACKEND; node scripts\auditFabricatedActions.js; $LASTEXITCODE
```
It searches every saved message for `IP_BLOCKED`, `blocklist`, `unknown_miner` and the old threat-intel mock text. For each match it prints one line with **date, user, message ID** and what matched, followed by the snippet:
```
2026-09-23T10:00:00Z  user=analyst1 (u1)  message=msg_a_…  session=sess_…  matched: IP_BLOCKED
    [IP_BLOCKED] summary: …"action":"IP_BLOCKED","target_ip":"203.0.113.9"…
```
**Exit code:** `0` means nothing found, `2` means matches were listed, `1` means an error (the message says what).

**Reading the results:**
- **`IP_BLOCKED` and `unknown_miner` are definite.** That analyst was shown a fake block or a fake miner. Each one needs a human follow-up: was any decision made on it?
- **`threat-intel mock`** means a fake "not malicious" verdict reached that answer. It will keep appearing for new messages until the merge ships.
- **`blocklist`** also matches legitimate advice ("consider adding this IP to the blocklist"). Read those snippets by hand.

### 7. Smoke test in the UI

Log in and ask these two questions. They deliberately contain **no IP address**, so they don't trigger the still-active threat-intel mock:
1. `Block the IP that attacked us most today`
2. `Check the running processes on agent 001`

**Pass:** neither answer says an IP was blocked or added to a blocklist, and neither mentions `unknown_miner` or any process list.

Then re-run the audit from step 6. **Pass:** no `IP_BLOCKED` or `unknown_miner` match dated after the restart.

If an answer still *claims* an IP was blocked, the model invented it without a tool. Note the exact text and report it. Don't retry until it goes away.

### 8. Send back

1. The full audit output from step 6 (both runs).
2. The output of `git log -1 --oneline`, or the list of files you copied.
3. The two smoke-test answers, copied as text.
4. Anything unexpected in the startup log.

The audit output contains usernames and fragments of security reports. Send it through the usual internal channel, not public chat or email.

---

## Rollback

The hotfix makes no database changes, so rollback is code-only:
```powershell
cd $BACKEND\..; git checkout c0e2010 -- backend/src/agent/runtime.js
```
For a copied folder, put the previous `runtime.js` back instead. Then restart.

**Rolling back re-enables both fabricating tools.** Only do it if the hotfixed backend won't start, and report it straight away.
