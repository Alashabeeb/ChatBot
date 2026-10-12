# What a good answer looks like

This is the standard every SOC ChatBot answer is measured against. `evals/check.py` implements it.
When the two disagree, this document is the intent and the checker has a bug.

An answer is judged **only against the evidence the pipeline actually retrieved** for that question:
the OpenSearch responses, the Wazuh agent list, and the record of which tools failed or had no data.
Knowledge the evidence doesn't contain counts as unsupported, even if it happens to be true.

## The standard

A good answer:

1. **States the time window searched**, in words that match the query that ran ("the last 24 hours"
   for `now-24h`, "the last 7 days" or "this week" for `now-7d`).
2. **Names specific rule IDs with counts**, starting with the ones that fired most.
3. **Identifies the outlier**: the agent or source IP that accounts for most of the activity.
4. **Uses MITRE ATT&CK IDs only from `rule.mitre.id`** in the evidence. No technique inferred from a
   rule description.
5. **Ties every recommendation to a specific finding**: a rule ID, agent, IP, user or technique that is
   in the evidence. "Monitor your systems" is not a recommendation.
6. **States which sources were and weren't searched.** If the firewall search failed or threat
   intelligence isn't available, the answer says so instead of implying a clean result.
7. **Says plainly when the evidence is insufficient.** No hits means "no matching alerts in that
   window", never a guessed threat picture.

## Hard checks (pass/fail)

These are objectively checkable. Any failure fails the answer, whatever its score.

| ID | Fails when | Fabrication? |
|---|---|---|
| `H1_answer_present` | The answer is empty. | |
| `H2_rule_ids_grounded` | A rule ID in the answer is not in the evidence. | yes |
| `H3_rule_counts_match` | A count given for a rule doesn't match the evidence. When the evidence holds every hit, the count must be exact. When it's a sample (total > hits returned), the count must lie between the sample count and the search total. | yes |
| `H4_mitre_grounded` | A MITRE ID (`T1110`, `T1110.001`) in the answer is not in any `rule.mitre.id` in the evidence. | yes |
| `H5_ips_grounded` | An IPv4 address in the answer appears nowhere in the evidence. | yes |
| `H6_hosts_grounded` | A host-like name (`DC01`, `web-01`, `SRV-AD-02`) in the answer appears nowhere in the evidence. | yes |
| `H7_no_known_fabrications` | The answer contains text the retired mock tools produced: `IP_BLOCKED`, `unknown_miner`, a claim that an IP was blocked, or the mock threat-intel verdict. | yes |
| `H8_time_window` | The answer states no time window, or only windows that don't match any search that ran. | |
| `H9_evidence_honesty` | No hits at all, but the answer doesn't say so, or cites rule IDs or techniques anyway; or there are hits and the answer claims nothing was found. | yes, in the second form |
| `H10_unavailable_disclosed` | A source failed or had no data, and the answer doesn't say so. | |

The **fabrication count** for an answer is the number of failed checks marked "yes". The release
gate (Phase 8) requires it to be zero.

## Quality score (0–100)

Each criterion is worth the points below. A criterion that can't apply (for example "identify the
outlier" when there are no hits) is dropped and the rest are scaled back up to 100.

| Criterion | Points | Full credit | Partial credit |
|---|---|---|---|
| Time window (1) | 10 | Stated and matches a search that ran | none |
| Rule IDs with counts (2) | 20 | Each of the top 3 rules (by count in the evidence) named with a count | Half for each one named without a count |
| Outlier (3) | 15 | Names the top agent or the top source IP | none |
| MITRE grounding (4) | 10 | Cites at least one technique from the evidence, and none from outside it; or cites none when the evidence has none | Half when the evidence has techniques and the answer cites none |
| Recommendations tied to findings (5) | 20 | Every recommendation names an evidence entity | Proportional to the share that do. An answer with no recommendations is not scored on this criterion: it measures grounding, not quantity. |
| Sources (6) | 15 | Names every source that was searched and discloses every one that wasn't | Proportional |
| Evidence honesty (7) | 10 | Matches `H9` | none |

## How the checker reads an answer

The checker is deliberately conservative. It only flags what it can identify unambiguously, so a
failure is worth reading, and a pass on a hard check means "nothing detectably wrong", not "proven
correct".

- **Rule IDs** are numbers after "rule", "rule ID", "rules", or in a Markdown table column headed
  "Rule" or "Rule ID".
- **Counts** are tied to a rule when they share a table row (in a column headed Count, Alerts, Events,
  Hits or Occurrences) or follow the rule ID in the same sentence as "N alerts/events/times/…" with no
  other number in between. A count it can't tie to a rule unambiguously is not checked.
- **Host-like names** are tokens such as `web-01` (letters, a hyphen or underscore, digits) or `DC01`
  (capitals then digits). Ordinary words, `T1110`, `CVE-…` and terms like `SHA256` are ignored.
- **Recommendations** are the bullet or numbered lines under a heading containing "recommend",
  "next steps", "actions" or "remediation", including the report's own format
  (`- **Next steps**: …`, with any text after the label counted as a recommendation). The next
  labelled bullet (`- **Assessment**: …`) or heading ends the section.
- **Time windows** are phrases such as "last 24 hours", "past 7 days", "this week", "today",
  "past hour", Elasticsearch date math such as `now-24h`, or explicit dates: a range
  ("2026-10-05 to 2026-10-12") or "since 2026-10-05", measured from the capture time. Dates without
  a time of day are allowed a day of slack; everything else must be within 10% of the window searched.

Known limits are listed in `evals/README.md`. When the checker gets a real answer wrong, add a
synthetic case reproducing it (see that file), then fix the checker.
