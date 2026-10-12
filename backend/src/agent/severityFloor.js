/**
 * Severity floor for "right now" questions (Phase 5). "What is going on right now" should surface what
 * matters, not every low-level event, so a search with no severity of its own is limited to
 * rule.level >= RIGHT_NOW_MIN_SEVERITY (default 7; 0 turns it off). A level the planner set, because
 * the analyst asked for one, is never overridden. The report header states the level searched.
 */
const RIGHT_NOW = /\b(?:right now|just now|at the moment|currently|happening now|as we speak|at present)\b/i;

export function rightNowMinSeverity() {
    const raw = process.env.RIGHT_NOW_MIN_SEVERITY;
    const value = raw === undefined || raw === '' ? 7 : Number(raw);
    return Number.isFinite(value) && value >= 0 ? value : 7;
}

export const isRightNowQuestion = text => RIGHT_NOW.test(String(text ?? ''));

/** Returns a new plan; the floor applies to log searches without a severity, except vulnerability searches. */
export function applySeverityFloor(plan, text, level = rightNowMinSeverity()) {
    if (!level || !isRightNowQuestion(text)) return plan;
    return plan.map(instruction => {
        const p = instruction.parameters ?? {};
        if (instruction.tool !== 'searchSecurityLogs' || p.intent === 'vulnerabilities') return instruction;
        if (p.minSeverity !== null && p.minSeverity !== undefined) return instruction;
        return { ...instruction, parameters: { ...p, minSeverity: level } };
    });
}
