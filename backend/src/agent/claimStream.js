import { SECTIONS } from './grounding.js';

/**
 * Reads the report model's JSON as it streams in (Phase 7) and hands over each claim as soon as its
 * object is complete, so it can be verified and shown before the model has finished. Only shape is
 * read here; every claim still goes through verifyClaims, and the final answer is always rebuilt from
 * the complete output (parseClaims), so a scanner mistake can delay a claim but never show one.
 *
 * onClaim(section, claim) for each element of answer/findings/assessment/next_steps;
 * onInsufficient() once, if "insufficient_evidence": true appears.
 */
export function createClaimScanner({ onClaim, onInsufficient = () => {} }) {
    let text = '';
    let pos = 0;
    let depth = 0;
    let inString = false;
    let escaped = false;
    let stringStart = -1;
    let lastKey = null;
    let section = null;
    let elementStart = -1;
    let insufficient = false;
    let started = false;
    let finished = false;

    function step(i) {
        const ch = text[i];
        if (inString) {
            if (escaped) escaped = false;
            else if (ch === '\\') escaped = true;
            else if (ch === '"') {
                inString = false;
                if (depth === 1) {
                    // A key at the top level is followed (after optional spaces) by a colon.
                    const rest = text.slice(i + 1).match(/^\s*:/);
                    if (rest) lastKey = text.slice(stringStart + 1, i);
                }
            }
            return;
        }
        if (ch === '"') {
            inString = true;
            stringStart = i;
        } else if (ch === '{' || ch === '[') {
            if (depth === 1 && ch === '[' && SECTIONS.includes(lastKey)) section = lastKey;
            if (depth === 2 && section && ch === '{') elementStart = i;
            depth++;
        } else if (ch === '}' || ch === ']') {
            depth--;
            if (depth === 2 && section && ch === '}' && elementStart !== -1) {
                const raw = text.slice(elementStart, i + 1);
                elementStart = -1;
                try {
                    onClaim(section, JSON.parse(raw));
                } catch {
                    // not valid JSON on its own: the final parse decides
                }
            }
            if (depth === 1 && ch === ']') section = null;
        }
    }

    return {
        push(piece) {
            text += piece;
            if (!started) {
                // Skip anything before the top-level object (a code fence, a sentence).
                const start = text.indexOf('{', pos);
                if (start === -1) {
                    pos = text.length;
                    return;
                }
                pos = start;
                started = true;
            }
            for (; pos < text.length && !finished; pos++) {
                step(pos);
                if (depth === 0) finished = true;   // the top-level object is complete
            }
            if (!insufficient && /"insufficient_evidence"\s*:\s*true/.test(text)) {
                insufficient = true;
                onInsufficient();
            }
        },
        get text() {
            return text;
        }
    };
}
