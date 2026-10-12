#!/usr/bin/env python3
"""Release gate: fails if answer quality drops or any fabricated claim gets through.

    python3 evals/gate.py                  run everything and compare with evals/gate_baseline.json
    python3 evals/gate.py --update         record the current scores as the new baseline (review the diff)
    python3 evals/gate.py --real <dir>     also gate real replayed answers (replayFixtures.js --allow-model --out <dir>)

Checks, all of which must pass:
  1. The checker's self-test: every SYNTHETIC case in evals/synthetic behaves as its "expect" says.
  2. The pipeline evaluation (backend/scripts/evalSyntheticPipeline.js): the invented scenarios run
     through the real pipeline with a faithful and an adversarial stub model. For both:
       - no fabrication reaches an answer, and no answer fails a hard check;
       - no case scores below its baseline score, and no mode's mean drops.
     The legacy pass-through (what the code before Phase 4 would have shown) must still show
     fabrications: if it doesn't, the evaluation has gone blind.
  3. With --real: no fabrication in any real replayed answer, and no question below its baseline score.

Scores can only go up through --update, which refuses to record a baseline that breaks rule 2's
absolute checks, and whose diff is reviewed like code. Never calls a model or the SIEM.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = REPO / 'evals' / 'gate_baseline.json'
GATED_MODES = ('faithful', 'adversarial')
TOLERANCE = 1e-6


def key_for(file_name):
    """SYNTHETIC-pipeline-<mode>--<scenario>.json -> pipeline/<mode>/<scenario>; real records -> real/<stem>."""
    name = Path(file_name).name
    if name.startswith('SYNTHETIC-pipeline-') and '--' in name:
        mode, scenario = name[len('SYNTHETIC-pipeline-'):-len('.json')].split('--', 1)
        return f'pipeline/{mode}/{scenario}'
    return f'real/{Path(name).stem}'


def run_self_test(directory=REPO / 'evals' / 'synthetic'):
    code = check.main([str(directory), '--expect'])
    return [] if code == 0 else ['checker self-test: a SYNTHETIC case no longer behaves as expected (see above)']


def run_pipeline_eval():
    out = Path(tempfile.mkdtemp(prefix='gate-pipeline-'))
    scores = out / 'scores.json'
    run = subprocess.run(['node', str(REPO / 'backend' / 'scripts' / 'evalSyntheticPipeline.js'), '--out', str(out), '--json', str(scores)],
                         cwd=REPO / 'backend', capture_output=True, text=True)
    if not scores.exists():
        print(run.stdout[-3000:], run.stderr[-3000:], file=sys.stderr)
        raise SystemExit('pipeline evaluation produced no scores')
    return json.loads(scores.read_text(encoding='utf-8'))['results']


def score_real(directory):
    results = []
    for f in sorted(Path(directory).glob('*.json')):
        if f.name in ('manifest.json', 'scores.json', 'comparison.json'):
            continue
        record = json.loads(f.read_text(encoding='utf-8'))
        if 'replay' not in record:
            continue
        result = check.check_case(record, 'replay')
        result['file'] = f.name
        results.append(result)
    return results


def evaluate(results, baseline):
    """Returns (problems, cases, means, notes): problems that fail the gate, the scores to record, and
    notes (new cases). A case not yet in the baseline can't have dropped: means are compared over the
    cases the baseline already holds, and --update adds the new one."""
    problems, notes = [], []
    comparable = {}
    cases, by_mode = {}, {}
    legacy_fabrications = 0
    seen_legacy = False
    for r in results:
        key = key_for(r['file'])
        kind, _, rest = key.partition('/')
        mode = rest.split('/')[0] if kind == 'pipeline' else 'real'
        label = rest if kind == 'pipeline' else key
        if mode == 'legacy':
            seen_legacy = True
            legacy_fabrications += r.get('fabrications', 0)
            continue
        if kind == 'pipeline' and mode not in GATED_MODES:
            continue
        if r.get('fabrications', 0):
            problems.append(f'{label}: {r["fabrications"]} fabrication(s) reached the answer ({", ".join(r.get("failed_checks", []))})')
        if kind == 'pipeline' and not r.get('pass', False):
            problems.append(f'{label}: failed hard check(s) {", ".join(r.get("failed_checks", []))}')
        cases[key] = r['score']
        by_mode.setdefault(mode, []).append(r['score'])
        base = baseline.get('cases', {}).get(key)
        if base is None:
            if baseline.get('cases'):
                notes.append(f'new case {label}: score {r["score"]:g} (not in the baseline yet; run --update to add it)')
        else:
            comparable.setdefault(mode, []).append(r['score'])
            if r['score'] + TOLERANCE < base:
                problems.append(f'{label}: score {r["score"]:g} < baseline {base:g}')
    for key in baseline.get('cases', {}):
        if key not in cases and (key.startswith('pipeline/') or any(k.startswith('real/') for k in cases)):
            problems.append(f'{key.partition("/")[2] if key.startswith("pipeline/") else key}: missing from the results')
    means = {mode: round(sum(v) / len(v), 3) for mode, v in by_mode.items()}
    for mode, scores in comparable.items():
        mean = round(sum(scores) / len(scores), 3)
        base = baseline.get('means', {}).get(mode)
        if base is not None and mean + TOLERANCE < base:
            problems.append(f'{mode}: mean {mean:g} < baseline {base:g}')
    if seen_legacy and legacy_fabrications == 0:
        problems.append('legacy pass-through shows no fabrications: the evaluation can no longer see them')
    return problems, cases, means, notes


def main(argv=None):
    parser = argparse.ArgumentParser(description='Release gate for answer quality.')
    parser.add_argument('--baseline', default=str(DEFAULT_BASELINE))
    parser.add_argument('--update', action='store_true', help='record the current scores as the new baseline')
    parser.add_argument('--real', help='directory of real replay records (replayFixtures.js --allow-model --out <dir>) to gate as well')
    parser.add_argument('--pipeline-results', help=argparse.SUPPRESS)   # tests: use these results instead of running the evaluation
    parser.add_argument('--skip-self-test', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--synthetic', default=str(REPO / 'evals' / 'synthetic'), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    baseline_path = Path(args.baseline)
    baseline = json.loads(baseline_path.read_text(encoding='utf-8')) if baseline_path.exists() else {}
    problems = [] if args.skip_self_test else run_self_test(args.synthetic)

    results = (json.loads(Path(args.pipeline_results).read_text(encoding='utf-8'))['results']
               if args.pipeline_results else run_pipeline_eval())
    if args.real:
        results = results + score_real(args.real)
    gate_problems, cases, means, notes = evaluate(results, {} if args.update else baseline)
    problems += gate_problems

    print()
    for mode, mean in sorted(means.items()):
        n = sum(1 for k in cases if (k.split('/')[1] if k.startswith('pipeline/') else 'real') == mode)
        print(f'  {mode:12} {n:3} case(s)  mean score {mean:g}' + (f'  (baseline {baseline["means"][mode]:g})' if mode in baseline.get('means', {}) else ''))
    for note in notes:
        print(f'  NOTE  {note}')
    for p in problems:
        print(f'  FAIL  {p}')

    if args.update:
        if problems:
            print('\nRELEASE GATE: FAIL (baseline not updated: fix the failures first)')
            return 1
        baseline_path.write_text(json.dumps({
            'generatedAt': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'note': 'Release gate baseline. Written by evals/gate.py --update; review the diff like code. Scores may only go down with an explained reason in docs/MERGE_DECISIONS.md.',
            'cases': dict(sorted(cases.items())),
            'means': dict(sorted(means.items())),
        }, indent=2) + '\n', encoding='utf-8')
        print(f'\nBaseline written to {baseline_path} ({len(cases)} cases). RELEASE GATE: PASS')
        return 0
    print(f'\nRELEASE GATE: {"FAIL" if problems else "PASS"}')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
