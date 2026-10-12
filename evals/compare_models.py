#!/usr/bin/env python3
"""Runs the captured fixtures through each configured model and compares them side by side.

For each model in the config, replays every fixture (backend/scripts/replayFixtures.js --allow-model):
the searches are served from the fixtures, the configured model writes the report, and the code
verifies its claims exactly as in production. Each answer is then scored with evals/check.py.

    python3 evals/compare_models.py --config evals/models.json --dry-run     validate, call nothing
    python3 evals/compare_models.py --config evals/models.json                compare report models
    python3 evals/compare_models.py --config evals/models.json --live-planner also ask each planner

Per model it reports quality (mean score, answers failing a hard check), fabrication (fabrications that
reached the answer, and claims the verification had to remove), format failures, and speed (the model
call alone, and the prompt size).

Guards:
  - Every model entry needs "approved_by": a model is never called without a named approval.
  - API keys never go in the config: "api_key_env" maps a setting to the NAME of an environment
    variable that holds the key.
  - Results hold real telemetry and answers: the default output is under baseline/ (gitignored).

Standard library only.
"""

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / 'backend'
ALLOWED_SETTINGS = {
    'LLM_API_URL', 'LLM_MODEL',
    'PLANNER_LLM_API_URL', 'PLANNER_LLM_MODEL',
    'REPORT_LLM_API_URL', 'REPORT_LLM_MODEL',
}
KEY_SETTINGS = {'LLM_API_KEY', 'PLANNER_LLM_API_KEY', 'REPORT_LLM_API_KEY'}


class ConfigError(Exception):
    pass


def load_config(path):
    try:
        config = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise ConfigError(f'cannot read {path}: {error}')
    models = config.get('models')
    if not isinstance(models, list) or not models:
        raise ConfigError('the config needs a non-empty "models" list')
    names = set()
    for i, m in enumerate(models):
        where = f'models[{i}]'
        name = m.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,60}', name or ''):
            raise ConfigError(f'{where}: "name" must be 1-60 letters, digits, ".", "_" or "-"')
        if name in names:
            raise ConfigError(f'{where}: duplicate name "{name}"')
        names.add(name)
        if not str(m.get('approved_by', '')).strip():
            raise ConfigError(f'{where} ("{name}"): no "approved_by". A model is only called once someone has approved its endpoint.')
        env = m.get('env', {})
        if not isinstance(env, dict):
            raise ConfigError(f'{where}: "env" must be an object')
        for key in env:
            if key in KEY_SETTINGS or 'KEY' in key.upper() or 'TOKEN' in key.upper() or 'SECRET' in key.upper():
                raise ConfigError(f'{where}: "{key}" looks like a credential. Put it in your environment and reference it with "api_key_env".')
            if key not in ALLOWED_SETTINGS:
                raise ConfigError(f'{where}: unknown setting "{key}" (allowed: {", ".join(sorted(ALLOWED_SETTINGS))})')
        keys = m.get('api_key_env', {})
        if not isinstance(keys, dict):
            raise ConfigError(f'{where}: "api_key_env" must be an object')
        for key, var in keys.items():
            if key not in KEY_SETTINGS:
                raise ConfigError(f'{where}: "api_key_env" can only set {", ".join(sorted(KEY_SETTINGS))}')
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', str(var)):
                raise ConfigError(f'{where}: "api_key_env.{key}" must be the name of an environment variable')
    return models


def model_env(model):
    env = dict(os.environ)
    env.pop('FIXTURES_LIVE_PLANNER', None)
    env.update({k: str(v) for k, v in model.get('env', {}).items()})
    for key, var in model.get('api_key_env', {}).items():
        if not os.environ.get(var):
            raise ConfigError(f'"{model["name"]}": environment variable {var} (for {key}) is not set')
        env[key] = os.environ[var]
    return env


def fixture_files(fixtures):
    return sorted(f for f in Path(fixtures).glob('*.json') if f.name != 'manifest.json')


def describe(model):
    env = model.get('env', {})
    parts = [f'{k}={v}' for k, v in sorted(env.items()) if k.endswith('_MODEL')]
    parts += [f'{k}=<set>' for k in sorted(env) if k.endswith('_URL')]
    parts += [f'{k} from ${v}' for k, v in sorted(model.get('api_key_env', {}).items())]
    return ', '.join(parts) or 'backend/.env defaults'


def summarize(name, records):
    scored = [(r, check.check_case(r, 'replay')) for r in records]
    replays = [r['replay'] for r in records]
    model_ms = [t['reasoningDuration'] for t in (x.get('timings') or {} for x in replays) if isinstance(t.get('reasoningDuration'), (int, float))]
    plan_ms = [t['planningDuration'] for t in (x.get('timings') or {} for x in replays) if isinstance(t.get('planningDuration'), (int, float))]
    prompt = [t['reportPromptChars'] for t in (x.get('timings') or {} for x in replays) if isinstance(t.get('reportPromptChars'), (int, float))]
    grounding = [x.get('grounding') or {} for x in replays]
    claims = sum(g.get('claims', 0) for g in grounding)
    dropped = sum(g.get('dropped', 0) for g in grounding)
    sources = [x.get('reportSource') for x in replays]
    return {
        'model': name,
        'cases': len(records),
        'replay_matched': sum(1 for x in replays if x.get('status') == 'matched'),
        'mean_score': round(statistics.mean(s['score'] for _, s in scored), 1) if scored else None,
        'failing_hard_check': sum(1 for _, s in scored if not s['pass']),
        'fabrications_shown': sum(s['fabrications'] for _, s in scored),
        'fabrication_rate': round(sum(s['fabrications'] for _, s in scored) / len(scored), 3) if scored else None,
        'claims': claims,
        'claims_dropped': dropped,
        'dropped_rate': round(dropped / claims, 3) if claims else None,
        'format_failures': sources.count('fallback_unverifiable'),
        'model_unavailable': sources.count('fallback_model_unavailable'),
        'model_ms_mean': round(statistics.mean(model_ms)) if model_ms else None,
        'model_ms_max': max(model_ms) if model_ms else None,
        'planning_ms_mean': round(statistics.mean(plan_ms)) if plan_ms else None,
        'prompt_chars_mean': round(statistics.mean(prompt)) if prompt else None,
        'per_question': [
            {'file': r.get('file') or '', 'question': r.get('question'), 'replay': r['replay'].get('status'), 'score': s['score'],
             'failed_checks': s['failed_checks'], 'fabrications': s['fabrications'], 'report_source': r['replay'].get('reportSource'),
             'claims_dropped': (r['replay'].get('grounding') or {}).get('dropped', 0)}
            for r, s in scored
        ],
    }


COLUMNS = [
    ('model', 'model', 18), ('cases', 'cases', 5), ('replay_matched', 'matched', 7), ('mean_score', 'score', 6),
    ('failing_hard_check', 'hard-fail', 9), ('fabrications_shown', 'fabr.shown', 10), ('claims_dropped', 'dropped', 7),
    ('dropped_rate', 'drop-rate', 9), ('format_failures', 'format-fail', 11), ('model_unavailable', 'unavail', 7),
    ('model_ms_mean', 'model-ms', 8), ('model_ms_max', 'max-ms', 7), ('prompt_chars_mean', 'prompt', 7),
]


def print_table(rows, live_planner):
    columns = COLUMNS + ([('planning_ms_mean', 'plan-ms', 7)] if live_planner else [])
    print('  '.join(label.rjust(w) if i else label.ljust(w) for i, (_, label, w) in enumerate(columns)))
    for row in rows:
        cells = []
        for i, (key, _, w) in enumerate(columns):
            value = row.get(key)
            text = '-' if value is None else str(value)
            cells.append(text.ljust(w) if i == 0 else text.rjust(w))
        print('  '.join(cells))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Compare models on the captured fixtures.')
    parser.add_argument('--config', required=True, help='JSON file listing the models (see evals/models.example.json)')
    parser.add_argument('--fixtures', default=str(BACKEND / 'fixtures'), help='captured fixtures (default backend/fixtures)')
    parser.add_argument('--out', help='output directory (default baseline/compare-<UTC time>, gitignored)')
    parser.add_argument('--live-planner', action='store_true', help='also ask each planner model for the plan (searches still come from the fixtures)')
    parser.add_argument('--dry-run', action='store_true', help='validate the config and fixtures; call nothing')
    args = parser.parse_args(argv)

    try:
        models = load_config(args.config)
        envs = {m['name']: model_env(m) for m in models} if not args.dry_run else {}
    except ConfigError as error:
        print(f'Config error: {error}', file=sys.stderr)
        return 2
    fixtures = fixture_files(args.fixtures)
    if not fixtures:
        print(f'No fixtures in {args.fixtures}.', file=sys.stderr)
        return 2
    for f in fixtures:
        if json.loads(f.read_text(encoding='utf-8')).get('synthetic'):
            print(f'{f.name} is a SYNTHETIC case; compare models on real captured fixtures only.', file=sys.stderr)
            return 2

    print(f'{len(fixtures)} fixture(s) from {args.fixtures}; {len(models)} model(s){"; live planner" if args.live_planner else ""}')
    for m in models:
        print(f'  {m["name"]}: {describe(m)} (approved by {m["approved_by"]})')
    if args.dry_run:
        print('Dry run: nothing was called.')
        return 0

    out = Path(args.out) if args.out else REPO / 'baseline' / f'compare-{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}'
    rows = []
    for m in models:
        target = out / m['name']
        cmd = ['node', str(BACKEND / 'scripts' / 'replayFixtures.js'), '--dir', str(Path(args.fixtures).resolve()),
               '--out', str(target.resolve()), '--allow-model'] + (['--live-planner'] if args.live_planner else [])
        print(f'\n[{m["name"]}] replaying...', flush=True)
        run = subprocess.run(cmd, cwd=BACKEND, env=envs[m['name']], capture_output=True, text=True)
        summary_lines = [l for l in run.stdout.splitlines() if l.startswith('[Replay]') or l.startswith('           -')]
        print('\n'.join(summary_lines))
        if run.returncode not in (0, 1):  # 1 = some fixture diverged, still scored
            print(run.stderr[-2000:], file=sys.stderr)
            print(f'[{m["name"]}] replay failed (exit {run.returncode}).', file=sys.stderr)
            return 1
        records = []
        for f in fixture_files(target):
            record = json.loads(f.read_text(encoding='utf-8'))
            record['file'] = f.name
            records.append(record)
        rows.append(summarize(m['name'], records))

    print()
    print_table(rows, args.live_planner)
    print('\nscore: mean checker score of the answers; hard-fail: answers failing a hard check; fabr.shown: fabrications that')
    print('reached the answer (should be 0: verification removes them); dropped: claims verification removed, i.e. what the')
    print('model tried to say without support; format-fail: output not in the required format (nothing shown); model-ms: the')
    print('report model call alone; prompt: characters sent to the report model.')
    (out / 'comparison.json').write_text(json.dumps({
        'generatedAt': datetime.now(timezone.utc).isoformat(),
        'fixtures': str(args.fixtures), 'livePlanner': args.live_planner,
        'models': [{'name': m['name'], 'approved_by': m['approved_by'], 'settings': describe(m)} for m in models],
        'results': rows,
    }, indent=2) + '\n', encoding='utf-8')
    print(f'\nDetails: {out / "comparison.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
