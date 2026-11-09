# Contributing to SecretSentinel

Thanks for your interest. SecretSentinel is a small tool and we want to keep it that way: readable code, few dependencies, and no network access at scan time.

## Development setup

Requirements: Python 3.10 or newer, git.

```bash
git clone <repository-url> secretsentinel
cd secretsentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Project layout

| Path | Purpose |
|------|---------|
| `src/secretsentinel/engine/` | Rule loading, regex matching, Shannon entropy |
| `src/secretsentinel/git/` | Working tree, staged changes and history (GitPython and `git` CLI) |
| `src/secretsentinel/filters/` | `.secretsentinelignore` and YAML allowlist |
| `src/secretsentinel/formatters/` | Console (Rich), JSON and SARIF output |
| `src/secretsentinel/rules/default.yaml` | Built-in detection rules |
| `hooks/` | pre-commit hook definition |
| `tests/` | Pytest suite |

## Adding a detection rule

1. Add an entry to `src/secretsentinel/rules/default.yaml`, or write a rule file and test it with `--rules-file`.
2. Give it a unique `id`, a `description`, a `severity`, and a `cwe` (usually `CWE-798`).
3. Use a capture group for the value so entropy scoring applies to the secret, not the surrounding text.
4. Set `min_entropy` for generic patterns to limit false positives.
5. Add a test in `tests/test_engine.py`. **Build the secret at runtime** (as the existing tests do), so the repository never contains a string that looks like a real credential.

## Secure coding rules for this project

- Never log, print or store a full secret. Use `redact()` for previews and SHA-256 digests for allowlist matching.
- Do not add network calls to the scanning path.
- Treat repository content as untrusted input: no `eval`, no `shell=True`, no unbounded reads. Keep the file size limit.
- Pass `git` arguments as lists, never through a shell.
- Parse YAML with `yaml.safe_load` only.
- New dependencies need a justification in the pull request and must be licensed under MIT, BSD, Apache-2.0 or a compatible license.

## Tests and style

- `pytest` must pass before you open a pull request.
- Every bug fix comes with a regression test.
- Keep functions small and typed where practical.

## Pull requests

1. Open an issue first for large changes.
2. Keep pull requests focused on one change.
3. Describe what changed, why, and how you tested it.
4. Do not include real credentials in code, tests, fixtures, screenshots or logs.

## Reporting security issues

Do not open a public issue for a vulnerability in SecretSentinel. See [SECURITY.md](SECURITY.md).

## Code of conduct

Be respectful and constructive. A formal code of conduct will be added before the first public release.
