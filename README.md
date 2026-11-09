# SecretSentinel

**Find hard-coded secrets in your repositories before they leak.**

SecretSentinel scans your working tree, your staged changes and your git history for API keys, tokens, passwords and private keys. It is a small Python CLI that runs locally, sends nothing over the network, and reports findings as a readable table, JSON or SARIF.

> **Status: alpha (v0.1 in progress).** The core scanner, git integration, filters, output formats and pre-commit hook are implemented and tested. Packaging for PyPI and the Docker image are still to do.

## Why SecretSentinel

- **Local only.** Your code never leaves your machine. No network access while scanning.
- **Working tree, staged changes and history.** Finds secrets in current files, in what you are about to commit, and in old commits that were later deleted but still live in the repository.
- **Easy to extend.** Detection rules are plain YAML: an ID, a regex, an optional entropy threshold and a severity.
- **Low noise.** Shannon entropy filters out placeholders. `.secretsentinelignore` skips paths, and a YAML allowlist accepts known findings by rule, path, or the SHA-256 of the secret, so the allowlist never stores the secret itself.
- **CI-ready.** JSON for scripts, SARIF 2.1.0 for GitHub code scanning, and a pre-commit hook.
- **Safe output.** Secrets are never printed in full. Reports show a short preview and the length.

## Installation

From a checkout of this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requires Python 3.10 or newer and `git` on the PATH. Supported platforms: Linux and macOS.

## Usage

```bash
# Scan the current directory. Inside a git repository, this covers tracked files
# and untracked files that are not ignored by .gitignore.
secretsentinel scan

# Scan a specific file or directory
secretsentinel scan path/to/project

# Scan only the lines you are about to commit
secretsentinel scan --staged

# Scan every added line in the commit history (all refs)
secretsentinel scan --history
secretsentinel scan --history --max-commits 500

# Machine-readable output
secretsentinel scan --format json
secretsentinel scan --format sarif --output results.sarif

# Extra rules, and an explicit allowlist
secretsentinel scan --rules-file my-rules.yaml --allowlist .secretsentinel-allow.yaml
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No secrets found |
| `1`  | At least one potential secret found |
| `2`  | Usage or configuration error (invalid rules, allowlist, or git options) |

## Configuration

### `.secretsentinelignore`

Placed at the repository root (or the scanned directory). One pattern per line:

```text
# comments start with #
tests/fixtures/*     # glob on the relative path
*.min.js            # no slash: matches the file name at any depth
vendor/             # trailing slash: everything under this directory
```

See [`.secretsentinelignore.example`](.secretsentinelignore.example).

### Allowlist

`.secretsentinel-allow.yaml` at the root (or any file passed with `--allowlist`):

```yaml
allow:
  - sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    reason: Known test value, already rotated
  - rule: generic-password-assignment
    path: tests/fixtures/*
    reason: Fake credentials in test fixtures
```

Each entry must set at least one of `rule`, `path` or `sha256`. When several are set, all must match. Get the digest of a finding from `--format json` (the `digest` field).

### Custom rules

```yaml
rules:
  - id: internal-service-token
    description: Internal service token
    regex: 'svc_tok_([A-Za-z0-9]{32})'   # group 1 is the secret
    severity: high                        # low | medium | high | critical
    cwe: CWE-798
    min_entropy: 3.0                      # 0 disables the entropy check
```

A custom rule with the same `id` as a built-in rule replaces it. Built-in rules live in [`src/secretsentinel/rules/default.yaml`](src/secretsentinel/rules/default.yaml).

## pre-commit hook

Add this to `.pre-commit-config.yaml` in your project, using a local install of SecretSentinel:

```yaml
repos:
  - repo: local
    hooks:
      - id: secretsentinel
        name: SecretSentinel
        entry: secretsentinel scan --staged
        language: system
        pass_filenames: false
        types: [text]
```

The hook definition shipped in [`hooks/.pre-commit-hooks.yaml`](hooks/.pre-commit-hooks.yaml) can be used once the project is published.

## Output

Console output is a table with severity, rule, location, a redacted preview and the CWE. JSON and SARIF include the same information. Neither format contains the full secret.

## Development

```bash
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the project layout, how to add rules and the secure coding rules we follow.

## Roadmap

| Weeks | Focus | Status |
|-------|-------|--------|
| 1-2   | CLI, regex engine, Shannon entropy | Done |
| 3-4   | Git integration: working tree, staged changes, history | Done |
| 5     | False-positive handling: `.secretsentinelignore`, YAML allowlist | Done |
| 6     | Output formats: console (Rich), JSON, SARIF | Done |
| 7     | pre-commit hook, `CONTRIBUTING.md`, `SECURITY.md` | Done |
| 8     | Tests, PyPI and Docker packaging, v0.1 launch | In progress |

## Security

SecretSentinel reports *potential* secrets and does not validate them against live services. Reports are sensitive: do not publish them, and redact them before sharing. See [SECURITY.md](SECURITY.md) to report a vulnerability in SecretSentinel itself.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
