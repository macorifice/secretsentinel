# Security policy

## Supported versions

SecretSentinel is pre-alpha. Only the latest commit on the default branch receives fixes until v0.1 is released.

## Reporting a vulnerability

Please do not report vulnerabilities in public issues or pull requests.

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. The report is visible only to you and the maintainers.

Include:

- the version or commit you tested
- steps to reproduce
- the impact you expect

Do not include real secrets in the report. Describe them and redact them.

> **Setup required:** private vulnerability reporting must be enabled in the repository settings (Settings > Code security) once the repository exists on GitHub.

## Scope

In scope:

- ways a crafted repository, file or patch could crash, hang or exhaust memory in the scanner
- ways a scan could leak secret values into logs, reports or exception messages
- unsafe handling of rules, ignore or allowlist files

Out of scope:

- false positives or negatives in detection rules (open a regular issue instead)
- secrets already present in a repository you own: rotate them first
