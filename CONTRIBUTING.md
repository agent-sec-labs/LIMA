# Contributing to 砺码 · LIMA

Thank you for improving LIMA. Keep changes reviewable, evidence-driven, and
safe by default.

## Development setup

LIMA requires Python 3.11 or newer. On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
node --check web\app.js
```

The container regression suite is the release-level check:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test
```

Normal tests must not require a real LLM key. Remote-model evaluations are
opt-in, cost-bearing experiments and must never run on untrusted pull requests.

## Workflow

1. Create or claim an issue for non-trivial work.
2. Branch from an up-to-date `main` using `feat/`, `fix/`, `docs/`, or `test/`.
3. Keep one logical change per pull request.
4. Add or update tests for changed behavior.
5. Run host tests and the relevant Docker/security checks.
6. Open a pull request and resolve all review comments and required checks.

Direct pushes, force pushes, and branch deletion on `main` are not part of the
project workflow.

## Security-sensitive changes

Changes to authentication, repository import, command execution, SQL, path
handling, GitHub publication, repair templates, Oracles, or workflow permissions
must include:

- the threat or failure model;
- a regression test covering the unsafe case;
- the security invariant that blocks exploitation;
- evidence that the safe case still works;
- no new network, filesystem, or credential authority beyond the task scope.

Never commit `.env`, tokens, private keys, imported repositories, production
reports, or personal data. Use `.env.example` with empty secret values.

## Commit and contribution terms

Use clear Conventional Commit-style messages, for example:

```text
feat: add evidence fusion for CWE-79
fix: reject symlink escape in repository import
test: cover unsafe SQL identifier repair
```

Sign off commits with `git commit -s` when possible. By intentionally submitting
a contribution for inclusion in LIMA, you agree that it is provided under the
Apache License, Version 2.0, and confirm that you have the right to submit it.

## Pull request acceptance

A pull request is ready when it is understandable without private context,
contains no secrets or unexplained generated artifacts, passes required CI,
has an approving review, and documents user-visible or security-relevant
behavior changes.
