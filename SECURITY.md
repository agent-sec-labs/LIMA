# Security Policy

## Supported versions

Security fixes are provided for the latest release on `main`. Older tags are
reference snapshots and may not receive patches.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities, exposed credentials, bypasses, or
unsafe repair behavior in a public issue.

Use GitHub's **Security → Report a vulnerability** form to submit a private
report. Include, when available:

- affected version or commit;
- vulnerable file, symbol, and execution path;
- minimal reproduction steps;
- expected security invariant and observed behavior;
- impact assessment and a proposed mitigation;
- whether any credential or production system may already be affected.

Maintainers aim to acknowledge a complete report within 5 business days. A
fix or disclosure date depends on severity, reproducibility, and coordination
with affected upstream projects. Please allow a reasonable remediation window
before public disclosure.

## Scope and safe research

Good-faith research against repositories and systems you own or are authorized
to test is welcome. Do not use LIMA to access systems without permission,
exfiltrate data, disrupt services, or publish third-party secrets.

LIMA is an evidence-assistance tool, not a security guarantee. Findings and
generated repairs require human review before production use. If a real secret
is discovered, revoke or rotate it first; deleting it from the latest file does
not remove it from Git history.
