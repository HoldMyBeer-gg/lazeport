# Security Policy

Lazeport handles pentest findings, which are about as sensitive as data gets. If you find a way to break it, I want to hear about it before anyone else does.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

**https://github.com/HoldMyBeer-gg/lazeport/security/advisories/new**

That opens a private thread between you and the maintainer. Please do not open a public issue, pull request, or discussion for anything security-related until a fix has shipped.

Include what you can of:

- The affected area (endpoint, page, file, or feature) and the version or commit you tested.
- Steps to reproduce, ideally a minimal request or payload.
- What an attacker gains: cross-organization data access, auth bypass, code execution, and so on.
- Any suggested fix, if you have one.

## What to expect

| Step | Target |
|------|--------|
| Acknowledgement | within 3 business days |
| Triage and severity assessment | within 7 days |
| Fix for confirmed issues | as fast as severity warrants, normally within 90 days |
| Disclosure | coordinated with you, with credit if you want it |

If you have not heard back in 7 days, reply on the advisory thread to bump it.

## Supported versions

There are no tagged releases yet. Deployments run from the `main` branch, and security fixes land there. Please test against current `main` before reporting.

## Scope

In scope: anything in this repository. Of particular interest:

- Cross-organization access to reports, findings, templates, connectors, or audit logs (RBAC bypass).
- Authentication, session, 2FA, SSO, or API key weaknesses.
- Server-side request forgery through user-supplied LLM or Jira URLs.
- Injection of any kind through pasted notes, scanner imports (SARIF, Burp, Nessus, CSV), or DOCX templates.
- Secrets leaking into logs, exports, or error responses.

Out of scope:

- Behaviour of third-party LLM providers, Jira, or identity providers themselves.
- Deployments that disable protections on purpose: `AUTH_DISABLED=1`, `DISABLE_2FA=1`, or the `ALLOW_PRIVATE_*_URLS` flags in production.
- Volumetric denial of service, rate-limit exhaustion without amplification, and findings that require physical access to the host.
- Reports from automated scanners without a demonstrated impact.

## Safe harbour

Good-faith research is welcome. If you stay within scope, avoid accessing or modifying data that is not yours, do not degrade the service for others, and give a reasonable window to fix before disclosing, I will not pursue legal action and will treat the report as the help it is.

## Hardening your own deployment

See [PRODUCTION.md](PRODUCTION.md) for the production checklist, the outbound URL policy, and the security headers the app sets. Dependency and code-scanning alerts for this repository are handled through GitHub Dependabot and CodeQL on every push.
