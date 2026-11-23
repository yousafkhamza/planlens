# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub: **Security → Report a vulnerability** on this repository.

Include the affected version, a minimal plan/config that reproduces the issue (with secrets removed), and the impact. I aim to acknowledge reports within 3 working days and to ship a fix or mitigation within 30 days for confirmed issues.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | ✅ |

## Threat model (summary)

planlens processes Terraform plan JSON, which **contains secrets in plain text** (Terraform only *marks* them sensitive). The design goals are:

1. **No exfiltration.** The engine makes no network calls. The CLI/Action only call the GitHub API (PR comment) and, if explicitly enabled, an AI provider. The AI provider receives addresses, actions, attribute names and finding text only, never attribute values. Account IDs, emails and IPs are masked.
2. **No secret disclosure in reports.** Values under a `*_sensitive` mask are rendered as `(sensitive)`. Secret detectors report the attribute name and the token type, never the value.
3. **Untrusted input.** Plans and configs are treated as untrusted. The web UI renders plan content with `textContent` only and ships a strict Content-Security-Policy. Config regexes are validated before use.
4. **Supply chain.** No runtime dependencies (everything is bundled and reviewed), committed bundles are checked against a fresh build in CI, workflow actions are pinned by SHA, and npm releases use provenance.

Out of scope: the security of your Terraform state/plan storage, and findings that a rule misses (please open a normal issue for missed detections).
