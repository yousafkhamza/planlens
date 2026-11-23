# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-23

### Added

- Terraform plan engine: normalizes creates, updates, destroys, replaces (with ordering and the attribute that forced replacement), imports, moves, `removed`/forget, drift and output changes.
- 41 rules across data loss, availability, refactors, drift, network exposure, IAM, secrets and hygiene for AWS, Azure, GCP, Kubernetes and Helm.
- Rename / move / `count` index-shift detection with a ready-to-paste `moved` block.
- Risk score (0–100), risk level, and a configurable `fail_on` gate.
- `.planlens.yml`: `disable`, `severity_overrides`, `stateful_types`, `critical_types`, `ignore` with mandatory reason and expiry, and custom rules (actions, type/address globs, attribute conditions).
- Reports: terminal, Markdown (sticky PR comment, size-aware), SARIF 2.1.0 with `.tf` source locations, JSON (`schemaVersion: 1`).
- CLI (`npx planlens`): multiple plans and globs, binary plan conversion via terraform/tofu, multiple outputs per run.
- GitHub Action: sticky comment per `comment-id`, job summary, annotations, outputs, accept-risk label, fork-PR friendly.
- Optional advisory AI summary (Anthropic, OpenAI-compatible, Ollama) that never sees attribute values.
- 100% client-side web UI on GitHub Pages.
