# Contributing

Thanks for helping make Terraform reviews safer.

## Setup

```bash
npm ci            # Node.js 22.12+ for development (the shipped CLI/Action support Node 20+)
npm run check     # typecheck, lint, tests with coverage gate, build
```

## Adding a rule

1. Pick the right file in `src/core/rules/` (`destructive`, `safeguards`, `network`, `iam`, `secrets`) and the next free ID in that range (`PL0xx` destructive/refactor, `PL1xx` safeguards, `PL2xx` network, `PL3xx` IAM, `PL4xx` secrets).
2. Report **what the plan introduces**. Use `introduced()` / `newStatements()` so pre-existing state isn't re-reported on every PR.
3. Never put attribute values in a message unless they're harmless. Use `display()`, which respects sensitive masks.
4. Register it in `src/core/rules/index.ts`.
5. Add positive **and** negative tests in `test/rules/`. If the resource shape matters, add it to a real fixture scenario in `test/fixtures/scenarios/` and run `npm run fixtures` (needs Terraform).
6. Run `npm run build`. It regenerates `docs/rules.md`, `dist/action.cjs` and the web bundle; commit them.

## Pull requests

- Keep PRs focused; include a CHANGELOG entry under "Unreleased".
- CI must be green: tests on Linux/macOS/Windows, the Node 20 runtime smoke test, real-Terraform e2e, and the dogfood Action run.
