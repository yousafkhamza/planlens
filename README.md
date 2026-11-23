# planlens

**Know what `terraform apply` will really do — before you run it.**

planlens reviews the Terraform **plan**, not the code. It catches destroyed databases, forced replacements, renames that recreate resources, opened security groups, widened IAM and plaintext secrets, then posts one clear, sticky comment on your pull request and gates the merge.

[![ci](https://github.com/yousafkhamza/planlens/actions/workflows/ci.yml/badge.svg)](https://github.com/yousafkhamza/planlens/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/planlens.svg)](https://www.npmjs.com/package/planlens)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**▶ [Try it in your browser](https://yousafkhamza.github.io/planlens/)**: drop a `plan.json` and get the full review. 100% client-side; your plan never leaves the tab.

---

## What a review looks like

> ## 🔴 planlens — Risk **99/100** · CRITICAL
> `envs/prod` · Terraform 1.9.8 · 4 critical · 6 high · 3 medium · Gate ❌ failed (fail-on: `high`)
>
> | Severity | Rule | Finding |
> |---|---|---|
> | 🔴 CRITICAL | `PL002` | `module.data.aws_db_instance.payments` (aws_db_instance) will be REPLACED — existing data will not carry over. |
> | 🔴 CRITICAL | `PL201` | `aws_security_group.api` allows inbound from 0.0.0.0/0 on 5432 — includes 5432 (PostgreSQL). |
> | 🔴 CRITICAL | `PL306` | `aws_iam_role.github_deploy` trusts OIDC subject `repo:*` — effectively unrestricted. |
> | 🟠 HIGH | `PL006` | `aws_s3_bucket.reports_old` is destroyed and an equivalent `module.storage.aws_s3_bucket.reports` is created — this looks like a rename/move. |
> | 🟠 HIGH | `PL110` | `aws_cloudtrail.org`: CloudTrail logging stopped. |
>
> **Forced by:** `storage_encrypted`: false → true · Order: destroy-then-create · `skip_final_snapshot = true` — no final snapshot will be taken · Deletion protection is ON — the apply will fail at the destroy step.
>
> **Fix:** add a `moved { from = aws_s3_bucket.reports_old  to = module.storage.aws_s3_bucket.reports }` block …

Every finding says **what** changes, **why** Terraform does it (the exact attribute that forces a replacement), and **how to fix it**.

## Why

| Problem | What planlens does |
|---|---|
| `terraform plan` output is thousands of lines in a CI log; reviewers approve the HCL diff and miss `# must be replaced`. | One sticky PR comment with a risk score, the dangerous changes first, and everything else collapsed. |
| A harmless-looking diff (rename, reordered `count` list, one attribute) destroys and recreates a stateful resource. | Shows the attribute that forced the replacement, detects renames / `count` shifts, and gives you the `moved` block. |
| Static scanners (Checkov, tfsec, Trivy) check code; they can't tell what *this PR* changes. | Rules look at the **change**: newly opened ports, newly widened policies, protection newly switched off. Pre-existing debt is not re-reported on every PR. |
| Exceptions become permanent. | Ignores need a written `reason` and can `expire`. Expired ignores re-surface automatically. |

## Quick start

### GitHub Actions

```yaml
permissions:
  contents: read
  pull-requests: write     # sticky PR comment
  security-events: write   # optional: SARIF → Security tab

steps:
  - uses: actions/checkout@v7
  - uses: hashicorp/setup-terraform@v4
    with: { terraform_wrapper: false }

  - run: |
      terraform init -input=false
      terraform plan -input=false -out=tf.plan
      terraform show -json tf.plan > plan.json
    working-directory: infra

  - uses: yousafkhamza/planlens@v1
    with:
      plan: infra/plan.json
      source-dir: infra        # annotate findings on the exact .tf line
      fail-on: high

  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with:
      sarif_file: planlens.sarif
      category: planlens
```

Full examples: [single workspace](examples/github-actions/terraform-pr.yml) · [one comment per environment](examples/github-actions/multi-env-matrix.yml) · [with Infracost](examples/github-actions/with-infracost.yml) · [GitLab CI](examples/gitlab/.gitlab-ci.yml)

### CLI

```bash
# Node.js ≥ 20, no install needed
npx planlens plan.json

# binary plan files are converted automatically (terraform or tofu on PATH)
npx planlens tf.plan --fail-on critical

# several workspaces at once, several outputs at once
npx planlens envs/*/plan.json --format markdown -o comment.md \
  --out sarif=planlens.sarif --out json=planlens.json
```

Exit codes: `0` gate passed · `1` findings at/above `--fail-on` · `2` usage or input error.

### Docker (Jenkins, Azure DevOps, Bitbucket, Atlantis…)

```bash
docker run --rm -u "$(id -u)" -v "$PWD:/work" ghcr.io/yousafkhamza/planlens:1 plan.json \
  --fail-on high --out markdown=planlens.md --out sarif=planlens.sarif
```

Multi-arch (amd64/arm64), non-root, base image pinned by digest, published with SBOM and provenance. Examples: [Azure DevOps](examples/azure-devops/azure-pipelines.yml) · [Jenkins](examples/jenkins/Jenkinsfile) · [Atlantis](examples/atlantis/repos.yaml)

## What it catches

42 rules across AWS, Azure, GCP, Kubernetes and Helm, plus an optional cost budget. Full list with remediation: **[docs/rules.md](docs/rules.md)**.

| Area | Examples |
|---|---|
| **Data loss** | Destroy/replace of RDS, Aurora, DynamoDB, S3, EBS, EFS, KMS keys, Route 53 zones, Cosmos DB, Cloud SQL, PVCs, namespaces… · deletion protection / final snapshot / backups / PITR / versioning turned off · `force_destroy` |
| **Blast radius** | Replacing clusters, load balancers, subnets, NAT gateways, IAM roles, EIPs, generated passwords/keys · mass destroys · destroy-then-create ordering · DB major version and Kubernetes upgrades · capacity scaled to zero |
| **Refactor mistakes** | Rename or move into a module that recreates a resource (with the `moved` block to fix it) · `count` index shifts · `removed` block hint |
| **Network exposure** | 0.0.0.0/0 or `::/0` on SSH/RDP/DB/cache ports or all ports (SG, SG rules, Azure NSG, GCP firewall) · public RDS / Cloud SQL / Azure DB firewall · internal → internet-facing LB · public EKS API · S3 Block Public Access off · public ACLs · IMDSv1 |
| **IAM** | `*:*` · `service:*` on `*` · privilege-escalation actions (iam:PassRole, CreatePolicyVersion, Attach/Put*Policy…) · AdministratorAccess-style attachments · `Principal: "*"` resource policies · **GitHub/EKS OIDC trust without `sub`** · roles assumable by anyone · public Lambda · Azure Owner/Contributor at subscription scope · GCP `allUsers` / primitive roles |
| **Secrets** | AWS keys, private keys, GitHub/GitLab/Slack/Stripe/OpenAI/Anthropic tokens in attributes (incl. base64 `user_data`) · secret-named env vars with literal values (Lambda, ECS, App Service, Cloud Run, Kubernetes) · secret-looking outputs without `sensitive = true` · long-lived access keys |
| **Hygiene** | Drift detected during refresh · imports · moved addresses |
| **Cost** *(with Infracost)* | Monthly cost increase above an absolute or percentage budget |

## GitHub Action reference

| Input | Default | Description |
|---|---|---|
| `plan` | *(required)* | Path(s)/glob(s) to `terraform show -json` output, newline or comma separated. Binary plans are converted if `terraform`/`tofu` is on PATH. |
| `fail-on` | config, else `high` | `critical` \| `high` \| `medium` \| `low` \| `info` \| `none` |
| `config` | `.planlens.yml` if present | Config file path. |
| `working-directory` | `.` | Base dir for plan paths, config and outputs. |
| `source-dir` | plan's directory | Terraform root module, used to point SARIF results and annotations at `.tf` lines (local modules are followed). |
| `comment` | `always` | `always`, `changes` (only create when there are changes or findings; always update an existing one), or `never`. |
| `comment-id` | `default` | Use one per environment or job to get separate sticky comments. |
| `accept-risk-label` | `planlens:accept-risk` | PR label that lets the gate pass (findings are still reported). Trigger on `labeled` to re-run. |
| `github-token` | `${{ github.token }}` | Needs `pull-requests: write`. |
| `step-summary` | `true` | Write the report to the job summary. |
| `sarif-file` / `json-file` / `markdown-file` | `planlens.sarif` / `.json` / `.md` | Output paths. |
| `infracost` | — | Path to `infracost breakdown --format json` output for the plan (see [Cost](#cost-infracost)). |
| `ai` / `ai-model` | — | Optional advisory summary (see below). |

**Outputs:** `passed`, `risk-score`, `risk-level`, `findings`, `critical`, `high`, `sarif-file`, `json-file`, `markdown-file`.

**Fork PRs** only get a read-only token, so planlens can't comment there. It still writes the job summary, annotations and SARIF, and logs how to fix it (for example, a `workflow_run` follow-up job).

## Configuration

Put `.planlens.yml` in the repo root (or pass `--config`). Every key is optional, and unknown keys are rejected so typos fail loudly. See the [annotated example](examples/.planlens.yml).

```yaml
fail_on: high
mass_destroy_threshold: 10
stateful_types: ["mongodbatlas_cluster"]   # extend the built-in lists (globs ok)
critical_types: ["cloudflare_record"]
disable: [PL108]
severity_overrides:
  PL204: high

ignore:                                     # accepted risks — reason is mandatory
  - rule: PL201
    address: "module.edge.aws_security_group.public_alb"
    reason: "Public ALB by design, fronted by WAF (SEC-1234)"
    expires: 2027-06-30                     # re-surfaces automatically after this date

rules:                                      # org rules, no code
  - id: ORG001
    title: No destroys in production modules
    severity: critical
    message: "{address} would be {action}d in production — needs a change ticket."
    when:
      actions: [delete, replace]
      address: "module.prod_*"
  - id: ORG002
    title: CostCenter tag is mandatory
    severity: medium
    when:
      actions: [create]
      type: ["aws_instance", "aws_db_instance"]
      attributes:
        - { path: tags.CostCenter, op: absent }
```

Attribute operators: `exists`, `absent`, `equals`, `not_equals`, `matches`, `not_matches`, `in`, `not_in`, `changed`. Paths use dots and `[n]`; nested blocks are traversed automatically (`vpc_config.endpoint_public_access`).

## Cost (Infracost)

Terraform plans contain no prices, so planlens never guesses them. Give it an Infracost estimate of the same plan to put the monthly cost delta next to the risk review and gate on a budget:

```bash
infracost breakdown --path plan.json --format json --out-file infracost.json
npx planlens plan.json --infracost infracost.json
```

```yaml
# .planlens.yml
cost:
  max_monthly_increase: 500          # PL501 if the bill rises by more than $500/mo
  max_monthly_increase_percent: 20   # …or by more than 20%
```

The PR comment shows `💰 Cost: $2,140.50 → $2,552.80 /mo (+$412.30/mo (+19%))` plus the largest per-resource deltas. In the Action, use the `infracost` input ([example](examples/github-actions/with-infracost.yml)). In the web UI, drop `plan.json` and `infracost.json` together; each file is routed by its content. If the estimate doesn't mention any resource in the plan, planlens warns that it was probably generated from a different plan.

## Optional AI summary

```bash
ANTHROPIC_API_KEY=… npx planlens plan.json --ai anthropic           # default model: claude-opus-5-5
OPENAI_API_KEY=…    npx planlens plan.json --ai openai --ai-model <model>   # or any OpenAI-compatible endpoint via OPENAI_BASE_URL
                    npx planlens plan.json --ai ollama --ai-model qwen2.5:7b  # fully local (OLLAMA_HOST)
```

The summary is **advisory**. It never changes the score or the gate. The model only receives resource addresses, action types, names of changed attributes and the finding messages, with account IDs, emails and IPs masked. **Attribute values are never sent.** If the call fails, the review is still produced and a warning explains why.

## Security model

- **Read-only.** planlens never calls cloud APIs and needs no cloud credentials. It reads a plan you already produced.
- **Sensitive values stay hidden.** Plan JSON contains sensitive values in plain text, marked as sensitive. planlens checks those marks and prints `(sensitive)`. Secret detectors report the attribute name only, never the value.
- **No telemetry.** The only outbound call is the PR comment (Action) and the optional AI summary you turn on.
- **The web UI is offline.** A strict Content-Security-Policy blocks network calls, and plan content is rendered with `textContent` only, so a malicious plan can't inject HTML.
- **Supply chain.** The engine has no runtime dependencies, and the shipped bundles are generated and checked for drift in CI. Actions in this repo's workflows are pinned by commit SHA with least-privilege `permissions`. npm releases are published with provenance.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Programmatic use

```ts
import { analyzePlan, renderMarkdown } from "planlens";

const report = analyzePlan(JSON.parse(planJson), { config: { fail_on: "critical" }, name: "prod" });
if (!report.passed) console.log(renderMarkdown([report]));
```

`report` has a stable JSON schema (`schemaVersion: 1`): `summary`, `score`, `level`, `passed`, `findings[]`, `suppressed[]`, `warnings[]`, `changes[]`.

## How planlens compares

| | planlens | Static IaC scanners | Raw plan in CI / Atlantis | Infracost |
|---|---|---|---|---|
| Looks at the *change* (destroys, replacements, regressions) | ✅ | ❌ (code only) | text only | cost only |
| Explains why something is replaced | ✅ | ❌ | partly | ❌ |
| Rename / count-shift detection with `moved` fix | ✅ | ❌ | ❌ | ❌ |
| Security regressions introduced by the PR | ✅ | ✅ (all, incl. existing) | ❌ | ❌ |
| Works without cloud credentials | ✅ | ✅ | needs plan | ✅ |
| Cost delta in the same review, budget gate | ✅ (reads Infracost JSON) | ❌ | ❌ | ✅ |

They complement each other: run a static scanner on code and planlens on the plan.

## Development

```bash
npm ci
npm run check        # typecheck + lint + tests (coverage gate) + build
npm run fixtures     # regenerate real plan fixtures with Terraform (needs terraform + network)
```

- `src/core`: pure engine (no Node/DOM APIs); the same code runs in the CLI, the Action and the browser.
- `src/report`: text / markdown / SARIF / JSON renderers.
- `src/node`, `src/action`: file loading, glob, source mapping, GitHub integration.
- `test/fixtures/real`: plans produced by **real Terraform** runs (`scripts/gen-fixtures.mjs`). CI regenerates them on Terraform 1.5, 1.9 and latest, and checks that binary-plan and JSON input give identical findings.
- `dist/action.cjs`, `docs/assets/planlens.js` and `docs/rules.md` are generated by `npm run build` and committed. CI fails if they're stale.

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © Yousaf K Hamza
