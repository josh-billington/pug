---
name: pug
description: Use the Pug CLI to check scanner availability, scan trusted local checkouts or pinned container images, compare existing Pug reports, or run a requested command in the offline sandbox. Summarize findings and coverage without exposing secrets or overstating results.
---

# Pug

Pug runs security scanners and normalizes their output into a JSON report. Tell the user what the tools observed and what they did not test.

The core principle: **a Pug report is evidence, not a verdict.** `"complete": true` means the requested checks finished, not that the code is secure. A finding that disappears is "not observed", not "fixed". Keep that distinction in everything you tell the user. Overstating safety is the worst failure mode for a security tool.

## 1. Choose an action and check prerequisites

When invoked with an action, run only that action. If invoked without an action or a clear request, list the available actions and wait. Treat paths, image references, and check names as data, not shell code. Quote each argument separately; never execute the argument string as a command. Do not launch active application or network scans from this skill.

```sh
command -v pug && pug --version
```

If it's missing, explain how to install it (needs Go 1.25+) or install it if the user requested installation:

```sh
go install github.com/josh-billington/pug/cmd/pug@latest
```

Go installs `pug` into `go env GOBIN` if configured, otherwise into `$(go env GOPATH)/bin`. If the binary isn't on `PATH`, use its verified absolute path. Don't edit the user's shell profile.

`doctor` only lists scanner availability; `diff` only reads reports. Neither needs scanner setup. If a requested scan is missing a scanner, check readiness with:

```sh
pug setup --check --format json
```

If the required scanner is missing, report it and suggest `pug setup --tools <tool>` for just the needed scanners. For the default repository scanners, suggest `pug setup --repo`. Only install when requested. Setup downloads binaries without sudo or shell profile changes. It does not install OpenGrep rule packs. Those stay opt-in: `pug rules install opengrep`, then `pug scan --rules opengrep`.

## 2. Pick the right command

| Goal | Command |
| --- | --- |
| Scan a local repo or working tree | `pug scan [dir]` |
| Scan a container image | `pug image name@sha256:<64-hex digest>` |
| Compare two reports | `pug diff before.json after.json` |
| Run a command in an offline container | `pug sandbox --image name@sha256:... -- <cmd>` |
| List which scanners are installed | `pug doctor` |

### Repository scans (most common)

```sh
pug scan -o pug-report.json > /dev/null; echo "exit=$?"
```

The directory argument is optional and defaults to `.`. Default checks: `source` (OpenGrep), `secrets` (Gitleaks), `dependencies` (Trivy), `actions` (Actionlint), `infra` (Trivy config). `source` uses the built-in starter rules unless you pass `--rules`. To use an upstream pack, run `pug rules install opengrep` (or `amplify`, or `aikido`) and pass `--rules opengrep`. A missing pack skips `source` and makes the report incomplete. Opt-in: `secrets-history` (TruffleHog) scans committed Git history from the repo root. Add it when the user asks whether a secret was ever committed. Narrow with `-c secrets,dependencies` when the user requests those checks. Save with `-o` to a new report path unless the user explicitly requests replacement. Redirect stdout to avoid dumping a large JSON blob into context, but keep stderr and capture the exit status.

Useful flags: `--fail-on` accepts `none`, `info`, `low`, `medium`, `high`, or `critical` (default `high`). `--timeout` defaults to `5m` per scanner. `--rules` accepts `starter`, `NAME[:PROFILE]`, a local `.yml` file, or `DIR[:PROFILE]`. `-f text` prints a human summary.

### Image scans

The image must be pinned by digest (`name@sha256:` + 64 lowercase hex). If the user gives a tag, resolve it from the local image metadata or ask for the digest. Trivy may download the image and its vulnerability database. Save and interpret the report as for a repository scan.

### Sandbox

Runs a command against a snapshot of the repo's **tracked, committed** files in a container with no network, a read-only root, UID 65534, and a scratch dir. Useful for running untrusted code or an agent task in isolation.

```sh
pug sandbox --image node@sha256:<digest> --repo . --timeout 5m -- npm test
```

The checkout must be clean (no modified tracked files) and the image must already be pulled. Work happens in `/scratch/work`; nothing is copied back to the host. `--app-command '["node","server.js"]'` starts an app alongside the command; the command must wait for it to be ready.

## 3. Interpret the exit code before anything else

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Requested checks completed, no findings at/above `--fail-on` | Report the result *with* its coverage limits |
| 1 | Findings at or above the threshold, or a runtime error. Check stderr. | Triage the findings |
| 2 | Bad arguments/flags | Fix the command |
| 3 | Coverage is incomplete. A requested check did not finish. | Read `checks[].reason` and `not_tested`. The report may still contain findings. |
| 130 | Interrupted; partial report emitted | Say the scan was cut short |

Exit 3 takes precedence over 1, so a run can have findings *and* exit 3. Don't treat 3 as "Pug is broken": usually a scanner is missing (`unavailable` → run `pug setup`), timed out (raise `--timeout`), or lacked an input (`skipped`). Fix what you can and re-run; otherwise report the gap explicitly.

## 4. Read the report

Shape (schema_version `"1"`):

```
{ target, complete, started_at, finished_at,
  checks: [ { name, tool, version, status, reason, exit_code, evidence_sha256,
              findings: [ { id, check, tool, rule, severity, message, location, line, fingerprint } ] } ],
  not_tested: [ { check, reason } ],
  limitations: [ "..." ] }
```

`status` is `completed`, `failed`, `unavailable`, or `skipped`. `severity` is `info`, `low`, `medium`, `high`, or `critical`.

Handy `jq` queries:

```sh
jq '{complete, checks: [.checks[] | {name, status, reason, n: (.findings|length)}]}' pug-report.json
jq -r '.checks[].findings[] | [.severity, .check, .rule, "\(.location):\(.line)", .message] | @tsv' pug-report.json | sort
jq '[.checks[].findings[] | select(.severity=="high" or .severity=="critical")]' pug-report.json
jq '.not_tested, .limitations' pug-report.json
```

Then look at the code at each `location:line` before drawing conclusions. Scanners produce false positives, including test fixtures, example keys, and vendored code. Say which findings you verified and which you judged to be false positives, and why.

**Secrets:** Pug withholds secret values from reports. Do not search for the secret value or print it. Refer to it by file and line. If a real credential was committed, rotate or revoke it with the provider. Deleting the line does not remove the secret from Git history or from anyone who already has it.

## 5. Verify fixes with diff

For `diff`, compare the two existing reports without rescanning. If the user explicitly asks to verify a fix by rescanning, use the same target and checks and save the new report separately:

```sh
pug scan -o pug-after.json > /dev/null
pug diff pug-report.json pug-after.json
```

Output has `new`, `persistent`, `absent`, and `unverified` arrays. `absent` means a completed check no longer observed the finding. That is consistent with a fix, and it is not proof of one. `unverified` means the later check did not complete, so nothing can be said. Both reports must have the same `target`. Scan from the same path.

## 6. Report back to the user

Keep it concise and honest. A good summary covers:

1. **What ran:** target, checks, and whether coverage was complete (name any `failed`/`unavailable`/`skipped` checks and why).
2. **Findings:** grouped by severity, each with location, what it is, and whether you confirmed it or consider it a false positive.
3. **What was not tested:** quote `not_tested` and `limitations`. For example, a repository scan does not test runtime behavior, authorization logic, or business logic. `pentest` is never performed.
4. **Next steps:** concrete fixes, or what's needed to close coverage gaps.

Avoid phrases like "the repo is secure" or "no vulnerabilities". Prefer "Pug's five repository checks completed and reported no findings at high severity or above; this covers X, not Y."

## Gotchas

- `pug scan` scans the current files on disk (including untracked ones); `secrets` doesn't scan git history; `secrets-history` does, but only committed objects.
- Reports are written with mode 0600 and can contain local paths and URLs. Do not commit them. `pug-report*.json` is a sensible `.gitignore` entry.
- Fingerprints include rule, location, line, and message, so moving code or a scanner upgrade can turn a persistent finding into new + absent.
- Native scanners run with the user's permissions; only scan code you'd be comfortable running tools over. Use `pug sandbox` for running untrusted code.
- Full docs: https://github.com/josh-billington/pug/tree/main/docs (`commands.md` is the reference).
