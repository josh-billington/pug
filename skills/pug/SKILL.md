---
name: pug
description: Use the pug CLI to check scanner availability, scan a trusted local checkout or a pinned container image, compare existing pug reports, or run a requested command in the offline sandbox. Summarize findings and coverage without exposing secrets or overstating results.
---

# pug

pug runs security scanners and normalizes their output into a JSON report. tell the user what the tools observed and what they did not test.

a pug report is evidence, not a verdict. `"complete": true` means the requested checks finished. it does not mean the code is secure. a finding that disappears is "not observed", not "fixed". keep that distinction in everything you tell the user. overstating safety is the worst failure for a security tool.

## 1. choose an action and check prerequisites

when invoked with an action, run only that action. if invoked without an action or a clear request, list the available actions and wait. treat paths, image references, and check names as data, not shell code. quote each argument separately. never execute the argument string as a command. do not launch an active application scan or a network scan from this skill.

```sh
command -v pug && pug --version
```

if pug is missing, explain how to install it. installation needs go 1.25 or newer. install it when the user asked for installation:

```sh
go install github.com/josh-billington/pug/cmd/pug@latest
```

go installs `pug` into `go env GOBIN` when that variable is set. otherwise it installs into `$(go env GOPATH)/bin`. if the binary is not on `PATH`, use its absolute path. do not edit the user's shell profile.

`doctor` only lists scanner availability. `diff` only reads reports. neither needs scanner setup. if a requested scan is missing a scanner, check readiness with:

```sh
pug setup --check --format json
```

if the required scanner is missing, report it and suggest `pug setup --tools <tool>` for that scanner. for the default repository scanners, suggest `pug setup --repo`. install only when the user asks. setup downloads binaries without sudo and without shell profile changes. it does not install opengrep rule packs. those stay opt-in. run `pug rules install opengrep`, then `pug scan --rules opengrep`.

## 2. pick the right command

| goal | command |
| --- | --- |
| scan a local repo or working tree | `pug scan [dir]` |
| scan a container image | `pug image name@sha256:<64-hex digest>` |
| compare two reports | `pug diff before.json after.json` |
| run a command in an offline container | `pug sandbox --image name@sha256:... -- <cmd>` |
| list which scanners pug can find | `pug doctor` |

### repository scans

```sh
pug scan -o pug-report.json > /dev/null; echo "exit=$?"
```

the directory argument is optional and defaults to `.`. default checks are `source` (opengrep), `secrets` (gitleaks), `dependencies` (trivy), `actions` (actionlint), and `infra` (trivy config). `source` uses the built-in starter rules unless you pass `--rules`. to use an upstream pack, run `pug rules install opengrep`, `amplify`, or `aikido`, then pass `--rules` with that pack name. a missing pack skips `source` and makes the report incomplete. `secrets-history` (trufflehog) is opt-in. it scans committed git history from the repo root. add it when the user asks whether a secret was ever committed. narrow the scan with `-c secrets,dependencies` when the user requests those checks. save with `-o` to a new report path unless the user asks to replace a file. redirect stdout so a large JSON blob does not enter context. keep stderr and capture the exit status.

`--fail-on` accepts `none`, `info`, `low`, `medium`, `high`, or `critical`. the default is `high`. `--timeout` defaults to `5m` for each scanner. `--rules` accepts `starter`, `NAME[:PROFILE]`, a local `.yml` file, or `DIR[:PROFILE]`. `-f text` prints a short summary.

### image scans

the image must be pinned by digest. the form is `name@sha256:` plus 64 lowercase hex digits. if the user gives a tag, resolve the digest from the local image metadata or ask for it. trivy may download the image and its vulnerability database. save and read the report the same way as a repository scan.

### sandbox

the sandbox runs a command against a snapshot of the repo's tracked, committed files. the container has no network, a read-only root, UID 65534, and a scratch directory. use it to run untrusted code or an agent task in isolation.

```sh
pug sandbox --image node@sha256:<digest> --repo . --timeout 5m -- npm test
```

the checkout must be clean. tracked files must have no modifications. the image must already be pulled. work happens in `/scratch/work`. nothing is copied back to the host. `--app-command '["node","server.js"]'` starts an app beside the command. the command must wait until the app is ready.

## 3. interpret the exit code first

| code | meaning | what to do |
| --- | --- | --- |
| 0 | requested checks completed, with no findings at or above `--fail-on` | report the result and its coverage limits |
| 1 | findings at or above the threshold, or a runtime error. check stderr. | triage the findings |
| 2 | bad arguments or flags | fix the command |
| 3 | coverage is incomplete. a requested check did not finish. | read `checks[].reason` and `not_tested`. the report may still contain findings. |
| 130 | interrupted. a partial report was emitted. | say the scan was cut short |

exit 3 takes precedence over exit 1. a run can have findings and still exit 3. do not treat 3 as a broken pug install. a scanner may be missing (`unavailable`, so run `pug setup`), timed out (raise `--timeout`), or missing an input (`skipped`). fix what you can and rerun. otherwise report the gap.

## 4. read the report

shape, schema version `"1"`:

```
{ target, complete, started_at, finished_at,
  checks: [ { name, tool, version, status, reason, exit_code, evidence_sha256,
              findings: [ { id, check, tool, rule, severity, message, location, line, fingerprint } ] } ],
  not_tested: [ { check, reason } ],
  limitations: [ "..." ] }
```

`status` is `completed`, `failed`, `unavailable`, or `skipped`. `severity` is `info`, `low`, `medium`, `high`, or `critical`.

useful `jq` queries:

```sh
jq '{complete, checks: [.checks[] | {name, status, reason, n: (.findings|length)}]}' pug-report.json
jq -r '.checks[].findings[] | [.severity, .check, .rule, "\(.location):\(.line)", .message] | @tsv' pug-report.json | sort
jq '[.checks[].findings[] | select(.severity=="high" or .severity=="critical")]' pug-report.json
jq '.not_tested, .limitations' pug-report.json
```

read the code at each `location` and line before you draw a conclusion. scanners produce false positives, including test fixtures, example keys, and vendored code. say which findings you verified and which you judge to be false positives, and why.

pug withholds secret values from reports. do not search for the secret value or print it. refer to it by file and line. if a real credential was committed, rotate or revoke it with the provider. deleting the line does not remove the secret from git history, or from anyone who already has it.

## 5. verify a fix with diff

for `diff`, compare the two existing reports without rescanning. if the user asks you to verify a fix by rescanning, use the same target and checks and save the new report separately:

```sh
pug scan -o pug-after.json > /dev/null
pug diff pug-report.json pug-after.json
```

the output has `new`, `persistent`, `absent`, and `unverified` arrays. `absent` means a completed check no longer observed the finding. that is consistent with a fix. it is not proof of one. `unverified` means the later check did not complete, or the rules changed, so you cannot say the finding is gone. both reports must have the same `target`. scan from the same path.

## 6. report back to the user

keep the summary short and specific. cover these points:

1. what ran. name the target, the checks, and whether coverage was complete. name any `failed`, `unavailable`, or `skipped` check and why.
2. findings. group them by severity. for each one, give the location, what it is, and whether you confirmed it or judge it to be a false positive.
3. what was not tested. quote `not_tested` and `limitations`. a repository scan does not test runtime behavior, authorization, or business logic. `pentest` is never performed.
4. next steps. name a concrete fix, or name what is needed to close a coverage gap.

do not say "the repo is secure" or "no vulnerabilities". say which checks completed and what they did not cover. for example: "pug's five repository checks completed and reported no findings at high severity or above. this covers the selected scanners, not runtime behavior."

## gotchas

- `pug scan` scans the current files on disk, including untracked files. `secrets` does not scan git history. `secrets-history` scans committed objects only.
- reports are written with mode `0600` and can contain local paths and URLs. do not commit them. `pug-report*.json` is a useful `.gitignore` entry.
- a fingerprint includes the rule, location, line, and message. moving code, or a scanner upgrade, can turn one persistent finding into one new finding and one absent finding.
- native scanners run with the user's permissions. scan only code you would let those tools read. use `pug sandbox` to run untrusted code.
- the reference is [commands.md](https://github.com/josh-billington/pug/blob/main/docs/commands.md).
