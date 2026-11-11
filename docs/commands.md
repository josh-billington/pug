# Command reference

Pug writes scan reports to stdout and diagnostics to stderr. Scan reports use JSON by default. Setup uses text by default and sends progress to stderr.

CLI definitions are in [`internal/cli/cli.go`](../internal/cli/cli.go) and [`internal/cli/setup.go`](../internal/cli/setup.go). The built binary exposes their current commands and flags:

```sh
pug --help
pug setup --help
pug scan --help
pug app --help
pug sandbox --help
```

## Commands

| Command | Purpose |
| --- | --- |
| `pug setup` | Checks native scanners and installs missing tools for the current user. |
| `pug doctor` | Lists executables found on `PATH` or in Pug's tool directory. It does not run version commands or check scanner databases. |
| `pug scan DIRECTORY` | Scans the current working tree with the selected repository checks. |
| `pug image NAME@sha256:DIGEST` | Runs Trivy vulnerability and misconfiguration checks. Trivy can fetch the image and database. |
| `pug app URL --allow-active` | Runs the selected application checks against the target. |
| `pug diff BEFORE.json AFTER.json` | Compares findings for the same target. |
| `pug sandbox [FLAGS] -- COMMAND [ARGS...]` | Runs a command and an optional application in an offline container. |
| `pug help [COMMAND]` | Prints help for Pug or a command. `--help` has the same purpose. |
| `pug completion SHELL` | Generates a shell completion script. |
| `pug --version` | Prints the build version. Local builds default to `dev`. |

## Setup flags

| Flag | Default | Behavior |
| --- | --- | --- |
| `--check` | `false` | Checks tools without downloads or installations. |
| `--tools` | `gitleaks,actionlint,opengrep,trivy,nuclei,schemathesis` | Selects at least one native scanner. Unknown or repeated names are invalid. |
| `--with-zap` | `false` | Also checks the ZAP image and pulls it if missing. Requires a running Docker daemon. |
| `--zap-image` | The tested image in [`internal/tools/tools.go`](../internal/tools/tools.go) | Selects the digest-pinned image for `--with-zap`. A custom image also needs `--zap-image` on `pug app`. |
| `--timeout` | `10m` | Sets a deadline per selected tool installation. Valid values are greater than zero and at most `1h`. |
| `--format` | `text` | Accepts `text` or `json`. Progress goes to stderr in both formats. |

Setup reuses working tools on `PATH` before checking Pug's tool directory. Existing tools are not upgraded or required to match the pinned versions. A failed version command marks the tool as failed. Setup continues with the remaining tools.

Docker and Git are optional for native scanner setup. With `--with-zap`, Docker and the image become required. Setup does not install Docker or Git, start daemons, or change group membership. A ZAP image marked ready has passed an image availability check, not a live scan.

### Setup results

With `--format json`, setup returns these fields:

| Field | Meaning |
| --- | --- |
| `ready` | Every selected native scanner runs, and any explicitly requested ZAP image is available through Docker. |
| `home` | Pug's installation directory. |
| `tools` | Selected native scanners, with `name`, `status`, and available `path`, `version`, or `detail` fields. |
| `docker` | Docker daemon status. Values are `ready`, `missing`, or `unavailable`. |
| `git` | Git status. Values are `ready`, `missing`, or `unavailable`. |
| `zap` | Image status when `--with-zap` is set. Values are `ready` or `missing`. |
| `next_step` | A command for the selected scanners, or instructions after a failure. |

Native scanner statuses are `ready`, `installed`, `missing`, or `failed`. Neither `ready` nor `installed` verifies scanner databases, schema files, or templates.

### Tool paths and versions

`PUG_HOME` selects Pug's installation directory and must be an absolute path. The default is `~/.local/share/pug`. Pug resolves bare tool names on `PATH` first, then in its own `bin` directory. Explicit executable paths do not use that fallback.

Automatic installation supports macOS and Linux with glibc, on amd64 and arm64. The binary release URLs and SHA-256 digests are in [`internal/setup/releases.json`](../internal/setup/releases.json).

| Missing tool | Version installed | Source |
| --- | --- | --- |
| Gitleaks | 8.30.1 | Upstream release binary |
| Actionlint | 1.7.12 | Upstream release binary |
| OpenGrep | 1.33.1 | Upstream release binary |
| Trivy | 0.76.2 | Upstream release binary |
| Nuclei | 3.11.1 | Upstream release binary |
| Schemathesis | 4.33.2 | uv tool environment with managed Python 3.12 |
| uv | 0.9.9 | Upstream release binary, only if Schemathesis needs it and uv is missing |

Setup gets the Schemathesis version from [`internal/setup/setup.go`](../internal/setup/setup.go). The Python environment and uv cache also live under `PUG_HOME`. uv selects the transitive dependency versions during installation. Pug does not lock them.

The release URLs and Schemathesis pin are visible with:

```sh
rg -n '"url"|schemathesis==' internal/setup/releases.json internal/setup/setup.go
```

The following commands expose the selected defaults and the tools available on the current machine:

```sh
pug setup --help
pug setup --check --format json
```

## Checks

| Check | Tool | Scope |
| --- | --- | --- |
| `source` | OpenGrep | Bundled patterns for JavaScript `eval`, Python shell and pickle calls, and Go shell calls, or a supplied local rule file. |
| `secrets` | Gitleaks | Current directory contents. Pug excludes Git history, secret values, and source snippets from the report. |
| `dependencies` | Trivy | Vulnerabilities in supported dependency manifests and lockfiles. |
| `actions` | Actionlint | GitHub Actions syntax, expressions, and action metadata. Shellcheck and Pyflakes subprocesses are disabled. |
| `infra` | Trivy | Supported infrastructure and container configuration checks. |
| `image` | Trivy | Container image vulnerabilities and misconfigurations. |
| `api` | Schemathesis | API contract checks and input fuzzing based on the supplied local schema. |
| `exposure` | Nuclei | Supplied local HTTP templates. Redirects and Interactsh callbacks are disabled. |
| `zap` | Docker and ZAP | Full scan using a preinstalled digest-pinned ZAP image. |

Repository defaults are `source,secrets,dependencies,actions,infra`. Application defaults are `api,exposure`. `pentest` appears in `not_tested` because Pug supplies no autonomous pentesting agent.

### Application check limits

Schemathesis uses one worker, 25 examples per operation, no redirects, and a limit of ten requests per second. Nuclei disables redirects and out-of-band callbacks, uses one concurrent template, and limits requests to five per second.

ZAP runs `zap-full-scan.py`, including active checks. The adapter sets a one-minute spider duration with `-m 1`. The Pug `--timeout` applies to the whole check. Target URL validation does not restrict outbound network access.

These values come from [`internal/scanner/scanner.go`](../internal/scanner/scanner.go) and are visible with:

```sh
rg -n -- '--?(max-redirects|workers|max-examples|rate-limit|concurrency)|"-m", "1"' internal/scanner/scanner.go
```

The live application tests in [`internal/scanner/scanner_integration_test.go`](../internal/scanner/scanner_integration_test.go) cover local fixtures.

## Scan flags

| Flag | Applies to | Default | Behavior |
| --- | --- | --- | --- |
| `--format` | `scan`, `image`, `app` | `json` | Accepts `json` or `text`. |
| `--output` | `scan`, `image`, `app` | Unset | Also saves the report. The parent directory must exist. |
| `--fail-on` | `scan`, `image`, `app` | `high` | Minimum severity that produces exit code `1`. Accepts `info`, `low`, `medium`, `high`, `critical`, or `none`. |
| `--timeout` | `scan`, `image`, `app` | `5m` | Sets a positive deadline per scanner, including its version lookup. |
| `--checks` | `scan`, `app` | Target defaults | Selects checks by name. Duplicate or unsupported names are invalid. |
| `--rules` | `scan` | Bundled rules | Selects a reviewed local OpenGrep rules file. |
| `--allow-active` | `app` | `false` | Required for every application scan. |
| `--schema` | `app` | Unset | Supplies the local OpenAPI schema for `api`. |
| `--templates` | `app` | Unset | Supplies the reviewed local templates for `exposure`. |
| `--zap-image` | `app` | The tested image in [`internal/tools/tools.go`](../internal/tools/tools.go) | Selects a preinstalled digest-pinned image for `zap`. |

A missing schema or template option skips the check that needs it and makes the report incomplete. A supplied path that does not exist is a usage error. An unavailable ZAP image makes the check fail. The ZAP container uses `--pull=never`. Trivy's `image` check can fetch its target image.

Image references require a lowercase, 64-character SHA-256 digest. Application targets must be absolute HTTP or HTTPS URLs without embedded credentials, query parameters, or fragments.

## Sandbox flags

| Flag | Default | Behavior |
| --- | --- | --- |
| `--repo` | `.` | Selects the root of a Git checkout with a commit and no changes to tracked files. |
| `--image` | Unset | Requires a preinstalled image pinned by digest. Docker uses `--pull=never`. |
| `--app-command` | Unset | Accepts an application command as a JSON array of arguments. |
| `--timeout` | `2m` | Limits the run, including snapshot preparation. Valid values are greater than zero and at most `30m`. |
| `--format` | `json` | Accepts `json` or `text`. |
| `--output` | Unset | Also saves the report. |

The image supplies `/bin/sh`, `mkdir`, `cp`, and the command's dependencies. Pug replaces the image's entrypoint with its launcher. The application starts beside the command. The command must wait for application readiness.

The command works on a source copy in `/scratch/work`. `/source` holds the read-only staged copy. Pug does not copy files back to the host checkout.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | A utility command completed, setup is ready, or requested scan checks completed without findings at the threshold. |
| `1` | Findings meet the threshold, or another runtime operation failed. |
| `2` | Command arguments, options, or flags are invalid. |
| `3` | Requested scan coverage or setup is incomplete. |
| `130` | A handled signal cancelled the operation. A running scan emits its partial report. |

Incomplete scan coverage takes precedence over a finding exit code. A report can contain findings when the process exits with code `3`. `--fail-on none` disables finding failures but does not suppress incomplete coverage.

## Scan report fields

Reports use the schema in [`internal/report/report.go`](../internal/report/report.go).

| Field | Meaning |
| --- | --- |
| `schema_version` | Report format version. The current value is `"1"`. |
| `pug_version` | Pug's build version. |
| `target` | Repository path, image reference, or application URL. |
| `started_at`, `finished_at` | Report timestamps in UTC. |
| `complete` | All requested checks completed. This does not describe complete security coverage. |
| `checks` | Check results with status, tool, timestamps, exit code, findings, and available version information. |
| `not_tested` | Requested checks that did not complete and categories that were not requested. |
| `limitations` | Limits that affect the interpretation of the results. |

Check statuses are `completed`, `failed`, `unavailable`, or `skipped`. Successful report parsing records `evidence_sha256`, a SHA-256 hash of the scanner report. The sandbox hashes command stdout instead. Neither hash authenticates its source.

Pug deletes temporary scanner reports after each check. Recorded commands can contain paths to those deleted reports. Saved reports use atomic replacement and mode `0600` on POSIX filesystems. Imported reports have a 32 MiB limit and validated finding fingerprints.

Finding fingerprints include the check, tool, rule, location, line number, and message. The same evidence produces the same fingerprint. Moving a line or changing a scanner message can change the fingerprint.

### Report comparison

`diff` requires the same target in both reports and classifies findings as follows:

| Category | Meaning |
| --- | --- |
| `new` | The finding appears only in the later report. |
| `persistent` | The finding appears in both reports. |
| `absent` | The later completed check did not report the finding. This does not prove a fix. |
| `unverified` | The later report does not complete the check needed to evaluate the missing finding. |

Database and rule changes can affect comparisons. The [Verification record](verification.md) lists tested scanner versions and results. The [Security boundaries](security.md) explain coverage and isolation limits.
