# command reference

pug writes scan reports to stdout and diagnostics to stderr. scan reports use JSON by default. setup uses text by default and sends progress to stderr.

the command definitions are in [`internal/cli/cli.go`](../internal/cli/cli.go) and [`internal/cli/setup.go`](../internal/cli/setup.go). the built binary exposes the current commands and flags:

```sh
pug --help
pug setup --help
pug scan --help
pug app --help
pug sandbox --help
```

## commands

| command | purpose |
| --- | --- |
| `pug setup` | checks native scanners and installs missing tools for the current user. |
| `pug doctor` | lists executables found on `PATH` or in pug's tool directory. it does not run version commands or check scanner databases. |
| `pug scan [DIR]` | scans a working tree. the default directory is `.`. |
| `pug image NAME@sha256:DIGEST` | runs trivy vulnerability and misconfiguration checks. trivy can fetch the image and database. |
| `pug app URL --allow-active` | runs the selected application checks against the target. |
| `pug net IP --ports SPEC --expect PORTS --allow-active` | scans TCP ports on one IP address and reports open ports that are not expected. |
| `pug diff BEFORE.json AFTER.json` | compares findings for the same target. |
| `pug rules list` | lists installed packs and built-in aliases as JSON, with paths, commits, profiles, and install state. |
| `pug rules install NAME\|URL[@COMMIT]...` | clones or updates upstream rule repositories with git. |
| `pug sandbox [FLAGS] -- COMMAND [ARGS...]` | runs a command and an optional application in an offline container. |
| `pug help [COMMAND]` | prints help for pug or one command. `--help` has the same purpose. |
| `pug completion SHELL` | generates a shell completion script. |
| `pug --version` | prints the build version. local builds default to `dev`. |

## setup flags

| flag | default | behavior |
| --- | --- | --- |
| `--check` | `false` | checks tools without downloads or installations. |
| `--repo` | `false` | selects gitleaks, actionlint, opengrep, and trivy. those are the tools for the default repository checks. do not combine `--repo` with `--tools`. |
| `--tools` | `gitleaks,actionlint,opengrep,trivy,nuclei,schemathesis` | selects at least one native scanner. `trufflehog` and `naabu` install only when named. unknown or repeated names are invalid. |
| `--with-zap` | `false` | also checks the ZAP image and pulls it if missing. requires a running Docker daemon. |
| `--zap-image` | the tested image in [`internal/tools/tools.go`](../internal/tools/tools.go) | selects the digest-pinned image for `--with-zap`. a custom image also needs `--zap-image` on `pug app`. |
| `--timeout` | `10m` | sets the deadline for each selected tool installation. valid values are greater than zero and at most `1h`. |
| `--format` | `text` | accepts `text` or `json`. progress goes to stderr in both formats. |

setup reuses working tools on `PATH` before it checks pug's tool directory. existing tools are not upgraded, and they do not have to match the pinned versions. a failed version command marks the tool as failed. setup continues with the remaining tools.

Docker and git are optional for native scanner setup. with `--with-zap`, Docker and the image become required. setup does not install Docker or git, start daemons, or change group membership. a ZAP image marked ready has passed an image availability check, not a live scan.

### setup results

with `--format json`, setup returns these fields:

| field | meaning |
| --- | --- |
| `ready` | every selected native scanner runs, and any explicitly requested ZAP image is available through Docker. |
| `home` | pug's installation directory. |
| `tools` | selected native scanners, with `name`, `status`, and available `path`, `version`, or `detail` fields. |
| `docker` | Docker daemon status. values are `ready`, `missing`, or `unavailable`. |
| `git` | git status. values are `ready`, `missing`, or `unavailable`. |
| `zap` | image status when `--with-zap` is set. values are `ready` or `missing`. |
| `next_step` | a command for the selected scanners, or instructions after a failure. |

native scanner statuses are `ready`, `installed`, `missing`, or `failed`. neither `ready` nor `installed` verifies scanner databases, schema files, or templates.

### tool paths and versions

`PUG_HOME` selects pug's installation directory and must be an absolute path. the default is `~/.local/share/pug`. pug resolves a bare tool name on `PATH` first, then in its own `bin` directory. an explicit executable path does not use that fallback.

automatic installation supports macOS and Linux with glibc, on amd64 and arm64. the binary release URLs and SHA-256 digests are in [`internal/setup/releases.json`](../internal/setup/releases.json).

| missing tool | version installed | source |
| --- | --- | --- |
| gitleaks | 8.30.1 | upstream release binary |
| trufflehog | 3.99.7 | upstream release binary |
| actionlint | 1.7.12 | upstream release binary |
| opengrep | 1.33.1 | upstream release binary |
| trivy | 0.76.2 | upstream release binary |
| naabu | 2.7.0 | upstream release binary, only with `--tools naabu` |
| nuclei | 3.11.1 | upstream release binary |
| schemathesis | 4.33.2 | uv tool environment with managed Python 3.12 |
| uv | 0.9.9 | upstream release binary, only if schemathesis needs it and uv is missing |

setup gets the schemathesis version from [`internal/setup/setup.go`](../internal/setup/setup.go). the Python environment and uv cache also live under `PUG_HOME`. uv selects the transitive dependency versions during installation. pug does not lock them.

the release URLs and the schemathesis pin are visible with:

```sh
rg -n '"url"|schemathesis==' internal/setup/releases.json internal/setup/setup.go
```

these commands show the selected defaults and the tools available on the current machine:

```sh
pug setup --help
pug setup --check --format json
```

## checks

| check | tool | scope |
| --- | --- | --- |
| `source` | opengrep | the rules selected with `--rules`. the default starter rules cover JavaScript `eval`, Python shell and pickle calls, and go shell calls. |
| `secrets` | gitleaks | current directory contents. pug excludes git history, secret values, and source snippets from the report. |
| `secrets-history` | trufflehog | committed git history on every ref, not uncommitted changes. the target must be the repository root. trufflehog runs with `--no-verification` and `--no-update`, so it sends no candidate secrets to providers. the `URI` detector is excluded because it flags every URL with embedded credentials, including test fixtures. pug keeps the detector, file, line, and commit, and drops secret values and committer details. opt-in only. |
| `dependencies` | trivy | vulnerabilities in supported dependency manifests and lockfiles. |
| `actions` | actionlint | GitHub Actions syntax, expressions, and action metadata. shellcheck and pyflakes subprocesses are disabled. |
| `infra` | trivy | supported infrastructure and container configuration checks. |
| `image` | trivy | container image vulnerabilities and misconfigurations. |
| `api` | schemathesis | API contract checks and input fuzzing from the supplied local schema. |
| `exposure` | nuclei | supplied local HTTP templates. redirects and Interactsh callbacks are disabled. |
| `zap` | Docker and ZAP | full scan using a preinstalled digest-pinned ZAP image. |
| `ports` | naabu | TCP connect scan of `--ports` and `--expect` on one IP address. open ports outside `--expect` are medium findings. if no expected port answers, the check fails, because a down or filtered host looks the same as a closed one. |

repository defaults are `source,secrets,dependencies,actions,infra`. add `secrets-history` with `--checks` after `pug setup --tools trufflehog`. application defaults are `api,exposure`. `pentest` appears in `not_tested` because pug supplies no autonomous pentesting agent.

### rule packs

| alias | clone URL |
| --- | --- |
| `opengrep` | `https://github.com/opengrep/opengrep-rules.git` |
| `amplify` | `https://github.com/amplify-security/opengrep-rules.git` |
| `aikido` | `https://github.com/AikidoSec/opengrep-rules.git` |

`pug rules install` requires git. `pug doctor` checks whether git is available. pass an alias, `github.com/owner/repo`, or an HTTPS git URL. a `file://` URL can use a local mirror. for a URL, the install name is the repository's final path component without `.git`. an invalid name, or a name reserved for a built-in alias, is a usage error. a URL must not contain credentials, a query, or a fragment.

without `@COMMIT`, each install clones the remote default branch HEAD, including when the pack is already installed. append a full commit ID to select a revision. pug clones into a temporary directory under `PUG_HOME/rules` and replaces `PUG_HOME/rules/NAME` after git succeeds. `--timeout` defaults to `5m` and limits each repository install. pug records no separate manifest. it reads the commit from the checkout.

a pack can also be a local directory. pug selects regular `.yml` and `.yaml` rule files anywhere in it. it excludes hidden directories, symlinks, test fixtures (`*.test.yml`, `*.test.yaml`, `*.fixed.*`), and YAML without a top-level `rules` list. a file with a top-level `rules` list that is invalid, such as a rule without an `id`, is a usage error that names the file. each selected file has a 16 MiB limit. profiles come from `configs/*.list`. a pack without an explicit profile uses `configs/default.list` if that file is present. otherwise it uses every rule file.

pug qualifies pack rule IDs so they stay the same across profiles and do not collide. a pack rule ID is the pack name, the rule file's path with dots for slashes and without its extension, and the upstream ID when it differs from the file name. for example, rule `no-eval` in `team/python/no-eval.yaml` from pack `mypack` becomes `mypack.team.python.no-eval`. a directory inside an installed pack uses that pack name and the folder's path under the pack, so `rules/opengrep/javascript/jose/security` yields ids such as `opengrep.javascript.jose.security...`. any other directory uses its base name as the pack name. starter rules and local file rules keep their IDs. `NAME:./file.list` selects rules from an installed pack using a local profile file. the file uses the same `path:id` lines as `configs/*.list`. pug combines the selected rules into one config for each scan. a rule that several values select runs once.

some profile entries name files that are absent from the checkout. pug skips those entries and counts them in the check's reason. the report lists them in `rules.unresolved`.

### port scan limits

`pug net` accepts one literal IPv4 or IPv6 address. hostnames, ranges, and zoned addresses are invalid. `--ports` takes numbers and ranges from 1 to 65535, such as `22,80,8000-8100`. naabu also scans every `--expect` port. `--fail-on` defaults to `medium` for `pug net`, so an unexpected open port exits with code `1`.

naabu runs a TCP connect scan at 500 packets per second with its default three retries. host discovery and update checks are off. a scan of all 65535 ports, or of a host that drops packets, can exceed the default five-minute `--timeout`. a timed-out scan is incomplete. pug does not pass naabu's passive (Shodan), cloud upload, proxy, or nmap options. naabu runs with `HOME` and `XDG_CONFIG_HOME` set to a private temporary directory, including for version checks, and with `DISABLE_CLOUD_UPLOAD=true`. UDP and service identification are not tested.

### application check limits

schemathesis uses one worker, 25 examples per operation, no redirects, and a limit of ten requests per second. nuclei disables redirects and out-of-band callbacks, uses one concurrent template, and limits requests to five per second.

ZAP runs `zap-full-scan.py`, including active checks. the adapter sets a one-minute spider duration with `-m 1`. the pug `--timeout` applies to the whole check. target URL validation does not restrict outbound network access.

these values come from [`internal/scanner/scanner.go`](../internal/scanner/scanner.go) and are visible with:

```sh
rg -n -- '--?(max-redirects|workers|max-examples|rate-limit|concurrency)|"-m", "1"' internal/scanner/scanner.go
```

the live application tests in [`internal/scanner/scanner_integration_test.go`](../internal/scanner/scanner_integration_test.go) cover local fixtures.

## scan flags

| flag | applies to | default | behavior |
| --- | --- | --- | --- |
| `--format`, `-f` | `scan`, `image`, `app`, `net` | `json` | accepts `json` or `text`. `scan` also accepts `sarif`, for [code scanning](scanning.md#upload-to-github-code-scanning). |
| `--output`, `-o` | `scan`, `image`, `app`, `net` | unset | also saves the report. the parent directory must exist. |
| `--fail-on` | `scan`, `image`, `app`, `net` | `high`, or `medium` for `net` | minimum severity that produces exit code `1`. accepts `info`, `low`, `medium`, `high`, `critical`, or `none`. |
| `--timeout` | `scan`, `image`, `app`, `net` | `5m` | sets a positive deadline for each scanner, including its version lookup. |
| `--checks`, `-c` | `scan` | repository defaults | selects checks by name. `-c` applies to `scan` only. duplicate or unsupported names are invalid. |
| `--checks` | `app` | `api,exposure` | selects `api`, `exposure`, or `zap`. |
| `--rules` | `scan` | `starter` | selects the `source` rules. accepts `starter`, an installed pack, `NAME:PROFILE`, `NAME:./file.list`, a reviewed local rules file, or `DIR[:PROFILE]`. a value that ends in `.yml` or `.yaml`, or that contains a path separator, is a path. `NAME:./file.list` is a local profile for that pack. repeat the flag or separate values with commas. |
| `--allow-active` | `app`, `net` | `false` | required for every application test and port scan. |
| `--schema` | `app` | unset | supplies the local OpenAPI schema for `api`. |
| `--templates` | `app` | unset | supplies the reviewed local templates for `exposure`. |
| `--zap-image` | `app` | the tested image in [`internal/tools/tools.go`](../internal/tools/tools.go) | selects a preinstalled digest-pinned image for `zap`. |

an invalid pack or profile name is a usage error. a missing local rules path, a missing profile file, a profile absent from an installed pack, or two different rules with the same ID is also a usage error. a selected pack that is not installed skips `source` and makes the report incomplete. a missing schema or template option skips the check that needs it and makes the report incomplete. a supplied path that does not exist is a usage error. an unavailable ZAP image makes the check fail. the ZAP container uses `--pull=never`. trivy's `image` check can fetch its target image.

an image reference requires a lowercase, 64-character SHA-256 digest. an application target must be an absolute HTTP or HTTPS URL without embedded credentials, a query, or a fragment.

## sandbox flags

| flag | default | behavior |
| --- | --- | --- |
| `--repo` | `.` | selects the root of a git checkout with a commit and no changes to tracked files. |
| `--image` | unset | requires a preinstalled image pinned by digest. Docker uses `--pull=never`. |
| `--app-command` | unset | accepts an application command as a JSON array of arguments. |
| `--timeout` | `2m` | limits the run, including snapshot preparation. valid values are greater than zero and at most `30m`. |
| `--format` | `json` | accepts `json` or `text`. |
| `--output` | unset | also saves the report. |

the image supplies `/bin/sh`, `mkdir`, `cp`, and the command's dependencies. pug replaces the image entrypoint with its launcher. the application starts beside the command. the command must wait until the application is ready.

the command works on a source copy in `/scratch/work`. `/source` holds the read-only staged copy. pug does not copy files back to the host checkout.

## exit codes

| code | meaning |
| --- | --- |
| `0` | a utility command completed, setup is ready, or the requested scan checks completed without findings at the threshold. |
| `1` | findings meet the threshold, or another runtime operation failed. |
| `2` | command arguments, options, or flags are invalid. |
| `3` | requested scan coverage or setup is incomplete. |
| `130` | a handled signal cancelled the operation. a running scan emits its partial report. |

incomplete scan coverage takes precedence over a finding exit code. a report can contain findings when the process exits with code `3`. `--fail-on none` disables finding failures. it does not suppress incomplete coverage.

## scan report fields

reports use the schema in [`internal/report/report.go`](../internal/report/report.go).

| field | meaning |
| --- | --- |
| `schema_version` | report format version. the current value is `"1"`. |
| `pug_version` | pug's build version. |
| `target` | repository path, image reference, or application URL. |
| `started_at`, `finished_at` | report timestamps in UTC. |
| `complete` | all requested checks completed. this does not describe complete security coverage. |
| `checks` | check results with status, tool, timestamps, exit code, findings, and available version information. |
| `not_tested` | requested checks that did not complete, and categories that were not requested. |
| `limitations` | limits that affect how you read the results. |

check statuses are `completed`, `failed`, `unavailable`, or `skipped`. a `source` check completes when opengrep could only partly parse some target files, such as templates or files with syntax errors. its reason counts the warnings. an invalid rule fails the check. successful report parsing records `evidence_sha256`, a SHA-256 hash of the scanner report. the sandbox hashes command stdout instead. neither hash authenticates its source.

the `source` check also records `rules`. that object holds the `--rules` values, the commit of each git checkout, the rule count, any `unresolved` profile entries, and `sha256`, the hash of the combined rules config.

pug deletes temporary scanner reports after each check. recorded commands can contain paths to those deleted reports. saved reports use atomic replacement and mode `0600` on POSIX filesystems. imported reports have a 32 MiB limit and validated finding fingerprints.

a finding fingerprint includes the check, tool, rule, location, line number, and message. the same evidence produces the same fingerprint. moving a line, or changing a scanner message, can change the fingerprint.

### report comparison

`diff` requires the same target in both reports. it classifies findings as follows:

| category | meaning |
| --- | --- |
| `new` | the finding appears only in the later report. |
| `persistent` | the finding appears in both reports. |
| `absent` | the later completed check ran the same rules and did not report the finding. this does not prove a fix. |
| `unverified` | the later report does not complete the check needed to evaluate the missing finding, or the check ran different rules. |

pug compares rules by the `rules.sha256` of each check. a database change can affect a comparison. the [verification record](verification.md) lists tested scanner versions and results. [security boundaries](security.md) explains coverage and isolation limits.
