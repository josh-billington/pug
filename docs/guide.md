# use pug

the commands assume `pug` is on `PATH`. from a checkout, use `./bin/pug`. native scanners run with your account's permissions, so scan trusted checkouts. see [security boundaries](security.md) before you handle hostile code. [the command reference](commands.md) lists every flag, report field, and exit code.

## install scanners

automatic installation requires macOS or Linux with glibc, on amd64 or arm64. on Windows, install the scanners on `PATH`, then use the check-only command below.

### install missing scanners

1. run setup as the account that runs scans.

	```sh
	pug setup
	```

	setup checks gitleaks, actionlint, opengrep, trivy, nuclei, and schemathesis. it installs missing tools under `~/.local/share/pug` and reuses working installations. pug finds its own tools without shell profile changes.

	for only the default repository scanners, run `pug setup --repo`. that selects gitleaks, actionlint, opengrep, and trivy. do not combine `--repo` with `--tools`.

	trufflehog backs only the opt-in `secrets-history` check, so it installs only with `pug setup --tools trufflehog`. naabu, used by `pug net`, installs only with `pug setup --tools naabu`.

2. confirm that setup prints `Selected scanners are ready.`

	if setup reports a failure, use [retry a failed installation](#retry-a-failed-installation). setup exits with code `3` when a selected tool is missing or fails.

3. run the scan command printed after `Next:`.

if you need a different installation directory, set `PUG_HOME` to an absolute path before setup. use the same value for later pug commands. see [tool paths and versions](commands.md#tool-paths-and-versions).

### check tools without installing

to check installed tools without downloading or installing anything, run:

```sh
pug setup --check
```

setup runs version commands and checks whether the Docker daemon responds. it exits with code `3` if a selected scanner is missing or fails. missing Docker or git does not block native scanner setup.

to select fewer scanners, pass their names with `--tools`:

```sh
pug setup --tools gitleaks,actionlint
```

for scripts, use JSON output:

```sh
pug setup --check --format json
```

check `ready` and the statuses in `tools`. progress goes to stderr. see [setup results](commands.md#setup-results) for the fields and status values.

### prepare ZAP

1. install Docker through your operating system.
2. start the Docker daemon.
3. pull pug's pinned ZAP image if it is missing.

	```sh
	pug setup --with-zap
	```

	setup reports `ZAP: ready` when the image is available. this checks image availability, not a live ZAP scan. setup also checks the selected native scanners.

if you choose another image, pass its full digest reference with `--zap-image` to both `pug setup` and `pug app`. see [run ZAP](#run-zap) for the scan procedure.

### retry a failed installation

if a download fails, check your network and proxy settings, then rerun setup. setup reuses tools that already work.

if a checksum does not match, check the pinned release asset before retrying. pug stops before it runs the downloaded binary.

if an installed tool's version command fails, repair or remove that installation. then rerun setup. tools on `PATH` take precedence over pug's installations.

if setup is interrupted, rerun it. uv can leave an unfinished Python environment or cache that a later run must complete.

if trivy fails during a scan, check its database access separately. setup checks that trivy runs. it does not check the vulnerability database. see [tool installation](security.md#tool-installation) for download verification and dependency limits.

## scan a repository

to run the default repository checks in the current directory, run:

```sh
pug scan -o pug-report-before.json
```

pass a directory when the checkout is not the current directory: `pug scan /path/to/repo -o pug-report-before.json`.

the default checks cover source patterns, secrets, dependency vulnerabilities, GitHub Actions, and infrastructure configuration. pug writes JSON to stdout and to `pug-report-before.json`.

to select checks, pass `-c`:

```sh
pug scan -c source,secrets,actions -f text
```

see [checks](commands.md#checks) for the tool and scope of each check. a missing or skipped requested check makes the report incomplete. one exception applies to `actions`. in a repository with no workflow YAML files, that check completes with nothing to lint and does not require actionlint.

## use a rule pack

the `source` check runs four starter rules by default. rule packs add upstream opengrep rules. `pug rules install` requires git and fetches rules from upstream. a source scan reads the installed files and does not fetch rules.

1. install the pack.

	```sh
	pug rules install amplify
	```

2. scan with a profile from the pack.

	```sh
	pug scan /path/to/repo -c source --rules amplify:security-audit
	```

`pug rules list` shows installed packs with their paths, checkout commits, and profiles. it also shows the built-in aliases and whether they are installed. running `pug rules install amplify` again updates that pack to the remote default branch HEAD. to select a revision, use `pug rules install amplify@COMMIT`, with the full commit ID.

other opengrep rules repositories work too:

```sh
pug rules install github.com/trailofbits/semgrep-rules
pug scan /path/to/repo -c source --rules amplify:security-audit,semgrep-rules
```

a pack without a profile in `--rules` uses `configs/default.list` if that file exists. otherwise it uses every rule file. pass `--rules` more than once, or separate values with commas, to combine packs, profiles, the starter rules, local rule files, and directories such as `./team-rules` or `./team-rules:audit`. see [rule packs](commands.md#rule-packs) for layout and file selection.

the `opengrep` and `amplify` packs use LGPL-2.1 with the Commons Clause, which restricts selling the rules. pug does not ship these packs. each user fetches them from upstream with `pug rules install`. review the license before you use a pack.

if a selected pack is not installed, the `source` check is skipped. its reason is the install command, and the report is incomplete.

`pug diff` compares the composed rules hashes recorded in the reports. when the rules differ, findings missing from the later report are `unverified`, not `absent`.

## compare reports after a fix

1. fix the finding in the checkout.
2. run the same checks against the same directory. repeat any directory argument and `-c` value from the first scan.

	if the first scan used the current directory and the default checks, run:

	```sh
	pug scan -o pug-report-after.json
	```

3. compare the saved reports.

	```sh
	pug diff pug-report-before.json pug-report-after.json
	```

the comparison lists `new`, `persistent`, `absent`, and `unverified` findings. if a check did not finish, missing findings remain `unverified`. see [report comparison](commands.md#report-comparison).

## upload to GitHub code scanning

`pug scan -f sarif` writes SARIF 2.1.0, which GitHub code scanning reads. findings appear in the repository's Security tab and on pull requests.

```sh
pug scan -f sarif -o pug.sarif > /dev/null
```

each completed check is its own run with its own category, such as `pug/secrets/`. a check that does not complete has no run. code scanning then leaves that check's open alerts alone, so a failed scan never closes an alert. file paths are relative to the scanned directory, so scan the repository root.

in a GitHub Actions job, upload the file with `github/codeql-action/upload-sarif` and the `security-events: write` permission. run the upload step even when the scan exits `1` for findings:

```yaml
- run: pug scan -f sarif -o pug.sarif > /dev/null
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pug.sarif
```

`pug diff` reads JSON reports, not SARIF. to compare reports as well, save a JSON report in a second scan.

## scan a container image

set `IMAGE` to a full image reference in `NAME@sha256:DIGEST` format. then run:

```sh
pug image "$IMAGE" -o pug-report-image.json
```

trivy can fetch the image and its vulnerability database. ZAP and sandbox image handling is separate.

## test an application

these checks send active requests and can change application data. use a disposable application with test data. review the local schema and templates before the scan.

1. start the application in the test environment.
2. replace the example URL, schema path, and template path with your values.
3. run the application checks.

	```sh
	pug app http://127.0.0.1:8000 \
		--allow-active \
		--schema /path/to/openapi.json \
		--templates /path/to/reviewed-http-templates \
		-o pug-report-app.json
	```

the report contains API findings from schemathesis and template findings from nuclei. see [application check limits](commands.md#application-check-limits) for request limits and redirect behavior.

## scan ports on a host

a port scan opens TCP connections to the address. scan only an address you are authorized to test.

1. list the ports the host should expose, such as `22` and `443`.
2. scan the address. replace the example values with yours.

	```sh
	pug net 192.0.2.10 \
		--ports 1-1024 \
		--expect 22,443 \
		--allow-active \
		-o pug-report-net.json
	```

each open port outside `--expect` is a finding, and the command exits with code `1`. if none of the expected ports answers, the report is incomplete and the command exits with code `3`. the host may be down, or a firewall may drop the scan. see [port scan limits](commands.md#port-scan-limits).

## run ZAP

ZAP crawls the target and sends active test requests. use a disposable environment. the ZAP container needs an address that it can reach.

1. prepare the image with [prepare ZAP](#prepare-zap).
2. start the target application.
3. run ZAP against the target address.

	for an application on the host with Docker Desktop, use:

	```sh
	pug app http://host.docker.internal:8000 \
		--allow-active --checks zap \
		--timeout 10m -o pug-report-zap.json
	```

on a Linux VPS, replace the URL with an address the ZAP container can reach. inside that container, `127.0.0.1` refers to the container itself. pug does not configure Docker networking.

if setup used a custom image, pass the same `--zap-image` reference to the scan. ZAP uses `--pull=never`, so the image must already be installed.

## run an offline command in the sandbox

use the sandbox to run a command against a copy of a clean git checkout. you can start an application beside the command in the same container.

you need git, a running Docker daemon, and a locally installed image pinned by SHA-256 digest. the image must contain `/bin/sh`, `mkdir`, `cp`, and the command's runtime and dependencies.

the container has no external network access. a hosted model API is unreachable. if you use an agent, the image must contain the offline agent and any local model it needs. pug supplies no agent, model, or credentials.

### run the command

1. set `SANDBOX_IMAGE` to your installed image's full `NAME@sha256:DIGEST` reference.
2. prepare a clean checkout with a commit.

	use the git checkout root for `--repo`. commit or stash changes to tracked files before the run. pug excludes untracked files and rejects tracked symlinks and submodules.

3. run your command after `--`.

	this example assumes the image contains Python and `/opt/offline-agent`, and the checkout contains `app.py`:

	```sh
	pug sandbox \
		--repo /path/to/clean-checkout \
		--image "$SANDBOX_IMAGE" \
		--app-command '["python3","app.py"]' \
		-o pug-report-sandbox.json \
		-- /opt/offline-agent test http://127.0.0.1:8000
	```

	replace the checkout path and the example commands with your values. omit `--app-command` if no application is needed.

the application and the command share container loopback. the command must wait until the application accepts requests.

### read the result

inspect `pug-report-sandbox.json`. a completed check means the command exited successfully and cleanup succeeded. pug records an output hash. it does not treat command output as security findings.

the command works in `/scratch/work`. pug leaves the host checkout unchanged and does not copy files back. see [sandbox flags](commands.md#sandbox-flags) for options and [disposable sandbox](security.md#disposable-sandbox) for isolation limits.

## run pug on a VPS

the VM must run Linux with glibc on amd64 or arm64, with network access for scanner downloads and git to clone the target. native scanners run with the account's permissions, so use a separate VM for code you do not trust. replace `user@vm` with your SSH login, and use `GOARCH=arm64` for an arm64 VM.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/pug-linux ./cmd/pug
scp bin/pug-linux user@vm:/tmp/pug
ssh user@vm 'mkdir -p ~/.local/bin && install -m 755 /tmp/pug ~/.local/bin/pug && ~/.local/bin/pug setup'
ssh user@vm 'cd /path/to/trusted-checkout && ~/.local/bin/pug scan -o ~/pug-report.json > /dev/null'
scp user@vm:pug-report.json ./pug-report.json
```

a nonzero scan exit can mean findings or incomplete coverage. see [exit codes](commands.md#exit-codes). for ZAP or the sandbox, install Docker on the VM first.
