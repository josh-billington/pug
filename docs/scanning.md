# run scans and compare reports

use these procedures to produce a pug report for a repository, a container image, or a running application. the commands assume `pug` is on `PATH`. from this checkout, use `./bin/pug`.

install the required scanners with [install scanners](setup.md). native scanners inherit your account's permissions, so scan trusted checkouts. see [security boundaries](security.md) before you handle hostile code.

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

1. prepare the image with [prepare ZAP](setup.md#prepare-zap).
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
