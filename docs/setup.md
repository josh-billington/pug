# install scanners

use this guide to install pug's native scanners and prepare ZAP. the commands assume `pug` is on `PATH`. from this checkout, use `./bin/pug`.

automatic installation requires macOS or Linux with glibc, on amd64 or arm64. on Windows, install the scanners on `PATH`, then use the check-only command below.

## install missing scanners

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

	for scan examples, see [run scans and compare reports](scanning.md).

if you need a different installation directory, set `PUG_HOME` to an absolute path before setup. use the same value for later pug commands. see [tool paths and versions](commands.md#tool-paths-and-versions).

## check tools without installing

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

## prepare ZAP

1. install Docker through your operating system.
2. start the Docker daemon.
3. pull pug's pinned ZAP image if it is missing.

	```sh
	pug setup --with-zap
	```

	setup reports `ZAP: ready` when the image is available. this checks image availability, not a live ZAP scan. setup also checks the selected native scanners.

if you choose another image, pass its full digest reference with `--zap-image` to both `pug setup` and `pug app`. see [run ZAP](scanning.md#run-zap) for the scan procedure.

## retry a failed installation

if a download fails, check your network and proxy settings, then rerun setup. setup reuses tools that already work.

if a checksum does not match, check the pinned release asset before retrying. pug stops before it runs the downloaded binary.

if an installed tool's version command fails, repair or remove that installation. then rerun setup. tools on `PATH` take precedence over pug's installations.

if setup is interrupted, rerun it. uv can leave an unfinished Python environment or cache that a later run must complete.

if trivy fails during a scan, check its database access separately. setup checks that trivy runs. it does not check the vulnerability database. see [tool installation](security.md#tool-installation) for download verification and dependency limits.
