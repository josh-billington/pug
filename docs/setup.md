# Install scanners

Use this guide to install Pug's native scanners and prepare ZAP. The commands assume `pug` is on `PATH`. From this checkout, use `./bin/pug` instead.

Automatic installation requires macOS or Linux with glibc, on amd64 or arm64. On Windows, install scanners on `PATH`, then use the check-only command below.

## Install missing scanners

1. Run setup as the account that runs scans.

	```sh
	pug setup
	```

	Setup checks Gitleaks, Actionlint, OpenGrep, Trivy, Nuclei, and Schemathesis. It installs missing tools under `~/.local/share/pug` and reuses working installations. Pug finds its own tools without shell profile changes.

2. Confirm that setup prints `Selected scanners are ready.`

	If setup reports a failure, use [Retry a failed installation](#retry-a-failed-installation). Setup exits with code `3` when a selected tool is missing or fails.

3. Run the scan command printed after `Next:`.

	For scan examples, see [Run scans and compare reports](scanning.md).

If you need a different installation directory, set `PUG_HOME` to an absolute path before setup. Use the same value for later Pug commands. See [Tool paths and versions](commands.md#tool-paths-and-versions).

## Check tools without installing

To check installed tools without downloading or installing anything, run:

```sh
pug setup --check
```

Setup runs version commands and checks whether Docker's daemon responds. It exits with code `3` if a selected scanner is missing or fails. Missing Docker or Git does not block native scanner setup.

To select fewer scanners, pass their names with `--tools`:

```sh
pug setup --tools gitleaks,actionlint
```

For scripts, use JSON output:

```sh
pug setup --check --format json
```

Check `ready` and the statuses in `tools`. Progress goes to stderr. See [Setup results](commands.md#setup-results) for the fields and status values.

## Prepare ZAP

1. Install Docker through your operating system.
2. Start the Docker daemon.
3. Pull Pug's pinned ZAP image if it is missing.

	```sh
	pug setup --with-zap
	```

	Setup reports `ZAP: ready` when the image is available. This checks image availability, not a live ZAP scan. Setup also checks the selected native scanners.

If you choose another image, pass its full digest reference with `--zap-image` to both `pug setup` and `pug app`. See [Run ZAP](scanning.md#run-zap) for the scan procedure.

## Retry a failed installation

If a download fails, check your network and proxy settings, then rerun setup. Setup reuses tools that already work.

If a checksum does not match, check the pinned release asset before retrying. Pug stops before running the downloaded binary.

If an installed tool's version command fails, repair or remove that installation. Then rerun setup. Tools on `PATH` take precedence over Pug's installations.

If setup is interrupted, rerun it. uv can leave an unfinished Python environment or cache that a later run must complete.

If Trivy fails during a scan, check its database access separately. Setup checks that Trivy runs but does not check the vulnerability database. See [Tool installation](security.md#tool-installation) for download verification and dependency limits.
