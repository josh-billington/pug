# Run scans and compare reports

Use these procedures to produce a Pug report for a repository, container image, or running application. The commands assume `pug` is on `PATH`. From this checkout, use `./bin/pug` instead.

Install the required scanners with [Install scanners](setup.md). Native scanners inherit your account's permissions, so scan trusted checkouts. See [Security boundaries](security.md) before handling hostile code.

## Scan a repository

To run the default repository checks, replace `/path/to/repo` with your checkout and run:

```sh
pug scan /path/to/repo --output pug-report-before.json
```

The default checks cover source patterns, secrets, dependency vulnerabilities, GitHub Actions, and infrastructure configuration. Pug writes JSON to stdout and to `pug-report-before.json`.

To select checks, pass `--checks`:

```sh
pug scan . --checks source,secrets,actions --format text
```

See [Checks](commands.md#checks) for the tool and scope of each check. A missing or skipped requested check makes the report incomplete. The exception is `actions` in a repository with no workflow YAML files: it completes with nothing to lint and does not require actionlint.

## Compare reports after a fix

1. Fix the finding in the checkout.
2. Run the same checks against the same target.

	```sh
	pug scan /path/to/repo --output pug-report-after.json
	```

3. Compare the saved reports.

	```sh
	pug diff pug-report-before.json pug-report-after.json
	```

The comparison lists `new`, `persistent`, `absent`, and `unverified` findings. If a check did not finish, missing findings remain `unverified`. See [Report comparison](commands.md#report-comparison).

## Scan a container image

Set `IMAGE` to a full image reference in `NAME@sha256:DIGEST` format. Then run:

```sh
pug image "$IMAGE" --output pug-report-image.json
```

Trivy can fetch the image and its vulnerability database. ZAP and sandbox image handling is separate.

## Test an application

These checks send active requests and can change application data. Use a disposable application with test data. Review the local schema and templates before the scan.

1. Start the application in the test environment.
2. Replace the example URL, schema path, and template path with your values.
3. Run the application checks.

	```sh
	pug app http://127.0.0.1:8000 \
		--allow-active \
		--schema /path/to/openapi.json \
		--templates /path/to/reviewed-http-templates \
		--output pug-report-app.json
	```

The report contains API findings from Schemathesis and template findings from Nuclei. See [Application check limits](commands.md#application-check-limits) for request limits and redirect behavior.

## Run ZAP

ZAP crawls the target and sends active test requests. Use a disposable environment. The ZAP container needs an address that it can reach.

1. Prepare the image with [Prepare ZAP](setup.md#prepare-zap).
2. Start the target application.
3. Run ZAP against the target address.

	For an application on the host with Docker Desktop, use:

	```sh
	pug app http://host.docker.internal:8000 \
		--allow-active --checks zap \
		--timeout 10m --output pug-report-zap.json
	```

On a Linux VPS, replace the URL with an address reachable from the ZAP container. Inside that container, `127.0.0.1` refers to the container itself. Pug does not configure Docker networking.

If setup used a custom image, pass the same `--zap-image` reference to the scan. ZAP uses `--pull=never`, so the image must already be installed.
