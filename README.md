# Pug

Pug is a Go CLI that runs security scanners and collects their findings in JSON reports. Build Pug and write your first report for a trusted local checkout with the steps below.

You need Go 1.25 or newer. Automatic scanner installation supports macOS and Linux with glibc, on amd64 and arm64. Native scanners run with your account's permissions.

Install with `go install github.com/josh-billington/pug/cmd/pug@latest`. This installs `pug` into `$(go env GOPATH)/bin`. To build from source instead, follow the steps below.

## Write your first report

1. From this repository's root, build Pug and check its version.

	```sh
	go build -trimpath -o bin/pug ./cmd/pug
	./bin/pug --version
	```

	The build creates `bin/pug`. The version is `dev` unless the build sets another value.

2. Install any missing scanners.

	```sh
	./bin/pug setup
	```

	Setup checks the native scanners and installs missing tools under `~/.local/share/pug`. When the selected scanners work, setup prints `Selected scanners are ready.` Pug finds these tools without changes to your shell's `PATH`.

	If setup reports a failure, follow [Install scanners](docs/setup.md) before continuing.

3. Scan the current checkout and save a report.

	```sh
	./bin/pug scan . --output pug-report.json
	```

	Pug prints JSON to stdout and saves the same report in `pug-report.json`. A report with `"complete": true` means the requested checks finished. It does not prove that the checkout is secure.

	The command exits with code `1` if findings meet the severity threshold. It exits with code `3` if a requested check is incomplete. Both cases can produce a report. See [Exit codes](docs/commands.md#exit-codes).

## Choose the next task

The following guides cover tasks beyond the first scan:

- [Install scanners](docs/setup.md), including check-only setup and ZAP.
- [Run scans and compare reports](docs/scanning.md) for repositories, images, and applications.
- [Run an offline command in the sandbox](docs/sandbox.md).
- [Run Pug on a VPS](docs/vps.md) through SSH.
- [Build and test Pug](docs/testing.md) before changing the code.

For flags, defaults, and report fields, see the [Command reference](docs/commands.md). The [Security boundaries](docs/security.md) explain tool access and isolation limits. The [Verification record](docs/verification.md) lists completed checks and untested behavior. [Skills used](docs/skills.md) records the implementation guidance.

## License

MIT. See [LICENSE](LICENSE).
