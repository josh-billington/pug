# pug

pug is a CLI tool for your agents, it makes 9 security scanning tools available to your agents and provides structured JSON output

pug wraps by default: 

- opengrep
- gitleaks
- trivy
- actionlint
- schemathesis
- nuclei

and optionally: 

- zap
- trufflehog
- naabu 

you'll need go v1.25 or newer. automatic scanner installation supports macOS and Linux with glibc, on amd64 and arm64. native scanners run with your account's permissions.

install with `go install github.com/josh-billington/pug/cmd/pug@latest`. this installs `pug` into `$(go env GOPATH)/bin`. to build from source instead, follow the steps below.

## write your first report

1. from this repository's root, build pug and check its version

	```sh
	go build -trimpath -o bin/pug ./cmd/pug
	./bin/pug --version
	```

	the build creates `bin/pug`. the version is `dev` unless the build sets another value

2. install any missing scanners

	```sh
	./bin/pug setup
	```

	setup checks the native scanners and installs missing tools under `~/.local/share/pug`. when the selected scanners work, setup prints `Selected scanners are ready.` pug finds these tools without changes to your shell's `PATH`.

	if setup reports a failure, follow [install scanners](docs/setup.md) before continuing.

3. scan the current checkout and save a report

	```sh
	./bin/pug scan . --output pug-report.json
	```

	pug prints JSON to stdout and saves the same report in `pug-report.json`. A report with `"complete": true` means the requested checks finished. It does not prove that the checkout is secure

	the command exits with code `1` if findings meet the severity threshold. it exits with code `3` if a requested check is incomplete. both cases return a report with structured output. see [exit codes](docs/commands.md#exit-codes).

## choose the next task

the following guides cover tasks beyond the first scan:

- [install scanners](docs/setup.md), including check-only setup and ZAP
- [run scans and compare reports](docs/scanning.md) for repositories, images, and applications, including upstream rule packs
- [run an offline command in the sandbox](docs/sandbox.md)
- [run pug on a VPS](docs/vps.md) through SSH
- [build and test pug](docs/testing.md) before changing the code

for flags, defaults, and report fields, see the [command reference](docs/commands.md). The [security boundaries](docs/security.md) explain tool access and isolation limits. the [verification record](docs/verification.md) lists completed checks and untested behavior. [skills used](docs/skills.md) records the implementation guidance

## license

mit license. see [LICENSE](LICENSE).
