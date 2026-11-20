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

## install and set up with your agent

paste this prompt into claude code, codex, or cursor. it installs the CLI, installs the pug skill, and prepares the repository scanners. it does not start a scan.

```text
Install Pug and set up the scanners for a repository scan.

Confirm Go 1.25 or newer with `go version`. Install the CLI with `go install github.com/josh-billington/pug/cmd/pug@latest`. Confirm `pug --version`. If the shell cannot find `pug`, use `$(go env GOPATH)/bin/pug`, or `$(go env GOBIN)/pug` when GOBIN is set. Do not edit the shell profile.

Install the Pug skill for this agent. If this session has the Pug checkout, copy only `skills/pug` into the user skills directory. For Claude Code, load this checkout with `claude --plugin-dir` set to the checkout path, so `/pug:doctor`, `/pug:scan`, `/pug:image`, and `/pug:diff` are available. For Codex and Cursor, the shared skill name is `pug`. Do not copy `skills/scan`, `skills/image`, `skills/diff`, or `skills/doctor`.

When `skills/pug` is on the default branch, this command installs the shared skill instead:

npx skills add josh-billington/pug --skill pug --agent claude-code codex cursor

Run `pug setup --repo`. That checks Gitleaks, Actionlint, OpenGrep, and Trivy, and installs any that are missing. Do not use sudo.

Report whether setup printed "Selected scanners are ready." Do not start a scan.
```

installing the skill does not install the `pug` binary or the scanners. the shared skill is [skills/pug/SKILL.md](skills/pug/SKILL.md). the other folders under `skills/` are claude code actions.

after setup, ask the agent for one action:

- `doctor` lists scanners. it does not install tools or run a scan
- `scan` runs the default repository checks. the directory is optional and defaults to `.`
- `image` scans one container image pinned as `name@sha256:` plus 64 lowercase hex digits
- `diff before.json after.json` compares two saved reports

in claude code those actions are `/pug:doctor`, `/pug:scan`, `/pug:image`, and `/pug:diff`. in codex, select `pug` from `/skills` or enter `$pug` and the action. in cursor agent chat, enter `/pug` and the action. if cursor does not list the skill, copy `skills/pug` to `~/.cursor/skills/pug` and start a new chat.

the skill does not launch active application or network scans. upstream OpenGrep rule packs stay opt-in: `pug rules install opengrep`, then `pug scan --rules opengrep`.

## write your first report

1. from this repository's root, build pug and check its version

	```sh
	go build -trimpath -o bin/pug ./cmd/pug
	./bin/pug --version
	```

	the build creates `bin/pug`. the version is `dev` unless the build sets another value

2. install any missing scanners

	```sh
	./bin/pug setup --repo
	```

	setup checks Gitleaks, Actionlint, OpenGrep, and Trivy, and installs missing tools under `~/.local/share/pug`. when the selected scanners work, setup prints `Selected scanners are ready.` pug finds these tools without changes to your shell's `PATH`. `./bin/pug setup` also installs Nuclei and Schemathesis.

	if setup reports a failure, follow [install scanners](docs/setup.md) before continuing.

3. scan the current checkout and save a report

	```sh
	./bin/pug scan -o pug-report.json
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
