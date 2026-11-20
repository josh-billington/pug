# pug

pug is a CLI tool for your agents, it makes 9 security scanning tools available to your agents and provides structured output as JSON

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

## install and set up with your agent

paste this prompt into claude code, codex, or cursor. the prompt installs pug, installs the skill, and installs the tools that pug wraps be default

```text
install pug and set up the scanners for a repository scan.

confirm go 1.25 or newer with `go version`. install pug with `go install github.com/josh-billington/pug/cmd/pug@latest`. confirm `pug --version`. if the shell cannot find `pug`, use `$(go env GOPATH)/bin/pug`. if GOBIN is set, use `$(go env GOBIN)/pug`. do not edit the shell profile.

install the pug skill for this agent. if this session has the pug checkout, copy only `skills/pug` into the user skills directory. for claude code, start claude with `--plugin-dir` set to the checkout path. that loads `/pug:doctor`, `/pug:scan`, `/pug:image`, and `/pug:diff`. for codex and cursor, the shared skill name is `pug`. do not copy `skills/scan`, `skills/image`, `skills/diff`, or `skills/doctor`.

when `skills/pug` is on the default branch, install the shared skill with:

npx skills add josh-billington/pug --skill pug --agent claude-code codex cursor

run `pug setup --repo`. that checks gitleaks, actionlint, opengrep, and trivy. it installs any that are missing. do not use sudo.

report whether setup printed `Selected scanners are ready.` do not start a scan.
```

the skill install does not install the `pug` binary or the scanners. the shared skill is [skills/pug/SKILL.md](skills/pug/SKILL.md). the other folders under `skills/` are claude code actions.

after setup, ask the agent for one action

- `doctor` lists scanners. it does not install tools or run a scan
- `scan` runs the default repository checks. the directory is optional and defaults to `.`
- `image` scans one container image pinned as `name@sha256:` plus 64 lowercase hex digits
- `diff before.json after.json` compares two saved reports

in claude code those actions are `/pug:doctor`, `/pug:scan`, `/pug:image`, and `/pug:diff`. in codex, select `pug` from `/skills` or enter `$pug` and the action. in cursor agent chat, enter `/pug` and the action. if cursor does not list the skill, copy `skills/pug` to `~/.cursor/skills/pug` and start a new chat

the skill does not launch active application or network scans (wip)

## other stuff your agents can do with pug

- [install scanners](docs/setup.md), including check-only setup and ZAP
- [run scans and compare reports](docs/scanning.md) for repositories, images, and applications, including upstream rule packs
- [run an offline command in the sandbox](docs/sandbox.md)
- [run pug on a VPS](docs/vps.md) through SSH
- [build and test pug](docs/testing.md) before changing the code

## license

mit license. see [LICENSE](LICENSE).
