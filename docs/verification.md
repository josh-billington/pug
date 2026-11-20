# verification record

this record describes runs completed on November 10, 2026, plus the rule-pack runs on November 16, 2026. results depend on the tested tools, rules, databases, inputs, and host. the initial runs used an Apple silicon Mac with go 1.27.2. additional Docker checks used a native Linux daemon as described below.

## automated checks

these commands passed during local verification:

```sh
make check
make build
TRIVY_SKIP_DB_UPDATE=true TRIVY_SKIP_CHECK_UPDATE=true \
	go test -tags=integration -count=1 -timeout=15m ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build -trimpath -o /tmp/pug-linux-amd64 ./cmd/pug
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
	go build -trimpath -o /tmp/pug-windows-amd64.exe ./cmd/pug
```

the Linux amd64 and Windows binaries compiled but were not executed. the GitHub workflow in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs formatting checks, vet, race tests, and a Linux build. the workflow had not run on GitHub when this record was written.

## native scanner results

the integration runs used opengrep 1.33.1, gitleaks 8.30.1, actionlint 1.7.12, trivy 0.76.2, schemathesis 4.33.2, and nuclei 3.11.1.

| check | observed result |
| --- | --- |
| gitleaks | detected a generated fake token, withheld its value, and reported it absent after file removal and a successful retest. |
| trufflehog 3.99.7 | on macOS arm64, reported a clean history as clean. detected a fake token that existed only in a deleted commit, reported that commit, and withheld the token and committer email. also completed with network access denied. |
| actionlint | detected invalid workflow expressions. |
| opengrep | detected JavaScript `eval` in a temporary fixture. |
| trivy configuration | detected two Dockerfile misconfigurations using embedded checks. |
| trivy dependencies | detected four vulnerability findings in a deliberately old Lodash lockfile. |
| schemathesis | sent requests to a local fixture server and detected invalid API responses. |
| nuclei | sent an HTTP request with a local template and detected the fixture's exposure marker. |
| naabu 2.7.0 | on macOS arm64, found an unexpected local listener, and marked a scan incomplete when the expected port was closed. wrote no configuration under `~/.config` or `~/Library/Application Support` during scans or setup version checks. |

the fixtures exist in temporary test directories. the tests generate fake secrets and do not use real credentials. the tests and their observed counts are available through:

```sh
go test -tags=integration ./internal/scanner \
	-run 'TestRealRepositoryScanners|TestRealSecretsHistory|TestRealPortScan|TestRealApplicationScanners' -v -count=1 -timeout=15m
```

counts can change when scanner rules or databases change.

trivy's native OCI downloads stalled on this host. the vulnerability database was downloaded from the upstream registry with `curl`. its SHA-256 hash matched the OCI layer digest before installation in trivy's cache. the database reported an update time of November 10, 2026.

the integration runs disabled further database updates and used trivy's embedded infrastructure checks. those runs did not verify trivy's native registry download path.

a self-scan completed the default repository checks without findings in the pug report. that result covers only the files and scanner inputs tested.

## error handling and snapshot tests

automated tests cover incomplete scan coverage for unavailable tools, failed processes, malformed reports, skipped API cases, and scanner finding exit codes without findings. they also cover cancellation, output limits, private report files, symlink-safe report replacement, fingerprint validation, and retests after failed checks.

git fixture tests verify that sandbox snapshots exclude untracked files and common credential filenames, preserve tracked source, and reject dirty tracked checkouts and tracked symlinks. a POSIX shell test checks that command arguments remain literal.

## live Docker verification

the sandbox isolation and timeout tests passed with Docker 29.1.3 and this locally installed image:

```sh
PUG_TEST_SANDBOX_IMAGE=node@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 \
	go test -tags=integration ./internal/sandbox -run TestDocker -v -count=1
```

the isolation test read tracked source and verified UID 65534. it rejected writes to the source mount and root filesystem, found no Docker socket or Ethernet interface, verified loopback access, and wrote to scratch. the timeout test stopped a long-running command and confirmed cleanup. no pug test containers remained afterward.

a `pug image` scan also completed against the pinned Node image with the cached vulnerability database and embedded infrastructure checks. these runs did not pull a sandbox image or change existing application containers.

## live ZAP verification

pug ran the ZAP full scan against a temporary HTTP fixture through Docker Desktop with this locally installed image:

```sh
PUG_TEST_ZAP_IMAGE=ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af \
	go test -tags=integration ./internal/scanner -run '^TestRealZAP$' -v -count=1 -timeout=12m
```

ZAP sent 249 requests, and pug normalized 23 findings. the scan finished in 51 seconds. ZAP returned exit code `2` for warnings, which pug accepted. pug read the JSON report, recorded its SHA-256 hash, and removed the container.

the fixture serves static HTML without security headers. the test verifies requests reaching the fixture, completed coverage, finding fingerprints, and a report hash. it uses `host.docker.internal` and a temporary host listener reachable by Docker Desktop. it does not measure production application coverage.

the sandbox and ZAP tests skip when their image variables are unset. a default integration run does not start containers.

## additional Docker and ZAP checks

on November 10, 2026, `TestDockerIsolation` and `TestDockerTimeout` passed on Docker Desktop (Docker 29.1.3), including with `umask 077`. they also passed on a native Linux Docker daemon (docker-in-docker, arm64), run as UID 65534 with `umask 077`. these checks verify that snapshot permissions no longer depend on the host umask and that container removal tolerates Docker's own `--rm` cleanup.

`TestZAPWorkspaceCleanup` passed on that native Linux daemon. a container running as UID 1000 created a locked nested directory that the host user could not remove. the fallback cleanup container removed it. on Docker Desktop, the test skips because file sharing maps container-written files to the host user. the cleanup command also emptied a mount using the real ZAP image's GNU find and correctly failed for a directory owned by a different UID.

`TestRealZAP` passed in 2 of 4 runs. in the 2 failures, ZAP itself exited with code `3` after about 22 requests, before report parsing. the failures were not reproducible by hand. pug does not currently record scanner stderr in the report.

## CLI setup verification

the setup runs produced these results:

| environment or check | observed result |
| --- | --- |
| macOS arm64, empty temporary `PUG_HOME`, restricted `PATH` | installed the native scanners. each binary passed its version check. setup installed uv and managed Python for schemathesis. |
| macOS repeat run | reused the installed scanners. `doctor` found them without `PATH` changes. a scan used the managed gitleaks executable, detected a generated fake token, and withheld its value. |
| Linux arm64, Debian Bookworm container | installed opengrep and schemathesis, and reused the other managed scanners from an earlier partial run. the unprivileged container had no host Docker socket, a read-only root filesystem, and a writable temporary tool directory. |
| Alpine container | the selected opengrep and uv binaries failed because they require glibc. setup then gained a check for musl-only Linux. an offline run confirmed the glibc error before downloads. |
| `setup --check --with-zap --format json` | reported the existing pinned ZAP image ready without pulling it. |

the setup and lookup unit tests cover check-only behavior, retries, preservation of existing tools, tool status, checksum mismatches, archive links, `PATH` precedence, cancellation, and ZAP pulls. these tests passed with:

```sh
go test ./internal/setup ./internal/tools ./internal/cli
```

no boat.dev VM was created. automatic installation was not run on amd64 or Windows. the [VPS guide](vps.md) describes the manual SSH steps.

## rule pack verification

these runs on November 16, 2026 used the built `bin/pug`, opengrep 1.33.1, a fresh temporary `PUG_HOME`, and upstream git repositories:

| check | observed result |
| --- | --- |
| `pug rules install amplify`, repeated, then `pug rules install amplify@e7643a008ec9027c96dfef7bdf5aedcac3847da8` | all succeeded at `e7643a008ec9`. the repeated install fetched the upstream default branch again. |
| `pug rules install github.com/trailofbits/semgrep-rules` | installed as `semgrep-rules` at `31390b3a99c0`. |
| `pug rules list` | listed both installed checkouts, their commits and profiles, and the built-in aliases with install state. |
| two `--rules amplify:security-audit` scans of the same fixture, then `pug diff` | both completed with 224 rules and 79 findings. the comparison had 79 persistent findings, zero new, zero absent, and zero unverified. |
| `--rules amplify,semgrep-rules`, then the same scan with the Trail of Bits directory path | both completed with 1,148 rules and 155 findings, with the same composed rules hash. |
| `--rules notinstalled` | skipped `source` with `run: pug rules install notinstalled`. exit code `3`. |
| `--rules -x`, `rules install -- -x`, and `rules install amplify@-x` | rejected as usage errors. exit code `2`. |

the audit scans reported one partial-parse warning and one unresolved profile entry. the combined scans reported one partial-parse warning and 30 unresolved profile entries.

unit tests cover profile resolution, ID qualification, alias expansion, file limits, path escapes, symlink and fixture filtering, CLI errors, and rule changes in `pug diff`. the rule-pack integration test initializes and commits a repository in `t.TempDir`, clones it through a `file://` URL, and runs real opengrep. it verifies repeat installs, updates, commit pins, stable rescans, and missing findings becoming unverified after rules change. these checks passed:

```sh
make check
go test -tags=integration ./internal/scanner -run 'TestRealOpenGrepPartialParseCompletesWithoutStrict|TestRealRulePackScan' -count=1 -v
```

## untested capabilities

the runs did not cover a hosted deployment, billing, a live coding-agent workflow, a local model, or an autonomous pentesting agent. pug does not supply those capabilities.
