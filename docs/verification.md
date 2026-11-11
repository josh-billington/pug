# Verification record

This record describes runs completed on November 10, 2026. Results depend on the tested tools, rules, databases, inputs, and host. The initial runs used an Apple silicon Mac with Go 1.27.2. Additional Docker checks used a native Linux daemon as described below.

## Automated checks

These commands passed during local verification:

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

The Linux amd64 and Windows binaries compiled but were not executed. The GitHub workflow in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs formatting checks, vet, race tests, and a Linux build. The workflow had not run on GitHub when this record was written.

## Native scanner results

The integration runs used OpenGrep 1.33.1, Gitleaks 8.30.1, Actionlint 1.7.12, Trivy 0.76.2, Schemathesis 4.33.2, and Nuclei 3.11.1.

| Check | Observed result |
| --- | --- |
| Gitleaks | Detected a generated fake token, withheld its value, and reported it absent after file removal and a successful retest. |
| Actionlint | Detected invalid workflow expressions. |
| OpenGrep | Detected JavaScript `eval` in a temporary fixture. |
| Trivy configuration | Detected two Dockerfile misconfigurations using embedded checks. |
| Trivy dependencies | Detected four vulnerability findings in a deliberately old Lodash lockfile. |
| Schemathesis | Sent requests to a local fixture server and detected invalid API responses. |
| Nuclei | Sent an HTTP request with a local template and detected the fixture's exposure marker. |

The fixtures exist in temporary test directories. The tests generate fake secrets and do not use real credentials. The tests and their observed counts are available through:

```sh
go test -tags=integration ./internal/scanner \
	-run 'TestRealRepositoryScanners|TestRealApplicationScanners' -v -count=1 -timeout=15m
```

Counts can change when scanner rules or databases change.

Trivy's native OCI downloads stalled on this host. The vulnerability database was downloaded from the upstream registry with `curl`. Its SHA-256 hash matched the OCI layer digest before installation in Trivy's cache. The database reported an update time of November 10, 2026.

The integration runs disabled further database updates and used Trivy's embedded infrastructure checks. Those runs did not verify Trivy's native registry download path.

A self-scan completed the default repository checks without findings in the Pug report. That result covers only the files and scanner inputs tested.

## Error handling and snapshot tests

Automated tests cover incomplete scan coverage for unavailable tools, failed processes, malformed reports, skipped API cases, and scanner finding exit codes without findings. They also cover cancellation, output limits, private report files, symlink-safe report replacement, fingerprint validation, and retests after failed checks.

Git fixture tests verify that sandbox snapshots exclude untracked files and common credential filenames, preserve tracked source, and reject dirty tracked checkouts and tracked symlinks. A POSIX shell test checks that command arguments remain literal.

## Live Docker verification

The sandbox isolation and timeout tests passed with Docker 29.1.3 and this locally installed image:

```sh
PUG_TEST_SANDBOX_IMAGE=node@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 \
	go test -tags=integration ./internal/sandbox -run TestDocker -v -count=1
```

The isolation test read tracked source and verified UID 65534. It rejected writes to the source mount and root filesystem, found no Docker socket or Ethernet interface, verified loopback access, and wrote to scratch. The timeout test stopped a long-running command and confirmed cleanup. No Pug test containers remained afterward.

A `pug image` scan also completed against the pinned Node image with the cached vulnerability database and embedded infrastructure checks. These runs did not pull a sandbox image or change existing application containers.

## Live ZAP verification

Pug ran the ZAP full scan against a temporary HTTP fixture through Docker Desktop with this locally installed image:

```sh
PUG_TEST_ZAP_IMAGE=ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af \
	go test -tags=integration ./internal/scanner -run '^TestRealZAP$' -v -count=1 -timeout=12m
```

ZAP sent 249 requests, and Pug normalized 23 findings. The scan finished in 51 seconds. ZAP returned exit code `2` for warnings, which Pug accepted. Pug read the JSON report, recorded its SHA-256 hash, and removed the container.

The fixture serves static HTML without security headers. The test verifies requests reaching the fixture, completed coverage, finding fingerprints, and a report hash. It uses `host.docker.internal` and a temporary host listener reachable by Docker Desktop. It does not measure production application coverage.

The sandbox and ZAP tests skip when their respective image variables are unset. A default integration run does not start containers.

## Additional Docker and ZAP checks

On November 10, 2026, `TestDockerIsolation` and `TestDockerTimeout` passed on Docker Desktop (Docker 29.1.3), including with `umask 077`. They also passed on a native Linux Docker daemon (docker-in-docker, arm64), run as UID 65534 with `umask 077`. These checks verify that snapshot permissions no longer depend on the host umask and that container removal tolerates Docker's own `--rm` cleanup.

`TestZAPWorkspaceCleanup` passed on that native Linux daemon. A container running as UID 1000 created a locked nested directory that the host user could not remove; the fallback cleanup container removed it. On Docker Desktop, the test skips because file sharing maps container-written files to the host user. The cleanup command also emptied a mount using the real ZAP image's GNU find and correctly failed for a directory owned by a different UID.

`TestRealZAP` passed in 2 of 4 runs. In the 2 failures, ZAP itself exited with code `3` after about 22 requests, before report parsing. The failures were not reproducible by hand. Pug does not currently record scanner stderr in the report.

## CLI setup verification

The setup runs produced these results:

| Environment or check | Observed result |
| --- | --- |
| macOS arm64, empty temporary `PUG_HOME`, restricted `PATH` | Installed the native scanners. Each binary passed its version check. Setup installed uv and managed Python for Schemathesis. |
| macOS repeat run | Reused the installed scanners. `doctor` found them without `PATH` changes. A scan used the managed Gitleaks executable, detected a generated fake token, and withheld its value. |
| Linux arm64, Debian Bookworm container | Installed OpenGrep and Schemathesis, and reused the other managed scanners from an earlier partial run. The unprivileged container had no host Docker socket, a read-only root filesystem, and a writable temporary tool directory. |
| Alpine container | The selected OpenGrep and uv binaries failed because they require glibc. Setup then gained a check for musl-only Linux. An offline run confirmed the glibc error before downloads. |
| `setup --check --with-zap --format json` | Reported the existing pinned ZAP image ready without pulling it. |

The setup and lookup unit tests cover check-only behavior, retries, preservation of existing tools, tool status, checksum mismatches, archive links, `PATH` precedence, cancellation, and ZAP pulls. These tests passed with:

```sh
go test ./internal/setup ./internal/tools ./internal/cli
```

No boat.dev VM was created. Automatic installation was not run on amd64 or Windows. The [VPS guide](vps.md) describes manual SSH steps.

## Untested capabilities

The runs did not cover a hosted deployment, billing, a live coding-agent workflow, a local model, or an autonomous pentesting agent. Pug does not supply those capabilities.
