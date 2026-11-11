# Security boundaries

Pug runs third-party tools under your account or inside Docker containers. Their access determines what a scan can read, change, or contact. A completed check means the selected tool finished, within the limits described below.

## Native scanners

Native scanners inherit your account's permissions and environment. Their parsers, configuration, and dependencies are trusted code. A native scan does not isolate tools from your machine.

Pug passes command arguments without a host shell. The scanners still interpret templates, configuration, external references, and project files. Argument handling therefore does not make hostile inputs safe to scan.

Repository scans inspect the current working tree. They do not freeze the checkout, inspect Git history, or restrict checks to a pull request's diff. Ignore rules, unsupported file types, missing lockfiles, parsing limits, and unavailable databases reduce coverage. A tool can complete with no findings because it has no applicable input.

The bundled OpenGrep rules detect a small set of suspicious patterns and can produce false positives. Actionlint checks workflow syntax and metadata. Neither tool provides a complete security assessment.

## Tool installation

`pug setup` installs missing scanners for the current user. Binary downloads use upstream release URLs and SHA-256 digests embedded in Pug. Pug verifies each download before running it or replacing an installed binary. From an archive, Pug copies only the executable. It does not extract archive paths or links.

A matching digest confirms the downloaded bytes. Pug still trusts the upstream release and its behavior.

Schemathesis uses uv with a pinned package version in a separate environment. uv can download managed Python 3.12 and resolve dependencies from its configured package index. Pug does not pin those transitive dependency versions. Setup disables uv project configuration and stores its environment under Pug's home directory.

Tools on `PATH` take precedence over Pug's installations. Setup checks whether existing tools run but does not upgrade them or enforce the catalog versions. Setup does not run installation scripts from a scanned repository. Ordinary scans do not invoke setup.

`setup --with-zap` can pull a digest-pinned image through Docker. Setup does not install Docker or Git, change group membership, or start system services. Native scanner setup can complete without either tool.

## Active application checks

Application checks send active requests and can change application data. `--allow-active` records an explicit choice to send those requests. The flag does not establish ownership of the target or enforce network isolation.

Schemathesis uses the supplied local schema and base URL. Nuclei uses supplied local HTTP templates. Both disable redirects. Schemas can contain external references, and templates can contain additional request logic. ZAP crawls and actively scans from the target. Pug does not enforce an outbound firewall for these tools.

Tests without credentials do not cover authenticated behavior. Business logic, authorization roles, and endpoints absent from the schema or crawl can remain untested.

## Reports and subprocesses

Each subprocess has a deadline. On Unix, cancellation kills the process group. On other platforms, cancellation kills only the direct child. Pug does not yet use a Windows job object to stop descendant processes.

The runner retains at most 16 MiB of stdout and 64 KiB of stderr in memory. Pug omits raw scanner diagnostics from scan reports. Before parsing a report file, Pug checks that it is a regular file no larger than 16 MiB. That check happens after the scanner runs and does not impose a disk quota.

Gitleaks receives full redaction flags. Pug replaces Gitleaks finding messages and omits source snippets from every parser. Reports omit API request and response bodies, but paths, URLs, rule names, and messages can still contain sensitive data.

Saved reports use mode `0600` on POSIX filesystems and atomic replacement. On Windows, report access follows the destination filesystem's ACLs. Pug replaces destination symlinks rather than following them. Imported reports have a 32 MiB limit and validated finding fingerprints.

## Disposable sandbox

The sandbox uses a locally installed image pinned by SHA-256 digest and starts Docker with `--pull=never`. The image supplies the command and its dependencies. Pug does not pass host environment variables, agent credentials, SSH state, or a Docker socket into the container.

Pug snapshots at most 5,000 tracked regular files and 50 MiB. The snapshot excludes untracked files and common credential filenames. Pug rejects tracked symlinks and submodules, and reads files through Go's rooted filesystem API. Source files can still contain embedded secrets.

The tracked checkout must be clean before and after the copy, and its commit must remain unchanged. These checks cannot make concurrent edits atomic. A checkout that stays idle during the snapshot avoids that race.

The container uses UID and GID 65534, no external network, a read-only root filesystem, no Linux capabilities, and no additional privileges. It has one CPU, 512 MiB of memory, no additional swap allowance, a limit of 128 processes, and 128 MiB of scratch space.

Pug mounts only the staged source and its launcher. The launcher copies source into `/scratch/work`, where the command can write. An optional application starts in the same container and shares loopback with the command. The command must wait until the application accepts requests. Hosted model APIs are unreachable.

On timeout or cancellation, Pug tries to force-remove the container and checks that it is gone. Docker outages can prevent cleanup and make the report incomplete. Containers share a kernel, so these limits do not guarantee protection against escapes.

The sandbox hashes bounded stdout, then discards it. It does not convert agent output into findings, copy files back, mark earlier findings as fixed, or approve code changes. A completed sandbox check records successful command execution and cleanup under the reported settings.

The snapshot and container limits come from [`internal/sandbox/sandbox.go`](../internal/sandbox/sandbox.go). The configured values are visible with:

```sh
rg -n -- 'count >|total >|--(cpus|memory|memory-swap|pids-limit|tmpfs)' internal/sandbox/sandbox.go
```

The [Verification record](verification.md#live-docker-verification) lists completed isolation tests.

## ZAP container

ZAP uses a separate container configuration because it needs network access to reach the target. Pug mounts a temporary report directory, drops capabilities, and limits CPU, memory, processes, and runtime. ZAP does not receive a source checkout.

Pug converts the ZAP JSON report into its report format, then deletes the original. Target URL validation does not restrict the container's outbound requests. The [ZAP scan procedure](scanning.md#run-zap) describes target addressing.
