# security boundaries

pug runs third-party tools under your account or inside Docker containers. their access determines what a scan can read, change, or contact. a completed check means the selected tool finished, within the limits below.

## native scanners

native scanners inherit your account's permissions and environment. their parsers, configuration, and dependencies are trusted code. a native scan does not isolate the tools from your machine.

pug passes command arguments without a host shell. the scanners still interpret templates, configuration, external references, and project files. argument handling does not make hostile inputs safe to scan.

a repository scan inspects the current working tree. it does not freeze the checkout, and it does not restrict checks to a pull request diff. only the opt-in `secrets-history` check reads git history. trufflehog makes a temporary clone inside the check workspace, and pug removes that clone after the check, including after a timeout. the check reads committed objects on every ref, not uncommitted changes. ignore rules, unsupported file types, missing lockfiles, parsing limits, and unavailable databases reduce coverage. a tool can complete with no findings because it has no applicable input.

the starter opengrep rules detect a small set of suspicious patterns and can produce false positives. actionlint checks workflow syntax and metadata. neither tool is a complete security assessment.

rule packs add upstream opengrep rules that pug does not review. they can miss issues or produce false positives. `pug rules install` uses git to fetch the upstream repository, with prompts, askpass helpers, hooks, and clone templates disabled. each user fetches their own rules. pug does not ship Commons Clause packs. during composition, pug confines reads to the pack directory, skips symlinks, hidden directories, and test fixtures, and limits each selected rule file to 16 MiB. reports record the checkout commit and a SHA-256 of the composed rules. `pug diff` treats a missing finding as unverified when those rules change. these records describe the rules used. pug still trusts the upstream rules.

## tool installation

`pug setup` installs missing scanners for the current user. binary downloads use upstream release URLs and SHA-256 digests embedded in pug. pug verifies each download before it runs the file or replaces an installed binary. from an archive, pug copies only the executable. it does not extract archive paths or links.

a matching digest confirms the downloaded bytes. pug still trusts the upstream release and its behavior.

schemathesis uses uv with a pinned package version in a separate environment. uv can download managed Python 3.12 and resolve dependencies from its configured package index. pug does not pin those transitive dependency versions. setup disables uv project configuration and stores the environment under pug's home directory.

tools on `PATH` take precedence over pug's installations. setup checks whether an existing tool runs. it does not upgrade that tool or enforce the catalog version. setup does not run an installation script from a scanned repository. an ordinary scan does not invoke setup.

`setup --with-zap` can pull a digest-pinned image through Docker. setup does not install Docker or git, change group membership, or start system services. native scanner setup can complete without either tool.

## active application checks

application checks send active requests and can change application data. `--allow-active` records an explicit choice to send those requests. the flag does not establish ownership of the target, and it does not enforce network isolation.

schemathesis uses the supplied local schema and base URL. nuclei uses the supplied local HTTP templates. both disable redirects. a schema can contain an external reference, and a template can contain more request logic. ZAP crawls and actively scans from the target. pug does not enforce an outbound firewall for these tools.

`pug net` opens TCP connections to one literal IP address at a fixed rate. naabu's passive, cloud upload, proxy, and update features stay off. naabu runs with `HOME` and `XDG_CONFIG_HOME` set to a private temporary directory, so it writes no configuration to your home directory. pug does not enforce an outbound firewall for the scan.

a test without credentials does not cover authenticated behavior. business logic, authorization roles, and endpoints absent from the schema or crawl can remain untested.

## reports and subprocesses

each subprocess has a deadline. on Unix, cancellation kills the process group. on other platforms, cancellation kills only the direct child. pug does not yet use a Windows job object to stop descendant processes.

the runner retains at most 16 MiB of stdout and 64 KiB of stderr in memory. pug omits raw scanner diagnostics from scan reports. before parsing a report file, pug checks that it is a regular file no larger than 16 MiB. that check happens after the scanner runs and does not impose a disk quota.

gitleaks receives full redaction flags. trufflehog's JSON output contains raw secret values. pug keeps that output in memory only, records its SHA-256 digest, and copies only the detector, file, line, and commit into the report. trufflehog verification is disabled because it would send candidate secrets to provider APIs. pug replaces gitleaks and trufflehog finding messages and omits source snippets from every parser. reports omit API request and response bodies. paths, URLs, rule names, and messages can still contain sensitive data.

saved reports use mode `0600` on POSIX filesystems and atomic replacement. on Windows, report access follows the destination filesystem ACLs. pug replaces a destination symlink rather than following it. an imported report has a 32 MiB limit and validated finding fingerprints.

## disposable sandbox

the sandbox uses a locally installed image pinned by SHA-256 digest and starts Docker with `--pull=never`. the image supplies the command and its dependencies. pug does not pass host environment variables, agent credentials, SSH state, or a Docker socket into the container.

pug snapshots at most 5,000 tracked regular files and 50 MiB. the snapshot excludes untracked files and common credential filenames. pug rejects tracked symlinks and submodules, and reads files through go's rooted filesystem API. source files can still contain embedded secrets.

the tracked checkout must be clean before and after the copy, and its commit must remain unchanged. these checks cannot make concurrent edits atomic. a checkout that stays idle during the snapshot avoids that race.

the container uses UID and GID 65534, no external network, a read-only root filesystem, no Linux capabilities, and no additional privileges. it has one CPU, 512 MiB of memory, no additional swap allowance, a limit of 128 processes, and 128 MiB of scratch space.

pug mounts only the staged source and its launcher. the launcher copies source into `/scratch/work`, where the command can write. an optional application starts in the same container and shares loopback with the command. the command must wait until the application accepts requests. a hosted model API is unreachable.

on timeout or cancellation, pug tries to force-remove the container and checks that it is gone. a Docker outage can prevent cleanup and make the report incomplete. containers share a kernel, so these limits do not stop a container escape.

the sandbox hashes bounded stdout, then discards it. it does not convert agent output into findings, copy files back, mark an earlier finding as fixed, or approve a code change. a completed sandbox check records successful command execution and cleanup under the reported settings.

the snapshot and container limits come from [`internal/sandbox/sandbox.go`](../internal/sandbox/sandbox.go). the configured values are visible with:

```sh
rg -n -- 'count >|total >|--(cpus|memory|memory-swap|pids-limit|tmpfs)' internal/sandbox/sandbox.go
```

`make integration` runs the isolation tests when `PUG_TEST_SANDBOX_IMAGE` is set.

## ZAP container

ZAP uses a separate container configuration because it needs network access to reach the target. pug mounts a temporary report directory, drops capabilities, and limits CPU, memory, processes, and runtime. ZAP does not receive a source checkout.

pug converts the ZAP JSON report into its report format, then deletes the original. target URL validation does not restrict the container's outbound requests. the [ZAP scan procedure](guide.md#run-zap) describes target addressing.
