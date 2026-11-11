# Run Pug on a VPS

Use SSH to install Pug on a Linux VM, run a repository scan, and copy the report back. The VM must use glibc and have an amd64 or arm64 CPU. These steps apply to a VM from boat.dev or another service with SSH access.

You need this checkout and Go 1.25 or newer on the build machine. The VM needs network access for scanner installation and databases, plus Git to clone the target repository. Pug does not create the VM or store provider credentials.

Native scanners run with the account's permissions. Use a separate VM for code you do not trust. Reports can contain private paths and URLs.

## Build and copy Pug

Replace `user@vm` with your SSH login. For an arm64 VM, use `GOARCH=arm64` and change the output filename to `bin/pug-linux-arm64` in both commands.

1. From this repository's root on the build machine, compile the Linux binary.

	```sh
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/pug-linux-amd64 ./cmd/pug
	```

2. Copy the binary to the VM.

	```sh
	scp bin/pug-linux-amd64 user@vm:/tmp/pug
	```

## Install scanners on the VM

1. Open an SSH session.

	```sh
	ssh user@vm
	```

2. Install Pug in the account's local binary directory.

	```sh
	mkdir -p "$HOME/.local/bin"
	install -m 755 /tmp/pug "$HOME/.local/bin/pug"
	```

3. Run setup as the account that runs scans.

	```sh
	"$HOME/.local/bin/pug" setup
	```

	Setup prints `Selected scanners are ready.` when the selected tools work. If a tool fails, follow [Retry a failed installation](setup.md#retry-a-failed-installation).

For scripts, use `setup --format json` and check `ready` and each tool's status. Setup runs without prompts.

## Scan and retrieve the report

1. Clone a trusted repository on the VM.
2. Change to that repository's directory.
3. Save the scan report in the account's home directory.

	```sh
	"$HOME/.local/bin/pug" scan . --output "$HOME/pug-report.json"
	```

	The scan prints JSON and saves `pug-report.json`. A nonzero exit code can indicate findings or incomplete coverage. See [Exit codes](commands.md#exit-codes).

4. Return to your local shell.

	```sh
	exit
	```

5. Copy the report back.

	```sh
	scp user@vm:pug-report.json ./pug-report.json
	```

For application scans, use [Test an application](scanning.md#test-an-application). For ZAP or the sandbox, install Docker through the VM's operating system first. No public HTTP endpoint is needed to run Pug over SSH.
