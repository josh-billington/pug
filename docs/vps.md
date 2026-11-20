# run pug on a VPS

use SSH to install pug on a Linux VM, run a repository scan, and copy the report back. the VM must use glibc and have an amd64 or arm64 CPU. these steps apply to a VM from boat.dev or another service with SSH access.

you need this checkout and go 1.25 or newer on the build machine. the VM needs network access for scanner installation and databases, plus git to clone the target repository. pug does not create the VM or store provider credentials.

native scanners run with the account's permissions. use a separate VM for code you do not trust. a report can contain private paths and URLs.

## build and copy pug

replace `user@vm` with your SSH login. for an arm64 VM, use `GOARCH=arm64` and change the output filename to `bin/pug-linux-arm64` in both commands.

1. from this repository's root on the build machine, compile the Linux binary.

	```sh
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/pug-linux-amd64 ./cmd/pug
	```

2. copy the binary to the VM.

	```sh
	scp bin/pug-linux-amd64 user@vm:/tmp/pug
	```

## install scanners on the VM

1. open an SSH session.

	```sh
	ssh user@vm
	```

2. install pug in the account's local binary directory.

	```sh
	mkdir -p "$HOME/.local/bin"
	install -m 755 /tmp/pug "$HOME/.local/bin/pug"
	```

3. run setup as the account that runs scans.

	```sh
	"$HOME/.local/bin/pug" setup
	```

	setup prints `Selected scanners are ready.` when the selected tools work. if a tool fails, follow [retry a failed installation](setup.md#retry-a-failed-installation).

for scripts, use `setup --format json` and check `ready` and each tool's status. setup runs without prompts.

## scan and retrieve the report

1. clone a trusted repository on the VM.
2. change to that repository's directory.
3. save the scan report in the account's home directory.

	```sh
	"$HOME/.local/bin/pug" scan -o "$HOME/pug-report.json"
	```

	the scan prints JSON and saves `pug-report.json`. a nonzero exit code can mean findings or incomplete coverage. see [exit codes](commands.md#exit-codes).

4. return to your local shell.

	```sh
	exit
	```

5. copy the report back.

	```sh
	scp user@vm:pug-report.json ./pug-report.json
	```

for an application scan, use [test an application](scanning.md#test-an-application). for ZAP or the sandbox, install Docker through the VM's operating system first. no public HTTP endpoint is needed to run pug over SSH.
