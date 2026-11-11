# Build and test Pug

Run these commands from the repository root. You need Go 1.25 or newer and `make`. Integration tests also use installed scanners. See [Install scanners](setup.md) to prepare them.

## Check the code and build

1. Run formatting checks, vet, and race tests.

	```sh
	make check
	```

	The command exits with code `0` when the checks pass.

2. Build the local binary.

	```sh
	make build
	```

	The build creates `bin/pug`.

## Run scanner integration tests

Run the installed scanners against temporary test fixtures:

```sh
make integration
```

The tests use deliberately vulnerable files and local HTTP servers. Tests skip scanners that are not installed. A passing run with skips does not verify those scanners.

Trivy can download large vulnerability databases and rule bundles. If you already have a current database and checks cache, skip updates with:

```sh
TRIVY_SKIP_DB_UPDATE=true TRIVY_SKIP_CHECK_UPDATE=true make integration
```

Without a checks cache, Trivy uses its embedded checks. Disabling updates can reduce coverage as rules and vulnerability data age.

## Include Docker tests

For sandbox tests, set `PUG_TEST_SANDBOX_IMAGE` to a locally installed image pinned by digest. The image must contain `/bin/sh`, `cp`, `cat`, `id`, `touch`, and `mkdir`.

For the ZAP test, set `PUG_TEST_ZAP_IMAGE` to a locally installed ZAP image pinned by digest. The test starts a temporary HTTP fixture and uses `host.docker.internal` to reach it through Docker Desktop.

After setting the image variables, run `make integration`. Each Docker test skips if its image variable is unset. See [Verification record](verification.md) for the image digests and the commands used in completed runs.
