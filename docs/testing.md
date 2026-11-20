# build and test pug

run these commands from the repository root. you need go 1.25 or newer and `make`. integration tests also use installed scanners. see [install scanners](setup.md) to prepare them.

## check the code and build

1. run formatting checks, vet, and race tests.

	```sh
	make check
	```

	the command exits with code `0` when the checks pass.

2. build the local binary.

	```sh
	make build
	```

	the build creates `bin/pug`.

## run scanner integration tests

run the installed scanners against temporary test fixtures:

```sh
make integration
```

the tests use deliberately vulnerable files and local HTTP servers. a test skips a scanner that is not installed. a passing run with skips does not verify those scanners.

trivy can download large vulnerability databases and rule bundles. if you already have a current database and checks cache, skip updates with:

```sh
TRIVY_SKIP_DB_UPDATE=true TRIVY_SKIP_CHECK_UPDATE=true make integration
```

without a checks cache, trivy uses its embedded checks. disabling updates can reduce coverage as rules and vulnerability data age.

## include Docker tests

for sandbox tests, set `PUG_TEST_SANDBOX_IMAGE` to a locally installed image pinned by digest. the image must contain `/bin/sh`, `cp`, `cat`, `id`, `touch`, and `mkdir`.

for the ZAP test, set `PUG_TEST_ZAP_IMAGE` to a locally installed ZAP image pinned by digest. the test starts a temporary HTTP fixture and uses `host.docker.internal` to reach it through Docker Desktop.

after you set the image variables, run `make integration`. each Docker test skips if its image variable is unset. see the [verification record](verification.md) for the image digests and the commands used in completed runs.
