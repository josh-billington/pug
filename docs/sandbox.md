# run an offline command in the sandbox

use the sandbox to run a command against a copy of a clean git checkout. you can start an application beside the command in the same container.

you need git, a running Docker daemon, and a locally installed image pinned by SHA-256 digest. the image must contain `/bin/sh`, `mkdir`, `cp`, and the command's runtime and dependencies.

the container has no external network access. a hosted model API is unreachable. if you use an agent, the image must contain the offline agent and any local model it needs. pug supplies no agent, model, or credentials.

## run the command

1. set `SANDBOX_IMAGE` to your installed image's full `NAME@sha256:DIGEST` reference.
2. prepare a clean checkout with a commit.

	use the git checkout root for `--repo`. commit or stash changes to tracked files before the run. pug excludes untracked files and rejects tracked symlinks and submodules.

3. run your command after `--`.

	this example assumes the image contains Python and `/opt/offline-agent`, and the checkout contains `app.py`:

	```sh
	pug sandbox \
		--repo /path/to/clean-checkout \
		--image "$SANDBOX_IMAGE" \
		--app-command '["python3","app.py"]' \
		-o pug-report-sandbox.json \
		-- /opt/offline-agent test http://127.0.0.1:8000
	```

	from this checkout, use `./bin/pug` if `pug` is not on `PATH`. replace the checkout path and the example commands with your values. omit `--app-command` if no application is needed.

the application and the command share container loopback. the command must wait until the application accepts requests.

## read the result

inspect `pug-report-sandbox.json`. a completed check means the command exited successfully and cleanup succeeded. pug records an output hash. it does not treat command output as security findings.

the command works in `/scratch/work`. pug leaves the host checkout unchanged and does not copy files back. see [sandbox flags](commands.md#sandbox-flags) for options and [disposable sandbox](security.md#disposable-sandbox) for isolation limits.
