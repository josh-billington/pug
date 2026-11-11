# Run an offline command in the sandbox

Use the sandbox to run a command against a copy of a clean Git checkout. You can start an application beside the command in the same container.

You need Git, a running Docker daemon, and a locally installed image pinned by SHA-256 digest. The image must contain `/bin/sh`, `mkdir`, `cp`, and the command's runtime and dependencies.

The container has no external network access. Hosted model APIs are unreachable. If you use an agent, the image must contain the offline agent and any local model it needs. Pug supplies no agent, model, or credentials.

## Run the command

1. Set `SANDBOX_IMAGE` to your installed image's full `NAME@sha256:DIGEST` reference.
2. Prepare a clean checkout with a commit.

	Use the Git checkout root for `--repo`. Commit or stash changes to tracked files before the run. Pug excludes untracked files and rejects tracked symlinks and submodules.

3. Run your command after `--`.

	This example assumes the image contains Python and `/opt/offline-agent`, and the checkout contains `app.py`:

	```sh
	pug sandbox \
		--repo /path/to/clean-checkout \
		--image "$SANDBOX_IMAGE" \
		--app-command '["python3","app.py"]' \
		--output pug-report-sandbox.json \
		-- /opt/offline-agent test http://127.0.0.1:8000
	```

	From this checkout, use `./bin/pug` if `pug` is not on `PATH`. Replace the checkout path and the example commands with your values. Omit `--app-command` if no application is needed.

The application and command share container loopback. The command must wait until the application is ready to accept requests.

## Read the result

Inspect `pug-report-sandbox.json`. A completed check means the command exited successfully and cleanup succeeded. Pug records an output hash but does not treat command output as security findings.

The command works in `/scratch/work`. Pug leaves the host checkout unchanged and does not copy files back. See [Sandbox flags](commands.md#sandbox-flags) for options and [Disposable sandbox](security.md#disposable-sandbox) for isolation limits.
