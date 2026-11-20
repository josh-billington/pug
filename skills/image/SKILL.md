---
name: image
description: Check a container image pinned by digest with Pug.
disable-model-invocation: true
argument-hint: "<image@sha256:digest>"
---

read `${CLAUDE_PLUGIN_ROOT}/skills/pug/SKILL.md` for the shared pug workflow. run only the `image` action. ask for the image if it was omitted.

Requested image: $ARGUMENTS
