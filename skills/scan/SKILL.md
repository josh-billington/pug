---
name: scan
description: Run Pug's defensive checks on a trusted local checkout.
disable-model-invocation: true
argument-hint: "[local directory] [checks to run]"
---

read `${CLAUDE_PLUGIN_ROOT}/skills/pug/SKILL.md` for the shared pug workflow. run only the `scan` action. when no directory is supplied, scan the current checkout.

Requested local directory and checks: $ARGUMENTS
