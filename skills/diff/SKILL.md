---
name: diff
description: Compare two existing Pug reports without running another scan.
disable-model-invocation: true
argument-hint: "<before.json> <after.json>"
---

read `${CLAUDE_PLUGIN_ROOT}/skills/pug/SKILL.md` for the shared pug workflow. run only the `diff` action. ask for any missing report path.

Requested reports (before, then after): $ARGUMENTS
