---
name: diff
description: Compare two existing Pug reports without running another scan.
disable-model-invocation: true
argument-hint: "<before.json> <after.json>"
---

Read `${CLAUDE_PLUGIN_ROOT}/skills/pug/SKILL.md` for the shared Pug workflow. Run only the `diff` action. Ask for any missing report path.

Requested reports (before, then after): $ARGUMENTS
