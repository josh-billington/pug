# skills used

the go skills were found with `npx skills find golang` before implementation. the source is [samber/cc-skills-golang](https://github.com/samber/cc-skills-golang/tree/d68d80aec298e1b74b37c2a472c002b5217248b3), commit `d68d80aec298e1b74b37c2a472c002b5217248b3`.

| skill | applied guidance |
| --- | --- |
| [go CLI](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-cli/SKILL.md) | cobra commands, stdout and stderr separation, injectable I/O, signal cancellation, and build version injection. |
| [go testing](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-testing/SKILL.md) | behavioral tests, named cases, real scanner fixtures, integration build tags, and race detection. |
| [go security](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-security/SKILL.md) | argument arrays, validation at boundaries, rooted file access, private reports, and explicit isolation limits. |
| [go context](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-context/SKILL.md) | propagated contexts, per-tool deadlines, and bounded cleanup after cancellation. |
| [go error handling](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-error-handling/SKILL.md) | wrapped errors, error classification, and one diagnostic emission at the CLI boundary. |
| [go code style](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-code-style/SKILL.md) | small packages, explicit structures, early returns, and a narrow public API. |

the direct go dependency is cobra, as declared in [`go.mod`](../go.mod). the CLI has no database or server. tests use the standard library for assertions and test doubles.
