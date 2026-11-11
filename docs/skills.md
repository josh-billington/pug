# Skills used

The Go skills were found with `npx skills find golang` before implementation. The source is [samber/cc-skills-golang](https://github.com/samber/cc-skills-golang/tree/d68d80aec298e1b74b37c2a472c002b5217248b3), commit `d68d80aec298e1b74b37c2a472c002b5217248b3`.

| Skill | Applied guidance |
| --- | --- |
| [Go CLI](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-cli/SKILL.md) | Cobra commands, stdout and stderr separation, injectable I/O, signal cancellation, and build version injection. |
| [Go testing](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-testing/SKILL.md) | Behavioral tests, named cases, real scanner fixtures, integration build tags, and race detection. |
| [Go security](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-security/SKILL.md) | Argument arrays, validation at boundaries, rooted file access, private reports, and explicit isolation limits. |
| [Go context](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-context/SKILL.md) | Propagated contexts, per-tool deadlines, and bounded cleanup after cancellation. |
| [Go error handling](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-error-handling/SKILL.md) | Wrapped errors, error classification, and one diagnostic emission at the CLI boundary. |
| [Go code style](https://github.com/samber/cc-skills-golang/blob/d68d80aec298e1b74b37c2a472c002b5217248b3/skills/golang-code-style/SKILL.md) | Small packages, explicit structures, early returns, and a narrow public API. |

The direct Go dependency is Cobra, as declared in [`go.mod`](../go.mod). The CLI has no database or server. Tests use the standard library for assertions and test doubles.
