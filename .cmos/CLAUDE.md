# cmos (managed file: `cmos init` rewrites it; put project facts in CLAUDE.md)

This project uses cmos, a Claude Code build harness. This text loads into every session and every agent.

## Rules
- Facts need a source: `path:line`, command output or a doc link. Write UNKNOWN when you have no source.
- Work that changes more than one file or about 30 lines starts with a plan (plan mode or `/cmos:plan`).
- Tests are the success criteria. Write or update the test first, then make it pass. Never weaken a test to pass it.
- Done means a green check on the current tree. In the loop, run `cmos check --quick`. The Stop hook checks your work before a session finishes.
- Keep each change small enough to review. Commit after each green step.
- Do not push to main or force-push. Do not use `--no-verify`, `git reset --hard` or `git add -A`.
- Do not read `.env` files. Get secrets from the environment.
- The project check is `cmos check`. It runs: `make check`.
- When Claude makes a mistake that a rule can prevent, add the rule with `/cmos:learn`.

## Codebase map
@map.md

## Project memory
@memory.md
