# Domain Docs

How the engineering skills should consume this repo's domain
documentation when exploring the codebase.

This repo is single-context: one `CONTEXT.md` and one `docs/adr/` at
the root.

## Before exploring, read these

- `CONTEXT.md` at the repo root
- `docs/adr/` — read the ADRs that touch the area you are about to
  work in

If any of these files do not exist, proceed silently. Do not flag their
absence and do not suggest creating them upfront. The `/domain-modeling`
skill (reached via `/grill-with-docs` and
`/improve-codebase-architecture`) creates them lazily, when terms or
decisions actually get resolved.

## File structure

```text
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-example-decision.md
│   └── 0002-another-decision.md
└── src/
```

## Use the glossary's vocabulary

When your output names a domain concept — in an issue title, a refactor
proposal, a hypothesis, a test name — use the term as defined in
`CONTEXT.md`. Do not drift to synonyms the glossary explicitly avoids.

If the concept you need is not in the glossary yet, that is a signal.
Either you are inventing language the project does not use
(reconsider), or there is a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly
rather than silently overriding it:

> _Contradicts ADR-0007 (event-sourced orders) — but worth reopening
> because…_
