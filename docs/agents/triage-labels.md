# Triage Labels

The skills speak in terms of five canonical triage roles. This file
maps those roles to the label strings actually used in this repo's
issue tracker.

Because this repo tracks issues as local markdown, a "label" is the
value of the `Status:` line near the top of an issue file.

## Roles

- `needs-triage` — maintainer needs to evaluate this issue.
- `needs-info` — waiting on the reporter for more information.
- `ready-for-agent` — fully specified, ready for an AFK agent.
- `ready-for-human` — requires human implementation.
- `wontfix` — will not be actioned.

Each role's label string is currently identical to the role name. When
a skill mentions a role (for example "apply the AFK-ready triage
label"), use the matching string above.

Edit this list if the vocabulary ever diverges from the role names.
