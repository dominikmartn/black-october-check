# Contributing

PRs are welcome. People paste this file into an agent that runs the commands on their machine, so every change has to hold up.

- Every new item needs a linked public source: a vendor advisory, release notes, a CVE entry or an incident page. A private email or a screenshot is not enough.
- "What we saw" lines only come from a real run. Say which OS and version, and when.
- Checks are read-only. Anything that changes the machine goes into the fixes, and the agent asks before each one.
- Never print secrets. No process arguments, no file contents.
- No em dashes. Plain, short sentences.

## Other platforms

The checks in README.md are for macOS. A Windows (PowerShell) version is welcome as `windows.md`, with the same structure: contract, read-only checks, fixes, undo.
