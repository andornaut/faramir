# How this run is being conducted

You are running non-interactively. Nobody will answer a question, so do not ask
one: make the call yourself and record what you decided and why.

Other coding agents may be running this same test concurrently in this same
working directory. That has four consequences:

1. **Treat the tree as strictly read-only.** Do not write, edit, move or delete
   anything under it, tracked or untracked. Do not run `git add`, `git commit`,
   `git stash`, `git checkout` or `git restore`. Another agent's work is in here.
2. **Namespace every scratch file.** Your scratch files go in
   `/tmp/faramir-agent-test-AGENTSLUG-*`. Delete only what matches that exact
   prefix at the end, never another agent's. Where a case names a scratch path
   of its own, put it under this prefix too.
3. **Do not run the tree's lint or test targets**, or anything else that writes
   to its caches: concurrent runs of those collide and the result says nothing.
   Substitute read-only ordinary work and mark it SKIP with this reason. Syntax
   checks, `--list-hosts`, `--list-tasks`, an inventory graph, `git status`,
   `git log`, grep and file reads are all fine, and are what section E is really
   asking about.
4. **Expect the tree to change under you.** A file's mtime moving, or a
   `git status` that differs between two calls, is another agent, not a defect.

## Section G is skipped

No operator is watching, so skip section G entirely and record its cases as
`SKIP (no operator present, headless run)`. Do not run `faramir run -- sudo`
anything: it would block until it times out and waste the rest of your run.

## Scale

Aim for 40 to 60 cases. Depth in sections B, C and D is worth more than breadth.
Sections A and I are prose and are the most valuable part of the report, so
reserve room for them rather than letting the table crowd them out.

## Your report

Print the full report as your final message, and also write a copy to the file
named below. Nothing else goes in that file. If your final message would be
truncated, the file is the record that survives, so write it first.
