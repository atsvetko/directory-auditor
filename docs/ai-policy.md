# AI usage policy

Most of this engine is written with an AI coding agent; the human decides, verifies and is
accountable. These rules apply to maintainers and contributors alike and are adopted at
milestone K0 of the implementation plan (`docs/ru/plan-v2-ai.pdf`).

## 1. The agent is inside the clean room

- No source from PingCastle, Purple Knight or any restrictively licensed tool is ever placed
  in an agent's context — not as a file, not as a paste, not as a URL to fetch.
- Agents work from the catalogue, primary references and this repository.
- All generated code passes a similarity scan against known open-source code in CI; a model
  can reproduce a fragment it has seen. Hits are resolved by a human before merge.

## 2. Data

- Cloud AI services see only synthetic snapshots (`tools/mksynth`) and lab domains.
- Real snapshots, logs and credentials from pilots are shared with an agent only redacted
  (`--redact`) or through a locally hosted model.
- Secrets (signing keys, tokens, passwords) are never visible to an agent. CI secrets live in
  the CI secret store; agents get read-only tokens at most.

## 3. CI is the judge, not the agent

- Acceptance criteria (requirements AR-1…AR-14, N-1…N-10) and the CI gates are changed only
  by a human in a reviewed pull request.
- "Tests pass" is a statement by the pipeline, never by the agent.

## 4. Reading budget

- The engine stays small so that a human can read it. Trust points — authentication, pack
  signature verification, the read-only surface in `internal/ldapx`, redaction — are read
  line by line by a human on every change.
- Everything else gets a second, independent agent review plus human spot checks; large
  generated diffs are split until they are readable.

## 5. Transparency

- Commits made with an agent carry a trailer (`Co-Authored-By:` or `AI-assisted:`).
- Pull requests state `AI-assisted: yes — <tool>` or `no`.
- The DCO sign-off is made by a human.

## 6. What the agent must never do

- Run against, or hold credentials for, any production directory.
- Change acceptance criteria, the read-only denylist, or the signature policy.
- Fetch or summarise restrictively licensed code "just to compare".
