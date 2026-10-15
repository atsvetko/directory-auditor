# Architecture decision records

One file per decision, numbered, never edited after acceptance — superseded by a new ADR instead.

Format: a **Status** line (proposed · accepted · superseded by ADR-NNNN · rejected, with the
date), then **Context** (why the question arose), **Decision**, **Alternatives** (what else was
considered and why it was rejected), **Consequences**. ADRs 0001–0006 predate the Alternatives
section; their alternatives are in [approach.md](../requirements/approach.md) §11–12 and §17.

Every decision that materially shapes the project gets an ADR here, whether a person or an AI
agent wrote the code — the reasons must live in the repository, not in a chat history.
ADRs 0007–0019 were recorded on 2026-10-15 from decisions already taken in earlier work sessions.

| # | Decision | Status |
|---|---|---|
| [0001](0001-engine-language-go.md) | Engine in Go, single static binary | accepted |
| [0002](0002-snapshot-architecture.md) | Collect → versioned snapshot → analyse → report | accepted |
| [0003](0003-check-packs-yaml-cel.md) | Checks are signed YAML packs with CEL conditions | accepted |
| [0004](0004-read-only-contract.md) | Read-only is a build-time property | accepted |
| [0005](0005-local-web-ui-on-loopback.md) | Local web UI on loopback | accepted |
| [0006](0006-signing-and-distribution.md) | Signing and distribution | accepted |
| [0007](0007-clean-room-catalogue.md) | Clean-room catalogue from primary sources only | accepted |
| [0008](0008-preview-checks-built-in.md) | Unverified entries ship as labelled preview checks; `--no-preview` | accepted |
| [0009](0009-providers-detect-first.md) | One provider per directory type, fingerprint first | accepted |
| [0010](0010-catalogue-provider-gating.md) | Catalogue decides which providers run a check | accepted |
| [0011](0011-catalogue-numbering.md) | Stable `DSA-NNNN` IDs in per-domain blocks | accepted |
| [0012](0012-privilege-tiers.md) | Three privilege tiers; admin config local and opt-in | accepted |
| [0013](0013-authentication-and-transport.md) | Kerberos first, encrypted transport, plaintext lab-only | accepted |
| [0014](0014-dns-srv-dc-discovery.md) | DC discovery through DNS SRV records | accepted |
| [0015](0015-demo-mode-separate.md) | Demo is explicit; failed connect never falls back to it | accepted |
| [0016](0016-licence-name-ownership.md) | Apache 2.0 open core, personal ownership, name | accepted |
| [0017](0017-bilingual-output.md) | Bilingual EN/RU text in the catalogue | accepted |
| [0018](0018-lab-tool-separate-binary.md) | Lab builder is a separate binary | accepted |
| [0019](0019-not-collected-status.md) | "Not collected" instead of silent pass | **proposed** |
