# Check packs

Empty on purpose. The catalogue (`../catalogue/`) is written and committed **before** the
first pack, as required by `docs/clean-room.md` (rule 5) and milestone K1 of the plan.

Layout once packs exist: `packs/<domain>/DSA-NNNN.yaml` with a `.sig` sidecar signed by the
maintainers at release. The format fixture used by engine tests lives in
`testdata/packs/` and is not a security check.
