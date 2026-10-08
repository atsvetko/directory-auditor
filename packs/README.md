# Check packs

Empty on purpose. The catalogue (`../catalogue/`) is written and committed **before** the
first pack, as required by `docs/clean-room.md` (rule 5) and milestone K1 of the plan.

Layout once packs exist: `packs/<domain>/DSA-NNNN.yaml` with a `.sig` sidecar signed by the
maintainers at release. The format fixture used by engine tests lives in
`testdata/packs/` and is not a security check.

## Condition helpers

Conditions are CEL expressions over `obj`. Besides `attr`, `attrs`, `intattr` and
`hasattr`, the engine provides (see `internal/check/helpers.go`):

| Helper | Meaning |
|---|---|
| `flags(obj, "attr", mask)` / `anyflag(…)` | all / any bits of a flag attribute set (CEL has no bitwise operators) |
| `mask_has(m, bits)` | bits on a plain integer, e.g. an ACE mask |
| `age_days(obj, "attr")` | days before the snapshot was collected; FILETIME or GeneralizedTime; `-1` when absent or "never" |
| `sid_rid(s)`, `sid_domain(s)` | split a SID string |
| `tier0(obj)`, `tier0_sid(s)` | Tier-0 status per `catalogue/TIER0.md` (nested groups, primaryGroupID, FSPs) |
| `sd_readable(obj)`, `sd_protected(obj)` | descriptor collected; DACL inheritance disabled |
| `aces(obj)`, `aces_of(obj, "attr")` | DACL entries as maps: `trustee`, `mask`, `allow`, `inherited`, `effective`, `object_type`, `inherited_object_type`, `trustee_tier0` |
| `objattr(dn, "attr")`, `objattrs(dn, "attr")`, `objexists(dn)` | read another snapshot object; `<default>` in the DN is the base DN |
| `smbbool(obj, "param", default)` | Samba boolean (yes/true/1/on), with a value for an absent parameter |
| `version_lt(a, b)`, `intval(s)` | dotted-version compare (unknown is never less); decimal or 0x-hex to int |

Synthetic objects the collectors add, so packs can match them with a filter: `cn=rootdse,cn=dirauditor`
(`dirauditorRootDSE`), and on a Samba DC `cn=global,cn=smb.conf,cn=dirauditor` (`dirauditorSmbConf`,
parameter names lower-cased, `_explicit` = set in the file, `_source` = testparm or file),
`cn=<share>,cn=shares,cn=smb.conf,cn=dirauditor` (`dirauditorSmbShare`) and `cn=samba,cn=dirauditor`
(`dirauditorSamba`, `version`).

Time is measured against the snapshot's collection time, so re-analysing an old
snapshot gives the same answer. Use `sd_readable(obj)` in ACL conditions so a
missing descriptor is reported as not collected rather than as a pass.
