// Package catalogue embeds the check catalogue — every DSA-NNNN.yaml under
// this directory — into the binary, so a prototype build evaluates the
// implemented entries as *preview checks* with no files beside the executable.
//
// Preview checks are unsigned and unverified (catalogue status "draft"): the
// report labels them and findings are leads to confirm, not verified results.
// Signed packs (packs/) replace them one by one as entries are verified; the
// user experience does not change. `--no-preview` turns them off.
//
// This file has no imports besides embed, so the root package can be used
// from internal/catalogue without an import cycle. The pattern covers any
// catalogue domain directory added later.
package catalogue

import "embed"

// Files holds the catalogue entries, keyed by "<domain>/DSA-NNNN.yaml".
//
//go:embed */*.yaml
var Files embed.FS
