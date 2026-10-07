// Package demo embeds the synthetic lab snapshot (tools/mksynth) so the wizard's
// "Try with demo data" works with no directory at all. Every name in it is invented.
package demo

import _ "embed"

//go:embed synthetic-lab.json.zst
var Snapshot []byte
