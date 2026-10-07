// Package buildinfo carries version metadata injected at build time with -ldflags.
package buildinfo

import "fmt"

// Set via: -ldflags "-X .../internal/buildinfo.Version=v0.1.0 -X .../internal/buildinfo.Commit=abc -X .../internal/buildinfo.Date=2026-10-07"
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a single-line description suitable for `dirauditor version`.
func String() string {
	return fmt.Sprintf("dirauditor %s (commit %s, built %s)", Version, Commit, Date)
}
