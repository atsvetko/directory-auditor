// Package app wires the subcommands: flag parsing, provider selection,
// collection, analysis, reporting, doctor and manifest. It owns no protocol
// code and no check logic.
package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/atsvetko/directory-auditor/internal/buildinfo"
	"github.com/atsvetko/directory-auditor/internal/check"
	"github.com/atsvetko/directory-auditor/internal/doctor"
	"github.com/atsvetko/directory-auditor/internal/ldapx"
	"github.com/atsvetko/directory-auditor/internal/provider"
	"github.com/atsvetko/directory-auditor/internal/provider/ad" // registers the AD / Samba provider
	"github.com/atsvetko/directory-auditor/internal/report"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// Scan collects a snapshot and analyses it in one go.
func Scan(ctx context.Context, args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(errw)
	var t provider.Target
	var packsDir, outDir, lang string
	var allowUnsigned bool
	fs.StringVar(&t.Server, "server", "", "domain controller host[:port]")
	fs.StringVar(&t.Domain, "domain", "", "DNS domain name")
	fs.StringVar(&t.BindUser, "user", "", "bind identity (DN or UPN); empty = current logon (not yet implemented)")
	fs.BoolVar(&t.UseLDAPS, "ldaps", true, "use LDAPS (636)")
	fs.BoolVar(&t.StartTLS, "starttls", false, "use StartTLS on 389 instead of LDAPS")
	fs.BoolVar(&t.InsecurePlaintext, "insecure-plaintext", false, "allow LDAP without TLS (lab only)")
	fs.StringVar(&t.PinSHA256, "pin", "", "hex SHA-256 of the server certificate to pin")
	fs.IntVar(&t.Tier, "tier", 0, "privilege tier to use: 0 user LDAP, 1 +SYSVOL/probes, 2 admin")
	fs.IntVar(&t.MaxQPS, "max-qps", 0, "throttle LDAP queries per second (0 = unlimited)")
	fs.StringVar(&packsDir, "packs", "packs", "directory with check packs")
	fs.StringVar(&outDir, "out", "dirauditor-out", "output directory")
	fs.StringVar(&lang, "lang", "en", "report language: en or ru")
	fs.BoolVar(&allowUnsigned, "allow-unsigned", false, "load unsigned packs (development only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if t.StartTLS {
		t.UseLDAPS = false
	}
	if t.Tier != 0 {
		fmt.Fprintln(errw, "tier 1 and 2 collection is not implemented yet; running tier 0")
		t.Tier = 0
	}
	if t.BindUser != "" {
		pw, err := promptPassword(errw, "Password for "+t.BindUser+": ")
		if err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
		t.BindPassword = pw
	}
	p, ok := provider.Get("ad")
	if !ok {
		fmt.Fprintln(errw, "error: AD provider not registered")
		return 1
	}
	fmt.Fprintf(errw, "collecting from %s (tier %d, read-only)…\n", t.Server, t.Tier)
	snap, err := p.Collect(ctx, t, func(msg string) { fmt.Fprintln(errw, "  ·", msg) })
	t.BindPassword = "" // used once, never kept
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		fmt.Fprintln(errw, "hint: run `dirauditor doctor --domain <domain> --server <dc>` to see why")
		return 1
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	snapPath := filepath.Join(outDir, "snapshot-"+time.Now().UTC().Format("20060102-150405")+".json.zst")
	if err := snapshot.WriteFile(snapPath, snap); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	fmt.Fprintf(errw, "snapshot: %s (%d objects, %d searches, %d requests, %s)\n", snapPath, len(snap.Objects), snap.Meta.QueryCount, snap.Meta.Requests, snap.Meta.Duration)
	for _, sk := range snap.Skipped {
		fmt.Fprintf(errw, "  not collected: %s (%s) %s\n", sk.Query, sk.Reason, sk.Detail)
	}
	return analyse(snap, packsDir, outDir, lang, allowUnsigned, out, errw)
}

// Analyse re-runs the checks on an existing snapshot — no directory access at all.
func Analyse(ctx context.Context, args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("analyse", flag.ContinueOnError)
	fs.SetOutput(errw)
	var snapPath, packsDir, outDir, lang string
	var allowUnsigned bool
	fs.StringVar(&snapPath, "snapshot", "", "snapshot file (.json.zst)")
	fs.StringVar(&packsDir, "packs", "packs", "directory with check packs")
	fs.StringVar(&outDir, "out", "dirauditor-out", "output directory")
	fs.StringVar(&lang, "lang", "en", "report language: en or ru")
	fs.BoolVar(&allowUnsigned, "allow-unsigned", false, "load unsigned packs (development only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if snapPath == "" {
		fmt.Fprintln(errw, "error: --snapshot is required")
		return 2
	}
	snap, err := snapshot.ReadFile(snapPath)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	return analyse(snap, packsDir, outDir, lang, allowUnsigned, out, errw)
}

func analyse(snap *snapshot.Snapshot, packsDir, outDir, lang string, allowUnsigned bool, out, errw io.Writer) int {
	packs, err := check.LoadDir(packsDir, check.LoadOptions{AllowUnsigned: allowUnsigned})
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if allowUnsigned {
		fmt.Fprintln(errw, "WARNING: --allow-unsigned is set; packs were not verified (development mode)")
	}
	res, err := check.Evaluate(snap, packs)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	jsonPath := filepath.Join(outDir, "report.json")
	htmlPath := filepath.Join(outDir, "report.html")
	if err := writeFile(jsonPath, func(w io.Writer) error { return report.WriteJSON(w, res) }); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if err := writeFile(htmlPath, func(w io.Writer) error { return report.WriteHTML(w, res, lang) }); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	c := res.Counts
	fmt.Fprintf(out, "score %d/100 — %d checked, %d passed, %d with findings (%d findings), %d skipped\n",
		res.Score, c.Checked, c.Passed, c.Failed, c.Findings, c.Skipped)
	for reason, n := range c.BySkip {
		fmt.Fprintf(out, "  skipped because of %s: %d\n", reason, n)
	}
	fmt.Fprintf(out, "report: %s\n        %s\n", htmlPath, jsonPath)
	return 0
}

// Doctor prints connectivity diagnostics with causes and fixes.
func Doctor(ctx context.Context, args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(errw)
	var domain, server string
	fs.StringVar(&domain, "domain", "", "DNS domain name")
	fs.StringVar(&server, "server", "", "domain controller host (optional when SRV records resolve)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if domain == "" && server == "" {
		fmt.Fprintln(errw, "error: --domain or --server is required")
		return 2
	}
	fmt.Fprintf(out, "Directory Auditor doctor — %s\n", buildinfo.Version)
	if doctor.Print(out, doctor.Run(ctx, domain, server)) {
		fmt.Fprintln(out, "all diagnostics passed")
		return 0
	}
	return 1
}

// Manifest handles `dirauditor manifest [--queries]`.
func Manifest(args []string, w io.Writer) int {
	PrintManifest(w)
	for _, a := range args {
		if a == "--queries" || a == "-queries" {
			PrintQueries(w)
		}
	}
	return 0
}

// PrintQueries lists every LDAP search the AD provider can issue, with the
// catalogue entries it serves — for approvers (review pack, approach §6.1).
func PrintQueries(w io.Writer) {
	scopes := map[ldapx.Scope]string{ldapx.ScopeBase: "base", ldapx.ScopeOneLevel: "one", ldapx.ScopeSubtree: "subtree"}
	fmt.Fprintln(w, "\nLDAP searches (AD / Samba provider, tier 0 — ordinary user):")
	for _, q := range append(ad.Plan, ad.SDBaseQuery) {
		b := q.Base
		if b != "default" && b != "<each Tier-0 DN>" {
			b += ",<default>"
		}
		sd := ""
		if q.SD {
			sd = " + nTSecurityDescriptor (DACL only, SD_FLAGS=0x4)"
		}
		fmt.Fprintf(w, "  %-14s base=%s scope=%s filter=%s\n                 attrs=%s%s\n                 why: %s\n",
			q.Name, b, scopes[q.Scope], q.Filter, strings.Join(q.Attrs, ","), sd, q.Purpose)
	}
}

// PrintManifest prints every behaviour of this binary (requirement AR-… `--manifest`).
func PrintManifest(w io.Writer) {
	fmt.Fprintf(w, `%s
Behaviours of this binary:
  network     : outbound only, to the directory server(s) you name (LDAP 389/636, DNS SRV lookups
                through the OS resolver). No other hosts are contacted. No update checks. No telemetry.
  listeners   : none (the local web UI is a later milestone and will bind to 127.0.0.1 only)
  writes      : output directory only (snapshot, report.json, report.html)
  directory   : read-only — no LDAP modify/add/delete code is linked (scripts/readonly-check.sh)
  credentials : prompted on the terminal, used once, never written to disk or environment
  packs       : loaded only with a valid Ed25519 signature unless --allow-unsigned is given
  providers   : %s
`, buildinfo.String(), strings.Join(provider.Names(), ", "))
}

func writeFile(path string, fn func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func promptPassword(w io.Writer, prompt string) (string, error) {
	fmt.Fprint(w, prompt)
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("stdin is not a terminal; a password cannot be read safely (no --password flag by design)")
	}
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(w)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
