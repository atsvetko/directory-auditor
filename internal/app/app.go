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
	"github.com/atsvetko/directory-auditor/internal/catalogue"
	"github.com/atsvetko/directory-auditor/internal/check"
	"github.com/atsvetko/directory-auditor/internal/demo"
	"github.com/atsvetko/directory-auditor/internal/doctor"
	"github.com/atsvetko/directory-auditor/internal/ldapx"
	"github.com/atsvetko/directory-auditor/internal/local/smbconf"
	"github.com/atsvetko/directory-auditor/internal/packset"
	"github.com/atsvetko/directory-auditor/internal/provider"
	"github.com/atsvetko/directory-auditor/internal/provider/ad" // registers the AD / Samba provider
	"github.com/atsvetko/directory-auditor/internal/provider/freeipa"
	"github.com/atsvetko/directory-auditor/internal/report"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
	"github.com/atsvetko/directory-auditor/internal/web"
)

// Scan collects a snapshot and analyses it in one go.
func Scan(ctx context.Context, args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(errw)
	var t provider.Target
	var o analyseOptions
	var providerName string
	checkFlags(fs, &o, "packs")
	fs.StringVar(&providerName, "provider", "auto", "directory type: auto, "+strings.Join(provider.Names(), ", "))
	fs.StringVar(&t.Server, "server", "", "domain controller host[:port]")
	fs.StringVar(&t.Domain, "domain", "", "DNS domain name")
	fs.StringVar(&t.BindUser, "user", "", "bind identity (DN or UPN); empty = current logon via Kerberos (no password)")
	fs.BoolVar(&t.UseLDAPS, "ldaps", true, "use LDAPS (636)")
	fs.BoolVar(&t.StartTLS, "starttls", false, "use StartTLS on 389 instead of LDAPS")
	fs.BoolVar(&t.InsecurePlaintext, "insecure-plaintext", false, "allow LDAP without TLS (lab only)")
	fs.StringVar(&t.PinSHA256, "pin", "", "hex SHA-256 of the server certificate to pin")
	fs.IntVar(&t.Tier, "tier", 0, "privilege tier to use: 0 user LDAP, 1 +SYSVOL/probes, 2 admin")
	fs.IntVar(&t.MaxQPS, "max-qps", 0, "throttle LDAP queries per second (0 = unlimited)")
	fs.StringVar(&o.OutDir, "out", "dirauditor-out", "output directory")
	var smbConf string
	var local, pwStdin bool
	fs.BoolVar(&pwStdin, "password-stdin", false, "read the bind password from the first line of stdin instead of the terminal (CI, pipes)")
	fs.StringVar(&smbConf, "smbconf", "", "also audit this Samba AD DC configuration file (run on the DC; tier 2)")
	fs.BoolVar(&local, "local", false, "auto-detect "+smbconf.DefaultPath+" on this machine and include it")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if t.StartTLS {
		t.UseLDAPS = false
	}
	if local && smbConf == "" {
		if smbConf = smbconf.Detect(""); smbConf == "" {
			fmt.Fprintln(errw, "error: --local: no readable Samba AD DC configuration at "+smbconf.DefaultPath)
			return 1
		}
	}
	if t.Tier > 1 && smbConf == "" {
		fmt.Fprintln(errw, "tier 2 currently means the local smb.conf audit (--smbconf / --local); other tier-2 probes are not implemented yet")
	}
	if t.Tier == 1 && providerName != "freeipa" {
		fmt.Fprintln(errw, "note: tier-1 probes exist for FreeIPA only so far; AD collection runs at tier 0")
	}

	// Configuration-only audit: no directory target, just the local smb.conf.
	if t.Server == "" && t.Domain == "" && smbConf != "" {
		snap := &snapshot.Snapshot{Schema: snapshot.SchemaVersion, Collected: time.Now().UTC(),
			Meta: snapshot.Meta{Provider: "ad", Dialect: "samba", Target: "local smb.conf", Tool: "dirauditor " + buildinfo.Version}}
		if !collectLocal(ctx, snap, smbConf, errw) {
			return 1
		}
		return finish(snap, o, out, errw)
	}
	if t.BindUser != "" {
		var pw string
		var err error
		if pwStdin {
			pw, err = readPasswordLine(os.Stdin)
		} else {
			pw, err = promptPassword(errw, "Password for "+t.BindUser+": ")
		}
		if err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
		t.BindPassword = pw
	}
	p, dialect, err := provider.Pick(ctx, providerName, t)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		fmt.Fprintln(errw, "hint: run `dirauditor doctor --domain <domain> --server <dc>` to see why")
		return 1
	}
	if dialect != "" {
		fmt.Fprintf(errw, "detected: %s (%s)\n", p.Name(), dialect)
	}
	fmt.Fprintf(errw, "collecting from %s (tier %d, read-only)…\n", t.Server, t.Tier)
	snap, err := p.Collect(ctx, t, func(msg string) { fmt.Fprintln(errw, "  ·", msg) })
	t.BindPassword = "" // used once, never kept
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		fmt.Fprintln(errw, "hint: run `dirauditor doctor --domain <domain> --server <dc>` to see why")
		return 1
	}
	if smbConf != "" {
		if snap.Meta.Dialect != "samba" {
			fmt.Fprintf(errw, "warning: --smbconf given but the directory is %s/%s, not Samba; smb.conf checks still run\n", snap.Meta.Provider, snap.Meta.Dialect)
		}
		if !collectLocal(ctx, snap, smbConf, errw) {
			return 1
		}
	}
	return finish(snap, o, out, errw)
}

// readPasswordLine reads one line (the password) from r. Used with
// --password-stdin so CI and scripts can pipe a secret in without putting it
// on the command line or in the environment.
func readPasswordLine(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return "", err
	}
	line := strings.TrimRight(strings.SplitN(string(b), "\n", 2)[0], "\r")
	if line == "" {
		return "", fmt.Errorf("--password-stdin: no password on stdin")
	}
	return line, nil
}

// collectLocal adds the local Samba configuration to the snapshot.
func collectLocal(ctx context.Context, snap *snapshot.Snapshot, path string, errw io.Writer) bool {
	fmt.Fprintf(errw, "reading local Samba configuration %s (testparm, samba -V)…\n", path)
	r, err := smbconf.Collect(ctx, smbconf.Options{Path: path})
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return false
	}
	if !strings.Contains(strings.ToLower(r.Role), "domain controller") {
		fmt.Fprintf(errw, "warning: server role is %q — not an AD DC; DC-specific findings may not apply\n", r.Role)
	}
	smbconf.Augment(snap, r)
	fmt.Fprintf(errw, "  · Samba %s, %d shares, values from %s\n", orUnknown(r.Version), len(r.Objects)-2, r.Source)
	return true
}

func orUnknown(s string) string {
	if s == "" {
		return "(version unknown)"
	}
	return s
}

// analyseOptions are the flags scan and analyse share.
type analyseOptions struct {
	packset.Options
	OutDir string
	Lang   string
	Quick  bool
}

// checkFlags registers the flags that choose which checks run.
func checkFlags(fs *flag.FlagSet, o *analyseOptions, defaultPacks string) {
	fs.StringVar(&o.PacksDir, "packs", defaultPacks, "directory with signed check packs")
	fs.BoolVar(&o.AllowUnsigned, "allow-unsigned", false, "load unsigned packs (development only)")
	fs.BoolVar(&o.NoPreview, "no-preview", false, "do not evaluate the preview checks built into this binary (unverified catalogue entries); signed packs only")
	fs.StringVar(&o.CatalogueDir, "catalogue", "", "take preview checks from this catalogue working tree instead of the built-in copy (for verifying entries)")
	fs.BoolVar(&o.Quick, "quick", false, "quick scan: run only checks marked quick")
	fs.StringVar(&o.Lang, "lang", "en", "report language: en or ru")
}

// finish writes the snapshot and analyses it.
func finish(snap *snapshot.Snapshot, o analyseOptions, out, errw io.Writer) int {
	outDir := o.OutDir
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
	return analyse(snap, o, out, errw)
}

// Wizard starts the local web UI. With no arguments (double-click) it opens the
// browser; `dirauditor ui --no-browser` only prints the address.
func Wizard(ctx context.Context, args []string, errw io.Writer) int {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(errw)
	var o analyseOptions
	var noBrowser bool
	checkFlags(fs, &o, "")
	fs.Lookup("packs").Usage = "directory with signed check packs (default: packs next to the binary, then ./packs)"
	fs.StringVar(&o.OutDir, "out", "dirauditor-out", "output directory for snapshots and reports")
	fs.BoolVar(&noBrowser, "no-browser", false, "do not open a browser; print the address only")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if o.PacksDir == "" {
		o.PacksDir = defaultPacksDir()
	}
	err := web.Run(ctx, web.Options{
		Checks: o.Options, OutDir: o.OutDir, Version: buildinfo.Version,
		Demo: demo.Snapshot, OpenBrowser: !noBrowser, Log: errw,
	})
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	return 0
}

// defaultPacksDir prefers packs/ beside the executable (the release layout),
// then packs/ in the working directory.
func defaultPacksDir() string {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "packs")
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return "packs"
}

// Analyse re-runs the checks on an existing snapshot — no directory access at all.
func Analyse(ctx context.Context, args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("analyse", flag.ContinueOnError)
	fs.SetOutput(errw)
	var snapPath string
	var o analyseOptions
	checkFlags(fs, &o, "packs")
	fs.StringVar(&snapPath, "snapshot", "", "snapshot file (.json.zst)")
	fs.StringVar(&o.OutDir, "out", "dirauditor-out", "output directory")
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
	if err := os.MkdirAll(o.OutDir, 0o750); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	return analyse(snap, o, out, errw)
}

func analyse(snap *snapshot.Snapshot, o analyseOptions, out, errw io.Writer) int {
	set, err := packset.Load(o.Options)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	for _, n := range set.Notes {
		fmt.Fprintln(errw, "NOTE:", n)
	}
	res, err := check.EvaluateWith(snap, set.Packs, check.EvalOptions{Quick: o.Quick})
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	jsonPath := filepath.Join(o.OutDir, "report.json")
	htmlPath := filepath.Join(o.OutDir, "report.html")
	if err := writeFile(jsonPath, func(w io.Writer) error { return report.WriteJSON(w, res) }); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if err := writeFile(htmlPath, func(w io.Writer) error { return report.WriteHTML(w, res, o.Lang) }); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	c := res.Counts
	fmt.Fprintf(out, "score %d/100 — %d checked, %d passed, %d with findings (%d findings), %d skipped\n",
		res.Score, c.Checked, c.Passed, c.Failed, c.Findings, c.Skipped)
	if res.Preview > 0 {
		fmt.Fprintf(out, "  preview checks: %d (unverified catalogue entries — confirm findings before acting)\n", res.Preview)
	}
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
	fmt.Fprintln(w, "\nLDAP searches (FreeIPA provider, authenticated user; containers that need a privilege are marked):")
	for _, q := range freeipa.Plan {
		b := q.Base
		if b != "" {
			b += ","
		}
		priv := ""
		if q.Privilege != "" {
			priv = " [needs privilege: " + q.Privilege + "]"
		}
		fmt.Fprintf(w, "  %-14s base=%s<default> scope=%s filter=%s%s\n                 attrs=%s\n                 why: %s\n",
			q.Name, b, scopes[q.Scope], q.Filter, priv, strings.Join(q.Attrs, ","), q.Purpose)
	}
	fmt.Fprintln(w, "  tier-1 probe   base=cn=users,cn=accounts,<default> scope=one filter=(uid=*) size-limit=3, before binding (DSA-0123)")
	fmt.Fprintln(w, "\nLDAP searches (AD / Samba provider, tier 0 — ordinary user):")
	for _, q := range append(ad.Plan, ad.SDBaseQuery) {
		b := q.Base
		if b != "default" && b != "<each Tier-0 DN>" && !strings.HasSuffix(b, "<config>") {
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
  listeners   : wizard only (no arguments or 'ui'): 127.0.0.1, random port, one-time token in the URL;
                CLI commands open no listener
  processes   : the wizard asks the OS to open the default browser once (rundll32 / open / xdg-open);
                with --smbconf/--local (or when the wizard finds a Samba DC configuration on this machine)
                it runs 'testparm -s -v --suppress-prompt <smb.conf>' and 'samba -V' / 'smbd -V',
                both read-only, and reads smb.conf. Secret-looking values are redacted.
  writes      : output directory only (snapshot, report.json, report.html)
  directory   : read-only — no LDAP modify/add/delete code is linked (scripts/readonly-check.sh)
  credentials : prompted on the terminal (or piped with --password-stdin), used once, never written to
                disk, the command line or the environment
  checks      : signed packs (Ed25519) from --packs, plus the preview checks built into this binary —
                implemented catalogue entries, unsigned and not yet verified by a human; reports label
                them. --no-preview evaluates signed packs only; the preview set is listed below.
  providers   : %s
`, buildinfo.String(), strings.Join(provider.Names(), ", "))
	pv, err := catalogue.Embedded()
	if err != nil {
		fmt.Fprintf(w, "\nPreview checks: unavailable (%v)\n", err)
		return
	}
	fmt.Fprintf(w, "\nPreview checks built in (%d; unsigned, catalogue status draft, not yet verified by a human):\n", len(pv))
	for _, p := range pv {
		fmt.Fprintf(w, "  %s  %-8s tier %d  %s  [%s]\n", p.ID, p.Severity, p.Tier, p.Title.EN, strings.Join(p.Provider, ","))
	}
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
