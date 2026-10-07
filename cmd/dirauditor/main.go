// Command dirauditor is the Directory Auditor entry point.
//
// Run modes (see docs/requirements/approach.md §2):
//
//	dirauditor                 # web wizard on 127.0.0.1 (not implemented yet — prints status)
//	dirauditor scan   ...      # collect a snapshot and analyse it
//	dirauditor analyse FILE    # analyse an existing snapshot
//	dirauditor doctor  ...     # diagnose connectivity: DNS SRV, LDAP, TLS
//	dirauditor manifest        # print every behaviour of this binary
//	dirauditor version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/atsvetko/directory-auditor/internal/app"
	"github.com/atsvetko/directory-auditor/internal/buildinfo"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if len(os.Args) < 2 {
		// Express path (web wizard) is a later milestone; until then explain what exists.
		fmt.Fprintln(os.Stderr, "Directory Auditor "+buildinfo.Version+" — engine skeleton.")
		fmt.Fprintln(os.Stderr, "The web wizard is not implemented yet. Available: scan, analyse, doctor, manifest, version.")
		fmt.Fprintln(os.Stderr, "Run `dirauditor help` for usage.")
		os.Exit(2)
	}

	code := run(ctx, os.Args[1], os.Args[2:])
	os.Exit(code)
}

func run(ctx context.Context, cmd string, args []string) int {
	switch cmd {
	case "version", "--version", "-v":
		fmt.Println(buildinfo.String())
		return 0
	case "manifest":
		app.PrintManifest(os.Stdout)
		return 0
	case "scan":
		return app.Scan(ctx, args, os.Stdout, os.Stderr)
	case "analyse", "analyze":
		return app.Analyse(ctx, args, os.Stdout, os.Stderr)
	case "doctor":
		return app.Doctor(ctx, args, os.Stdout, os.Stderr)
	case "help", "-h", "--help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage(os.Stderr)
		return 2
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `Directory Auditor — read-only security auditor for directory services.

Usage:
  dirauditor scan     --server HOST [--domain DOMAIN] [--packs DIR] [--out DIR] [--insecure-plaintext]
  dirauditor analyse  --snapshot FILE [--packs DIR] [--out DIR]
  dirauditor doctor   --domain DOMAIN [--server HOST]
  dirauditor manifest
  dirauditor version

Every command is read-only. The binary contains no code path that writes to a directory,
to SYSVOL, to DNS or to a registry; see docs/clean-room.md and scripts/readonly-check.sh.
`)
	_ = flag.CommandLine
}
