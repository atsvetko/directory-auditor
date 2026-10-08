// Command dirauditor is the Directory Auditor entry point.
//
// Run modes (see docs/requirements/approach.md §2):
//
//	dirauditor                 # web wizard on 127.0.0.1 (opens the browser)
//	dirauditor ui      ...     # the same, with options (--no-browser, --packs, --out)
//	dirauditor scan   ...      # collect a snapshot and analyse it
//	dirauditor analyse FILE    # analyse an existing snapshot
//	dirauditor doctor  ...     # diagnose connectivity: DNS SRV, LDAP, TLS
//	dirauditor manifest        # print every behaviour of this binary
//	dirauditor version
//
// Samba before 4.24.0 writes the serial of its self-generated TLS certificate
// as a host-endian uint32 of time(NULL) (source4/lib/tls/tlscert.c; 4.24.0
// switched to PUSH_BE_U64), so on x86 the DER INTEGER is negative about half
// the time, and Go 1.23+ refuses such certificates ("x509: negative serial
// number"). A negative serial is an encoding defect, not a trust decision —
// chain verification and --pin still apply — so this binary accepts it.
//
//go:debug x509negativeserial=1
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
		// Express path: double-click → local wizard in the browser.
		os.Exit(app.Wizard(ctx, nil, os.Stderr))
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
		return app.Manifest(args, os.Stdout)
	case "ui", "wizard":
		return app.Wizard(ctx, args, os.Stderr)
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
  dirauditor                                   # start the wizard in your browser (double-click)
  dirauditor ui       [--no-browser] [--packs DIR] [--out DIR]
  dirauditor scan     --server HOST [--domain DOMAIN] [--packs DIR] [--out DIR] [--insecure-plaintext]
                      [--smbconf /etc/samba/smb.conf | --local]   # on a Samba DC: include its configuration
  dirauditor scan     --smbconf /etc/samba/smb.conf              # configuration-only audit, no LDAP
  dirauditor analyse  --snapshot FILE [--packs DIR] [--out DIR]
  dirauditor doctor   --domain DOMAIN [--server HOST]
  dirauditor manifest [--queries]   # behaviours; --queries lists every LDAP search
  dirauditor version

Every command is read-only. The binary contains no code path that writes to a directory,
to SYSVOL, to DNS or to a registry; see docs/clean-room.md and scripts/readonly-check.sh.
`)
	_ = flag.CommandLine
}
