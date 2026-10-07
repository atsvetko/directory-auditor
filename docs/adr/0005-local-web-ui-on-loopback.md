# ADR-0005: The primary UX is a local web wizard on loopback

**Status:** accepted (2026-10-07) · approach §2.1

## Context
Admins asked for a nice UX with a connection wizard; the hard constraints forbid Electron,
WebView2 and any runtime dependency.

## Decision
Launching the binary without arguments starts an HTTP server bound to `127.0.0.1` on a random
port with a one-time token in the URL, opens the default browser, and shows the express path
("Scan now" with detected domain and identity) and a seven-step wizard. Assets are embedded
in the binary; no external resources; strict CSP; `Host` and `Origin` are checked. `--console`
provides the same wizard as numbered prompts; flags provide automation.

## Consequences
- Directory-sourced strings are attacker-controlled: contextual auto-escaping everywhere,
  fuzzing of the renderer with hostile values in CI.
- Loopback HTTP, not self-signed HTTPS (browser warnings teach the wrong habit). Remote use is
  SSH port forwarding.
- EDR "new listener" alerts and PAW restrictions are documented; console mode is first-class.
