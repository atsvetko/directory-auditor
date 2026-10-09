# labctl — Directory Auditor lab control panel

A single tool you run on the **Hyper-V host** that gives you a local web panel to:

1. **Build** dirauditor from a local clone (any branch, tag or commit — `main` by default);
2. **Create and provision** the lab VMs from ISOs you supply — Windows AD DCs
   and Samba-based **Альт Домен** DCs — on an isolated switch;
3. **Deploy + scan** each target with the freshly built binary and check the
   findings against the `*-expect.yaml` files, with a live log.

It is a **separate** tool from the read-only auditor and is never linked into
it, so the auditor's read-only guarantee is untouched. The lab it builds is
deliberately weak and must stay on an isolated network.

## Prerequisites (on the host)

- Windows with **Hyper-V** and PowerShell, run as Administrator.
- **Go** (the version in `go.mod`) and **git** on `PATH`.
- A clone of this repo (`repo_dir` in the config).
- Optional: **oscdimg** (Windows ADK) to auto-answer Windows installs; **ssh/scp**
  (built into Windows) for the Альт Домен target.
- Install **ISOs** you provide for each OS (Windows Server eval, Альт Домен).

## Setup

```powershell
cd <repo>\cmd\labctl
copy lab.example.yaml lab.yaml      # then edit, or edit it in the UI
go run .                            # or: go build -o labctl.exe . ; .\labctl.exe
```

It prints a `http://127.0.0.1:<port>/?t=<token>` URL (loopback + one-time token)
and opens it. The panel has four parts:

1. **Credentials** — the admin password (for provisioning) and the ordinary
   audit account (for scans). Held in memory for the session only; never written
   to `lab.yaml`.
2. **Build the tool** — fetches and builds the chosen ref into `work_dir\bin`
   (Windows + Linux binaries).
3. **Lab** — one row per machine with its VM state, whether a `vuln-baseline`
   checkpoint exists, the last scan result, and per-machine actions. **Edit
   config** adds/removes machines and sets names, domains, IPs, ISOs and sizes.
4. **Log** — live output of whatever action is running.

## The workflow

Per machine, once:

1. **create** — makes the VM from its ISO on the lab switch (with an
   autounattend answer file when oscdimg is present; otherwise install the OS
   through the Hyper-V console, then continue).
2. **provision** — promotes it to a DC and seeds the weak fixtures
   (`tools/lab/windows/*.ps1` over PowerShell Direct for Windows;
   `tools/lab/samba/*.sh` over SSH for Альт Домен).
3. **snapshot** — takes the `vuln-baseline` checkpoint.

Then, any time (nightly or on demand):

- **Reset + scan all** — restores every machine to its baseline, deploys the
  built binary, scans it, and runs `verify` against its expect file. Or use the
  per-row **reset** / **scan** buttons.

## Security

- Isolated **internal** Hyper-V switch only — no route to your real network.
- Every lab script refuses unless `DIRAUDITOR_LAB=1` (labctl sets it for the
  provisioning it drives).
- Credentials live in memory for the session, not in the config file.
- The panel listens on `127.0.0.1` with a one-time token, like the auditor's own
  wizard.

## Honest limitations (v1)

- The Hyper-V / PowerShell / SSH orchestration is written but was **not executed
  in this environment** (no Windows/Hyper-V here); the first host run is where it
  is validated, like the lab scripts themselves.
- Windows auto-install needs the ADK's `oscdimg`; without it, install the OS once
  through the console, then use **provision**. Альт Домен installs are interactive
  in this version (its preseed varies by build) — labctl takes over at
  **provision** over SSH (key-based auth to `root@<ip>`).
- One action runs at a time (the lab VMs are shared hardware).
