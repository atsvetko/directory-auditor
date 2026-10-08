// Package smbconf reads the configuration of a Samba AD DC on the machine the
// auditor runs on (tier 2: this needs local read access to smb.conf, which on a
// DC means root or a backup operator). It is the only local collector.
//
// What it runs and reads, so the manifest can say so:
//   - `testparm -s -v --suppress-prompt <smb.conf>` — Samba's own parser; prints
//     every parameter with its effective value, defaults included. Read-only.
//   - the smb.conf file itself — to know which parameters are set explicitly.
//   - `samba -V` (or `smbd -V`) — the running version, which decides defaults.
//
// Nothing is written. Values whose parameter name suggests a secret are redacted
// before they enter the snapshot.
package smbconf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// DNs and object classes of the synthetic objects this collector adds.
const (
	GlobalDN    = "cn=global,cn=smb.conf,cn=dirauditor"
	SharesBase  = "cn=shares,cn=smb.conf,cn=dirauditor"
	VersionDN   = "cn=samba,cn=dirauditor"
	ClassGlobal = "dirauditorSmbConf"
	ClassShare  = "dirauditorSmbShare"
	ClassSamba  = "dirauditorSamba"
	DefaultPath = "/etc/samba/smb.conf"
)

// Exec runs a command and returns its stdout. Tests substitute it.
type Exec func(ctx context.Context, name string, args ...string) ([]byte, error)

// Options control the collection.
type Options struct {
	Path string // smb.conf path; "" = DefaultPath
	Exec Exec   // nil = os/exec with a 20 s timeout
}

// Result is what Collect adds to a snapshot.
type Result struct {
	Objects []snapshot.Object
	Skipped []snapshot.Skipped
	Version string // Samba version, "" when unknown
	Source  string // "testparm" (effective values) or "file" (explicit values only)
	Role    string // server role as configured
}

// Detect reports the smb.conf path when this machine looks like a Samba AD DC
// whose configuration the current user can read; "" otherwise.
func Detect(path string) string {
	if path == "" {
		path = DefaultPath
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sections, err := parseINI(f)
	if err != nil {
		return ""
	}
	role := strings.ToLower(sections["global"]["server role"])
	if strings.Contains(role, "domain controller") || strings.Contains(role, "dc") {
		return path
	}
	return ""
}

// Collect reads the configuration. It never fails hard on a missing tool: what
// could not be read is recorded in Result.Skipped.
func Collect(ctx context.Context, o Options) (*Result, error) {
	if o.Path == "" {
		o.Path = DefaultPath
	}
	if o.Exec == nil {
		o.Exec = defaultExec
	}
	res := &Result{}

	// 1. Explicit settings from the file (always).
	f, err := os.Open(o.Path)
	if err != nil {
		return nil, fmt.Errorf("smbconf: %w", err)
	}
	explicit, err := parseINI(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("smbconf: parse %s: %w", o.Path, err)
	}
	res.Role = explicit["global"]["server role"]

	// 2. Version.
	for _, bin := range []string{"samba", "smbd"} {
		out, err := o.Exec(ctx, bin, "-V")
		if err != nil {
			continue
		}
		if v := parseVersion(string(out)); v != "" {
			res.Version = v
			break
		}
	}
	if res.Version == "" {
		res.Skipped = append(res.Skipped, snapshot.Skipped{Query: "samba-version", Reason: "error",
			Detail: "neither `samba -V` nor `smbd -V` answered; defaults that depend on the version are treated as unknown"})
	}

	// 3. Effective values via testparm; fall back to the file alone.
	effective := explicit
	res.Source = "file"
	if out, err := o.Exec(ctx, "testparm", "-s", "-v", "--suppress-prompt", o.Path); err == nil {
		if parsed, perr := parseINI(strings.NewReader(string(out))); perr == nil && len(parsed["global"]) > 0 {
			effective = parsed
			res.Source = "testparm"
		}
	} else {
		res.Skipped = append(res.Skipped, snapshot.Skipped{Query: "smb.conf-effective", Reason: "error",
			Detail:  "testparm is not available (" + err.Error() + "); only explicitly set parameters are known, defaults are not expanded",
			Classes: []string{"dirauditorSmbConfDefaults"}})
	}

	// Objects.
	global := snapshot.Object{DN: GlobalDN, Class: []string{ClassGlobal}, Attrs: map[string][]string{
		"objectClass": {ClassGlobal}, "_path": {o.Path}, "_source": {res.Source},
	}}
	var explicitNames []string
	for k := range explicit["global"] {
		explicitNames = append(explicitNames, k)
	}
	sort.Strings(explicitNames)
	global.Attrs["_explicit"] = explicitNames
	for k, v := range effective["global"] {
		global.Attrs[k] = []string{redact(k, v)}
	}
	// Parametric options (dsdb:…, kdc:…) are only printed by testparm when set;
	// make sure explicit ones are present even when testparm dropped them.
	for k, v := range explicit["global"] {
		if _, ok := global.Attrs[k]; !ok {
			global.Attrs[k] = []string{redact(k, v)}
		}
	}
	res.Objects = append(res.Objects, global)

	var shares []string
	for name := range effective {
		if name != "global" {
			shares = append(shares, name)
		}
	}
	sort.Strings(shares)
	for _, name := range shares {
		o := snapshot.Object{DN: "cn=" + name + "," + SharesBase, Class: []string{ClassShare},
			Attrs: map[string][]string{"objectClass": {ClassShare}, "name": {name}}}
		for k, v := range effective[name] {
			o.Attrs[k] = []string{redact(k, v)}
		}
		res.Objects = append(res.Objects, o)
	}
	ver := snapshot.Object{DN: VersionDN, Class: []string{ClassSamba}, Attrs: map[string][]string{
		"objectClass": {ClassSamba}, "version": {res.Version}, "smbconf": {o.Path}, "role": {res.Role}}}
	res.Objects = append(res.Objects, ver)
	return res, nil
}

// Augment adds the local configuration to a snapshot collected from the
// directory (or to an empty one for a configuration-only audit) and raises the
// snapshot's tier to 2, since local DC configuration is administrator-level data.
func Augment(snap *snapshot.Snapshot, r *Result) {
	snap.Objects = append(snap.Objects, r.Objects...)
	snap.Skipped = append(snap.Skipped, r.Skipped...)
	if snap.Meta.Tier < 2 {
		snap.Meta.Tier = 2
	}
	if snap.Meta.Dialect == "" {
		snap.Meta.Dialect = "samba"
	}
	if snap.Meta.Provider == "" {
		snap.Meta.Provider = "ad"
	}
	if snap.Meta.Extra == nil {
		snap.Meta.Extra = map[string]string{}
	}
	snap.Meta.Extra["smbconf"] = r.Objects[0].Attr("_path")
	snap.Meta.Extra["smbconf_source"] = r.Source
	if r.Version != "" {
		snap.Meta.Extra["samba_version"] = r.Version
	}
}

var versionRe = regexp.MustCompile(`(?i)version\s+(\d+\.\d+\.\d+)`)

func parseVersion(s string) string {
	if m := versionRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// parseINI reads smb.conf / testparm output: [section] headers, "key = value"
// lines, ';' and '#' comments, '\' line continuations. Keys are lower-cased
// with runs of blanks collapsed, as Samba itself matches them. Later values win.
// `include =` and `config file =` directives are recorded, not followed.
func parseINI(r interface{ Read([]byte) (int, error) }) (map[string]map[string]string, error) {
	out := map[string]map[string]string{"global": {}}
	section := "global"
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	var pending string
	for sc.Scan() {
		line := sc.Text()
		if pending != "" {
			line = pending + strings.TrimSpace(line)
			pending = ""
		}
		if strings.HasSuffix(line, `\`) {
			pending = strings.TrimSuffix(line, `\`)
			continue
		}
		t := strings.TrimSpace(line)
		if t == "" || t[0] == ';' || t[0] == '#' {
			continue
		}
		if t[0] == '[' {
			end := strings.IndexByte(t, ']')
			if end < 0 {
				return nil, errors.New("unterminated section header: " + t)
			}
			section = strings.ToLower(strings.TrimSpace(t[1:end]))
			if _, ok := out[section]; !ok {
				out[section] = map[string]string{}
			}
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq < 0 {
			continue
		}
		key := normKey(t[:eq])
		val := strings.TrimSpace(t[eq+1:])
		out[section][key] = val
	}
	return out, sc.Err()
}

func normKey(k string) string {
	return strings.Join(strings.Fields(strings.ToLower(k)), " ")
}

// redact hides values of parameters whose names denote secrets. Samba keeps
// real secrets in secrets.tdb, but third-party modules and parametric options
// can put passwords in smb.conf; a report must never carry one.
func redact(key, val string) string {
	k := strings.ToLower(key)
	for _, safe := range []string{"password hash gpg key ids", "password hash userpassword schemes", "old password allowed period",
		"password server", "smb passwd file", "passwd program", "passwd chat", "passwd chat debug", "passwd chat timeout",
		"unix password sync", "pam password change", "encrypt passwords", "passdb backend", "passdb expand explicit",
		"ldap passwd sync", "min password length", "check password script", "password level", "password hash"} {
		if k == safe {
			return val
		}
	}
	if strings.Contains(k, "password") || strings.Contains(k, "passwd") || strings.Contains(k, "secret") ||
		strings.HasSuffix(k, "_pass") || strings.HasSuffix(k, " pass") || strings.HasSuffix(k, ":pass") {
		if val == "" {
			return ""
		}
		return "<redacted>"
	}
	return val
}

func defaultExec(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd.Output()
}
