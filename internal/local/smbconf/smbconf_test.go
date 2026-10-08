package smbconf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

const conf = `# Global parameters
[global]
	dns forwarder = 10.0.0.1
	netbios name = DC1
	realm = LAB.EXAMPLE
	server role = active directory domain controller
	Server   Schannel = auto
	reject md5 clients = no
	dsdb:schema update allowed = yes
	idmap config LAB : ldap_user_pass = hunter2
	log level = 1 auth_audit:3 \
	   dsdb_audit:5

[sysvol]
	path = /var/lib/samba/sysvol
	read only = No

[netlogon]
	path = /var/lib/samba/sysvol/lab.example/scripts
	read only = No

[public]
	path = /srv/public
	guest ok = yes
`

const testparmOut = `Load smb config files from /etc/samba/smb.conf
# Global parameters
[global]
	dns forwarder = 10.0.0.1
	netbios name = DC1
	realm = LAB.EXAMPLE
	server role = active directory domain controller
	server schannel = auto
	reject md5 clients = No
	ldap server require strong auth = Yes
	server signing = default
	ntlm auth = ntlmv2-only
	allow dns updates = secure only
	server min protocol = SMB2_02
	tls enabled = Yes
	log level = 1 auth_audit:3 dsdb_audit:5
	idmap config LAB : ldap_user_pass = hunter2
	dsdb:schema update allowed = yes

[sysvol]
	path = /var/lib/samba/sysvol
	read only = No

[netlogon]
	path = /var/lib/samba/sysvol/lab.example/scripts
	read only = No

[public]
	path = /srv/public
	guest ok = Yes
`

func fakeExec(withTestparm bool) Exec {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "samba":
			return []byte("Version 4.21.3-Debian\n"), nil
		case "testparm":
			if withTestparm {
				return []byte(testparmOut), nil
			}
			return nil, errors.New("exec: \"testparm\": executable file not found in $PATH")
		}
		return nil, errors.New("not found")
	}
}

func write(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "smb.conf")
	if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCollectWithTestparm(t *testing.T) {
	p := write(t)
	r, err := Collect(context.Background(), Options{Path: p, Exec: fakeExec(true)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "4.21.3" || r.Source != "testparm" || !strings.Contains(r.Role, "domain controller") {
		t.Errorf("result %+v", r)
	}
	var g snapshot.Object
	for _, o := range r.Objects {
		if o.DN == GlobalDN {
			g = o
		}
	}
	if g.Attr("server schannel") != "auto" || g.Attr("ldap server require strong auth") != "Yes" || g.Attr("dsdb:schema update allowed") != "yes" {
		t.Errorf("global attrs: %v", g.Attrs)
	}
	if g.Attr("idmap config lab : ldap_user_pass") != "<redacted>" {
		t.Errorf("secret not redacted: %q", g.Attr("idmap config lab : ldap_user_pass"))
	}
	if !strings.Contains(strings.Join(g.Attrs["_explicit"], ","), "server schannel") || strings.Contains(strings.Join(g.Attrs["_explicit"], ","), "ntlm auth") {
		t.Errorf("_explicit = %v", g.Attrs["_explicit"])
	}
	if g.Attr("log level") != "1 auth_audit:3 dsdb_audit:5" {
		t.Errorf("log level = %q", g.Attr("log level"))
	}
	names := map[string]bool{}
	for _, o := range r.Objects {
		if o.Class[0] == ClassShare {
			names[o.Attr("name")] = true
		}
	}
	if len(names) != 3 || !names["public"] {
		t.Errorf("shares = %v", names)
	}
	snap := &snapshot.Snapshot{Meta: snapshot.Meta{Provider: "ad", Dialect: "samba"}}
	Augment(snap, r)
	if snap.Meta.Tier != 2 || snap.Meta.Extra["samba_version"] != "4.21.3" || len(snap.Objects) != 5 {
		t.Errorf("augmented meta %+v objects %d", snap.Meta, len(snap.Objects))
	}
}

func TestCollectFileOnly(t *testing.T) {
	p := write(t)
	r, err := Collect(context.Background(), Options{Path: p, Exec: fakeExec(false)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "file" {
		t.Errorf("source %q", r.Source)
	}
	if len(r.Skipped) != 1 || r.Skipped[0].Reason != "error" || r.Skipped[0].Classes[0] != "dirauditorSmbConfDefaults" {
		t.Errorf("skipped = %+v", r.Skipped)
	}
	g := r.Objects[0]
	if g.Attr("server schannel") != "auto" || g.Attr("ntlm auth") != "" || g.Attr("log level") != "1 auth_audit:3 dsdb_audit:5" {
		t.Errorf("file-only attrs: %v", g.Attrs)
	}
}

func TestDetect(t *testing.T) {
	if Detect(write(t)) == "" {
		t.Error("DC config not detected")
	}
	p := filepath.Join(t.TempDir(), "smb.conf")
	os.WriteFile(p, []byte("[global]\nserver role = member server\n"), 0o600)
	if Detect(p) != "" {
		t.Error("member server detected as DC")
	}
	if Detect(filepath.Join(t.TempDir(), "missing")) != "" {
		t.Error("missing file detected")
	}
}

func TestRedact(t *testing.T) {
	cases := map[[2]string]string{
		{"password hash gpg key ids", "ABCDEF0123456789"}: "ABCDEF0123456789",
		{"old password allowed period", "60"}:             "60",
		{"idmap config x : ldap_user_pass", "x"}:          "<redacted>",
		{"vfs module : secret token", "x"}:                "<redacted>",
		{"server schannel", "yes"}:                        "yes",
	}
	for in, want := range cases {
		if got := redact(in[0], in[1]); got != want {
			t.Errorf("redact(%q)=%q want %q", in[0], got, want)
		}
	}
}
