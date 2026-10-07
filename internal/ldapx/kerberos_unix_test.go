//go:build !windows

package ldapx

import (
	"fmt"
	"os"
	"testing"
)

func TestCCachePath(t *testing.T) {
	cases := map[string]string{
		"":                  fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid()),
		"FILE:/tmp/x.cc":    "/tmp/x.cc",
		"/var/run/krb5cc_1": "/var/run/krb5cc_1",
	}
	for env, want := range cases {
		t.Setenv("KRB5CCNAME", env)
		got, err := ccachePath()
		if err != nil || got != want {
			t.Errorf("KRB5CCNAME=%q: got %q, %v; want %q", env, got, err, want)
		}
	}
	for _, env := range []string{"KCM:", "KEYRING:persistent:1000", "DIR:/run/user/1000/krb5cc"} {
		t.Setenv("KRB5CCNAME", env)
		if _, err := ccachePath(); err == nil {
			t.Errorf("KRB5CCNAME=%q accepted; static binary cannot read it", env)
		}
	}
}

func TestKerberosRefusesIP(t *testing.T) {
	c := &Conn{opts: Options{Server: "10.0.0.5:636"}}
	if _, err := c.BindCurrentUser(); err == nil {
		t.Fatal("Kerberos bind to an IP address must be refused with a hint")
	}
}
