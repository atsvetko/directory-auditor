package web

import (
	"github.com/atsvetko/directory-auditor/internal/local/smbconf"

	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Detection is what the Connect step pre-fills.
type Detection struct {
	Domain   string `json:"domain,omitempty"`
	Server   string `json:"server,omitempty"`
	Identity string `json:"identity,omitempty"`
	Kerberos bool   `json:"kerberos"` // a current-logon Kerberos bind is plausible
	Source   string `json:"source,omitempty"`
	// SmbConf is the readable Samba AD DC configuration on this machine, if any.
	SmbConf string `json:"smbconf,omitempty"`
}

// Detect finds the domain this computer belongs to and a DC for it, using only
// local configuration and DNS — no directory traffic.
func Detect(ctx context.Context) Detection {
	var d Detection
	if u, err := user.Current(); err == nil {
		d.Identity = u.Username
	}
	switch runtime.GOOS {
	case "windows":
		// Set by Windows for domain logons only.
		if dom := os.Getenv("USERDNSDOMAIN"); dom != "" {
			d.Domain, d.Kerberos, d.Source = strings.ToLower(dom), true, "logon session"
		}
	default:
		if realm := krb5DefaultRealm(krb5Conf()); realm != "" {
			d.Domain, d.Source = strings.ToLower(realm), "krb5.conf"
		} else if s := resolvSearch("/etc/resolv.conf"); s != "" {
			d.Domain, d.Source = s, "resolv.conf"
		}
		if p := os.Getenv("KRB5CCNAME"); p == "" || strings.HasPrefix(p, "FILE:") || strings.HasPrefix(p, "/") {
			path := strings.TrimPrefix(p, "FILE:")
			if path == "" {
				path = "/tmp/krb5cc_" + uidString()
			}
			if _, err := os.Stat(path); err == nil {
				d.Kerberos = true
			}
		}
	}
	if d.Domain != "" {
		d.Server = findDC(ctx, d.Domain)
	}
	d.SmbConf = smbconf.Detect("")
	if d.Server == "" && d.SmbConf != "" {
		// On the DC itself the DC is this host.
		if h, err := os.Hostname(); err == nil {
			d.Server = h
		}
	}
	return d
}

// findDC returns the first DC from DNS SRV, preferring the DC-specific record.
func findDC(ctx context.Context, domain string) string {
	r := &net.Resolver{}
	for _, name := range []string{"_ldap._tcp.dc._msdcs." + domain, "_ldap._tcp." + domain} {
		c, cancel := context.WithTimeout(ctx, 4*time.Second)
		_, addrs, err := r.LookupSRV(c, "", "", name)
		cancel()
		if err != nil || len(addrs) == 0 {
			continue
		}
		sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].Priority < addrs[j].Priority })
		return strings.TrimSuffix(addrs[0].Target, ".")
	}
	return ""
}

func krb5Conf() string {
	if p := os.Getenv("KRB5_CONFIG"); p != "" {
		return p
	}
	return "/etc/krb5.conf"
}

func krb5DefaultRealm(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	inLib := false
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "[") {
			inLib = strings.EqualFold(l, "[libdefaults]")
			continue
		}
		if inLib && strings.HasPrefix(l, "default_realm") {
			if kv := strings.SplitN(l, "=", 2); len(kv) == 2 {
				return strings.TrimSpace(kv[1])
			}
		}
	}
	return ""
}

func resolvSearch(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && (fields[0] == "search" || fields[0] == "domain") {
			return strings.ToLower(fields[1])
		}
	}
	return ""
}

func uidString() string {
	if u, err := user.Current(); err == nil {
		return u.Uid
	}
	return ""
}

// openBrowser asks the OS to open the wizard URL in the default browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return os.ErrNotExist // headless: the URL is printed instead
		}
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
