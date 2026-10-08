package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/atsvetko/directory-auditor/internal/catalogue"
	"github.com/atsvetko/directory-auditor/internal/demo"
	"github.com/atsvetko/directory-auditor/internal/packset"
	_ "github.com/atsvetko/directory-auditor/internal/provider/ad"
)

func start(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s := &Server{opts: Options{Checks: packset.Options{PacksDir: "../../testdata/packs", AllowUnsigned: true}, Demo: demo.Snapshot, Log: io.Discard}, token: "tok123", last: time.Now()}
	_, s.stop = context.WithCancel(context.Background())
	ts := httptest.NewUnstartedServer(nil)
	s.addr = ts.Listener.Addr().String()
	ts.Config.Handler = s.routes()
	ts.Start()
	t.Cleanup(ts.Close)
	return s, ts
}

func do(t *testing.T, ts *httptest.Server, method, path, body string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestGuards(t *testing.T) {
	_, ts := start(t)
	tok := map[string]string{"X-DA-Token": "tok123"}
	cases := []struct {
		name, method, path, body string
		hdr                      map[string]string
		want                     int
	}{
		{"page without token", "GET", "/", "", nil, 403},
		{"page with token", "GET", "/?t=tok123", "", nil, 200},
		{"api without token", "GET", "/api/detect", "", nil, 403},
		{"api wrong token", "GET", "/api/detect", "", map[string]string{"X-DA-Token": "nope"}, 403},
		{"dns rebinding host", "GET", "/?t=tok123", "", map[string]string{"Host": "attacker.example"}, 403},
		{"cross-site origin", "POST", "/api/connect", `{"mode":"demo"}`, map[string]string{"X-DA-Token": "tok123", "Content-Type": "application/json", "Origin": "http://attacker.example"}, 403},
		{"form post", "POST", "/api/connect", "mode=demo", map[string]string{"X-DA-Token": "tok123", "Content-Type": "application/x-www-form-urlencoded"}, 415},
		{"static needs no token", "GET", "/app.js", "", nil, 200},
		{"result before scan", "GET", "/api/result", "", tok, 404},
	}
	for _, c := range cases {
		if got, body := do(t, ts, c.method, c.path, c.body, c.hdr); got != c.want {
			t.Errorf("%s: %d, want %d (%s)", c.name, got, c.want, body)
		}
	}
	req, _ := http.NewRequest("GET", ts.URL+"/?t=tok123", nil)
	resp, _ := ts.Client().Do(req)
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP = %q", csp)
	}
}

func TestDemoFlow(t *testing.T) {
	_, ts := start(t)
	h := map[string]string{"X-DA-Token": "tok123", "Content-Type": "application/json"}
	if code, body := do(t, ts, "POST", "/api/connect", `{"mode":"demo"}`, h); code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("connect: %d %s", code, body)
	}
	if code, body := do(t, ts, "POST", "/api/scan", `{"quick":false}`, h); code != 200 {
		t.Fatalf("scan: %d %s", code, body)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body := do(t, ts, "GET", "/api/status", "", h)
		if strings.Contains(body, `"state":"done"`) {
			break
		}
		if strings.Contains(body, `"state":"error"`) || time.Now().After(deadline) {
			t.Fatalf("status: %s", body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, body := do(t, ts, "GET", "/api/result", "", h)
	var res struct {
		Inventory struct {
			Tier0 []struct{ DN, Reason string } `json:"tier0"`
		} `json:"inventory"`
		Checks []struct {
			ID      string
			Status  string
			Preview bool
		} `json:"checks"`
		Unsigned bool `json:"unsigned_packs"`
		Preview  int  `json:"preview_checks"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	builtIn, err := catalogue.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	// One unsigned fixture pack (development mode) plus every built-in preview check.
	if len(res.Inventory.Tier0) != 9 || len(res.Checks) != 1+len(builtIn) || res.Preview != len(builtIn) || !res.Unsigned {
		t.Errorf("tier0 %d, checks %d, preview %d (want %d), unsigned %v", len(res.Inventory.Tier0), len(res.Checks), res.Preview, len(builtIn), res.Unsigned)
	}
	for _, c := range res.Checks {
		if c.Preview != strings.HasPrefix(c.ID, "DSA-") {
			t.Errorf("%s: preview=%v", c.ID, c.Preview)
		}
	}
	// /api/info tells the Connect page what will run.
	if _, body := do(t, ts, "GET", "/api/info", "", h); !strings.Contains(body, `"preview":`+itoa(len(builtIn))) || !strings.Contains(body, `"packs":1`) {
		t.Errorf("info: %s", body)
	}
	if code, body := do(t, ts, "GET", "/api/report.html?lang=ru&t=tok123", "", nil); code != 200 || !strings.Contains(body, "lang=\"ru\"") {
		t.Errorf("report download: %d", code)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestNoPreview(t *testing.T) {
	s, ts := start(t)
	s.opts.Checks.NoPreview = true
	h := map[string]string{"X-DA-Token": "tok123", "Content-Type": "application/json"}
	if _, body := do(t, ts, "GET", "/api/info", "", h); !strings.Contains(body, `"preview":0`) || !strings.Contains(body, `"packs":1`) {
		t.Errorf("info: %s", body)
	}
}

func TestManualConnectNeedsPassword(t *testing.T) {
	_, ts := start(t)
	h := map[string]string{"X-DA-Token": "tok123", "Content-Type": "application/json"}
	_, body := do(t, ts, "POST", "/api/connect", `{"mode":"manual","domain":"x.invalid","server":"dc.x.invalid","user":"a@x.invalid"}`, h)
	if !strings.Contains(body, "password is needed") {
		t.Errorf("got %s", body)
	}
}

func TestKrb5DefaultRealm(t *testing.T) {
	p := t.TempDir() + "/krb5.conf"
	conf := "[logging]\n default = x\n[libdefaults]\n  dns_lookup_realm = false\n  default_realm = CORP.EXAMPLE.COM\n[realms]\n"
	if err := writeFile(p, conf); err != nil {
		t.Fatal(err)
	}
	if got := krb5DefaultRealm(p); got != "CORP.EXAMPLE.COM" {
		t.Errorf("realm = %q", got)
	}
}
