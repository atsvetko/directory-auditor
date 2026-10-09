// Package web is the local wizard: Connect · Scan · Results in the browser.
// It is a thin front end over the same provider, check and report packages the
// CLI uses — no extra capabilities.
//
// Security model (approach §2.1, §6.1):
//   - listens on 127.0.0.1 only, on a random port;
//   - every API call needs a random one-time token that is only in the launch URL;
//   - the Host header must be the loopback address (blocks DNS rebinding) and
//     POSTs must be JSON from the same origin (blocks cross-site form posts);
//   - strict CSP, no third-party assets, nothing is fetched from the internet;
//   - a password typed into the form lives in this process's memory until the
//     scan finishes and is then cleared; it is never written anywhere.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/atsvetko/directory-auditor/internal/catalogue"
	"github.com/atsvetko/directory-auditor/internal/check"
	"github.com/atsvetko/directory-auditor/internal/doctor"
	"github.com/atsvetko/directory-auditor/internal/local/smbconf"
	"github.com/atsvetko/directory-auditor/internal/packset"
	"github.com/atsvetko/directory-auditor/internal/provider"
	"github.com/atsvetko/directory-auditor/internal/report"
	"github.com/atsvetko/directory-auditor/internal/runlog"
	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

//go:embed static
var static embed.FS

// Options configure the wizard.
type Options struct {
	Checks      packset.Options // which checks run: signed packs and/or built-in preview checks
	OutDir      string
	Version     string
	Demo        []byte // zstd snapshot used by "Try with demo data"
	OpenBrowser bool
	Log         io.Writer
	IdleTimeout time.Duration // stop after this long without any request (0 = 2h)
}

// Server is one wizard session.
type Server struct {
	opts         Options
	token        string
	addr         string
	stop         context.CancelFunc
	mu           sync.Mutex
	target       *provider.Target // set by a successful connect; holds the password until the scan ends
	demo         bool
	conn         connectResp
	providerName string
	job          *job
	last         time.Time
}

type job struct {
	State   string   `json:"state"` // running, done, error, cancelled
	Phase   string   `json:"phase"`
	Percent int      `json:"percent"`
	Log     []string `json:"log"`
	Error   string   `json:"error,omitempty"`

	cancel context.CancelFunc
	result *check.Result
	html   map[string][]byte // lang -> report
	json   []byte
	runlog *runlog.Log // run-<stamp>.log in the output folder (memory only for the demo)
}

// Run serves the wizard until ctx is cancelled, the user clicks Quit, or the
// session is idle for IdleTimeout.
func Run(ctx context.Context, opts Options) error {
	if opts.Log == nil {
		opts.Log = os.Stderr
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 2 * time.Hour
	}
	tok := make([]byte, 24)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("web: cannot listen on 127.0.0.1: %w", err)
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	s := &Server{opts: opts, token: hex.EncodeToString(tok), addr: ln.Addr().String(), stop: stop, last: time.Now()}
	srv := &http.Server{Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}

	url := "http://" + s.addr + "/?t=" + s.token
	fmt.Fprintf(opts.Log, "Directory Auditor %s — wizard running at\n\n  %s\n\nOnly this computer can open it. Press Ctrl+C or click Quit to stop.\n", opts.Version, url)
	if opts.OpenBrowser {
		if err := openBrowser(url); err != nil {
			fmt.Fprintln(opts.Log, "(could not open a browser automatically — copy the address above)")
		}
	}
	go s.idleWatch(ctx)
	go func() {
		<-ctx.Done()
		sh, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(sh)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	s.clearSecret()
	return nil
}

func (s *Server) idleWatch(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			idle := time.Since(s.last) > s.opts.IdleTimeout && (s.job == nil || s.job.State != "running")
			s.mu.Unlock()
			if idle {
				fmt.Fprintln(s.opts.Log, "wizard idle — stopping")
				s.stop()
				return
			}
		}
	}
}

func (s *Server) routes() http.Handler {
	sub, _ := fs.Sub(static, "static")
	files := http.FileServer(http.FS(sub))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenOK(r) {
			http.Error(w, "Open the address printed in the console (it contains a one-time token).", http.StatusForbidden)
			return
		}
		b, _ := static.ReadFile("static/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.Handle("GET /app.js", files)
	mux.Handle("GET /app.css", files)
	api := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if !s.tokenOK(r) {
				writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "missing or wrong session token"})
				return
			}
			if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"ok": false, "error": "JSON only"})
				return
			}
			h(w, r)
		})
	}
	api("GET /api/info", s.info)
	api("GET /api/library", s.library)
	api("GET /api/detect", s.detect)
	api("POST /api/connect", s.connect)
	api("POST /api/scan", s.scan)
	api("GET /api/status", s.status)
	api("POST /api/cancel", s.cancel)
	api("GET /api/result", s.result)
	api("GET /api/report.html", s.reportHTML)
	api("GET /api/report.json", s.reportJSON)
	api("GET /api/run.log", s.runLog)
	api("POST /api/quit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); s.stop() }()
	})
	return s.guard(mux)
}

// guard enforces loopback Host/Origin and sets security headers on every response.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.addr {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != "http://"+s.addr {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		s.mu.Lock()
		s.last = time.Now()
		s.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) tokenOK(r *http.Request) bool {
	got := r.Header.Get("X-DA-Token")
	if got == "" {
		got = r.URL.Query().Get("t")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// library serves the full check catalogue as reference data for the UI's
// Library view: every check with its severity, remediation and framework
// mappings (MITRE ATT&CK, ANSSI). It describes what the product can do and runs
// nothing.
func (s *Server) library(w http.ResponseWriter, _ *http.Request) {
	items, err := catalogue.Library()
	if err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "count": len(items), "items": items})
}

func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	set, err := packset.Load(s.opts.Checks)
	resp := map[string]any{"ok": true, "version": s.opts.Version, "packs": set.FromDir, "packs_dir": s.opts.Checks.PacksDir,
		"preview": set.Preview, "preview_source": set.PreviewSource, "notes": set.Notes, "demo": len(s.opts.Demo) > 0}
	if err != nil {
		resp["packs_error"] = err.Error()
	}
	writeJSON(w, 200, resp)
}

func (s *Server) detect(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, Detect(r.Context()))
}

type connectReq struct {
	Mode       string `json:"mode"` // auto, manual, demo
	Domain     string `json:"domain"`
	Server     string `json:"server"`
	ServerName string `json:"server_name"` // expected DC name when Server is an IP
	User       string `json:"user"`
	Password   string `json:"password"`
	Security   string `json:"security"` // auto, ldaps, starttls, none
	Pin        string `json:"pin"`
	SmbConf    bool   `json:"smbconf"` // include the local Samba DC configuration (when detected)
}

type connectResp struct {
	OK        bool   `json:"ok"`
	Domain    string `json:"domain,omitempty"`
	Server    string `json:"server,omitempty"`
	Identity  string `json:"identity,omitempty"`
	Kind      string `json:"kind,omitempty"` // ad, samba, freeipa, demo
	Provider  string `json:"provider,omitempty"`
	Transport string `json:"transport,omitempty"` // how the session is protected
	Encrypted bool   `json:"encrypted,omitempty"`
	SmbConf   string `json:"smbconf,omitempty"` // local configuration that will be included
	Error     string `json:"error,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	var q connectReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&q); err != nil {
		writeJSON(w, 400, connectResp{Error: "bad request"})
		return
	}
	s.mu.Lock()
	busy := s.job != nil && s.job.State == "running"
	s.mu.Unlock()
	if busy {
		writeJSON(w, 409, connectResp{Error: "a scan is running"})
		return
	}
	if q.Mode == "demo" {
		if len(s.opts.Demo) == 0 {
			writeJSON(w, 200, connectResp{Error: "this build has no demo data"})
			return
		}
		s.setTarget(nil, true, connectResp{OK: true, Domain: "lab.example", Server: "demo snapshot", Identity: "synthetic data", Kind: "demo"})
		writeJSON(w, 200, s.conn)
		return
	}

	t := provider.Target{TLS: q.Security, PinSHA256: q.Pin, InsecurePlaintext: q.Security == "none"}
	if t.TLS == "" || t.TLS == "none" {
		t.TLS = "auto"
	}
	switch q.Mode {
	case "auto":
		d := Detect(r.Context())
		if d.Domain == "" || d.Server == "" {
			writeJSON(w, 200, connectResp{Error: "no domain was detected on this computer", Hint: "choose “Enter domain and credentials”"})
			return
		}
		t.Domain, t.Server = d.Domain, d.Server
	case "manual":
		t.Domain, t.Server, t.BindUser, t.BindPassword = strings.TrimSpace(q.Domain), strings.TrimSpace(q.Server), strings.TrimSpace(q.User), q.Password
		t.ServerName = strings.TrimSpace(q.ServerName)
		if t.Server == "" && t.Domain != "" {
			t.Server = findDC(r.Context(), t.Domain)
		}
		if t.Server == "" {
			writeJSON(w, 200, connectResp{Error: "no domain controller found", Hint: "enter the domain controller name, or check that this computer uses the domain's DNS"})
			return
		}
		if t.BindUser != "" && t.BindPassword == "" {
			writeJSON(w, 200, connectResp{Error: "a password is needed for " + t.BindUser, Hint: "or leave User empty to use your current logon (Kerberos)"})
			return
		}
	default:
		writeJSON(w, 400, connectResp{Error: "unknown mode"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	p, _, err := provider.Pick(ctx, "auto", t)
	if err != nil {
		writeJSON(w, 200, connectResp{Error: err.Error(), Hint: diagnose(ctx, t)})
		return
	}
	res, err := p.Check(ctx, t)
	if err != nil {
		hint := diagnose(ctx, t)
		writeJSON(w, 200, connectResp{Error: err.Error(), Hint: hint})
		return
	}
	resp := connectResp{OK: true, Domain: firstNonEmpty(t.Domain, res.Domain), Server: t.Server, Identity: res.Identity, Kind: res.Dialect, Provider: p.Name(),
		Transport: res.Transport, Encrypted: res.Encrypted}
	if q.SmbConf {
		resp.SmbConf = smbconf.Detect("")
	}
	s.setTarget(&t, false, resp)
	writeJSON(w, 200, resp)
}

func (s *Server) setTarget(t *provider.Target, demo bool, c connectResp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.target != nil {
		s.target.BindPassword = ""
	}
	s.target, s.demo, s.conn = t, demo, c
	s.providerName = c.Provider
}

func (s *Server) clearSecret() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.target != nil {
		s.target.BindPassword = ""
	}
}

// diagnose turns a failed connect into one actionable line using doctor.
func diagnose(ctx context.Context, t provider.Target) string {
	for _, st := range doctor.Run(ctx, t.Domain, t.Server) {
		if !st.OK {
			return st.Name + ": " + st.Cause + " — " + st.Fix
		}
	}
	return "the server answered every diagnostic; check the account name and password, or run `dirauditor doctor`"
}

func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Quick bool `json:"quick"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&q)
	s.mu.Lock()
	if s.job != nil && s.job.State == "running" {
		s.mu.Unlock()
		writeJSON(w, 409, map[string]any{"ok": false, "error": "a scan is already running"})
		return
	}
	if s.target == nil && !s.demo {
		s.mu.Unlock()
		writeJSON(w, 409, map[string]any{"ok": false, "error": "connect first"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{State: "running", Phase: "starting", cancel: cancel}
	s.job = j
	var t provider.Target
	if s.target != nil {
		t = *s.target
	}
	demo, pname, conf := s.demo, s.providerName, s.conn
	s.mu.Unlock()
	go s.runJob(ctx, j, t, demo, q.Quick, pname, conf)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// planSteps is the number of progress messages a collection normally emits;
// it only drives the progress bar.
const planSteps = 11

func (s *Server) runJob(ctx context.Context, j *job, t provider.Target, demo, quick bool, pname string, conf connectResp) {
	defer j.cancel()
	defer s.clearSecret() // the password is not needed after collection
	outDir := s.opts.OutDir
	if demo {
		outDir = "" // nothing from the demo is written to disk
	}
	lg := runlog.Open(outDir, []string{"ui", "mode=" + conf.Kind, "server=" + t.Server, "domain=" + t.Domain, "identity=" + conf.Identity,
		fmt.Sprintf("tier=%d", t.Tier), fmt.Sprintf("quick=%v", quick), "provider=" + pname})
	s.mu.Lock()
	j.runlog = lg
	s.mu.Unlock()
	progress := func(msg string) {
		lg.Printf("%s", msg)
		s.mu.Lock()
		defer s.mu.Unlock()
		j.Log = append(j.Log, msg)
		j.Phase = msg
		if p := len(j.Log) * 90 / planSteps; p < 90 {
			j.Percent = p
		} else {
			j.Percent = 90
		}
	}
	fail := func(state string, err error) {
		lg.Printf("%s: %v", state, err)
		lg.Close(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		j.State, j.Error = state, err.Error()
	}

	var snap *snapshot.Snapshot
	var err error
	if demo {
		progress("reading demo snapshot")
		snap, err = snapshot.Read(bytes.NewReader(s.opts.Demo))
	} else {
		p, ok := provider.Get(pname)
		if !ok {
			p, _ = provider.Get("ad")
		}
		snap, err = p.Collect(ctx, t, progress)
		if err == nil && conf.SmbConf != "" {
			progress("reading local Samba configuration " + conf.SmbConf)
			if r, lerr := smbconf.Collect(ctx, smbconf.Options{Path: conf.SmbConf}); lerr != nil {
				snap.Skipped = append(snap.Skipped, snapshot.Skipped{Query: "smb.conf", Reason: "error", Detail: lerr.Error()})
			} else {
				smbconf.Augment(snap, r)
			}
		}
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fail("cancelled", errors.New("scan cancelled"))
		} else {
			fail("error", err)
		}
		return
	}
	progress("evaluating checks")
	set, err := packset.Load(s.opts.Checks)
	if err != nil {
		fail("error", err)
		return
	}
	for _, n := range set.Notes {
		progress(n)
	}
	res, err := check.EvaluateWith(snap, set.Packs, check.EvalOptions{Quick: quick})
	if err != nil {
		fail("error", err)
		return
	}
	var jb bytes.Buffer
	_ = report.WriteJSON(&jb, res)
	html := map[string][]byte{}
	for _, l := range []string{"en", "ru"} {
		var hb bytes.Buffer
		_ = report.WriteHTML(&hb, res, l)
		html[l] = hb.Bytes()
	}
	c := res.Counts
	lg.Printf("score %d/100 — %d checked, %d passed, %d with findings (%d findings), %d skipped; preview checks %d; %d objects, %d searches, %d LDAP requests, collection %s",
		res.Score, c.Checked, c.Passed, c.Failed, c.Findings, c.Skipped, res.Preview, len(snap.Objects), snap.Meta.QueryCount, snap.Meta.Requests, snap.Meta.Duration)
	for _, sk := range snap.Skipped {
		lg.Printf("not collected: %s (%s) %s", sk.Query, sk.Reason, sk.Detail)
	}
	if !demo && s.opts.OutDir != "" {
		s.save(snap, jb.Bytes(), html["en"], lg.Stamp, progress)
	}
	lg.Close(0)
	s.mu.Lock()
	j.result, j.json, j.html = res, jb.Bytes(), html
	j.State, j.Percent, j.Phase = "done", 100, "done"
	s.mu.Unlock()
}

// save writes snapshot and reports to the output folder, as the CLI does.
func (s *Server) save(snap *snapshot.Snapshot, js, html []byte, stamp string, progress func(string)) {
	if err := os.MkdirAll(s.opts.OutDir, 0o750); err != nil {
		progress("could not create output folder: " + err.Error())
		return
	}
	sp := filepath.Join(s.opts.OutDir, "snapshot-"+stamp+".json.zst")
	if err := snapshot.WriteFile(sp, snap); err == nil {
		progress("saved " + sp)
	} else {
		progress("could not save the snapshot: " + err.Error())
	}
	for name, b := range map[string][]byte{"report-" + stamp + ".json": js, "report-" + stamp + ".html": html} {
		if err := os.WriteFile(filepath.Join(s.opts.OutDir, name), b, 0o640); err != nil {
			progress("could not save " + name + ": " + err.Error())
		}
	}
	progress("saved reports and run-" + stamp + ".log in " + s.opts.OutDir)
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job == nil {
		writeJSON(w, 200, map[string]any{"state": "idle"})
		return
	}
	writeJSON(w, 200, s.job)
}

func (s *Server) cancel(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	if s.job != nil && s.job.State == "running" {
		s.job.cancel()
	}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) done() *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job == nil || s.job.State != "done" {
		return nil
	}
	return s.job
}

func (s *Server) result(w http.ResponseWriter, _ *http.Request) {
	j := s.done()
	if j == nil {
		writeJSON(w, 404, map[string]any{"ok": false, "error": "no finished scan"})
		return
	}
	writeJSON(w, 200, j.result)
}

func (s *Server) reportHTML(w http.ResponseWriter, r *http.Request) {
	j := s.done()
	if j == nil {
		http.Error(w, "no finished scan", 404)
		return
	}
	l := r.URL.Query().Get("lang")
	if l != "ru" {
		l = "en"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="directory-auditor-report.html"`)
	_, _ = w.Write(j.html[l])
}

func (s *Server) reportJSON(w http.ResponseWriter, _ *http.Request) {
	j := s.done()
	if j == nil {
		http.Error(w, "no finished scan", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="directory-auditor-report.json"`)
	_, _ = w.Write(j.json)
}

// runLog serves the current or last job's run log, for bug reports.
func (s *Server) runLog(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	j := s.job
	s.mu.Unlock()
	if j == nil || j.runlog == nil {
		http.Error(w, "no scan yet", 404)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="directory-auditor-run.log"`)
	_, _ = w.Write(j.runlog.Bytes())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}
