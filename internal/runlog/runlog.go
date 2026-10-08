// Package runlog writes run-<stamp>.log into the output folder: what version
// ran, with which arguments, every progress line with a timestamp, the notes
// and errors the user saw, and how it ended. A bug report with this file
// needs no second round-trip. It never contains credentials: passwords are
// read from the terminal or stdin, not from arguments, and nothing echoes them.
package runlog

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/atsvetko/directory-auditor/internal/buildinfo"
)

// Log is one run. Lines are mirrored in memory (Bytes) so the wizard can
// offer the log for download even when the folder is not writable.
type Log struct {
	mu    sync.Mutex
	f     *os.File
	mem   bytes.Buffer
	start time.Time
	Stamp string // UTC yyyymmdd-hhmmss, shared with the snapshot and report names
	Path  string // "" when the folder could not be used
	line  []byte // partial line from Writer
}

// Open creates the output folder and run-<stamp>.log in it. A folder that
// cannot be written is not fatal: the log then lives in memory only and Path
// is empty. args are logged as given (they never carry a password).
func Open(outDir string, args []string) *Log { return open(outDir, args, time.Now()) }

func open(outDir string, args []string, now time.Time) *Log {
	l := &Log{start: now, Stamp: now.UTC().Format("20060102-150405")}
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o750); err == nil {
			for i := 0; i < 10; i++ { // a second run in the same second gets -2, -3, …
				suffix := ""
				if i > 0 {
					suffix = fmt.Sprintf("-%d", i+1)
				}
				p := filepath.Join(outDir, "run-"+l.Stamp+suffix+".log")
				if f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640); err == nil {
					l.f, l.Path = f, p
					break
				} else if !os.IsExist(err) {
					break
				}
			}
		}
	}
	host, _ := os.Hostname()
	l.raw(fmt.Sprintf("%s\n%s/%s %s · host %s · started %s (%s)\nargs: %s\n",
		buildinfo.String(), runtime.GOOS, runtime.GOARCH, runtime.Version(), host,
		now.UTC().Format(time.RFC3339), now.Format("2006-01-02 15:04:05 MST"), strings.Join(args, " ")))
	return l
}

// Printf adds one timestamped line.
func (l *Log) Printf(format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushPartial()
	l.raw(l.prefix() + fmt.Sprintf(format, a...) + "\n")
}

// Writer returns an io.Writer that timestamps every line written to it; use
// it in an io.MultiWriter so console output is mirrored into the log.
func (l *Log) Writer() io.Writer { return writer{l} }

type writer struct{ l *Log }

func (w writer) Write(p []byte) (int, error) {
	l := w.l
	l.mu.Lock()
	defer l.mu.Unlock()
	rest := p
	for {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			l.line = append(l.line, rest...)
			break
		}
		l.line = append(l.line, rest[:i]...)
		l.raw(l.prefix() + string(l.line) + "\n")
		l.line = l.line[:0]
		rest = rest[i+1:]
	}
	return len(p), nil
}

// Close writes the closing line and closes the file.
func (l *Log) Close(exitCode int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushPartial()
	l.raw(l.prefix() + fmt.Sprintf("finished: exit %d after %s\n", exitCode, time.Since(l.start).Round(time.Millisecond)))
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}

// Bytes returns the whole log so far.
func (l *Log) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.mem.Bytes()...)
}

func (l *Log) prefix() string { return fmt.Sprintf("+%8.3fs ", time.Since(l.start).Seconds()) }

func (l *Log) flushPartial() {
	if len(l.line) > 0 {
		l.raw(l.prefix() + string(l.line) + "\n")
		l.line = l.line[:0]
	}
}

func (l *Log) raw(s string) {
	l.mem.WriteString(s)
	if l.f != nil {
		_, _ = l.f.WriteString(s)
	}
}
