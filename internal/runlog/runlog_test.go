package runlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLog(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	l := open(dir, []string{"scan", "--server", "dc1", "--password-stdin"}, now)
	if l.Path == "" || !strings.HasPrefix(filepath.Base(l.Path), "run-"+l.Stamp) {
		t.Fatalf("path %q stamp %q", l.Path, l.Stamp)
	}
	w := l.Writer()
	_, _ = w.Write([]byte("partial"))
	_, _ = w.Write([]byte(" line\nsecond\nthird without newline"))
	l.Printf("note %d", 7) // flushes the partial third line first
	l.Close(3)
	b, err := os.ReadFile(l.Path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"args: scan --server dc1 --password-stdin", "s partial line\n", "s second\n", "s third without newline\n", "s note 7\n", "finished: exit 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("log lacks %q:\n%s", want, got)
		}
	}
	if string(l.Bytes()) != got {
		t.Error("memory mirror differs from the file")
	}
	// Same second, second run: a new file, not a clobbered one.
	l2 := open(dir, nil, now)
	if l2.Path != filepath.Join(dir, "run-"+l.Stamp+"-2.log") {
		t.Errorf("second run went to %q", l2.Path)
	}
	l2.Close(0)
	if b, _ := os.ReadFile(l.Path); !strings.Contains(string(b), "exit 3") {
		t.Error("first log was clobbered")
	}
}

func TestMemoryOnly(t *testing.T) {
	l := Open("", []string{"ui"})
	l.Printf("hello")
	l.Close(0)
	if l.Path != "" || !strings.Contains(string(l.Bytes()), "hello") {
		t.Errorf("path %q bytes %q", l.Path, l.Bytes())
	}
}
