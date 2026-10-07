package ldapx

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestSDFlagsControlEncoding(t *testing.T) {
	got := sdFlagsControl(SDFlagsDACL).Encode().Bytes()
	oid := []byte(OIDSDFlags)
	want := append([]byte{0x30, byte(2 + len(oid) + 7), 0x04, byte(len(oid))}, oid...)
	want = append(want, 0x04, 0x05, 0x30, 0x03, 0x02, 0x01, 0x04) // OCTET STRING { SEQUENCE { INTEGER 4 } }
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding\n got % x\nwant % x", got, want)
	}
}

func TestParseRange(t *testing.T) {
	cases := []struct {
		in       string
		name     string
		lo, hi   int
		isRanged bool
	}{
		{"member;range=0-1499", "member", 0, 1499, true},
		{"member;Range=1500-*", "member", 1500, -1, true},
		{"member", "member", 0, 0, false},
		{"member;range=x-1", "member;range=x-1", 0, 0, false},
	}
	for _, c := range cases {
		n, lo, hi, ok := parseRange(c.in)
		if n != c.name || lo != c.lo || hi != c.hi || ok != c.isRanged {
			t.Errorf("parseRange(%q) = %q %d %d %v", c.in, n, lo, hi, ok)
		}
	}
}

func TestThrottle(t *testing.T) {
	c := &Conn{opts: Options{MaxQPS: 20}}
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := c.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 190*time.Millisecond {
		t.Fatalf("5 requests at 20 qps took %v, want ≥200ms", el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.wait(ctx); err == nil {
		t.Fatal("wait ignored cancellation")
	}
}

func TestDialRefusesPlaintext(t *testing.T) {
	if _, err := Dial(context.Background(), Options{Server: "127.0.0.1:1"}); err == nil {
		t.Fatal("plaintext dial accepted")
	}
}
