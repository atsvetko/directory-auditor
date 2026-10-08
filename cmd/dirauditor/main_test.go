package main

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// A certificate with a negative serial number, as Samba before 4.24.0 produces
// about half the time (host-endian uint32 serial). The go:debug directive in
// main.go must keep such certificates parseable.
const negativeSerialPEM = `-----BEGIN CERTIFICATE-----
MIIBeDCCAR2gAwIBAgIEoDxWLjAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA5kYy5s
YWIuZXhhbXBsZTAeFw0yNjEwMDgxMTMzNTNaFw0yNjEwMDkxMTMzNTNaMBkxFzAV
BgNVBAMMDmRjLmxhYi5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
10eRyL6QQiefm+Di/U/jR8A+bPHNzvKvvVRigOfoKobZ9UJb179sARPsCdKxtjiZ
47y6r67sQLWko/qmNXdda6NTMFEwHQYDVR0OBBYEFBYGhdU8nhZ/YKK+BKbhTAu9
a20RMB8GA1UdIwQYMBaAFBYGhdU8nhZ/YKK+BKbhTAu9a20RMA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANi7nsMJ1dicy0+xYgpPoDvYgteEpr1q
IC2mKEhjD/QuAiEAt5TnLv8K4428v+LCFnBW6unKv2BDmuEzHWtUXAIigho=
-----END CERTIFICATE-----`

func TestNegativeSerialAccepted(t *testing.T) {
	block, _ := pem.Decode([]byte(negativeSerialPEM))
	if block == nil {
		t.Fatal("bad fixture")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Samba-style certificate rejected: %v (is the //go:debug x509negativeserial=1 directive still in main.go?)", err)
	}
	if c.SerialNumber.Sign() >= 0 {
		t.Fatalf("fixture serial is not negative: %s", c.SerialNumber)
	}
}
