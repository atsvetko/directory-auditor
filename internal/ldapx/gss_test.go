package ldapx

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

// xorContext is a stand-in security context for the framing tests: tokens
// are a one-byte flag plus the data XORed with a key, so framing bugs show
// up as garbage rather than being masked by real crypto.
type xorContext struct{ key byte }

func (x xorContext) Step([]byte) ([]byte, bool, error) { return nil, true, nil }
func (x xorContext) Wrap(d []byte, conf bool) ([]byte, error) {
	out := make([]byte, 1+len(d))
	if conf {
		out[0] = 1
	}
	for i, b := range d {
		out[i+1] = b ^ x.key
	}
	return out, nil
}
func (x xorContext) Unwrap(t []byte) ([]byte, bool, error) {
	if len(t) == 0 {
		return nil, false, errors.New("empty")
	}
	out := make([]byte, len(t)-1)
	for i, b := range t[1:] {
		out[i] = b ^ x.key
	}
	return out, t[0] == 1, nil
}
func (x xorContext) Identity() string { return "x" }
func (x xorContext) Close() error     { return nil }

// frame writes one protected buffer the way the server would.
func frame(ctx gssContext, data []byte) []byte {
	tok, _ := ctx.Wrap(data, true)
	out := make([]byte, 4+len(tok))
	binary.BigEndian.PutUint32(out, uint32(len(tok)))
	copy(out[4:], tok)
	return out
}

func TestSecConnArmWhileReaderBlocked(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	sc := &secConn{Conn: client}
	ctx := xorContext{key: 0x5a}

	// Plain phase: bytes pass through untouched.
	go func() { _, _ = server.Write([]byte("plain-bind-response")) }()
	buf := make([]byte, 64)
	n, err := sc.Read(buf)
	if err != nil || string(buf[:n]) != "plain-bind-response" {
		t.Fatalf("plain read: %q %v", buf[:n], err)
	}

	// The reader goroutine blocks in Read before the bind completes…
	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, 1) // ber.ReadPacket reads a byte at a time
		var all []byte
		for len(all) < len("sealed search result") {
			n, err := sc.Read(b)
			if err != nil {
				got <- nil
				return
			}
			all = append(all, b[:n]...)
		}
		got <- all
	}()
	time.Sleep(20 * time.Millisecond)
	// …then the bind finishes and the layer is armed; the next server bytes
	// are a protected buffer, delivered in two TCP segments to exercise
	// the partial-prefix path.
	sc.arm(ctx, true, 65536)
	fr := frame(ctx, []byte("sealed search result"))
	go func() {
		_, _ = server.Write(fr[:3])
		time.Sleep(10 * time.Millisecond)
		_, _ = server.Write(fr[3:])
	}()
	select {
	case all := <-got:
		if string(all) != "sealed search result" {
			t.Fatalf("got %q", all)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not get the unwrapped data")
	}

	// Writes are framed and wrapped, split by the server's maximum.
	sc.maxOut = 128 + 5
	done := make(chan error, 1)
	go func() { _, err := sc.Write([]byte("0123456789abcdef")); done <- err }()
	var wire bytes.Buffer
	for wire.Len() < 2*(4+1+5)+(4+1+6) {
		b := make([]byte, 64)
		n, err := server.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		wire.Write(b[:n])
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var plain []byte
	r := bytes.NewReader(wire.Bytes())
	for r.Len() > 0 {
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(r, hdr); err != nil {
			t.Fatal(err)
		}
		tok := make([]byte, binary.BigEndian.Uint32(hdr))
		if _, err := io.ReadFull(r, tok); err != nil {
			t.Fatal(err)
		}
		d, conf, err := ctx.Unwrap(tok)
		if err != nil || !conf {
			t.Fatalf("unwrap: %v conf=%v", err, conf)
		}
		plain = append(plain, d...)
	}
	if string(plain) != "0123456789abcdef" {
		t.Fatalf("server saw %q", plain)
	}
}

func TestSaslClientLayerChoice(t *testing.T) {
	ctx := xorContext{key: 1}
	offer := func(mask byte) []byte {
		tok, _ := ctx.Wrap([]byte{mask, 0x00, 0xA0, 0x00}, false)
		return tok
	}
	cases := []struct {
		name    string
		overTLS bool
		mask    byte
		want    byte
		err     bool
	}{
		{"plain: seal preferred", false, 7, saslLayerConf, false},
		{"plain: sign when no seal", false, 3, saslLayerIntegrity, false},
		{"plain: none only is refused", false, 1, 0, true},
		{"tls: none", true, 7, saslLayerNone, false},
		{"tls: server insists on a layer", true, 6, saslLayerConf, false},
	}
	for _, c := range cases {
		s := &saslClient{ctx: ctx, overTLS: c.overTLS}
		reply, err := s.NegotiateSaslAuth(offer(c.mask), "")
		if c.err {
			if err == nil {
				t.Errorf("%s: no error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		d, _, _ := ctx.Unwrap(reply)
		if s.layer != c.want || d[0] != c.want || s.maxOut != 0xA000 {
			t.Errorf("%s: layer %d reply %v max %d", c.name, s.layer, d, s.maxOut)
		}
		if c.want == saslLayerNone && !bytes.Equal(d[1:4], []byte{0, 0, 0}) {
			t.Errorf("%s: max must be 0 with no layer: %v", c.name, d)
		}
	}
}

// acceptorWrap is the server side of RFC 4121 wrap tokens, written
// independently from krb5Context.Wrap so the round trip proves the format.
func acceptorWrap(t *testing.T, key types.EncryptionKey, subkey bool, seq uint64, data []byte, conf bool, rrc int) []byte {
	t.Helper()
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	hdr := []byte{0x05, 0x04, wrapFlagSentByAcceptor, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if subkey {
		hdr[2] |= wrapFlagAcceptorSubkey
	}
	binary.BigEndian.PutUint64(hdr[8:], seq)
	var body []byte
	if conf {
		hdr[2] |= wrapFlagSealed
		plain := append(append([]byte{}, data...), hdr...)
		_, body, err = et.EncryptMessage(key.KeyValue, plain, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		binary.BigEndian.PutUint16(hdr[4:6], uint16(et.GetHMACBitLength()/8))
		ch := append([]byte{}, hdr...)
		ch[4], ch[5], ch[6], ch[7] = 0, 0, 0, 0
		sum, err := et.GetChecksumHash(key.KeyValue, append(append([]byte{}, data...), ch...), keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			t.Fatal(err)
		}
		body = append(append([]byte{}, data...), sum...)
	}
	// Rotate right by rrc, as Windows acceptors do, and record it.
	if rrc > 0 && rrc < len(body) {
		body = append(append([]byte{}, body[len(body)-rrc:]...), body[:len(body)-rrc]...)
		binary.BigEndian.PutUint16(hdr[6:8], uint16(rrc))
	}
	return append(hdr, body...)
}

func acceptorUnwrap(t *testing.T, key types.EncryptionKey, tok []byte) ([]byte, bool) {
	t.Helper()
	et, _ := crypto.GetEtype(key.KeyType)
	hdr := tok[:16]
	if hdr[2]&wrapFlagSentByAcceptor != 0 {
		t.Fatal("initiator token has the acceptor flag")
	}
	ec := int(binary.BigEndian.Uint16(hdr[4:6]))
	body := rotateLeft(tok[16:], int(binary.BigEndian.Uint16(hdr[6:8])))
	if hdr[2]&wrapFlagSealed != 0 {
		plain, err := et.DecryptMessage(key.KeyValue, body, keyusage.GSSAPI_INITIATOR_SEAL)
		if err != nil {
			t.Fatalf("acceptor decrypt: %v", err)
		}
		want := append([]byte{}, hdr...)
		want[6], want[7] = 0, 0
		if !bytes.Equal(plain[len(plain)-16:], want) {
			t.Fatal("acceptor: header copy mismatch")
		}
		return plain[:len(plain)-16-ec], true
	}
	data, sum := body[:len(body)-ec], body[len(body)-ec:]
	want := append([]byte{}, hdr...)
	want[4], want[5], want[6], want[7] = 0, 0, 0, 0
	calc, _ := et.GetChecksumHash(key.KeyValue, append(append([]byte{}, data...), want...), keyusage.GSSAPI_INITIATOR_SEAL)
	if !bytes.Equal(calc, sum) {
		t.Fatal("acceptor: checksum mismatch")
	}
	return data, false
}

func TestKrb5WrapRoundTrip(t *testing.T) {
	for _, et := range []int32{etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA384_192} {
		e, err := crypto.GetEtype(et)
		if err != nil {
			t.Fatal(err)
		}
		mk := func() types.EncryptionKey {
			size := e.GetKeyByteSize()
			if et == etypeID.AES256_CTS_HMAC_SHA384_192 {
				size = 32 // gokrb5 reports the seed length (24) for this etype; the AES key is 32 bytes
			}
			k := make([]byte, size)
			_, _ = rand.Read(k)
			return types.EncryptionKey{KeyType: et, KeyValue: k}
		}
		session, sub := mk(), mk()
		for _, useSub := range []bool{false, true} {
			k := &krb5Context{key: session, seq: 7, done: true}
			if useSub {
				k.subkey = sub
			}
			wrapKey := session
			if useSub {
				wrapKey = sub
			}
			for _, conf := range []bool{true, false} {
				msg := []byte("search request " + string(rune('0'+et)))
				tok, err := k.Wrap(msg, conf)
				if err != nil {
					t.Fatalf("etype %d sub=%v conf=%v: %v", et, useSub, conf, err)
				}
				if flag := tok[2] & wrapFlagAcceptorSubkey; (flag != 0) != useSub {
					t.Errorf("subkey flag %x for sub=%v", flag, useSub)
				}
				got, gotConf := acceptorUnwrap(t, wrapKey, tok)
				if !bytes.Equal(got, msg) || gotConf != conf {
					t.Fatalf("acceptor got %q conf=%v", got, gotConf)
				}
				// Acceptor → initiator, with and without the Windows-style rotation.
				for _, rrc := range []int{0, 28, 5} {
					reply := []byte("search result entries, some longer than a block of sixteen bytes")
					tok := acceptorWrap(t, wrapKey, useSub, 42, reply, conf, rrc)
					got, gotConf, err := k.Unwrap(tok)
					if err != nil || !bytes.Equal(got, reply) || gotConf != conf {
						t.Fatalf("etype %d sub=%v conf=%v rrc=%d: %q %v %v", et, useSub, conf, rrc, got, gotConf, err)
					}
				}
			}
			// Tampering is detected.
			tok := acceptorWrap(t, wrapKey, useSub, 43, []byte("fine"), true, 0)
			tok[len(tok)-1] ^= 0x01
			if _, _, err := k.Unwrap(tok); err == nil {
				t.Error("tampered sealed token accepted")
			}
			// A token for the other key is rejected.
			other := mk()
			tok = acceptorWrap(t, other, useSub, 44, []byte("fine"), false, 0)
			if _, _, err := k.Unwrap(tok); err == nil {
				t.Error("token under a foreign key accepted")
			}
		}
	}
	// RC4 session keys are refused with a clear message.
	k := &krb5Context{key: types.EncryptionKey{KeyType: etypeID.RC4_HMAC, KeyValue: make([]byte, 16)}, done: true}
	if _, err := k.Wrap([]byte("x"), true); err == nil || !bytes.Contains([]byte(err.Error()), []byte("AES")) {
		t.Errorf("rc4: %v", err)
	}
}

func TestAuthenticatorChecksumAndBindings(t *testing.T) {
	sum := authenticatorChecksum([]int{32, 16, 2}, nil)
	if len(sum) != 24 || binary.LittleEndian.Uint32(sum[0:4]) != 16 || binary.LittleEndian.Uint32(sum[20:24]) != 50 {
		t.Fatalf("checksum %x", sum)
	}
	if !bytes.Equal(sum[4:20], make([]byte, 16)) {
		t.Fatal("Bnd must be zero without channel bindings")
	}
	withCB := authenticatorChecksum([]int{32}, []byte("tls-server-end-point:abc"))
	if bytes.Equal(withCB[4:20], make([]byte, 16)) {
		t.Fatal("Bnd must carry the binding hash")
	}
	if h := channelBindingHash([]byte("tls-server-end-point:abc")); !bytes.Equal(withCB[4:20], h[:]) {
		t.Fatal("Bnd differs from channelBindingHash")
	}
	for _, c := range []struct{ in, hint, name, realm string }{
		{"audit@lab.example", "", "audit", "LAB.EXAMPLE"},
		{"audit", "lab.example", "audit", "LAB.EXAMPLE"},
		{`LAB\audit`, "lab.example", "audit", "LAB.EXAMPLE"},
		{`lab.example\audit`, "", "audit", "LAB.EXAMPLE"},
		{"audit", "", "audit", ""},
	} {
		if n, r := splitPrincipal(c.in, c.hint); n != c.name || r != c.realm {
			t.Errorf("%q/%q → %q %q", c.in, c.hint, n, r)
		}
	}
}
