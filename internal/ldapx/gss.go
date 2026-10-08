package ldapx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// gssContext is a Kerberos (GSS-API) security context as the LDAP client
// needs it: establish it with the server, then protect every message. One
// implementation uses SSPI (Windows), the other gokrb5 (everything else).
type gssContext interface {
	// Step feeds the server's token (nil for the first call) and returns the
	// next token for the server; done is true once the context is complete.
	Step(in []byte) (out []byte, done bool, err error)
	// Wrap protects data: signed, and encrypted when conf is true.
	Wrap(data []byte, conf bool) ([]byte, error)
	// Unwrap verifies (and decrypts) a token from the server.
	Unwrap(token []byte) (data []byte, conf bool, err error)
	// Identity names the authenticated principal.
	Identity() string
	Close() error
}

// SASL GSSAPI security layers (RFC 4752 §3.3).
const (
	saslLayerNone      byte = 1
	saslLayerIntegrity byte = 2
	saslLayerConf      byte = 4

	// saslMaxIn is the largest protected buffer we accept from the server
	// (RFC 4752: three octets, network byte order).
	saslMaxIn = 0x00A00000
)

// saslClient drives go-ldap's SASL/GSSAPI bind with a context that survives
// the bind, so the negotiated security layer can protect the session. Which
// layer is negotiated depends on whether TLS is already underneath: none over
// TLS (confidentiality comes from TLS, channel binding ties the two), else
// confidentiality, else integrity — never "none" on a plaintext connection.
type saslClient struct {
	ctx     gssContext
	overTLS bool

	layer  byte // negotiated
	maxOut int  // largest buffer the server accepts
}

func (s *saslClient) InitSecContextWithOptions(target string, token []byte, _ []int) ([]byte, bool, error) {
	out, done, err := s.ctx.Step(token)
	if err != nil {
		return nil, false, err
	}
	// go-ldap's convention: the second value is "needs another init round".
	return out, !done, nil
}

func (s *saslClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return s.InitSecContextWithOptions(target, token, nil)
}

// NegotiateSaslAuth reads the server's layer offer and answers with the
// chosen layer and our maximum buffer (RFC 4752 §3.1).
func (s *saslClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	offer, _, err := s.ctx.Unwrap(token)
	if err != nil {
		return nil, fmt.Errorf("sasl: server offer: %w", err)
	}
	if len(offer) != 4 {
		return nil, fmt.Errorf("sasl: server offer is %d bytes, want 4", len(offer))
	}
	offered := offer[0]
	s.maxOut = int(offer[1])<<16 | int(offer[2])<<8 | int(offer[3])
	switch {
	case s.overTLS && offered&saslLayerNone != 0:
		s.layer = saslLayerNone
	case offered&saslLayerConf != 0:
		s.layer = saslLayerConf
	case offered&saslLayerIntegrity != 0:
		s.layer = saslLayerIntegrity
	case s.overTLS:
		return nil, errors.New("sasl: server offers no acceptable security layer")
	default:
		return nil, errors.New("sasl: the server offers neither signing nor sealing, and the connection is not encrypted — use LDAPS or StartTLS")
	}
	reply := make([]byte, 4, 4+len(authzid))
	reply[0] = s.layer
	if s.layer != saslLayerNone {
		reply[1], reply[2], reply[3] = byte(saslMaxIn>>16&0xff), byte(saslMaxIn>>8&0xff), byte(saslMaxIn&0xff)
	}
	reply = append(reply, authzid...)
	return s.ctx.Wrap(reply, false)
}

// DeleteSecContext is called by go-ldap when the bind finishes; the context
// must outlive the bind, so this is a no-op and Conn.Close releases it.
func (s *saslClient) DeleteSecContext() error { return nil }

func (s *saslClient) layerName() string {
	switch s.layer {
	case saslLayerConf:
		return "sealed"
	case saslLayerIntegrity:
		return "signed"
	}
	return "none"
}

// secConn is the plaintext TCP connection with a SASL security layer that
// can be switched on after the bind (RFC 4422 §3.7, RFC 4752 §3.3): every
// buffer on the wire is a 4-byte big-endian length followed by a wrap token.
//
// Arming happens while go-ldap's reader goroutine may already be blocked in
// Read, so Read decides what the bytes are only after they arrive: between the
// last bind response and our first protected request the server sends nothing,
// so the first bytes read after arming are the start of a protected buffer.
type secConn struct {
	net.Conn

	mu     sync.Mutex
	armed  bool
	ctx    gssContext
	conf   bool
	maxOut int

	rmu   sync.Mutex
	plain bytes.Buffer // decrypted bytes not yet handed to the reader
	wmu   sync.Mutex
}

func (c *secConn) arm(ctx gssContext, conf bool, maxOut int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctx, c.conf, c.maxOut, c.armed = ctx, conf, maxOut, true
}

func (c *secConn) isArmed() (gssContext, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ctx, c.conf, c.armed
}

func (c *secConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.plain.Len() > 0 {
		return c.plain.Read(p)
	}
	ctx, _, armed := c.isArmed()
	if !armed {
		// Plain phase: read raw bytes, then re-check — the bind may have
		// completed while we were blocked, in which case these bytes begin
		// a protected buffer.
		n, err := c.Conn.Read(p)
		if n == 0 {
			return 0, err
		}
		if ctx, _, armed = c.isArmed(); !armed {
			return n, err
		}
		if err := c.readFrame(ctx, p[:n]); err != nil {
			return 0, err
		}
		return c.plain.Read(p)
	}
	if err := c.readFrame(ctx, nil); err != nil {
		return 0, err
	}
	return c.plain.Read(p)
}

// readFrame reads one protected buffer (prefix bytes already consumed from
// the wire, if any), unwraps it and appends the plaintext to c.plain.
func (c *secConn) readFrame(ctx gssContext, prefix []byte) error {
	hdr := make([]byte, 4)
	n := copy(hdr, prefix)
	rest := prefix[n:]
	if n < 4 {
		if _, err := io.ReadFull(c.Conn, hdr[n:]); err != nil {
			return err
		}
	}
	size := int(binary.BigEndian.Uint32(hdr))
	if size <= 0 || size > saslMaxIn {
		return fmt.Errorf("ldapx: protected buffer of %d bytes is out of range", size)
	}
	tok := make([]byte, size)
	m := copy(tok, rest)
	if m < size {
		if _, err := io.ReadFull(c.Conn, tok[m:]); err != nil {
			return err
		}
	}
	data, _, err := ctx.Unwrap(tok)
	if err != nil {
		return fmt.Errorf("ldapx: protected buffer from the server failed verification: %w", err)
	}
	c.plain.Write(data)
	return nil
}

func (c *secConn) Write(p []byte) (int, error) {
	ctx, conf, armed := c.isArmed()
	if !armed {
		return c.Conn.Write(p)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	chunk := c.maxOut - 128 // room for the wrap token's header and trailer
	if chunk <= 0 {
		chunk = 1 << 16
	}
	for off := 0; off < len(p); off += chunk {
		end := off + chunk
		if end > len(p) {
			end = len(p)
		}
		tok, err := ctx.Wrap(p[off:end], conf)
		if err != nil {
			return off, err
		}
		frame := make([]byte, 4+len(tok))
		binary.BigEndian.PutUint32(frame, uint32(len(tok)))
		copy(frame[4:], tok)
		if _, err := c.Conn.Write(frame); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

// rotateLeft undoes the RRC right-rotation of a wrap token body (RFC 4121 §4.2.5).
func rotateLeft(b []byte, rrc int) []byte {
	if len(b) == 0 {
		return b
	}
	rrc %= len(b)
	if rrc == 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	out = append(out, b[rrc:]...)
	out = append(out, b[:rrc]...)
	return out
}
