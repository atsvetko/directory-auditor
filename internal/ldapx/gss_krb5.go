package ldapx

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	goasn1 "github.com/jcmturner/gofork/encoding/asn1"

	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// krb5Context is the GSS-API Kerberos v5 mechanism (RFC 4121) on gokrb5:
// AP-REQ/AP-REP context establishment, then wrap tokens with integrity or
// confidentiality. Only the AES enctypes are supported for per-message
// protection; RC4 session keys use the older RFC 1964/4757 token format,
// which this client does not implement — such domains use LDAPS instead.
type krb5Context struct {
	cl    *client.Client
	spn   string
	cb    []byte // GSS channel-binding application data (tls-server-end-point), or nil
	flags []int

	key    types.EncryptionKey // ticket session key
	subkey types.EncryptionKey // acceptor subkey from AP-REP, when present
	seq    uint64              // our next sequence number
	done   bool
}

const (
	wrapFlagSentByAcceptor = 0x01
	wrapFlagSealed         = 0x02
	wrapFlagAcceptorSubkey = 0x04
)

func newKrb5Context(cl *client.Client, spn string, channelBinding []byte) *krb5Context {
	return &krb5Context{cl: cl, spn: spn, cb: channelBinding,
		flags: []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}}
}

func (k *krb5Context) Identity() string {
	return k.cl.Credentials.CName().PrincipalNameString() + "@" + k.cl.Credentials.Realm()
}

func (k *krb5Context) Close() error {
	k.cl.Destroy()
	return nil
}

// Step implements the initiator side of RFC 4121 §4.1: AP-REQ out, AP-REP in.
func (k *krb5Context) Step(in []byte) ([]byte, bool, error) {
	if in == nil {
		tkt, key, err := k.cl.GetServiceTicket(k.spn)
		if err != nil {
			return nil, false, fmt.Errorf("service ticket for %s: %w", k.spn, err)
		}
		k.key = key
		auth, err := types.NewAuthenticator(k.cl.Credentials.Domain(), k.cl.Credentials.CName())
		if err != nil {
			return nil, false, err
		}
		auth.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: authenticatorChecksum(k.flags, k.cb)}
		k.seq = uint64(auth.SeqNumber)
		apReq, err := messages.NewAPReq(tkt, key, auth)
		if err != nil {
			return nil, false, err
		}
		// Mutual authentication is requested through the GSS checksum flags in
		// the authenticator, not the AP-REQ mutual-required option — matching
		// what MIT/Windows GSSAPI send, which Samba and AD expect.
		body, err := apReq.Marshal()
		if err != nil {
			return nil, false, err
		}
		// The mechanism OID must be marshaled with gokrb5's forked asn1, which
		// knows ObjectIdentifier; the standard library sees the forked named
		// type as a plain []int and would encode a SEQUENCE OF INTEGER (the
		// acceptor then rejects the context with "logon failure").
		oid, err := goasn1.Marshal(gssapi.OIDKRB5.OID())
		if err != nil {
			return nil, false, err
		}
		tok := append(oid, 0x01, 0x00) // TOK_ID KRB_AP_REQ
		tok = append(tok, body...)
		return asn1tools.AddASNAppTag(tok, 0), false, nil
	}
	var t spnego.KRB5Token
	if err := t.Unmarshal(in); err != nil {
		return nil, false, fmt.Errorf("server token: %w", err)
	}
	if t.IsKRBError() {
		return nil, false, t.KRBError
	}
	if !t.IsAPRep() {
		return nil, false, errors.New("server token is neither AP-REP nor KRB-ERROR")
	}
	enc, err := crypto.DecryptEncPart(t.APRep.EncPart, k.key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, false, fmt.Errorf("AP-REP: %w", err)
	}
	var part messages.EncAPRepPart
	if err := part.Unmarshal(enc); err != nil {
		return nil, false, fmt.Errorf("AP-REP: %w", err)
	}
	k.subkey = part.Subkey
	k.done = true
	return nil, true, nil
}

// authenticatorChecksum is the RFC 4121 §4.1.1 checksum: Lgth=16, Bnd (MD5 of
// the channel bindings, zeros when none), Flags.
func authenticatorChecksum(flags []int, cb []byte) []byte {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[0:4], 16)
	if cb != nil {
		sum := channelBindingHash(cb)
		copy(a[4:20], sum[:])
	}
	var f uint32
	for _, i := range flags {
		f |= uint32(i)
	}
	binary.LittleEndian.PutUint32(a[20:24], f)
	return a
}

// checksumHeader returns the 16-byte wrap-token header with the EC and RRC
// fields zeroed, as the integrity checksum is computed over (RFC 4121 §4.2.4).
func checksumHeader(hdr []byte) []byte {
	h := make([]byte, 16)
	copy(h, hdr)
	h[4], h[5], h[6], h[7] = 0, 0, 0, 0
	return h
}

// channelBindingHash is MD5 over the GSS channel bindings structure (RFC 2744
// §3.11, RFC 4121 §4.1.1.2) with unspecified addresses and the given
// application data.
func channelBindingHash(appData []byte) [16]byte {
	var b bytes.Buffer
	le := func(v uint32) { _ = binary.Write(&b, binary.LittleEndian, v) }
	le(0) // initiator addrtype GSS_C_AF_UNSPEC
	le(0) // initiator address length
	le(0) // acceptor addrtype
	le(0) // acceptor address length
	le(uint32(len(appData)))
	b.Write(appData)
	return md5.Sum(b.Bytes())
}

func (k *krb5Context) wrapKey() (types.EncryptionKey, byte) {
	if k.subkey.KeyType != 0 && len(k.subkey.KeyValue) > 0 {
		return k.subkey, wrapFlagAcceptorSubkey
	}
	return k.key, 0
}

func supportedEtype(id int32) error {
	switch id {
	case etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA256_128, etypeID.AES256_CTS_HMAC_SHA384_192:
		return nil
	}
	return fmt.Errorf("session key type %d: only AES session keys are supported for LDAP signing and sealing (RC4 domains: use LDAPS)", id)
}

// Wrap builds an initiator wrap token (RFC 4121 §4.2.6.2). With conf the
// body is E(data | filler | header) under KG_USAGE_INITIATOR_SEAL; without,
// data | checksum(data | header) under the same usage.
func (k *krb5Context) Wrap(data []byte, conf bool) ([]byte, error) {
	if !k.done {
		return nil, errors.New("context not established")
	}
	key, keyFlag := k.wrapKey()
	if err := supportedEtype(key.KeyType); err != nil {
		return nil, err
	}
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 16)
	hdr[0], hdr[1], hdr[3] = 0x05, 0x04, 0xFF
	hdr[2] = keyFlag
	binary.BigEndian.PutUint64(hdr[8:], k.seq)
	k.seq++
	if conf {
		hdr[2] |= wrapFlagSealed
		// EC = 0 (CTS modes need no filler); RRC = 0; the header copy inside
		// the ciphertext carries RRC 0 as well.
		plain := make([]byte, 0, len(data)+16)
		plain = append(plain, data...)
		plain = append(plain, hdr...)
		_, ct, err := et.EncryptMessage(key.KeyValue, plain, keyusage.GSSAPI_INITIATOR_SEAL)
		if err != nil {
			return nil, err
		}
		return append(hdr, ct...), nil
	}
	// Integrity only: the wire EC is the checksum length, but the checksum is
	// computed over data | header with EC and RRC zeroed (MIT/RFC 4121 §4.2.6.1).
	binary.BigEndian.PutUint16(hdr[4:6], uint16(et.GetHMACBitLength()/8))
	sum, err := et.GetChecksumHash(key.KeyValue, append(append([]byte{}, data...), checksumHeader(hdr)...), keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		return nil, err
	}
	out := append(hdr, data...)
	return append(out, sum...), nil
}

// Unwrap verifies an acceptor wrap token and returns its data.
func (k *krb5Context) Unwrap(tok []byte) ([]byte, bool, error) {
	if len(tok) < 16 || tok[0] != 0x05 || tok[1] != 0x04 || tok[3] != 0xFF {
		return nil, false, errors.New("not a wrap token")
	}
	flags := tok[2]
	if flags&wrapFlagSentByAcceptor == 0 {
		return nil, false, errors.New("wrap token was not sent by the acceptor")
	}
	key := k.key
	if flags&wrapFlagAcceptorSubkey != 0 {
		if len(k.subkey.KeyValue) == 0 {
			return nil, false, errors.New("token uses the acceptor subkey, but the AP-REP carried none")
		}
		key = k.subkey
	}
	if err := supportedEtype(key.KeyType); err != nil {
		return nil, false, err
	}
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, false, err
	}
	ec := int(binary.BigEndian.Uint16(tok[4:6]))
	rrc := int(binary.BigEndian.Uint16(tok[6:8]))
	hdr := tok[:16]
	body := rotateLeft(tok[16:], rrc)
	if flags&wrapFlagSealed != 0 {
		plain, err := et.DecryptMessage(key.KeyValue, body, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			return nil, true, err
		}
		if len(plain) < 16+ec {
			return nil, true, errors.New("sealed token too short")
		}
		want := make([]byte, 16)
		copy(want, hdr)
		want[6], want[7] = 0, 0 // the embedded header copy has RRC 0
		if !bytes.Equal(plain[len(plain)-16:], want) {
			return nil, true, errors.New("sealed token header mismatch")
		}
		return plain[:len(plain)-16-ec], true, nil
	}
	if len(body) < ec {
		return nil, false, errors.New("signed token too short")
	}
	data, sum := body[:len(body)-ec], body[len(body)-ec:]
	calc, err := et.GetChecksumHash(key.KeyValue, append(append([]byte{}, data...), checksumHeader(hdr)...), keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(calc, sum) {
		return nil, false, errors.New("signed token checksum mismatch")
	}
	return data, false, nil
}

// krb5ConfigFor builds a minimal krb5 configuration for a domain whose KDC is
// the directory server itself (every AD and Samba DC is a KDC), for the
// password path where no krb5.conf exists on the machine.
func krb5ConfigFor(realm, kdc string) string {
	realm = strings.ToUpper(realm)
	return fmt.Sprintf("[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n udp_preference_limit = 1\n[realms]\n %s = {\n  kdc = %s\n }\n", realm, realm, kdc)
}
