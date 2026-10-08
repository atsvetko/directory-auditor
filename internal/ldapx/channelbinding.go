package ldapx

import (
	"crypto"
	"crypto/x509"
)

// tlsServerEndPoint returns the RFC 5929 "tls-server-end-point" channel
// binding data for the server certificate: the prefix plus the certificate
// hash, using the certificate's signature hash (SHA-256 for MD5/SHA-1 and
// unknown algorithms, as RFC 5929 §4.1 requires). nil when the certificate
// cannot be bound.
func tlsServerEndPoint(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	var h crypto.Hash
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		h = crypto.SHA384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		h = crypto.SHA512
	default:
		h = crypto.SHA256
	}
	hasher := h.New()
	hasher.Write(cert.Raw)
	return append([]byte("tls-server-end-point:"), hasher.Sum(nil)...)
}
