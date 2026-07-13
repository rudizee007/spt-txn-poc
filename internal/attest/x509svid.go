package attest

// x509svid.go — SPIFFE X.509-SVID verification. The leaf certificate's URI SAN
// carries the spiffe:// identity; the chain is verified to a configured trust
// bundle with crypto/x509 (memory-safe, standard library).

import (
	"crypto/x509"
	"fmt"
	"time"
)

// X509Bundle is the trust bundle for a SPIFFE trust domain: the set of CA
// certificates the leaf must chain to.
type X509Bundle struct {
	Roots *x509.CertPool
}

// VerifyX509SVID verifies a SPIFFE X.509-SVID presented as a leaf plus any
// intermediates (DER-encoded, leaf first), against the bundle. It returns an
// Identity whose Subject is the leaf's spiffe:// URI SAN.
//
// now is the verification time (injectable for tests); zero means time.Now().
func VerifyX509SVID(der [][]byte, bundle X509Bundle, now time.Time) (Identity, error) {
	if len(der) == 0 {
		return Identity{}, fmt.Errorf("%w: empty certificate chain", ErrMalformed)
	}
	if bundle.Roots == nil {
		return Identity{}, fmt.Errorf("%w: nil trust bundle", ErrKey)
	}
	if now.IsZero() {
		now = time.Now()
	}

	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: leaf parse: %v", ErrMalformed, err)
	}
	inter := x509.NewCertPool()
	for _, d := range der[1:] {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return Identity{}, fmt.Errorf("%w: intermediate parse: %v", ErrMalformed, err)
		}
		inter.AddCert(c)
	}

	// A SPIFFE SVID carries exactly one URI SAN and no DNS/IP/email SANs.
	if len(leaf.URIs) != 1 {
		return Identity{}, fmt.Errorf("%w: SVID leaf must have exactly one URI SAN, got %d", ErrSubject, len(leaf.URIs))
	}
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return Identity{}, fmt.Errorf("%w: SVID leaf must carry no DNS/IP/email SAN", ErrSubject)
	}
	spiffeID := leaf.URIs[0].String()
	trustDomain, err := spiffeTrustDomain(spiffeID)
	if err != nil {
		return Identity{}, err
	}

	// Chain verification. KeyUsage any: SVIDs are used for client/server auth;
	// we assert the cryptographic chain, not an EKU policy the SPIFFE profile
	// leaves open.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         bundle.Roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return Identity{}, fmt.Errorf("%w: chain: %v", ErrSignature, err)
	}

	return Identity{
		Method:         MethodSPIFFEX509SVID,
		Subject:        spiffeID,
		TrustDomain:    trustDomain,
		IssuedAt:       leaf.NotBefore,
		NotBefore:      leaf.NotBefore,
		ExpiresAt:      leaf.NotAfter,
		EvidenceDigest: evidenceDigest(der[0]), // leaf DER
		Claims:         map[string]any{"serial": leaf.SerialNumber.String()},
	}, nil
}
