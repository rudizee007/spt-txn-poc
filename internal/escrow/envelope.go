// Package escrow implements the SPT-Txn Section 9.6 escrow envelope and
// deanonymization flow — Milestone 7.
//
// At CAT issuance the real identity behind a humanAnchor is sealed into an
// escrow envelope encrypted to the escrow authority's key. The envelope is
// stored keyed by humanAnchor and is never touched during normal transactions.
// It can be opened only via a signed, lawful-basis deanonymization request
// (deanon.go), giving accountable anonymity: holders are pseudonymous day to
// day, but recoverable under due process.
//
// Crypto (POC): single-party ECIES — an ephemeral X25519 ECDH to the escrow
// public key, a SHA-256 key-derivation with domain separation, and AES-256-GCM
// with the humanAnchor|issuer|iat tuple as additional authenticated data, so an
// envelope cannot be silently re-pointed at a different anchor. Production
// hardening (v2): HKDF for derivation and FROST threshold decryption so no
// single party holds the escrow key. Standard library only.
package escrow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// Envelope is an encrypted escrow record. The AAD fields are stored in the
// clear (they are also the lookup key and binding context) but are
// authenticated: changing any of them makes Open fail.
type Envelope struct {
	EphemeralPub []byte // X25519 ephemeral public key (32 bytes)
	Nonce        []byte // AES-GCM nonce (12 bytes)
	Ciphertext   []byte // AES-256-GCM sealed identity material
	HumanAnchor  string // vault key + AAD
	Issuer       string // AAD
	IssuedAt     int64  // AAD
}

func aad(humanAnchor, iss string, iat int64) []byte {
	return []byte(fmt.Sprintf("spt-txn-escrow-aad-v1|%s|%s|%d", humanAnchor, iss, iat))
}

// deriveKey turns an ECDH shared secret into a 256-bit AEAD key with domain
// separation. POC KDF; production should use HKDF.
func deriveKey(shared []byte) []byte {
	sum := sha256.Sum256(append([]byte("spt-txn-escrow-aead-v1\x00"), shared...))
	return sum[:]
}

// Seal encrypts identity material to the escrow public key, binding the
// envelope to (humanAnchor, issuer, iat) via AAD.
func Seal(identity []byte, escrowPub *ecdh.PublicKey, humanAnchor, issuer string, iat int64) (*Envelope, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(escrowPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	block, err := aes.NewCipher(deriveKey(shared))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, identity, aad(humanAnchor, issuer, iat))

	return &Envelope{
		EphemeralPub: eph.PublicKey().Bytes(),
		Nonce:        nonce,
		Ciphertext:   ct,
		HumanAnchor:  humanAnchor,
		Issuer:       issuer,
		IssuedAt:     iat,
	}, nil
}

// Open decrypts the envelope with the escrow private key. It fails if any AAD
// field was altered or the wrong key is used.
func (e *Envelope) Open(escrowPriv *ecdh.PrivateKey) ([]byte, error) {
	ephPub, err := ecdh.X25519().NewPublicKey(e.EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	shared, err := escrowPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	block, err := aes.NewCipher(deriveKey(shared))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, e.Nonce, e.Ciphertext, aad(e.HumanAnchor, e.Issuer, e.IssuedAt))
	if err != nil {
		return nil, fmt.Errorf("escrow open failed (wrong key or tampered AAD): %w", err)
	}
	return plain, nil
}

// NewEscrowKey generates an X25519 escrow keypair (POC helper; in production the
// public key is registered with role "escrow" and the private key is held by
// the escrow authority / threshold group).
func NewEscrowKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}
