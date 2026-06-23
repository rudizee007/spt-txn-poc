// cmd/regkey — Register real signify public keys in the Trust Registry.
//
// Reads signify .pub files and updates the in-memory Trust Registry via
// the trsvc HTTP API. Run this once after trsvc starts to replace the
// zero-byte placeholder keys with the real keys from /var/spt-txn/*/keys/.
//
// Usage:
//   regkey -tr http://127.0.0.1:8081 -iss domain-a.authorg \
//          -role ct_issuer -pub /var/spt-txn/a/keys/ct-issuer.pub
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	sock := flag.String("sock", "/var/spt-txn/sockets/tr-admin.sock", "trsvc admin Unix socket (registration is socket-only, owner 0600)")
	iss  := flag.String("iss",  "",                       "Issuer identifier")
	role := flag.String("role", "",                       "Role (ct_issuer|tts_issuer|escrow|audit)")
	pub  := flag.String("pub",  "",                       "Path to signify .pub file")
	flag.Parse()

	if *iss == "" || *role == "" || *pub == "" {
		flag.Usage()
		os.Exit(1)
	}

	pubKey, err := loadSignifyPub(*pub)
	if err != nil {
		log.Fatalf("load public key: %v", err)
	}
	log.Printf("loaded public key: %s", hex.EncodeToString(pubKey))

	// Determine key type from role.
	keyType := "Ed25519"
	if *role == "escrow" {
		keyType = "X25519"
	}

	// Call the Trust Registry update endpoint.
	body := map[string]any{
		"iss":        *iss,
		"role":       *role,
		"key_type":   keyType,
		"public_key": hex.EncodeToString(pubKey),
	}
	bodyJSON, _ := json.Marshal(body)

	// Registration is served only on the local Unix socket, so dial it directly
	// rather than a TCP address. Access is gated by the socket's filesystem
	// permissions (review C1).
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", *sock)
			},
		},
	}
	url := "http://unix/tr/register"
	resp, err := client.Post(url, "application/json", bytes.NewReader(bodyJSON))
	if err != nil {
		log.Fatalf("POST %s (socket %s): %v", url, *sock, err)
	}
	defer resp.Body.Close()

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Fatalf("register failed (%d): %v", resp.StatusCode, result)
	}
	log.Printf("registered %s / %s with key %s", *iss, *role, hex.EncodeToString(pubKey))
}

// loadSignifyPub reads a signify .pub file and extracts the 32-byte
// Ed25519 public key.
//
// Signify public key format (base64-decoded):
//   [0:2]   algorithm ("Ed")
//   [2:10]  fingerprint (8 bytes)
//   [10:42] Ed25519 public key (32 bytes)
func loadSignifyPub(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var b64line string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "untrusted") {
			b64line = line
			break
		}
	}
	if b64line == "" {
		return nil, fmt.Errorf("no base64 line in %s", path)
	}

	raw, err := base64.StdEncoding.DecodeString(b64line)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 42 {
		return nil, fmt.Errorf("key too short: %d bytes", len(raw))
	}
	if string(raw[0:2]) != "Ed" {
		return nil, fmt.Errorf("unexpected algorithm: %q", raw[0:2])
	}

	return raw[10:42], nil
}
