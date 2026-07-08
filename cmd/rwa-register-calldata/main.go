// Command rwa-register-calldata generates the calldata to register a holder in
// CompliantRWATokenV2 under a msg.sender-bound SPT-Txn compliance proof.
//
// Two tiers (match the token's deployed Mode):
//
//	Tier 1 (address-bound attribute, no issuer):
//	  go run ./cmd/rwa-register-calldata -tier 1 -dir ./zk \
//	    -holder 0xYourHolderAddress -rwa 0xYourToken -account deployer
//
//	Tier 2 (issuer-bound eligibility):
//	  go run ./cmd/rwa-register-calldata -tier 2 -dir ./zk \
//	    -holder 0xYourHolderAddress -rwa 0xYourToken -account deployer \
//	    -issuer-key ./zk/rwa-issuer.key
//
// -holder MUST equal the address of the keystore -account that sends register(),
// because the proof is bound to that address (that is the whole point — a proof
// minted for one address cannot be replayed by another).
//
// Tier 2 uses a persistent Baby Jubjub issuer key (generated + saved on first run,
// 0600). Its public (X, Y) is printed: pin it in the token constructor / setConfig
// as (issuerX, issuerY). The private key never leaves the file.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
)

func main() {
	tier := flag.Int("tier", 2, "compliance tier: 1 (address-bound attribute) | 2 (issuer-bound eligibility)")
	dir := flag.String("dir", "./zk", "directory with pinned setup keys (from zk-setup)")
	holder := flag.String("holder", "", "holder Ethereum address the proof binds to (must equal the -account sender)")
	rwa := flag.String("rwa", "<RWA_TOKEN>", "deployed CompliantRWATokenV2 address (for the register snippet)")
	account := flag.String("account", "deployer", "cast keystore account that will send register()")
	amount := flag.Uint64("amount", 5000, "secret attribute amount (must be >= threshold)")
	threshold := flag.Uint64("threshold", 1000, "public policy threshold")
	issuerKey := flag.String("issuer-key", "./zk/rwa-issuer.key", "Tier 2: path to the persistent Baby Jubjub issuer key")
	flag.Parse()

	log.SetPrefix("rwa-register-calldata: ")
	log.SetFlags(0)

	addrBytes, err := parseAddr(*holder)
	if err != nil {
		log.Fatalf("bad -holder: %v", err)
	}
	blinding := make([]byte, 32)
	if _, err := rand.Read(blinding); err != nil {
		log.Fatal(err)
	}

	switch *tier {
	case 1:
		art, err := zkproof.Load(zkproof.CircuitAddrThreshold, *dir)
		if err != nil {
			log.Fatalf("load addrthreshold keys from %s: %v (run zk-setup first)", *dir, err)
		}
		proof, commit, err := art.ProveAddrThreshold(*amount, blinding, *threshold, addrBytes)
		if err != nil {
			log.Fatalf("prove: %v", err)
		}
		if err := art.VerifyAddrThreshold(proof, commit, *threshold, addrBytes); err != nil {
			log.Fatalf("native self-verify failed (would revert on-chain): %v", err)
		}
		solProof, err := zkproof.MarshalProofSolidity(proof)
		if err != nil {
			log.Fatalf("marshal: %v", err)
		}
		fmt.Println("CompliantRWATokenV2 register — Tier 1 (address-bound attribute)")
		fmt.Println(strings.Repeat("=", 62))
		fmt.Printf("  holder (bound)  : %s\n", *holder)
		fmt.Printf("  amount (secret) : %d   threshold (pub) : %d\n", *amount, *threshold)
		fmt.Printf("  commitment      : %s\n", commit.String())
		fmt.Printf("  proof (bytes)   : %s\n\n", solProof)
		fmt.Println("  register cast snippet (send from the SAME address as -holder):")
		fmt.Printf("    cast send %s \"register(bytes,uint256)\" \\\n", *rwa)
		fmt.Printf("      %s %s \\\n", solProof, commit.String())
		fmt.Printf("      --rpc-url \"$SEPOLIA\" --account %s\n", *account)

	case 2:
		issuer, created, err := loadOrCreateIssuer(*issuerKey)
		if err != nil {
			log.Fatalf("issuer key: %v", err)
		}
		pub := issuer.PublicKey.Bytes()
		ix, iy, err := zkproof.IssuerPubXY(pub)
		if err != nil {
			log.Fatalf("issuer pubkey: %v", err)
		}
		sig, _, err := zkproof.AttestEligibility(issuer, addrBytes, *amount, blinding)
		if err != nil {
			log.Fatalf("issuer attest: %v", err)
		}
		art, err := zkproof.Load(zkproof.CircuitEligibility, *dir)
		if err != nil {
			log.Fatalf("load eligibility keys from %s: %v (run zk-setup first)", *dir, err)
		}
		proof, _, err := art.ProveEligibility(*amount, blinding, *threshold, addrBytes, pub, sig)
		if err != nil {
			log.Fatalf("prove: %v", err)
		}
		if err := art.VerifyEligibility(proof, *threshold, addrBytes, pub); err != nil {
			log.Fatalf("native self-verify failed (would revert on-chain): %v", err)
		}
		solProof, err := zkproof.MarshalProofSolidity(proof)
		if err != nil {
			log.Fatalf("marshal: %v", err)
		}
		fmt.Println("CompliantRWATokenV2 register — Tier 2 (issuer-bound eligibility)")
		fmt.Println(strings.Repeat("=", 62))
		if created {
			fmt.Printf("  NEW issuer key generated and saved (0600): %s\n", *issuerKey)
		}
		fmt.Printf("  holder (bound)  : %s\n", *holder)
		fmt.Printf("  amount (secret) : %d   threshold (pub) : %d\n", *amount, *threshold)
		fmt.Printf("  trusted issuer  : pin these in the token (constructor / setConfig):\n")
		fmt.Printf("    issuerX = %s\n", ix.String())
		fmt.Printf("    issuerY = %s\n", iy.String())
		fmt.Printf("  proof (bytes)   : %s\n\n", solProof)
		fmt.Println("  register cast snippet (send from the SAME address as -holder):")
		fmt.Printf("    cast send %s \"register(bytes,uint256)\" \\\n", *rwa)
		fmt.Printf("      %s 0 \\\n", solProof)
		fmt.Printf("      --rpc-url \"$SEPOLIA\" --account %s\n", *account)
		fmt.Println("\n  (Tier 2 ignores the uint256 arg — the commitment stays hidden in the signed message.)")

	default:
		log.Fatalf("unknown -tier %d (want 1 or 2)", *tier)
	}
}

// parseAddr decodes a 0x-prefixed 20-byte Ethereum address.
func parseAddr(s string) ([]byte, error) {
	h := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if len(h) != 40 {
		return nil, fmt.Errorf("expected a 20-byte (40 hex char) address, got %q", s)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// loadOrCreateIssuer loads a persistent Baby Jubjub issuer key, generating and
// saving one (0600) if the file does not exist.
func loadOrCreateIssuer(path string) (priv *eddsabn254.PrivateKey, created bool, err error) {
	if b, rerr := os.ReadFile(path); rerr == nil {
		k := new(eddsabn254.PrivateKey)
		if _, serr := k.SetBytes(b); serr != nil {
			return nil, false, fmt.Errorf("parse issuer key %s: %w", path, serr)
		}
		return k, false, nil
	}
	k, gerr := eddsabn254.GenerateKey(rand.Reader)
	if gerr != nil {
		return nil, false, gerr
	}
	if werr := os.WriteFile(path, k.Bytes(), 0o600); werr != nil {
		return nil, false, fmt.Errorf("save issuer key %s: %w", path, werr)
	}
	return k, true, nil
}
