// Command aptos-pay submits a real Aptos APT transfer from an x402gate ALLOW
// decision — the Aptos analog of clients/xrpl-pay / clients/hedera-pay (P0-A).
//
// The offline core (cmd/gatesvc) decides IF the agent may pay; this tool settles
// the APT transfer on Aptos. NOTE: Aptos has NO transaction memo field, so unlike
// XRPL/Hedera the humanAnchor is NOT written on-chain here — it is bound
// cryptographically into the SPT-Txn attestation via the context hash (verifier
// step 8), which the merchant still checks. Putting the anchor on-chain would use
// a Move anchor module/event (grant work), mirroring clients/hcs-anchor on Hedera.
//
// Lives in its own module so the Aptos SDK never enters the offline core.
//
// Credentials (env only — never a flag, never the repo):
//
//	APTOS_OPERATOR_KEY       ed25519 private key (hex; the payer "agent")
//	APTOS_OPERATOR_ADDRESS   optional; only needed if the account's key was rotated
//
// Security:
//   - Default network is TESTNET. Mainnet requires -network mainnet AND a
//     confirmation prompt (skipped with -yes or -json).
//   - -dry-run derives the account and prints the transfer without any network call.
//
// -amount is in OCTAS (1 APT = 100,000,000 octas), mirroring drops/tinybars so the
// gate ceiling/price numbers carry over unchanged.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
)

const (
	opKeyEnv  = "APTOS_OPERATOR_KEY"
	opAddrEnv = "APTOS_OPERATOR_ADDRESS"
)

func main() {
	network := flag.String("network", "testnet", "aptos network: testnet | mainnet | devnet")
	to := flag.String("to", "", "destination account address 0x… (required)")
	amount := flag.String("amount", "", "amount in OCTAS (required); 1 APT = 100,000,000 octas")
	currency := flag.String("currency", "APT", "currency: APT (Fungible Assets are a later step)")
	memo := flag.String("memo", "", "humanAnchor (bound in the attestation; Aptos has no on-chain memo)")
	jsonOut := flag.Bool("json", false, "print only a machine-readable JSON result to stdout (for cmd/agent)")
	whoami := flag.Bool("whoami", false, "print the operator account address from the environment and exit")
	yes := flag.Bool("yes", false, "skip the mainnet confirmation prompt (non-interactive use)")
	dryRun := flag.Bool("dry-run", false, "derive the account and print the transfer without submitting")
	// Accepted for cmd/agent compatibility; not used on Aptos.
	_ = flag.String("sourcetag", "", "ignored on Aptos (agent compatibility)")
	_ = flag.String("context-hash", "", "ignored on Aptos (agent compatibility)")
	flag.Parse()

	account, err := loadAccount()
	if err != nil {
		log.Fatal(err)
	}
	if *whoami {
		fmt.Println(account.Address.String())
		return
	}

	if *to == "" || *amount == "" {
		log.Fatal("both -to and -amount are required")
	}
	if strings.ToUpper(*currency) != "APT" {
		log.Fatalf("currency %q not yet supported: only APT for now (Fungible Assets later)", *currency)
	}
	octas, err := strconv.ParseUint(strings.TrimSpace(*amount), 10, 64)
	if err != nil || octas == 0 {
		log.Fatalf("-amount must be a positive integer of octas, got %q", *amount)
	}
	var toAddr aptos.AccountAddress
	if err := toAddr.ParseStringRelaxed(*to); err != nil {
		log.Fatalf("-to %q: %v", *to, err)
	}
	if toAddr == account.Address {
		log.Fatal("sender and receiver must differ")
	}

	if !*jsonOut {
		fmt.Printf("aptos-pay — %s\n", *network)
		fmt.Printf("  from (payer agent) : %s\n", account.Address.String())
		fmt.Printf("  to (merchant)      : %s\n", *to)
		fmt.Printf("  amount             : %d octas (%.8f APT)\n", octas, float64(octas)/1e8)
		if *memo != "" {
			fmt.Printf("  humanAnchor        : %s (bound in attestation; not on-chain)\n", *memo)
		}
	}
	if *dryRun {
		if *jsonOut {
			b, _ := json.Marshal(map[string]any{"dry_run": true, "from": account.Address.String(), "to": *to, "octas": octas})
			fmt.Println(string(b))
			return
		}
		fmt.Println("\n  -dry-run: not connecting, not submitting.")
		return
	}

	if isMainnet(*network) && !*jsonOut && !*yes {
		fmt.Printf("\n⚠  REAL payment on Aptos %s: %d octas to %s\n   type 'yes' to proceed: ", *network, octas, *to)
		var resp string
		_, _ = fmt.Scanln(&resp)
		if strings.TrimSpace(resp) != "yes" {
			log.Fatal("aborted (not confirmed)")
		}
	}

	client, err := aptos.NewClient(networkConfig(*network))
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	// 0x1::aptos_account::transfer(recipient, amount)
	toBytes, err := bcs.Serialize(&toAddr)
	if err != nil {
		log.Fatalf("serialize recipient: %v", err)
	}
	amountBytes, err := bcs.SerializeU64(octas)
	if err != nil {
		log.Fatalf("serialize amount: %v", err)
	}
	resp, err := client.BuildSignAndSubmitTransaction(account, aptos.TransactionPayload{
		Payload: &aptos.EntryFunction{
			Module:   aptos.ModuleId{Address: aptos.AccountOne, Name: "aptos_account"},
			Function: "transfer",
			ArgTypes: []aptos.TypeTag{},
			Args:     [][]byte{toBytes, amountBytes},
		},
	})
	if err != nil {
		log.Fatalf("submit transfer: %v", err)
	}
	if _, err := client.WaitForTransaction(resp.Hash); err != nil {
		log.Fatalf("wait for transaction: %v", err)
	}
	explorer := fmt.Sprintf("https://explorer.aptoslabs.com/txn/%s?network=%s", resp.Hash, *network)

	if *jsonOut {
		b, _ := json.Marshal(map[string]any{"tx_hash": resp.Hash, "explorer": explorer, "status": "submitted"})
		fmt.Println(string(b))
		return
	}
	fmt.Printf("\n  SUBMITTED\n")
	fmt.Printf("    transaction hash : %s\n", resp.Hash)
	fmt.Printf("    explorer         : %s\n", explorer)
}

// loadAccount derives the payer account from APTOS_OPERATOR_KEY (and the optional
// APTOS_OPERATOR_ADDRESS for rotated keys).
func loadAccount() (*aptos.Account, error) {
	keyHex := os.Getenv(opKeyEnv)
	if keyHex == "" {
		return nil, fmt.Errorf("set %s in the environment (never a flag or the repo)", opKeyEnv)
	}
	priv := &crypto.Ed25519PrivateKey{}
	if err := priv.FromHex(keyHex); err != nil {
		return nil, fmt.Errorf("%s: %w", opKeyEnv, err)
	}
	if addrStr := os.Getenv(opAddrEnv); addrStr != "" {
		var addr aptos.AccountAddress
		if err := addr.ParseStringRelaxed(addrStr); err != nil {
			return nil, fmt.Errorf("%s: %w", opAddrEnv, err)
		}
		return aptos.NewAccountFromSigner(priv, addr)
	}
	return aptos.NewAccountFromSigner(priv)
}

func networkConfig(network string) aptos.NetworkConfig {
	switch network {
	case "testnet":
		return aptos.TestnetConfig
	case "mainnet":
		return aptos.MainnetConfig
	case "devnet":
		return aptos.DevnetConfig
	default:
		log.Fatalf("unknown network %q (want testnet|mainnet|devnet)", network)
		return aptos.TestnetConfig
	}
}

func isMainnet(network string) bool { return network == "mainnet" }
