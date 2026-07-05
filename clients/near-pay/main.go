// Command near-pay submits a real NEAR transfer from an x402gate ALLOW decision —
// the NEAR analog of the other chain submitters (P0-N). NEAR is fully non-EVM:
// human-readable named accounts ("agent.alice.testnet"), yoctoNEAR amounts
// (1 NEAR = 10^24 yocto), and Borsh-serialized transactions — the sharpest test
// yet of the blockchain-agnostic boundary (gate/verifier/merchant unchanged).
//
// A native NEAR Transfer action has no memo field, so — like Aptos — the
// humanAnchor is bound cryptographically into the SPT-Txn attestation (context
// hash, verifier step 8), NOT written on-chain here. On-chain anchoring would use
// a FunctionCall/log or a NEP-141 ft_transfer memo (grant work). The merchant
// still checks the context-hash binding either way.
//
// Lives in its own module so the NEAR SDK never enters the offline core.
//
// Credentials (env only — never a flag, never the repo). NEAR is account-based:
// a key is an access key ON an account, so unlike every other chain the payer
// address is NOT derivable from the key — both are required:
//
//	NEAR_OPERATOR_KEY   the payer's full-access private key, "ed25519:<base58>"
//	NEAR_ACCOUNT_ID     the payer account id, e.g. "agent.alice.testnet"
//
// Security:
//   - Default network is TESTNET. Mainnet requires -network mainnet AND a
//     confirmation prompt (skipped with -yes or -json).
//   - -dry-run prints the transfer without any network call.
//
// -amount is in YOCTONEAR (1 NEAR = 1e24), mirroring drops/tinybars/octas/wei/
// lamports so the gate ceiling/price numbers carry over unchanged.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	uint128 "github.com/eteu-technologies/golang-uint128"
	"github.com/eteu-technologies/near-api-go/pkg/client"
	"github.com/eteu-technologies/near-api-go/pkg/types"
	"github.com/eteu-technologies/near-api-go/pkg/types/action"
	"github.com/eteu-technologies/near-api-go/pkg/types/hash"
	"github.com/eteu-technologies/near-api-go/pkg/types/key"
)

const (
	keyEnv  = "NEAR_OPERATOR_KEY"
	acctEnv = "NEAR_ACCOUNT_ID"
)

func main() {
	network := flag.String("network", "testnet", "near network: testnet | mainnet")
	endpoint := flag.String("endpoint", "", "override the RPC endpoint (default: the network's public RPC)")
	to := flag.String("to", "", "destination NEAR account id (required)")
	amount := flag.String("amount", "", "amount in YOCTONEAR (required); 1 NEAR = 1e24 yocto")
	currency := flag.String("currency", "NEAR", "currency: NEAR (NEP-141 fungible tokens are a later step)")
	memo := flag.String("memo", "", "humanAnchor (bound in the attestation; NEAR native transfer has no on-chain memo)")
	jsonOut := flag.Bool("json", false, "print only a machine-readable JSON result to stdout (for cmd/agent)")
	whoami := flag.Bool("whoami", false, "print the operator account id from $NEAR_ACCOUNT_ID and exit")
	yes := flag.Bool("yes", false, "skip the mainnet confirmation prompt (non-interactive use)")
	dryRun := flag.Bool("dry-run", false, "print the transfer without submitting")
	// Accepted for cmd/agent compatibility; not used on NEAR.
	_ = flag.String("sourcetag", "", "ignored on NEAR (agent compatibility)")
	_ = flag.String("context-hash", "", "ignored on NEAR (agent compatibility)")
	flag.Parse()

	account := strings.TrimSpace(os.Getenv(acctEnv))
	if *whoami {
		if account == "" {
			log.Fatalf("set %s in the environment (the payer account id)", acctEnv)
		}
		fmt.Println(account)
		return
	}

	if account == "" {
		log.Fatalf("set %s in the environment (the payer account id)", acctEnv)
	}
	if *to == "" || *amount == "" {
		log.Fatal("both -to and -amount are required")
	}
	if !strings.EqualFold(*currency, "NEAR") {
		log.Fatalf("currency %q not yet supported: only NEAR for now (NEP-141 later)", *currency)
	}
	if strings.TrimSpace(*to) == account {
		log.Fatal("sender and receiver must differ")
	}
	yocto, ok := new(big.Int).SetString(strings.TrimSpace(*amount), 10)
	if !ok || yocto.Sign() <= 0 {
		log.Fatalf("-amount must be a positive integer of yoctoNEAR, got %q", *amount)
	}
	bal := types.Balance(uint128.FromBig(yocto))

	if !*jsonOut {
		fmt.Printf("near-pay — %s\n", networkLabel(*network, *endpoint))
		fmt.Printf("  from (payer agent) : %s\n", account)
		fmt.Printf("  to (merchant)      : %s\n", *to)
		fmt.Printf("  amount             : %s yoctoNEAR (%s NEAR)\n", yocto.String(), yoctoToNEARString(yocto))
		if *memo != "" {
			fmt.Printf("  humanAnchor        : %s (bound in attestation; not on-chain)\n", *memo)
		}
	}
	if *dryRun {
		if *jsonOut {
			b, _ := json.Marshal(map[string]any{"dry_run": true, "from": account, "to": *to, "yocto": yocto.String()})
			fmt.Println(string(b))
			return
		}
		fmt.Println("\n  -dry-run: not connecting, not submitting.")
		return
	}

	if isMainnet(*network) && !*jsonOut && !*yes {
		fmt.Printf("\n⚠  REAL payment on NEAR MAINNET: %s yoctoNEAR to %s\n   type 'yes' to proceed: ", yocto.String(), *to)
		var resp string
		_, _ = fmt.Scanln(&resp)
		if strings.TrimSpace(resp) != "yes" {
			log.Fatal("aborted (not confirmed)")
		}
	}

	keyStr := strings.TrimSpace(os.Getenv(keyEnv))
	if keyStr == "" {
		log.Fatalf("set %s in the environment (never a flag or the repo)", keyEnv)
	}
	keyPair, err := key.NewBase58KeyPair(keyStr)
	if err != nil {
		log.Fatalf("%s: %v (want \"ed25519:<base58>\")", keyEnv, err)
	}

	ep := rpcEndpoint(*network, *endpoint)
	rpc, err := client.NewClient(ep)
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	ctx := client.ContextWithKeyPair(context.Background(), keyPair)

	// Attach a recent block hash, fetched with our OWN lenient JSON decode rather
	// than the library's BlockDetails. The 2022-era library strict-decodes every
	// RPC response (DisallowUnknownFields) and current nearcore's block header
	// carries fields it doesn't model — so BlockDetails would fail. Its internal
	// access-key/nonce query is on a stable struct and still works.
	bh, err := latestBlockHash(ctx, ep)
	if err != nil {
		log.Fatalf("latest block: %v", err)
	}

	// Async broadcast (broadcast_tx_async) returns just the tx hash, so we also
	// avoid decoding the evolved, strict-decoded execution-outcome struct. The
	// transfer is valid (recent block hash + queried nonce) and executes; the
	// merchant verifies the SPT-Txn attestation, not on-chain status. (The earlier
	// "unknown field name" was nearcore's error envelope for a zero-block-hash tx.)
	txnHash, err := rpc.TransactionSend(ctx, account, strings.TrimSpace(*to),
		[]action.Action{action.NewTransfer(bal)}, client.WithBlockHash(bh))
	if err != nil {
		log.Fatalf("submit transfer: %v", err)
	}
	txHash := txnHash.String()
	explorer := explorerURL(*network, txHash)

	if *jsonOut {
		b, _ := json.Marshal(map[string]any{"tx_hash": txHash, "explorer": explorer, "status": "submitted"})
		fmt.Println(string(b))
		return
	}
	fmt.Printf("\n  SUBMITTED\n")
	fmt.Printf("    tx hash   : %s\n", txHash)
	fmt.Printf("    explorer  : %s\n", explorer)
}

func rpcEndpoint(network, override string) string {
	if override != "" {
		return override
	}
	switch network {
	case "testnet":
		// If the public endpoint is deprecated/rate-limited, override with a
		// provider such as FastNEAR: https://test.rpc.fastnear.com
		return "https://rpc.testnet.near.org"
	case "mainnet":
		return "https://rpc.mainnet.near.org"
	default:
		log.Fatalf("unknown network %q (want testnet|mainnet)", network)
		return "https://rpc.testnet.near.org"
	}
}

func networkLabel(network, override string) string {
	if override != "" {
		return override
	}
	return network
}

func explorerURL(network, hash string) string {
	switch network {
	case "mainnet":
		return "https://nearblocks.io/txns/" + hash
	default: // testnet
		return "https://testnet.nearblocks.io/txns/" + hash
	}
}

// yoctoToNEARString renders a yoctoNEAR big.Int as a decimal NEAR string, purely
// for the human-readable print line (24 fractional digits, trimmed).
func yoctoToNEARString(yocto *big.Int) string {
	denom := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil)
	whole := new(big.Int)
	frac := new(big.Int)
	whole.QuoRem(yocto, denom, frac)
	fracStr := frac.String()
	for len(fracStr) < 24 { // left-pad to 24 digits ('0' flag is ignored for %s)
		fracStr = "0" + fracStr
	}
	fracStr = strings.TrimRight(fracStr, "0")
	if fracStr == "" {
		return whole.String()
	}
	return whole.String() + "." + fracStr
}

func isMainnet(network string) bool { return network == "mainnet" }

// latestBlockHash fetches a recent final block hash via a raw JSON-RPC call with
// a lenient decode (ignoring unknown fields), bypassing the library's strict
// block decoder. It supplies the transaction's reference block hash.
func latestBlockHash(ctx context.Context, endpoint string) (hash.CryptoHash, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	const body = `{"jsonrpc":"2.0","id":"blk","method":"block","params":{"finality":"final"}}`
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return hash.CryptoHash{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return hash.CryptoHash{}, err
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			Header struct {
				Hash string `json:"hash"`
			} `json:"header"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return hash.CryptoHash{}, err
	}
	if out.Result.Header.Hash == "" {
		return hash.CryptoHash{}, fmt.Errorf("no block hash in response (error: %s)", strings.TrimSpace(string(out.Error)))
	}
	return hash.NewCryptoHashFromBase58(out.Result.Header.Hash)
}
