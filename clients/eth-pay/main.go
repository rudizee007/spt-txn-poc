// Command eth-pay submits a real EVM (Ethereum / L2) transfer from an x402gate
// ALLOW decision — the EVM analog of the other chain submitters (P0-E). One
// binary covers Ethereum L1 and every EVM L2; the network is chosen by -endpoint.
//
// Unlike Aptos, an EVM transaction has a `data` field, so the humanAnchor is
// written ON-CHAIN (visible on Etherscan as the tx input data) — matching
// XRPL/Hedera. The context-hash binding (verifier step 8) is unchanged.
//
// Lives in its own module so go-ethereum never enters the offline core.
//
// Credentials (env only — never a flag, never the repo):
//
//	ETH_OPERATOR_KEY   the payer's ECDSA private key (hex, 0x-optional)
//
// Security:
//   - Default endpoint is Sepolia (testnet). Any endpoint whose chain id is 1
//     (Ethereum mainnet) triggers a confirmation prompt (skipped with -yes/-json).
//   - -dry-run derives the address and prints the transfer without any network call.
//
// -amount is in WEI (1 ETH = 1e18 wei), mirroring drops/tinybars/octas.
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	opKeyEnv   = "ETH_OPERATOR_KEY"
	defaultRPC = "https://ethereum-sepolia-rpc.publicnode.com"
)

func main() {
	endpoint := flag.String("endpoint", defaultRPC, "EVM JSON-RPC endpoint (default Sepolia testnet)")
	to := flag.String("to", "", "destination address 0x… (20-byte) (required)")
	amount := flag.String("amount", "", "amount in WEI (required); 1 ETH = 1e18 wei")
	currency := flag.String("currency", "ETH", "currency: ETH (ERC-20 is a later step)")
	memo := flag.String("memo", "", "humanAnchor written to the tx data field (on-chain), from x402gate ALLOW")
	jsonOut := flag.Bool("json", false, "print only a machine-readable JSON result to stdout (for cmd/agent)")
	whoami := flag.Bool("whoami", false, "print the operator address derived from $ETH_OPERATOR_KEY and exit")
	yes := flag.Bool("yes", false, "skip the mainnet confirmation prompt (non-interactive use)")
	dryRun := flag.Bool("dry-run", false, "derive the address and print the transfer without submitting")
	// Accepted for cmd/agent compatibility; not used on EVM.
	_ = flag.String("sourcetag", "", "ignored on EVM (agent compatibility)")
	_ = flag.String("context-hash", "", "ignored on EVM (agent compatibility)")
	flag.Parse()

	key, from, err := loadKey()
	if err != nil {
		log.Fatal(err)
	}
	if *whoami {
		fmt.Println(from.Hex())
		return
	}

	if *to == "" || *amount == "" {
		log.Fatal("both -to and -amount are required")
	}
	if strings.ToUpper(*currency) != "ETH" {
		log.Fatalf("currency %q not yet supported: only ETH for now (ERC-20 later)", *currency)
	}
	value, ok := new(big.Int).SetString(strings.TrimSpace(*amount), 10)
	if !ok || value.Sign() < 0 {
		log.Fatalf("-amount must be a non-negative integer of wei, got %q", *amount)
	}
	if !common.IsHexAddress(*to) {
		log.Fatalf("-to %q is not a valid EVM address (0x + 40 hex)", *to)
	}
	toAddr := common.HexToAddress(*to)
	data := common.FromHex(ensure0x(*memo)) // humanAnchor bytes, on-chain

	if !*jsonOut {
		fmt.Printf("eth-pay — %s\n", *endpoint)
		fmt.Printf("  from (payer agent) : %s\n", from.Hex())
		fmt.Printf("  to (merchant)      : %s\n", toAddr.Hex())
		fmt.Printf("  amount             : %s wei\n", value.String())
		if *memo != "" {
			fmt.Printf("  data[humanAnchor]  : %s (on-chain)\n", *memo)
		}
	}
	if *dryRun {
		if *jsonOut {
			b, _ := json.Marshal(map[string]any{"dry_run": true, "from": from.Hex(), "to": toAddr.Hex(), "wei": value.String(), "data": *memo})
			fmt.Println(string(b))
			return
		}
		fmt.Println("\n  -dry-run: not connecting, not submitting.")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client, err := ethclient.DialContext(ctx, *endpoint)
	if err != nil {
		log.Fatalf("dial %s: %v", *endpoint, err)
	}
	defer client.Close()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		log.Fatalf("chain id: %v", err)
	}
	if chainID.Cmp(big.NewInt(1)) == 0 && !*jsonOut && !*yes {
		fmt.Printf("\n⚠  REAL payment on Ethereum MAINNET: %s wei to %s\n   type 'yes' to proceed: ", value.String(), toAddr.Hex())
		var resp string
		_, _ = fmt.Scanln(&resp)
		if strings.TrimSpace(resp) != "yes" {
			log.Fatal("aborted (not confirmed)")
		}
	}

	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		log.Fatalf("nonce: %v", err)
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		log.Fatalf("gas price: %v", err)
	}
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &toAddr,
		Value:    value,
		Gas:      30000, // plain transfer (21000) + a 32-byte data anchor headroom
		GasPrice: gasPrice,
		Data:     data,
	})
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), key)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	if err := client.SendTransaction(ctx, signedTx); err != nil {
		log.Fatalf("send: %v", err)
	}
	hash := signedTx.Hash().Hex()
	explorer := explorerURL(chainID, hash)

	if *jsonOut {
		b, _ := json.Marshal(map[string]any{"tx_hash": hash, "explorer": explorer, "status": "submitted"})
		fmt.Println(string(b))
		return
	}
	fmt.Printf("\n  SUBMITTED\n")
	fmt.Printf("    tx hash   : %s\n", hash)
	fmt.Printf("    chain id  : %s\n", chainID.String())
	fmt.Printf("    explorer  : %s\n", explorer)
}

func loadKey() (*ecdsa.PrivateKey, common.Address, error) {
	keyHex := strings.TrimPrefix(strings.TrimSpace(os.Getenv(opKeyEnv)), "0x")
	if keyHex == "" {
		return nil, common.Address{}, fmt.Errorf("set %s in the environment (never a flag or the repo)", opKeyEnv)
	}
	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("%s: %w", opKeyEnv, err)
	}
	return key, crypto.PubkeyToAddress(key.PublicKey), nil
}

func explorerURL(chainID *big.Int, hash string) string {
	switch chainID.Int64() {
	case 1:
		return "https://etherscan.io/tx/" + hash
	case 11155111:
		return "https://sepolia.etherscan.io/tx/" + hash
	default:
		return fmt.Sprintf("(chain id %s) tx %s", chainID.String(), hash)
	}
}

func ensure0x(s string) string {
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s
	}
	return "0x" + s
}
