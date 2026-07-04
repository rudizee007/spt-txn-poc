// Command sol-pay submits a real Solana SOL transfer from an x402gate ALLOW
// decision — the Solana analog of clients/xrpl-pay / clients/hedera-pay /
// clients/aptos-pay / clients/eth-pay (P0-S).
//
// The offline core (cmd/gatesvc) decides IF the agent may pay; this tool settles
// the SOL transfer on Solana. Solana is NOT EVM — ed25519 keys, base58 addresses,
// and lamports — which makes it the sharpest test of the blockchain-agnostic
// adapter boundary: the gate/verifier/merchant are unchanged, only this ~200-line
// submitter is new.
//
// The humanAnchor rides ON-CHAIN via an SPL Memo instruction (program
// MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr) attached to the same transaction —
// visible on Solana explorers, matching XRPL/Hedera/Ethereum (unlike Aptos, which
// has no memo and binds the anchor only in the attestation context hash). The
// context-hash binding (verifier step 8) is unchanged either way.
//
// Lives in its own module so the Solana SDK never enters the offline core.
//
// Credentials (env only — never a flag, never the repo):
//
//	SOL_OPERATOR_KEY   the payer's ed25519 secret key, in any of:
//	                     - base58 (Phantom "export private key")
//	                     - a JSON array of 64 bytes ([12,34,...]) — solana-keygen format
//	                     - a path to a solana-keygen id.json file
//
// Security:
//   - Default network is DEVNET (fund with `solana airdrop 1`). Mainnet requires
//     -network mainnet AND a confirmation prompt (skipped with -yes or -json).
//   - -dry-run derives the address and prints the transfer without any network call.
//
// -amount is in LAMPORTS (1 SOL = 1,000,000,000 lamports), mirroring
// drops/tinybars/octas/wei so the gate ceiling/price numbers carry over unchanged.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
)

const opKeyEnv = "SOL_OPERATOR_KEY"

// SPL Memo program (v2). Attaching this instruction writes the humanAnchor to the
// ledger where any explorer / indexer can read it, with no custom program.
var memoProgramID = solana.MustPublicKeyFromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

func main() {
	network := flag.String("network", "devnet", "solana network: devnet | testnet | mainnet")
	endpoint := flag.String("endpoint", "", "override the RPC endpoint (default: the network's public RPC)")
	to := flag.String("to", "", "destination base58 address (required)")
	amount := flag.String("amount", "", "amount in LAMPORTS (required); 1 SOL = 1,000,000,000 lamports")
	currency := flag.String("currency", "SOL", "currency: SOL (SPL/Token-2022 is a later step)")
	memo := flag.String("memo", "", "humanAnchor written to the tx via the SPL Memo program (on-chain), from x402gate ALLOW")
	jsonOut := flag.Bool("json", false, "print only a machine-readable JSON result to stdout (for cmd/agent)")
	whoami := flag.Bool("whoami", false, "print the operator address derived from $SOL_OPERATOR_KEY and exit")
	yes := flag.Bool("yes", false, "skip the mainnet confirmation prompt (non-interactive use)")
	dryRun := flag.Bool("dry-run", false, "derive the address and print the transfer without submitting")
	// Accepted for cmd/agent compatibility; not used on Solana.
	_ = flag.String("sourcetag", "", "ignored on Solana (agent compatibility)")
	_ = flag.String("context-hash", "", "ignored on Solana (agent compatibility)")
	flag.Parse()

	priv, err := loadKey()
	if err != nil {
		log.Fatal(err)
	}
	from := priv.PublicKey()
	if *whoami {
		fmt.Println(from.String())
		return
	}

	if *to == "" || *amount == "" {
		log.Fatal("both -to and -amount are required")
	}
	if strings.ToUpper(*currency) != "SOL" {
		log.Fatalf("currency %q not yet supported: only SOL for now (SPL/Token-2022 later)", *currency)
	}
	lamports, err := strconv.ParseUint(strings.TrimSpace(*amount), 10, 64)
	if err != nil || lamports == 0 {
		log.Fatalf("-amount must be a positive integer of lamports, got %q", *amount)
	}
	toAddr, err := solana.PublicKeyFromBase58(strings.TrimSpace(*to))
	if err != nil {
		log.Fatalf("-to %q is not a valid base58 Solana address: %v", *to, err)
	}
	if toAddr.Equals(from) {
		log.Fatal("sender and receiver must differ")
	}
	if len(*memo) > 566 {
		log.Fatalf("-memo exceeds the 566-byte SPL Memo limit (%d bytes)", len(*memo))
	}

	if !*jsonOut {
		fmt.Printf("sol-pay — %s\n", networkLabel(*network, *endpoint))
		fmt.Printf("  from (payer agent) : %s\n", from.String())
		fmt.Printf("  to (merchant)      : %s\n", toAddr.String())
		fmt.Printf("  amount             : %d lamports (%.9f SOL)\n", lamports, float64(lamports)/1e9)
		if *memo != "" {
			fmt.Printf("  memo[humanAnchor]  : %s (on-chain, SPL Memo)\n", *memo)
		}
	}
	if *dryRun {
		if *jsonOut {
			b, _ := json.Marshal(map[string]any{"dry_run": true, "from": from.String(), "to": toAddr.String(), "lamports": lamports, "memo": *memo})
			fmt.Println(string(b))
			return
		}
		fmt.Println("\n  -dry-run: not connecting, not submitting.")
		return
	}

	if isMainnet(*network) && !*jsonOut && !*yes {
		fmt.Printf("\n⚠  REAL payment on Solana MAINNET: %d lamports to %s\n   type 'yes' to proceed: ", lamports, toAddr.String())
		var resp string
		_, _ = fmt.Scanln(&resp)
		if strings.TrimSpace(resp) != "yes" {
			log.Fatal("aborted (not confirmed)")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := rpc.New(rpcEndpoint(*network, *endpoint))

	recent, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		log.Fatalf("latest blockhash: %v", err)
	}

	instructions := []solana.Instruction{
		system.NewTransferInstruction(lamports, from, toAddr).Build(),
	}
	if *memo != "" {
		instructions = append(instructions, memoInstruction{signer: from, data: []byte(*memo)})
	}

	tx, err := solana.NewTransaction(instructions, recent.Value.Blockhash, solana.TransactionPayer(from))
	if err != nil {
		log.Fatalf("build tx: %v", err)
	}
	if _, err := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(from) {
			return &priv
		}
		return nil
	}); err != nil {
		log.Fatalf("sign: %v", err)
	}

	sig, err := client.SendTransaction(ctx, tx)
	if err != nil {
		log.Fatalf("send: %v", err)
	}
	confirm(ctx, client, sig) // best-effort; non-fatal on lag
	explorer := explorerURL(*network, sig.String())

	if *jsonOut {
		b, _ := json.Marshal(map[string]any{"tx_hash": sig.String(), "explorer": explorer, "status": "submitted"})
		fmt.Println(string(b))
		return
	}
	fmt.Printf("\n  SUBMITTED\n")
	fmt.Printf("    signature : %s\n", sig.String())
	fmt.Printf("    explorer  : %s\n", explorer)
}

// confirm polls the signature status until it is confirmed/finalized, or the
// context expires. Non-fatal: like XRPL's load-balanced nodes, a status lag does
// not mean the transfer failed — the signature + explorer link are authoritative.
func confirm(ctx context.Context, client *rpc.Client, sig solana.Signature) {
	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		out, err := client.GetSignatureStatuses(ctx, true, sig)
		if err == nil && out != nil && len(out.Value) > 0 && out.Value[0] != nil {
			st := out.Value[0]
			if st.Err != nil {
				log.Printf("warning: transaction reported an error on-chain: %v", st.Err)
				return
			}
			if st.ConfirmationStatus == rpc.ConfirmationStatusConfirmed ||
				st.ConfirmationStatus == rpc.ConfirmationStatusFinalized {
				return
			}
		}
		time.Sleep(time.Second)
	}
}

// memoInstruction is a minimal SPL Memo program instruction: the program ID, the
// payer as a signer account, and the raw UTF-8 memo bytes as instruction data.
type memoInstruction struct {
	signer solana.PublicKey
	data   []byte
}

func (m memoInstruction) ProgramID() solana.PublicKey { return memoProgramID }
func (m memoInstruction) Accounts() []*solana.AccountMeta {
	return []*solana.AccountMeta{{PublicKey: m.signer, IsSigner: true, IsWritable: false}}
}
func (m memoInstruction) Data() ([]byte, error) { return m.data, nil }

// loadKey reads the payer ed25519 secret key from $SOL_OPERATOR_KEY, accepting
// base58, a solana-keygen JSON byte array, or a path to an id.json file.
func loadKey() (solana.PrivateKey, error) {
	raw := strings.TrimSpace(os.Getenv(opKeyEnv))
	if raw == "" {
		return nil, fmt.Errorf("set %s in the environment (never a flag or the repo)", opKeyEnv)
	}
	switch {
	case strings.HasPrefix(raw, "["): // solana-keygen JSON array of 64 bytes
		var nums []int
		if err := json.Unmarshal([]byte(raw), &nums); err != nil {
			return nil, fmt.Errorf("%s: parse JSON key array: %w", opKeyEnv, err)
		}
		b := make([]byte, len(nums))
		for i, n := range nums {
			b[i] = byte(n)
		}
		if len(b) != 64 {
			return nil, fmt.Errorf("%s: JSON key must be 64 bytes, got %d", opKeyEnv, len(b))
		}
		return solana.PrivateKey(b), nil
	case fileExists(raw): // path to a solana-keygen id.json
		priv, err := solana.PrivateKeyFromSolanaKeygenFile(raw)
		if err != nil {
			return nil, fmt.Errorf("%s (keygen file %q): %w", opKeyEnv, raw, err)
		}
		return priv, nil
	default: // base58 (Phantom export)
		priv, err := solana.PrivateKeyFromBase58(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: not base58/JSON/keyfile: %w", opKeyEnv, err)
		}
		return priv, nil
	}
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func rpcEndpoint(network, override string) string {
	if override != "" {
		return override
	}
	switch network {
	case "devnet":
		return rpc.DevNet_RPC
	case "testnet":
		return rpc.TestNet_RPC
	case "mainnet", "mainnet-beta":
		return rpc.MainNetBeta_RPC
	default:
		log.Fatalf("unknown network %q (want devnet|testnet|mainnet)", network)
		return rpc.DevNet_RPC
	}
}

func networkLabel(network, override string) string {
	if override != "" {
		return override
	}
	return network
}

func explorerURL(network, sig string) string {
	switch network {
	case "devnet":
		return "https://explorer.solana.com/tx/" + sig + "?cluster=devnet"
	case "testnet":
		return "https://explorer.solana.com/tx/" + sig + "?cluster=testnet"
	default: // mainnet
		return "https://explorer.solana.com/tx/" + sig
	}
}

func isMainnet(network string) bool { return network == "mainnet" || network == "mainnet-beta" }
