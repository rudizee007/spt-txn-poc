// Command hcs-anchor anchors an SPT-Txn context hash or audit-log Merkle root to
// a Hedera Consensus Service (HCS) topic, and verifies anchors via the public
// mirror node. It is Hedera grant milestone A1.
//
// It deliberately lives OUTSIDE the SPT-Txn authorization core, in its own Go
// module: the verifier/token packages never import the Hedera SDK (the
// blockchain-agnostic invariant). This client holds the Hedera operator
// credentials and submits transactions; the core does not. The hash it anchors
// is produced by the main module's `cmd/anchor` (the real spt_txn_context_hash),
// or is an audit-log Merkle root.
//
// Credentials come from the ENVIRONMENT, never flags (flags leak via the process
// list and shell history):
//
//	HEDERA_OPERATOR_ID    e.g. 0.0.12345
//	HEDERA_OPERATOR_KEY   the operator private key string
//
// Subcommands:
//
//	hcs-anchor create-topic [-network testnet]
//	hcs-anchor anchor  -topic 0.0.X -type ctx -hash <64hex> [-network testnet]
//	hcs-anchor verify  -topic 0.0.X -hash <64hex>           [-network testnet]   (keyless)
//
// create-topic and anchor require the operator credentials + HBAR (your action).
// verify uses only the public mirror node — no key, no cost.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "create-topic":
		fs := flag.NewFlagSet("create-topic", flag.ExitOnError)
		network := fs.String("network", "testnet", "testnet|mainnet|previewnet")
		_ = fs.Parse(os.Args[2:])
		err = cmdCreateTopic(*network)
	case "anchor":
		fs := flag.NewFlagSet("anchor", flag.ExitOnError)
		network := fs.String("network", "testnet", "testnet|mainnet|previewnet")
		topic := fs.String("topic", "", "HCS topic id, e.g. 0.0.12345")
		typ := fs.String("type", "ctx", "anchor type: ctx (context hash) | audit (audit root)")
		hash := fs.String("hash", "", "32-byte hash in hex (the spt_txn_context_hash or audit root)")
		_ = fs.Parse(os.Args[2:])
		err = cmdAnchor(*network, *topic, *typ, *hash)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		network := fs.String("network", "testnet", "testnet|mainnet|previewnet")
		topic := fs.String("topic", "", "HCS topic id, e.g. 0.0.12345")
		hash := fs.String("hash", "", "32-byte hash in hex to look for")
		_ = fs.Parse(os.Args[2:])
		err = cmdVerify(*network, *topic, *hash)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `hcs-anchor — anchor SPT-Txn hashes to Hedera Consensus Service (milestone A1)

  hcs-anchor create-topic [-network testnet]
  hcs-anchor anchor  -topic 0.0.X -type ctx -hash <64hex> [-network testnet]
  hcs-anchor verify  -topic 0.0.X -hash <64hex>           [-network testnet]   (keyless)

create-topic / anchor read HEDERA_OPERATOR_ID and HEDERA_OPERATOR_KEY from the environment.
verify uses only the public mirror node (no key, no cost).
`)
}

// newClient builds a network client with the operator from the environment.
// Used only by the write subcommands; verify never calls it.
func newClient(network string) (*hiero.Client, error) {
	var client *hiero.Client
	switch network {
	case "testnet":
		client = hiero.ClientForTestnet()
	case "mainnet":
		client = hiero.ClientForMainnet()
	case "previewnet":
		client = hiero.ClientForPreviewnet()
	default:
		return nil, fmt.Errorf("unknown network %q (want testnet|mainnet|previewnet)", network)
	}
	idStr, keyStr := os.Getenv("HEDERA_OPERATOR_ID"), os.Getenv("HEDERA_OPERATOR_KEY")
	if idStr == "" || keyStr == "" {
		return nil, fmt.Errorf("set HEDERA_OPERATOR_ID and HEDERA_OPERATOR_KEY in the environment")
	}
	opID, err := hiero.AccountIDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("HEDERA_OPERATOR_ID: %w", err)
	}
	opKey, err := hiero.PrivateKeyFromString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("HEDERA_OPERATOR_KEY: %w", err)
	}
	client.SetOperator(opID, opKey)
	return client, nil
}

func cmdCreateTopic(network string) error {
	client, err := newClient(network)
	if err != nil {
		return err
	}
	defer client.Close()

	resp, err := hiero.NewTopicCreateTransaction().
		SetTopicMemo("spt-txn anchor topic").
		Execute(client)
	if err != nil {
		return fmt.Errorf("create topic: %w", err)
	}
	receipt, err := resp.GetReceipt(client)
	if err != nil {
		return fmt.Errorf("create topic receipt: %w", err)
	}
	if receipt.TopicID == nil {
		return fmt.Errorf("no topic id in receipt (status %s)", receipt.Status)
	}
	fmt.Printf("created HCS topic %s on %s\n", receipt.TopicID.String(), network)
	fmt.Printf("anchor to it with:  hcs-anchor anchor -network %s -topic %s -type ctx -hash <64hex>\n", network, receipt.TopicID.String())
	return nil
}

func cmdAnchor(network, topic, typ, hash string) error {
	if topic == "" {
		return fmt.Errorf("-topic is required")
	}
	env, err := NewEnvelope(AnchorType(typ), hash)
	if err != nil {
		return err
	}
	msg, err := env.Bytes()
	if err != nil {
		return err
	}
	client, err := newClient(network)
	if err != nil {
		return err
	}
	defer client.Close()

	topicID, err := hiero.TopicIDFromString(topic)
	if err != nil {
		return fmt.Errorf("topic id %q: %w", topic, err)
	}
	resp, err := hiero.NewTopicMessageSubmitTransaction().
		SetTopicID(topicID).
		SetMessage(msg).
		Execute(client)
	if err != nil {
		return fmt.Errorf("submit message: %w", err)
	}
	receipt, err := resp.GetReceipt(client)
	if err != nil {
		return fmt.Errorf("submit receipt: %w", err)
	}
	fmt.Printf("anchored %s hash %s to topic %s (status %s)\n", env.Type, env.Hash, topic, receipt.Status)
	fmt.Printf("confirm the durable, keyless proof (consensus timestamp + sequence) with:\n")
	fmt.Printf("  hcs-anchor verify -network %s -topic %s -hash %s\n", network, topic, env.Hash)
	return nil
}

func cmdVerify(network, topic, hash string) error {
	if topic == "" || hash == "" {
		return fmt.Errorf("-topic and -hash are required")
	}
	proof, err := VerifyOnMirror(network, topic, hash, 25*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("ANCHORED  type=%s hash=%s\n", proof.Type, proof.Hash)
	fmt.Printf("  topic               : %s\n", proof.TopicID)
	fmt.Printf("  sequence number     : %d\n", proof.SequenceNumber)
	fmt.Printf("  consensus timestamp : %s\n", proof.ConsensusTimestamp)
	return nil
}
