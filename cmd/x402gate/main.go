// Command x402gate is a proof-of-concept payer-side gate for x402 agentic
// payments on the XRP Ledger. x402 settles a payment; this gate decides whether
// the agent is AUTHORIZED to make it before it signs anything.
//
// Given an x402 payment requirement (price, currency, merchant pay-to address)
// and the agent's capability ceiling, it mints a real CAT -> CT -> SPT-Txn chain
// for the corresponding XRPL Payment and runs the eight-step verifier:
//
//   - If the payment is within the agent's capability scope, the gate ALLOWS it
//     and emits the humanAnchor (a zero-knowledge commitment to the accountable
//     person) as the XRPL Payment Memo, plus the SourceTag and the
//     spt_txn_context_hash — so the on-ledger payment is accountable and (for
//     regulated transfers) Travel-Rule-bindable, with no PII on the wire.
//   - If the payment exceeds the agent's scope, the SPT-Txn mint is refused and
//     the gate DENIES it: the agent must not sign the x402 payment.
//
// This is the SPT-Txn x402 payer-gate milestone: it reuses the same offline
// authorization engine as cmd/anchor. It does NOT submit anything to the network
// or call x402 facilitators; wiring it into T54's Python `x402-xrpl` client (so
// the gate runs before `x402_requests` signs the Payment) is the integration
// step. Nothing here contacts a ledger.
//
//	go run ./cmd/x402gate -price 1000 -ceiling 5000            # ALLOW
//	go run ./cmd/x402gate -price 9000 -ceiling 5000            # DENY (over scope)
//	go run ./cmd/x402gate -price 0.5 -currency RLUSD -ceiling 100
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

const (
	issOrg     = "domain-a.authorg"
	issTTS     = "domain-a.tts"
	aud        = "domain-b.execorg"
	htm        = "POST"
	htu        = "https://foss.violetskysecurity.com/b/verify"
	agentAddr  = "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT" // the payer agent's XRPL account
	defaultPay = "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW" // a sample merchant pay-to
)

func main() {
	price := flag.String("price", "1000", "x402 price to pay (XRP/drops or RLUSD amount, as the merchant declares)")
	currency := flag.String("currency", "XRP", "payment currency: XRP or RLUSD")
	payto := flag.String("payto", defaultPay, "merchant XRPL pay-to (classic r-address)")
	ceiling := flag.Float64("ceiling", 5000, "the agent's capability ceiling (max it may spend under its CT)")
	sourceTag := flag.String("sourcetag", "402", "x402 SourceTag stamped on the Payment")
	flag.Parse()

	l, err := ledger.Get("xrpl")
	if err != nil {
		log.Fatalf("xrpl adapter: %v", err)
	}

	// ── Trust Registry + issuer keys (held locally by the verifier) ────
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		log.Fatal(err)
	}
	orgPub, orgPriv := genKey()
	ttsPub, ttsPriv := genKey()
	holderPub, holderPriv := genKey()
	mustReg(reg, issOrg, trustregistry.RoleCTIssuer, orgPub)
	mustReg(reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	// ── The agent's authority: CAT -> CT bounded by the ceiling ────────
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issOrg, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": *ceiling, "currency": *currency},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: holderPub,
	}, orgPriv)
	if err != nil {
		log.Fatalf("CAT: %v", err)
	}
	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issOrg, ParentCAT: cat.Token, ParentIssuerKey: orgPub,
		RequestedScope:  tbac.Scope{"max_amount": *ceiling, "currency": *currency},
		HolderPublicKey: holderPub,
	}, orgPriv)
	if err != nil {
		log.Fatalf("CT: %v", err)
	}

	anchor := cat.HumanAnchor.String()

	// ── The x402 payment, as an XRPL Payment context. The humanAnchor is
	//    carried in the Memo so it is bound into the spt_txn_context_hash. ──
	tc := ledger.TxnContext{
		Chain: "xrpl", Originator: agentAddr, Beneficiary: *payto,
		Amount: *price, Currency: *currency, Timestamp: time.Now().Unix(),
		Extra: map[string]string{"DestinationTag": *sourceTag, "Memo": anchor},
	}

	fmt.Println("SPT-Txn × x402 payer-gate (XRPL)")
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("  x402 requirement     : pay %s %s to %s (SourceTag %s)\n", *price, *currency, *payto, *sourceTag)
	fmt.Printf("  agent capability     : up to %.0f %s under its CT\n", *ceiling, *currency)

	// ── Gate: mint the SPT-Txn for this payment. Scope is enforced at mint;
	//    an over-ceiling payment is refused here — that is the gate saying NO. ──
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: ct.Token, ParentIssuerKey: orgPub,
		HolderPublicKey: holderPub, Ledger: l, Txn: tc,
	}, ttsPriv)
	if err != nil {
		fmt.Println()
		fmt.Printf("  GATE: DENY — the agent must NOT sign this x402 payment.\n")
		fmt.Printf("  reason: payment is outside the agent's capability scope (%v)\n", err)
		return
	}

	// ── Verify the whole chain offline for this exact payment ──────────
	proof, err := dpop.Proof(holderPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		log.Fatalf("dpop: %v", err)
	}
	d := verifier.New(reg).Verify(context.Background(), verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{ct.Token}, CAT: cat.Token, Txn: tc, Audience: aud,
	})
	if !d.Allow {
		fmt.Println()
		fmt.Printf("  GATE: DENY — verification failed at step %d (%s): %s\n", d.Step, d.StepName, d.Reason)
		return
	}

	_, ctxHash, err := ledger.ContextHash(l, tc)
	if err != nil {
		log.Fatalf("context hash: %v", err)
	}

	fmt.Println()
	fmt.Printf("  GATE: ALLOW — agent is authorized; sign the x402 payment and stamp:\n")
	fmt.Printf("    XRPL Payment.Destination     : %s\n", *payto)
	fmt.Printf("    XRPL Payment.Amount          : %s %s\n", *price, *currency)
	fmt.Printf("    XRPL Payment.SourceTag       : %s\n", *sourceTag)
	fmt.Printf("    XRPL Payment.Memos[0] (anchor): %s\n", anchor)
	fmt.Printf("    spt_txn_context_hash         : %s\n", ctxHash)
	fmt.Println()
	fmt.Println("  → accountable to one human (zero-knowledge anchor), scope-bounded,")
	fmt.Println("    and Travel-Rule-bindable — with no PII on the XRP Ledger.")
}

func genKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return pub, priv
}

func mustReg(reg *trustregistry.MockRegistry, iss string, role trustregistry.Role, pub ed25519.PublicKey) {
	err := reg.Register(context.Background(), &trustregistry.Record{
		Iss: iss, Role: role, PublicKey: pub, KeyType: "Ed25519",
		ValidFrom:  time.Now().Add(-time.Hour),
		ValidUntil: time.Now().Add(time.Hour),
		Status:     trustregistry.StatusActive,
	})
	if err != nil {
		log.Fatalf("register %s/%s: %v", iss, role, err)
	}
}
