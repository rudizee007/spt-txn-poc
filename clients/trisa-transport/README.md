# spt-txn-trisa-transport

TRISA **Secure Envelope** transport for SPT-Txn Travel Rule payloads. Separate Go
module so the gRPC/GDS/mTLS dependencies (when added) stay out of the
dependency-light core.

## What's built (pure stdlib, fully tested offline)

The **sealing scheme**, mirroring TRISA's `SecureEnvelope`:

- payload encrypted with **AES-256-GCM** (random nonce prepended to ciphertext);
- **HMAC-SHA256** over the ciphertext, verified constant-time *before* decryption;
- the AES key and HMAC secret each sealed to the recipient's RSA public key with
  **RSA-OAEP/SHA-256**.

```go
env, _ := trisatransport.Seal(payloadJSON, recipientPub, "key-1") // sender
plain, _ := trisatransport.Open(env, recipientPriv)               // recipient
```

`Seal`/`Open` are transport-agnostic and need no network. Tests cover round-trip,
tampered-payload (HMAC fail), wrong-key, bad-algorithm, and not-sealed.

```
go test ./...
```

## What it carries

The `payload` bytes are the SPT-Txn Travel Rule payload produced by the core
module's `internal/trisa` bridge (the SD-JWT selective disclosure + the three
Groth16 proofs + `txn_context_hash`), marshalled to JSON. Sealing them yields
**defence in depth**: SPT-Txn's zero-knowledge controls *what* the counterparty
can compute; TRISA sealing adds confidentiality at rest and crypto-erasure.

## What's scoped, not built (cert-gated — your action)

`transport.go` defines the `Transport` interface (`KeyExchange`, `Lookup`,
`Transfer`) that the network layer implements. A concrete gRPC implementation
needs, and is deliberately deferred until you have:

- a TRISA **identity certificate** registered at `trisa.directory`,
- the **TRISA Go SDK** + grpc + protobuf,
- **mutual-TLS** to the counterparty node,
- **GDS** (Global Directory Service) counterparty resolution.

None of those are needed to build, test, or audit the sealing scheme. Implement
`Transport` in a separate/build-tagged package once certificate onboarding is
done; `SendSealed` already encodes the correct resolve→seal→send ordering so a
caller cannot send an unsealed payload by mistake.

## Security notes

- HMAC is verified before GCM decryption (no decrypt-on-unauthenticated-data).
- 2048-bit RSA is used in tests for speed; production uses the counterparty's
  certificate key from GDS (typically ≥3072-bit or the cert's actual key).
- This module does **not** terminate TLS or validate certificate chains — that is
  the network layer's job (mTLS + the TRISA trust chain).
