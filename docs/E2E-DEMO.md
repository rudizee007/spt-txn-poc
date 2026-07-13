# SPT-Txn end-to-end demo

Two ways to see the system work: a one-command guided tour that runs the whole
story in-process, and the individual services wired the way a real deployment
would use them. (For on-chain / host operational procedures see `RUNBOOK.md`.)

## 1. The guided tour (one command)

```sh
go run ./cmd/spt-demo
```

It runs, with real cryptography and narration, the full arc:

1. **Attest** a workload's SPIFFE JWT-SVID.
2. **Seal** that attestation into a root Compliance Attestation Token (CAT).
3. **Delegate** agent to sub-agent, scope attenuating at each hop (10000, 8000, 5000 USD).
4. The sub-agent **declares an intent** and mints a transaction token bound to it.
5. **Verify offline** (signatures, attenuation, freshness, status list): **ALLOW**.
6. **Emit a signed receipt** into the append-only transparency log.
7. **Revoke** the leaf via the status list; an equivalent request now **DENIES**.
8. **Goal hijack**: the same valid token used for a different call; intent binding **DENIES** it.
9. **Witnesses co-sign** the log's tree head; a **rewritten history is refused**.
10. **Export** the receipt to NIST 800-53 / DORA / SOC2 control evidence.
11. **Crypto-agility**: rewriting the suite id fails, because it is covered by the signature.

Exit code 0, with a green ALLOW and red DENY in the narration, means every
property held. This is the "watch it work" artifact; the package tests are the
exhaustive proof underneath it.

## 2. The services, wired

### Attested issuance (workload identity to CAT)

`cmd/workload-bridge` is an RFC 8693 exchange endpoint. A workload presents an
attested identity (SPIFFE JWT/X.509-SVID, K8s ServiceAccount token, or a cloud
workload-identity OIDC assertion) and receives a CAT with the attestation
sealed. Human-identity issuance (OIDC IdP to CAT) is the sibling
`cmd/idp-bridge` (proven against Keycloak and Auth0; the same standard flow
targets Okta / Ping / Janssen).

```sh
SPT_WL_AUDIENCE=spt-txn-exchange \
SPT_WL_ISSUER=https://kubernetes.default.svc \
SPT_WL_JWKS_FILE=/path/to/trust-bundle.jwks \
go run ./cmd/workload-bridge
# POST /token  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
#              subject_token=<assertion> subject_token_type=urn:violetsky:token-type:k8s-sa
#              audience=spt-txn-exchange holder_key_hex=<64 hex>
```

### Enforcement point (the gateway skins)

One decision core, three stateless skins; pick the one your platform speaks:

```sh
# Envoy ext_authz (HTTP mode)
go run ./cmd/extauthz  -upstream mcp://payments -tts-pub <hex> -log-key-file key.hex -policy-hash <hex>
# OPA-compatible decision API
go run ./cmd/opashim   -tts-pub <hex> -log-key-file key.hex -policy-hash <hex>
# Envoy ext_authz (gRPC mode); needs the Envoy protos, see below
go build -tags envoygrpc ./cmd/grpc-extauthz/ && ./grpc-extauthz -upstream mcp://payments ...
```

All three strip the token before forwarding (no credential passthrough) and emit
a receipt per decision. p99 of the decision path is about 72 microseconds
(`go test -run TestDecideP99Budget ./internal/decision/`), well inside the 10ms
budget.

### Evidence: verify a receipt, export controls

```sh
# prove one control fired at one transaction, offline
go run ./cmd/receiptverify -receipt r.json -logpub <hex> [-log audit.jsonl -root root.json]
# export the log to auditor-consumable control evidence
go run ./cmd/receiptexport -log audit.jsonl -format csv     # or -framework EU-DORA
```

## 3. Verify everything

```sh
sh scripts/verify-p1p2p3p6.sh     # vet, unit + property tests, fuzz smoke, full build, govulncheck
go test ./internal/conformance/   # cross-implementation vectors (Go matches an independent impl)
```

## Optional: gRPC ext_authz (build-tagged, heavy deps — think before enabling)

The gRPC Envoy `ext_authz` filter lives in `cmd/grpc-extauthz` behind the
`envoygrpc` build tag, so it never affects the default build. **Prefer the HTTP
`ext_authz` skin (`cmd/extauthz`) unless you specifically need the gRPC filter**
— it covers Envoy/Istio without any of the cost below.

Enabling gRPC is a deliberate operation, not a casual `go get`:

- It pulls ~8 modules (go-control-plane, grpc, genproto, cncf/xds, vtprotobuf,
  protoc-gen-validate, …) into the module graph.
- Those deps upgrade `golang.org/x/crypto`, which then **desyncs the `go.sum`
  entries the pinned gnark (poseidon2 / groth16 bn254) ZK stack depends on** —
  so a naive `go get` breaks the ZK build until `go.sum` is reconciled.

If you genuinely need it, do it deliberately and re-verify the ZK paths:

```sh
go get github.com/envoyproxy/go-control-plane/envoy/service/auth/v3@latest google.golang.org/grpc@latest
go get github.com/consensys/gnark/backend/groth16/bn254@v0.15.0   # re-pin the ZK go.sum
go mod tidy
go build -tags envoygrpc ./cmd/grpc-extauthz/
go test  -tags envoygrpc ./cmd/grpc-extauthz/
sh scripts/verify-p1p2p3p6.sh   # confirm the x/crypto bump didn't break anything else
```

To back it all out and keep the core lean: `git checkout go.mod go.sum`.
