# Key-custody plan — encrypted key volume on OpenBSD (runbook)

> Status 2026-06-30: **planned, not urgent** (current keys are testnet-only; H4 in
> SECURITY-REVIEW.md is MITIGATED via perms + pledge/unveil, encryption-at-rest
> DEFERRED). This is the near-term encryption-at-rest step. HSM is the parallel/better
> track for the signing key (§6). Companion to `FIPS-140-3-PLAN.md`.

---

## 0. Storage baseline (measured 2026-06-30)

- Host `foss`: single **~50 GB `sd0`**, **fully partitioned — no free space, no 2nd disk**.
- `/usr` at 87% (264 MB free) — steady state (base OS, doesn't grow; packages go to the
  separate `/usr/local`, 5 GB free). No action needed.
- `/var` at 2% — healthy. Swap is already encrypted (OpenBSD default).
- **Therefore any new encrypted volume must be an *attached* provider block volume**
  (appears as `sd1`); it cannot be carved out of `sd0`, and no rebuild is required.

## 1. Design decision (read before doing anything)

Real at-rest protection on a VPS requires the **unlock passphrase to live off the box**
(operator's head / a secrets manager), which makes **reboots attended**. Scope the work
so that attended-unlock does not take down the public website:

| Material | Encrypt on the crypto volume? | Why |
|---|---|---|
| Issuer signing keys (`*.sec`), escrow keys | **Yes** | High value; the SPT-Txn services they gate can be started manually after a reboot |
| Audit trail / any PII / escrow envelopes | **Yes** | Sensitive data at rest |
| TLS cert key (`/etc/ssl/private/foss…key`) | **No — leave on root** | Reissuable via certbot; keep relayd/httpd auto-starting (no attended TLS) |
| Non-secret config / binaries | No | Not sensitive |

**Do NOT** store the unlock keydisk on `sd0` — that defeats the purpose (a disk snapshot
would contain both the keydisk and the encrypted volume). Passphrase, or an external
keydisk only.

## 2. Prerequisites / choices to make

- **Volume size:** small is fine — 5 GB covers keys + audit data comfortably.
- **Unlock method:** **passphrase** (recommended; nothing stored on host) → attended
  reboots. Accept that the SPT-Txn signing/issuer services must be **started manually
  after each reboot** (do not enable them in `rc.d` autostart if they need the keys).
- **Change window:** brief service downtime while keys move (steps 6–8).

## 3. Attach and identify the volume

```sh
# In the provider panel: attach a new block volume to the instance.
dmesg | tail                       # watch for the new disk
sysctl hw.disknames                # confirm sd1 now appears
doas disklabel sd1                 # confirm size, empty
```

## 4. Create the softraid CRYPTO volume

```sh
# 4a. Put a RAID partition spanning the new disk
doas fdisk -iy sd1                 # write a fresh MBR
doas disklabel -E sd1
#   in the editor:  a  →  partition a, offset default, size '*', FS type: RAID  →  w  →  q

# 4b. Create the encrypted (CRYPTO) volume — prompts for a passphrase (twice)
doas bioctl -c C -l /dev/sd1a softraid0
#   note the new device it creates, e.g. "sd2" (check: dmesg | tail)

# 4c. Put a filesystem on the crypto device
doas disklabel -E sd2
#   a  →  partition a, size '*', FS type 4.2BSD  →  w  →  q
doas newfs /dev/sd2a
```

## 5. Mount and lock down

```sh
doas mkdir -p /secure                     # mount point for the encrypted volume
doas mount /dev/sd2a /secure
doas chmod 700 /secure
```

## 6. Move the keys (brief downtime)

```sh
# 6a. Identify current key paths first (issuer signify/Ed25519 *.sec, escrow keys).
#     e.g. find them:
doas find / -xdev -name '*.sec' 2>/dev/null

# 6b. Stop the services that hold the keys (adjust to your rc.d names)
doas rcctl stop trsvc agentverify        # example service names

# 6c. Move keys onto the encrypted volume, preserving perms
doas mkdir -p /secure/keys
doas mv /path/to/keys/*.sec /secure/keys/
doas chown <svcuser>:<svcgroup> /secure/keys/*.sec
doas chmod 0400 /secure/keys/*.sec
```

## 7. Repoint services + unveil to the new path

- Update each service's **key path** (config/env/flags) to `/secure/keys/…`.
- Update each service's **`unveil()`** allow-list to include `/secure/keys` (read-only)
  and remove the old path — so the pledge/unveil sandbox still confines each service to
  only its own key on the new volume.
- If a service auto-starts at boot, **disable autostart** (`doas rcctl disable <svc>`) —
  it can't start until `/secure` is unlocked and mounted (step 9).

## 8. Restart and verify

```sh
doas rcctl start trsvc agentverify
# verify the live endpoints and a real sign/verify still work:
#   the Travel-Rule and agent health checks, and a token mint against the moved key.
```

## 9. Reboot procedure (the attended step — document for operators)

After any reboot, before the SPT-Txn services can run:

```sh
doas bioctl -c C -l /dev/sd1a softraid0   # re-enter the passphrase → recreates sd2
doas mount /dev/sd2a /secure
doas rcctl start trsvc agentverify
```

Optionally script steps 2–3 of this in `/etc/rc.local` *after* the passphrase prompt, but
the passphrase itself must be entered by a human (console/SSH) — that is the point.

## 10. Securely remove the old plaintext keys

Once verified working from `/secure`:

```sh
# the old copies were on an unencrypted partition; overwrite before deleting
doas rm -P /path/to/old/keys/*.sec        # rm -P overwrites on OpenBSD FFS
```
(Perfect erasure on SSD/COW/VPS storage isn't guaranteed — this is best-effort; the real
protection is that new keys only ever live on the crypto volume.)

## 11. Rollback / safety

- Keep a **sealed offline backup** of the keys before moving (so a bad move isn't fatal).
- If `/secure` fails to unlock, services stay down (fail-closed) — that is the intended
  safety property, not a bug.

## 12. What this does and does NOT protect

- **Protects:** offline disk theft, provider-side decommissioned disks, and **cloud
  snapshots** — the exact VPS exposure that perms + pledge/unveil cannot touch.
- **Does NOT protect:** a live root compromise (volume is decrypted while mounted), or a
  hypervisor memory snapshot of the running instance.

## 6b (parallel track). The signing key's better home: HSM

softraid crypto suits **data at rest** and **attended** key material. For an **always-on
signing key**, the attended-reboot trade-off is real, and the cleaner answer is to take
the key off the disk entirely:

1. **Now, free:** build the **SoftHSM2 / PKCS#11** signing path so the app is HSM-ready
   behind a standard interface (config swap, not code change, to a real HSM later).
2. **Real HSM (VPS-compatible):** **AWS KMS or GCP Cloud KMS** — both now sign with
   **Ed25519** (AWS since Nov 2025; GCP supported), so no algorithm migration; key never
   leaves the FIPS-validated HSM. Solves at-rest **and** unattended availability, at the
   cost of a cloud dependency + per-op fee. (Azure Managed HSM still lacks Ed25519.)
3. **Self-sovereign alternative:** move `foss` to bare-metal/colo and use a **YubiHSM 2 /
   Nitrokey HSM** (USB) — not possible on a VPS.

Recommended sequencing: softraid-crypto the **audit/PII data + escrow keys** now (attended
unlock is fine for those), and put the **issuer signing key** on the SoftHSM→cloud-HSM
track rather than making the whole signing service reboot-attended.

### 6c. SoftHSM2 / PKCS#11 — VALIDATED on OpenBSD (2026-06-30)

Proven working on the `foss` OpenBSD host:
- Installed via `pkg_add softhsm2 opensc`; module at `/usr/local/lib/softhsm/libsofthsm2.so`
  (Botan backend, self-contained — no LibreSSL dependency).
- Config `/etc/softhsm2.conf` → `directories.tokendir = /var/lib/softhsm/tokens` (Option 1;
  move tokendir to the softraid-crypto volume for Option 2 at-rest).
- Token `spt-issuer` initialized (SoftHSM v2.6, PIN-gated, slot 0).
- **Ed25519 supported.** In-token keypair generated with `--key-type EC:edwards25519`;
  private key is **`always sensitive, never extractable, local`** — never leaves the token.
- **Signing works.** `--mechanism EDDSA` produced a 64-byte Ed25519 signature from the
  in-token key. → Keep Ed25519 end-to-end; AWS/GCP KMS also sign Ed25519, so upgrading
  SoftHSM → real HSM is a config swap, not an algorithm change.

**Remaining work (code, on the Mac):**
1. Wire a `crypto.Signer` over PKCS#11 in the issuer/signing code (`github.com/miekg/pkcs11`,
   `C_SignInit(CKM_EDDSA)` → `C_Sign`), replacing the on-disk `.sec` load. Set
   `SOFTHSM2_CONF` + the module path in the service env; add both to the `unveil` allow-list.
2. **Generate fresh issuer keys IN the token** (non-extractable) rather than importing the
   old on-disk keys, and **rotate the Trust Registry** to the new public keys — so no issuer
   key ever exists outside an HSM boundary.
3. Later: point the same PKCS#11 config at **AWS/GCP KMS** for a real HSM (unattended,
   FIPS-validated) or keep SoftHSM on the encrypted volume for a self-sovereign posture.

### 6d. Integration recipe (the crypto.Signer refactor)

The PKCS#11 signer is `internal/hsm/pkcs11signer.go` (build tag `pkcs11`; `go get
github.com/miekg/pkcs11`; `CGO_ENABLED=1 go build -tags pkcs11 ./...`). It implements
`crypto.Signer`. Because `ed25519.PrivateKey` also implements `crypto.Signer`, the
refactor is backward-compatible.

**Change the issuer signatures from `ed25519.PrivateKey` to `crypto.Signer`** and replace
the sign call. Example (`internal/cattoken/cattoken.go`):

```go
// before:
func Issue(req IssueRequest, signingKey ed25519.PrivateKey) (*CAT, error) { ...
    sig := ed25519.Sign(signingKey, []byte(signingInput))
// after:
func Issue(req IssueRequest, signer crypto.Signer) (*CAT, error) { ...
    sig, err := signer.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0)) // Ed25519: opts=Hash(0)
    if err != nil { return nil, err }
```

Apply the same swap in: `cattoken.Issue`, `cttoken.Issue` + `Delegate`, `txntoken.Issue`,
`sdjwt.Issue` + `IssueBound`, `audit.PublishRoot`, `vaspregistry.Publish`,
`escrow.deanon.Sign`. Callers pass either an on-disk `ed25519.PrivateKey` (unchanged) or an
`*hsm.Signer`. Existing tests that pass an `ed25519.PrivateKey` keep working.

**Construct the signer at service startup** (e.g. in `cmd/tr-svc`), PIN from env/secret:

```go
signer, err := hsm.Open(hsm.Config{
    ModulePath: os.Getenv("SPT_PKCS11_MODULE"), // /usr/local/lib/softhsm/libsofthsm2.so
    TokenLabel: "spt-issuer",
    KeyLabel:   "spt-issuer-cat",
    PIN:        os.Getenv("SPT_PKCS11_PIN"),
})
```
Add `SOFTHSM2_CONF`, `SPT_PKCS11_MODULE`, `SPT_PKCS11_PIN` to the service env, and add the
module path + `/var/lib/softhsm` (or the encrypted tokendir) to the service's `unveil`
allow-list (read + the dlopen path).

**Generate the real in-token issuer key (non-extractable) and read its public key** for the
Trust Registry (do NOT import the old on-disk key):

```sh
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login \
  --keypairgen --key-type EC:edwards25519 --label spt-issuer-cat
# export the public key to register in the Trust Registry:
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login \
  --read-object --type pubkey --label spt-issuer-cat -o spt-issuer-cat.pub.der
```
Then register that public key for the issuer role and retire the old key in the registry
(registry-governed rotation — no verifier change needed).
