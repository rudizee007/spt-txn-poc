# Dependency Advisories — Status and Accepted Risk

**Last reviewed:** 2026-07-18. **Tool of record:** `govulncheck` (call-graph
reachability), run in `scripts/verify-p1p2p3p6.sh`. **Standard:** we treat
*reachable* (called) vulnerabilities as blocking and fix them; we track
*module-level* (present but not called) findings and accept them only with a
documented reason.

## Current status

`govulncheck ./...` reports **0 vulnerabilities called by this code** (Symbol and
Package results clean) and **1 module-level finding** not reached by any code
path. GitHub Dependabot reports a higher raw count because it enumerates every
advisory in the full dependency graph — including transitive and test-only
modules — without reachability analysis. govulncheck is authoritative here; its
reachability result is what gates a release.

## Fixed 2026-07-18

Bumped `golang.org/x/crypto` v0.48.0 → **v0.52.0** and `golang.org/x/sys` v0.41.0
→ **v0.45.0**. This cleared 14 module-level findings that were present but
unreachable: `GO-2026-5005/5006/5013/5014/5015/5016/5017/5018/5019/5020/5021/5023`
(all `golang.org/x/crypto/ssh` or `ssh/agent`, fixed in x/crypto v0.52.0) and
`GO-2026-5024` (`golang.org/x/sys/windows` integer overflow, Windows-only, fixed
in x/sys v0.44.0). SPT-Txn does no SSH in code and does not target Windows; these
rode in transitively (grpc / go-spiffe / tooling).

Note: x/crypto v0.52.0 requires x/sys ≥ v0.45.0, so the two bumps must move
together — pinning x/sys below 0.45.0 silently forces x/crypto back to 0.51.0 and
re-opens the ssh advisories.

## Accepted (open, with reason)

**GO-2026-5932 — `golang.org/x/crypto/openpgp` unmaintained.** `Fixed in: N/A`
(no upstream fix; the package is deprecated). **Not reachable:** SPT-Txn does not
import or call `golang.org/x/crypto/openpgp` — it is pulled only as part of the
`golang.org/x/crypto` module by a transitive dependency, and govulncheck's symbol
analysis confirms zero call paths reach it. There is nothing to upgrade to, and
nothing calls it, so this finding is accepted. It will clear if and when the
transitive dependency drops the openpgp package or the module removes it. This is
the reason `govulncheck` prints "1 vulnerability in modules you require"; it does
**not** fail the build, because govulncheck exits non-zero only on *called*
vulnerabilities.

## Policy

- A new **called** (Symbol-result) vulnerability blocks release and must be fixed
  or the affected call removed.
- A new **module-level** finding is either fixed by a compatible bump or recorded
  here with a reachability justification.
- Do **not** run a blanket `go get -u ./...` on this graph — gnark-crypto, envoy,
  and grpc make mass upgrades high-risk for zero reachability benefit. Prefer
  targeted bumps and let Dependabot PRs handle the transitive tree incrementally.
