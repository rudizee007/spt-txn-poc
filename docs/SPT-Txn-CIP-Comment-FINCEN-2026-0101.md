# Comment on the Permitted Payment Stablecoin Issuer Customer Identification Program NPRM

**Re:** Docket FINCEN-2026-0101 (also OCC-2026-0331; RIN 1506-AB24), *Permitted Payment Stablecoin Issuer Customer Identification Program*. Joint notice of proposed rulemaking by FinCEN, the OCC, the Board of Governors of the Federal Reserve System, the FDIC, and the NCUA (91 FR, published June 22, 2026).

**Submitted by:** Rudolf J. Coetzee, Violet Sky Security SEZC (Cayman Islands), maintainer of SPT-Txn, an open-source, blockchain-agnostic identity-attestation and authorization framework.

## 1. Summary of position

We support the proposed rule's objective, that permitted payment stablecoin issuers (PPSIs) identify and verify their account holders. We ask that the final rule be technology-neutral and outcome-based, and that it expressly recognize a PPSI's ability to satisfy the identification-and-verification obligation through cryptographically verifiable, reusable identity attestations, zero-knowledge predicate verification, and data-minimizing selective disclosure. These methods meet the customer-identification standard while reducing the duplicated personal-data repositories and the five-year-retention breach surface that the rule would otherwise create. Reliable identification and lawful access do not require every issuer to re-collect and warehouse raw identity documents.

## 2. Interest of the commenter

Violet Sky Security SEZC develops SPT-Txn (Sovereign Policy Token Transactions), an open-source (Apache-2.0) framework for privacy-preserving identity attestation and authorization. It issues reusable Compliance Attestation Tokens bound to a decentralized identifier, proves compliance predicates in zero knowledge (Groth16 over BN254), discloses only the required fields via SD-JWT, protects stored identity envelopes with post-quantum hybrid encryption, and verifies offline through an eight-step engine that makes no live issuer or chain call. It extends the IETF OAuth Transaction Tokens line (draft-coetzee-oauth-spt-txn-tokens). We comment as a technology provider with implemented experience in the mechanisms at issue.

## 3. The rule concentrates duplicated identity data, and it can reduce that risk

Requiring each PPSI to collect and retain the name, date of birth, address, and taxpayer identification number of every account holder for five years multiplies the number of high-value personal-data repositories across the ecosystem. Each repository is a breach target and a data-protection liability that interacts with the GDPR, the EU Travel Rule, and comparable regimes. The identification objective can be met while minimizing how many parties hold raw identity data and how much of it moves between them.

## 4. Recommendations

**4.1 Recognize reliance on cryptographically verifiable third-party identity attestations.** Existing customer-identification rules already permit a financial institution, under specified conditions, to rely on another institution's program. The final rule should confirm that a PPSI may satisfy identification and verification by relying on a verifiable attestation that a qualified party performed equivalent identification, issued once and cryptographically checkable by any relying issuer, instead of independently re-collecting the same documents. This preserves the standard while cutting duplication and repeated onboarding.

**4.2 Permit zero-knowledge verification and selective disclosure.** A PPSI can cryptographically verify that an account holder was identified and verified to the required standard, and can prove attributes such as age or jurisdiction, without every party re-viewing the underlying documents. The mandated data elements (name, date of birth, address, and taxpayer identification number) should be disclosed, encrypted, only to the party required to hold them, rather than transmitted across the payment path.

**4.3 Encourage data minimization and encryption at rest, with cryptographic agility.** Five-year retention of identity records is a natural target for "harvest now, decrypt later" collection. Consistent with United States post-quantum policy and NIST FIPS 203 and 204, the rule should encourage encryption of retained records and a migration path to post-quantum algorithms, so that identity data collected today remains protected against future decryption.

**4.4 Preserve lawful access through a recoverable human anchor.** Privacy is not anonymity. A design can bind each account and transaction to a human anchor, a zero-knowledge commitment to the identified person, that is producible to authorized authorities under lawful process and is never exposed to intermediaries or the public. This serves the purpose of customer identification, namely reliable identity available to supervisors and law enforcement, without normalizing broad exposure of identity data.

**4.5 Address the "identify at issuance, not at payment" gap with portable attestations.** The proposal's distinction between primary and secondary market activity leaves transactions in which the issuer is not a direct party. A portable, cryptographically verifiable identity attestation lets a relying party confirm that a counterparty was identified without re-collecting personal data, which helps close the gap the proposal itself acknowledges.

**4.6 Adopt a technology-neutral, outcome-based standard.** The obligation is best defined by result: the issuer can demonstrate that each account holder was identified and verified to the required standard, and can produce the required identity data to authorized parties on lawful request. Defining the rule by outcome, rather than by mandating raw-document re-collection or a specific architecture, keeps it durable and lets privacy-preserving methods satisfy it.

**4.7 Favor open, interoperable attestation standards.** Recognizing standards-based, portable credentials such as SD-JWT, the IETF OAuth Transaction Tokens line, and W3C Verifiable Credentials reduces vendor lock-in and lets identification assurance move across issuers and jurisdictions without bespoke integrations.

## 5. Conclusion

Effective customer identification and strong data protection are not in tension. We ask the agencies to adopt a technology-neutral, outcome-based rule that permits reusable, cryptographically verifiable identity attestations, zero-knowledge verification, and data-minimizing selective disclosure, with lawful access preserved through a recoverable human anchor. Such a rule would meet the GENIUS Act's identification objective while reducing the concentration and exposure of Americans' identity data. We would welcome the opportunity to provide technical detail or a working reference implementation.

Respectfully submitted,
Rudolf J. Coetzee, Violet Sky Security SEZC (Cayman Islands).
foss.violetskysecurity.com
www.violetskysecurity.com
draft-coetzee-oauth-spt-txn-tokens (IETF)
