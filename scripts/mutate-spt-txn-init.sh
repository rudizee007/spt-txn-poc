#!/usr/bin/env bash
# Mutation check for cmd/spt-txn-init -- the deployment generator.
#
# The generator handles private key material and produces the configuration
# an enforcement point runs under, so its guards are security guards. Every
# mutation below leaves a tool that still runs and still writes a deployment
# directory, which is exactly why reading the tests is not enough to know
# they hold.
#
#   I-1  a non-empty output directory is overwritten
#   I-2  the output directory is not 0700
#   I-3  a private key file is not 0600
#   I-4  a non-http(s) scheme passes the URL validator
#   I-5  a host-less URL passes the URL validator
#   I-6  the non-empty validator accepts blank input
#   I-7  the identifier charset admits / space @
#   I-8  the identifier traversal check is dropped
#   I-9  the wrapped command leaves the required set (non-interactive)
#   I-10 the snapshot is signed with the issuer key, self-check intact
#        (killed because generation REFUSES: the self-check is what fires)
#   I-11 the snapshot is signed with the issuer key AND the self-check is
#        disabled (killed by the real verifier in the test, which is the
#        property I-10 relies on)
#   I-12 issuer.pub is written with the private key
#   I-13 the summary carries the private issuer key
#   I-14 the failure path stops removing the temporary directory
#   I-15 shellQuote stops escaping the quote character
#   I-16 the prompt accepts invalid input without re-asking
#   I-17 mint.sh is emitted for the A2A profile
#   I-18 the profile validator admits skins not in this tree
#   I-19 the policy hash is not base64url
#   I-20 the policy hash is over different bytes than policy.json
#   I-21 run.sh drops -audience
#   I-22 the snapshot record's role is ct_issuer, not tts_issuer
#   I-23 the snapshot record carries the publication key, not the issuer key
#   I-24 a present-but-invalid -public-url is not validated
#   I-25 non-interactive mode skips validation after defaults
#   I-26 a flag-supplied audience is re-asked interactively
#   I-27 the field name on an upstream error points at another flag
#   I-28 an invalid did:web:<audience> is offered as the issuer default
#
# Added after adversarial review (2026-09-07), which found P-1, P-3, P-5 and
# P-6 SURVIVING and the interrupt path untested:
#
#   P-1  log.key leaves privateFiles (the 0600, no-leak and PRIVATE-marker
#        assertions all ranged over that list, so they went with it)
#   P-3  the post-write Chmod is dropped (only observable under a hostile umask)
#   P-5  O_EXCL becomes O_TRUNC
#   P-6  the registry scratch file ships in the deployment
#   S-1  the interrupt handler stops removing the temporary directory
#   S-2  the interrupt handler swallows the signal instead of re-raising it
#   Y-1  a symlink output path is followed and silently replaced
#   M-1  a code span's delimiter stops growing past the backticks inside it
#   M-2  the shell block's fence stops growing past the backticks inside it
#   M-3  a table cell stops escaping pipes
#   B-1  the build command drops CGO_ENABLED=0 (a2a-pep is then not static)
#   R-1  the README stops saying the PEP does not read the snapshot
#   A-1  run.sh goes back to advising a re-run the installer refuses
#
# NOT COVERED BY MUTATION, and why:
#
#   * the EOF handling in prompter.ask. Every single-site mutation of it that
#     compiles still returns errInputClosed one loop later, because a closed
#     reader keeps returning EOF: the two checks are belt and braces on each
#     other. TestPrompt_ClosedInputIsAnErrorNotAnAnswer asserts the behaviour.
#   * the self-check ALONE (Verify after Sign, correct key). With Sign correct,
#     removing the check changes no output. I-11 is the honest version: it
#     shows the check is what would have caught I-10's defect, by removing it
#     and letting the test's own Verify catch it instead.
#   * the write lock against the interrupt handler. Removing it opens a
#     microsecond race between RemoveAll and a concurrent OpenFile; the test
#     blocks the child OUTSIDE the lock (in the beforeWrite hook) so that the
#     interrupt itself is deterministic, and a race cannot be asserted with a
#     named test that passes on the clean tree every time.
#
# Restores the file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
F=cmd/spt-txn-init/main.go
BAK=$(mktemp)
cp "$F" "$BAK"
trap 'cp "$BAK" "$F"; rm -f "$BAK"' EXIT INT TERM

# run_mutation NAME TEST FROM TO [FROM2 TO2]
#
# The optional second pair exists for I-11, which has to change two places at
# once to say anything. Each anchor must match exactly once.
run_mutation() {
  local name="$1" want_test="$2"
  shift 2
  cp "$BAK" "$F"
  # A test that fails on the CLEAN tree also fails under mutation and scores as
  # "killed" -- a false green. Assert it passes before trusting that it failed.
  if ! go test ./cmd/spt-txn-init/ -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the test, not the mapping."
    return 1
  fi
  while [ "$#" -ge 2 ]; do
    local from="$1" to="$2"
    shift 2
    if ! grep -qF -- "$from" "$F"; then
      echo "FAIL      $name: anchor not found -- the mutation was never applied"
      return 1
    fi
    if ! python3 - "$F" "$from" "$to" <<'PY'
import sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert s.count(a) == 1, f"anchor appears {s.count(a)} times"
open(p, "w").write(s.replace(a, b))
PY
    then
      echo "FAIL      $name: anchor did not match exactly once -- the mutation was"
      echo "          NOT applied, so a pass below would mean nothing. Re-anchor it."
      return 1
    fi
  done
  if ! go build -o /dev/null ./cmd/spt-txn-init/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile -- rewrite it, do not skip it"
    return 1
  fi
  if go test ./cmd/spt-txn-init/ -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "SURVIVED  $name -- $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "I-1 non-empty output directory overwritten" \
  "TestGenerate_RefusesANonEmptyOutputDirectory" \
  "	if len(entries) > 0 {
		return errOutDirNotEmpty" \
  "	if len(entries) < 0 {
		return errOutDirNotEmpty" || rc=1

run_mutation "I-2 output directory not 0700" \
  "TestGenerate_Permissions" \
  "	if err := os.Chmod(tmp, 0o700); err != nil {" \
  "	if err := os.Chmod(tmp, 0o755); err != nil {" || rc=1

run_mutation "I-3 private key file not 0600" \
  "TestGenerate_Permissions" \
  "	if err := g.write(dir, fileIssuerKey, hexLine(ttsPriv), 0o600); err != nil {" \
  "	if err := g.write(dir, fileIssuerKey, hexLine(ttsPriv), 0o644); err != nil {" || rc=1

run_mutation "I-4 non-http(s) scheme passes" \
  "TestValidateAbsoluteURL" \
  "	if u.Scheme != \"http\" && u.Scheme != \"https\" {" \
  "	if u.Scheme == \"\" {" || rc=1

run_mutation "I-5 host-less URL passes" \
  "TestValidateAbsoluteURL" \
  "	if u.Host == \"\" {
		return errURLNoHost" \
  "	if false {
		return errURLNoHost" || rc=1

run_mutation "I-6 non-empty validator accepts blank" \
  "TestNonEmpty" \
  "	if strings.TrimSpace(s) == \"\" {
		return errEmpty" \
  "	if false && strings.TrimSpace(s) == \"\" {
		return errEmpty" || rc=1

run_mutation "I-7 identifier charset admits / space @" \
  "TestValidateIdentifier" \
  "		case c == '-', c == '_', c == '.', c == ':':" \
  "		case c == '-', c == '_', c == '.', c == ':', c == '/', c == ' ', c == '@':" || rc=1

run_mutation "I-8 identifier traversal check dropped" \
  "TestValidateIdentifier" \
  "	if strings.Contains(s, \"..\") {
		return errIdentTraversal" \
  "	if false {
		return errIdentTraversal" || rc=1

run_mutation "I-9 wrapped command leaves the required set" \
  "TestResolveNonInteractive_NamesEveryMissingValue" \
  "		return append([]string{\"-server-identity\", \"-- <wrapped-server-command>\"}, common...)" \
  "		return append([]string{\"-server-identity\"}, common...)" || rc=1

# I-10 / I-11: the snapshot's signing key. With the self-check intact, signing
# with the wrong key makes generation refuse (the test's generate() fatals);
# with it disabled the bad artifact is written and the test's own call to the
# real Verify refuses it. Both must be killed; only the second says the TEST
# checks the signature.

run_mutation "I-10 snapshot signed with the issuer key (self-check intact)" \
  "TestGenerate_SnapshotVerifiesWithTheRealVerifier" \
  "	manifest, err := trustsnapshot.Sign(body, snapshotID, g.now, issuerIDs, nil, pubPriv)" \
  "	manifest, err := trustsnapshot.Sign(body, snapshotID, g.now, issuerIDs, nil, ttsPriv)" || rc=1

run_mutation "I-11 snapshot signed with the issuer key AND self-check disabled" \
  "TestGenerate_SnapshotVerifiesWithTheRealVerifier" \
  "	manifest, err := trustsnapshot.Sign(body, snapshotID, g.now, issuerIDs, nil, pubPriv)" \
  "	manifest, err := trustsnapshot.Sign(body, snapshotID, g.now, issuerIDs, nil, ttsPriv)" \
  "		return nil, fmt.Errorf(\"%w: %v\", errSnapshotSelfCheck, err)" \
  "		_ = errSnapshotSelfCheck" || rc=1

run_mutation "I-12 issuer.pub written with the private key" \
  "TestGenerate_NoPrivateKeyMaterialOnStdout" \
  "	if err := g.write(dir, fileIssuerPub, hexLine(ttsPub), 0o644); err != nil {" \
  "	if err := g.write(dir, fileIssuerPub, hexLine(ttsPriv), 0o644); err != nil {" || rc=1

run_mutation "I-13 summary carries the private issuer key" \
  "TestGenerate_NoPrivateKeyMaterialOnStdout" \
  "		TTSPubHex:         ttsPubHex," \
  "		TTSPubHex:         hex.EncodeToString(ttsPriv)," || rc=1

# I-14 RE-ANCHORED 2026-09-07: the interrupt handler now also calls RemoveAll,
# so the bare line matched twice. Anchored on the error-path defer.
# Re-anchored 2026-09-09: the defer is conditioned on an explicit success flag
# now, not on the named error return, so that a panic also cleans up (J-6).
run_mutation "I-14 failure path stops removing the temporary directory" \
  "TestGenerate_FailureLeavesNoHalfWrittenDeployment" \
  "		if rmErr := os.RemoveAll(tmp); rmErr != nil {" \
  "		if rmErr := error(nil); rmErr != nil {" || rc=1

run_mutation "I-15 shellQuote stops escaping the quote character" \
  "TestShellQuote_RoundTripsThroughSh" \
  "	return \"'\" + strings.ReplaceAll(s, \"'\", \`'\\''\`) + \"'\"" \
  "	return \"'\" + s + \"'\"" || rc=1

run_mutation "I-16 prompt accepts invalid input without re-asking" \
  "TestPrompt_ReAsksOnInvalidInputAndAcceptsValid" \
  "		if verr := validate(v); verr != nil {" \
  "		if verr := validate(v); verr != nil && false {" || rc=1

run_mutation "I-17 mint.sh emitted for the A2A profile" \
  "TestMintScript_OnlyForMCP" \
  "	if cfg.Profile == profileMCP {
		if err := g.write(dir, fileMintScript" \
  "	if true {
		if err := g.write(dir, fileMintScript" || rc=1

run_mutation "I-18 profile validator admits skins not in this tree" \
  "TestValidateProfile" \
  "	case profileMCP, profileA2A:
		return nil" \
  "	case profileMCP, profileA2A, \"forward-auth\", \"envoy\", \"http\":
		return nil" || rc=1

run_mutation "I-19 policy hash is not base64url" \
  "TestPolicyHash_IsTheBase64URLSHA256OfPolicyJSON" \
  "	return base64.RawURLEncoding.EncodeToString(sum[:])" \
  "	return base64.StdEncoding.EncodeToString(sum[:])" || rc=1

run_mutation "I-20 policy hash over different bytes than policy.json" \
  "TestPolicyHash_IsTheBase64URLSHA256OfPolicyJSON" \
  "	return b, policyHashOf(b), nil" \
  "	return b, policyHashOf(b[:len(b)-1]), nil" || rc=1

run_mutation "I-21 run.sh drops -audience" \
  "TestRunScript_CarriesEveryRequiredFlag" \
  "	fmt.Fprintf(&b, \"  -audience %s \\\\\\n\", shellQuote(cfg.Audience))" \
  "	b.WriteString(\"\")" || rc=1

run_mutation "I-22 snapshot record role is ct_issuer" \
  "TestGenerate_SnapshotBindsTheIssuerKeyThePEPPins" \
  "		Role:       trustregistry.RoleTTSIssuer," \
  "		Role:       trustregistry.RoleCTIssuer," || rc=1

run_mutation "I-23 snapshot record carries the publication key" \
  "TestGenerate_SnapshotBindsTheIssuerKeyThePEPPins" \
  "	body, issuerIDs, err := g.buildRegistryBody(dir, cfg.Issuer, ttsPub)" \
  "	body, issuerIDs, err := g.buildRegistryBody(dir, cfg.Issuer, pubPub)" || rc=1

run_mutation "I-24 present-but-invalid -public-url not validated" \
  "TestValidate_NamesTheFieldAndTheRule" \
  "		if cfg.PublicURL != \"\" {
			if err := validateAbsoluteURL(cfg.PublicURL); err != nil {" \
  "		if false {
			if err := validateAbsoluteURL(cfg.PublicURL); err != nil {" || rc=1

run_mutation "I-25 non-interactive skips validation after defaults" \
  "TestResolveNonInteractive_NamesEveryMissingValue" \
  "	applyDefaults(cfg)
	return validate(cfg)
}

// resolveInteractive" \
  "	applyDefaults(cfg)
	return nil
}

// resolveInteractive" || rc=1

run_mutation "I-26 flag-supplied audience re-asked interactively" \
  "TestResolveInteractive_FlagsAreNotReAsked" \
  "	if cfg.Audience == \"\" {
		cfg.Audience, err = p.ask(" \
  "	if true {
		cfg.Audience, err = p.ask(" || rc=1

run_mutation "I-27 upstream error names another flag" \
  "TestValidate_NamesTheFieldAndTheRule" \
  "		if err := validateAbsoluteURL(cfg.Upstream); err != nil {
			return &fieldError{\"-upstream\", err}" \
  "		if err := validateAbsoluteURL(cfg.Upstream); err != nil {
			return &fieldError{\"-public-url\", err}" || rc=1

run_mutation "P-1 log.key leaves privateFiles" \
  "TestGenerate_NoPrivateKeyMaterialOnStdout" \
  "var privateFiles = []string{fileLogKey, filePublicationKey}" \
  "var privateFiles = []string{filePublicationKey}" || rc=1

# Re-anchored 2026-09-09: the restatement is now fchmod on the descriptor
# already held, not os.Chmod on a re-resolved path.
run_mutation "P-3 post-write Chmod dropped" \
  "TestGenerate_PermissionsUnderAHostileUmask" \
  "	if err := f.Chmod(mode); err != nil {" \
  "	if err := error(nil); err != nil {" || rc=1

run_mutation "P-5 O_EXCL becomes O_TRUNC" \
  "TestWrite_RefusesToOverwrite" \
  "os.O_WRONLY|os.O_CREATE|os.O_EXCL" \
  "os.O_WRONLY|os.O_CREATE|os.O_TRUNC" || rc=1

run_mutation "P-6 registry scratch file ships" \
  "TestGenerate_DirectoryContainsExactlyTheDocumentedFiles" \
  "	if err := os.Remove(scratch); err != nil {" \
  "	if err := error(nil); err != nil {" || rc=1

run_mutation "S-1 interrupt handler stops removing the temporary directory" \
  "TestGenerate_InterruptRemovesTheTemporaryDirectory" \
  "			_ = os.RemoveAll(tmp)
			signal.Reset(sig)" \
  "			_ = tmp
			signal.Reset(sig)" || rc=1

run_mutation "S-2 interrupt handler swallows the signal" \
  "TestGenerate_InterruptRemovesTheTemporaryDirectory" \
  "			signal.Reset(sig)
			raise(sig)" \
  "			signal.Reset(sig)
			os.Exit(0)" || rc=1

run_mutation "Y-1 symlink output path followed" \
  "TestGenerate_RefusesASymlinkOutputPath" \
  "	if st.Mode()&os.ModeSymlink != 0 {
		return errOutDirSymlink" \
  "	if false {
		return errOutDirSymlink" || rc=1

run_mutation "M-1 code span delimiter stops growing" \
  "TestREADME_EscapesOperatorValues" \
  "	d := strings.Repeat(\"\`\", longestRun(s, '\`')+1)" \
  "	d := \"\`\"" || rc=1

run_mutation "M-2 shell block fence stops growing" \
  "TestREADME_EscapesOperatorValues" \
  "	n := longestRun(content, '\`') + 1
	if n < 3 {" \
  "	n := 3
	if n < 3 {" || rc=1

run_mutation "M-3 table cell stops escaping pipes" \
  "TestMarkdownHelpers" \
  "func mdCell(s string) string { return mdCode(strings.ReplaceAll(s, \"|\", \`\\|\`)) }" \
  "func mdCell(s string) string { return mdCode(s) }" || rc=1

run_mutation "B-1 build command drops CGO_ENABLED=0" \
  "TestREADME_BuildCommandsProduceStaticBinaries" \
  "	return \"CGO_ENABLED=0 go build -o /usr/local/bin/\" + name + \" ./cmd/\" + name" \
  "	return \"go build -o /usr/local/bin/\" + name + \" ./cmd/\" + name" || rc=1

run_mutation "R-1 README stops saying the PEP does not read the snapshot" \
  "TestREADME_LabelsThePostureHonestly" \
  "	fmt.Fprintf(&b, \"2. **The PEP does not read the snapshot.** \`run.sh\` pins \`%s\` directly, and nothing\\n\", fileIssuerPub)" \
  "	fmt.Fprintf(&b, \"2. **Load the snapshot.** \`run.sh\` pins \`%s\` directly, and nothing\\n\", fileIssuerPub)" || rc=1

run_mutation "A-1 run.sh advises the refused re-run" \
  "TestRunScript_AdvisesAWorkingPath" \
  "	b.WriteString(\"# To change a value, run spt-txn-init again into a NEW directory\\n\")" \
  "	b.WriteString(\"# To change a value, re-run spt-txn-init rather than editing\\n\")" || rc=1

run_mutation "I-28 invalid issuer default offered" \
  "TestResolveInteractive_NoInvalidIssuerDefault" \
  "		if validateIdentifier(def) != nil {
			def = \"\"" \
  "		if false {
			def = \"\"" || rc=1

# ── guards added after the adversarial pass of 2026-09-09 ─────────────────

run_mutation "J-1 control bytes accepted in an operator value (unit)" \
  "TestNonEmpty_RefusesControlBytes" \
  "		if s[i] < 0x20 || s[i] == 0x7f {" \
  "		if s[i] < 0x00 || s[i] == 0x7f {" || rc=1

run_mutation "J-2 control bytes accepted in an operator value (end to end)" \
  "TestGenerate_RefusesAControlByteInAnOperatorValue" \
  "		if s[i] < 0x20 || s[i] == 0x7f {" \
  "		if s[i] < 0x00 || s[i] == 0x7f {" || rc=1

run_mutation "J-3 a TTL the decision engine will refuse is generated anyway" \
  "TestValidate_RefusesATTLTheEngineWouldReject" \
  "	if cfg.MaxTokenTTL > maxAcceptableTokenTTL {" \
  "	if cfg.MaxTokenTTL > maxAcceptableTokenTTL*1000 {" || rc=1

run_mutation "J-4 the listen port stops being checked for digits" \
  "TestValidateListenAddr" \
  "	for i := 0; i < len(port); i++ {" \
  "	for i := 0; i < 0; i++ {" || rc=1

run_mutation "J-5 the output path is not re-checked under the lock" \
  "TestGenerate_RefusesAnOutputPathSwappedAfterTheCheck" \
  "	if err := checkOutDir(outDir); err != nil {
		return nil, fmt.Errorf(\"%w: %v\", errOutDirChanged, err)" \
  "	if err := checkOutDir(outDir); err != nil && false {
		return nil, fmt.Errorf(\"%w: %v\", errOutDirChanged, err)" || rc=1

run_mutation "J-6 cleanup goes back to the named error return" \
  "TestGenerate_PanicLeavesNoTemporaryDirectory" \
  "		if success {
			return
		}" \
  "		if success || err == nil {
			return
		}" || rc=1

run_mutation "J-7 the private key leaks in base64 rather than hex" \
  "TestGenerate_NoPrivateKeyMaterialOnStdout" \
  "	if err := g.write(dir, fileIssuerPub, hexLine(ttsPub), 0o644); err != nil {" \
  "	if err := g.write(dir, fileIssuerPub, []byte(base64.StdEncoding.EncodeToString(ttsPriv)+\"\\n\"), 0o644); err != nil {" || rc=1

run_mutation "J-8 the PEP binary comes back from the environment" \
  "TestRunScript_DoesNotResolveThePEPFromTheEnvironment" \
  "	b.WriteString(\"  exit 1\nfi\n\")
	return b.String(), shellQuote(bin)" \
  "	b.WriteString(\"  exit 1\nfi\n\")
	return b.String(), \"\\\"\$\" + strings.ToUpper(strings.ReplaceAll(bin, \"-\", \"_\")) + \"\\\"\"" || rc=1

run_mutation "J-9 -pep-binary is accepted and then ignored" \
  "TestRunScript_PinsTheBinaryWhenGiven" \
  "	if pin != \"\" {" \
  "	if pin != \"\" && false {" || rc=1

run_mutation "J-10 a relative -pep-binary is accepted" \
  "TestValidate_RefusesARelativePEPBinary" \
  "		if !filepath.IsAbs(cfg.PEPBinary) {" \
  "		if !filepath.IsAbs(cfg.PEPBinary) && false {" || rc=1

run_mutation "J-11 run.sh goes back to overstating the policy hash" \
  "TestRunScript_StatesWhatThePolicyHashCovers" \
  "	b.WriteString(\"# policy version was in force. It does NOT cover the wiring below\n\")" \
  "	b.WriteString(\"# Every value below is also recorded in policy.json.\n\")" || rc=1

run_mutation "J-12 the issuer private key is written even with an external issuer" \
  "TestGenerate_ExternalIssuerWritesNoIssuerPrivateKey" \
  "	if selfIssued {
		if err := g.write(dir, fileIssuerKey, hexLine(ttsPriv), 0o600); err != nil {" \
  "	if true {
		if err := g.write(dir, fileIssuerKey, hexLine(ttsPriv), 0o600); err != nil {" || rc=1

run_mutation "J-13 -tts-pub is accepted without being checked" \
  "TestValidate_RefusesABadTTSPub" \
  "		if err != nil || len(raw) != ed25519.PublicKeySize || strings.ToLower(cfg.TTSPubHex) != cfg.TTSPubHex {" \
  "		if false && (err != nil || len(raw) != ed25519.PublicKeySize || strings.ToLower(cfg.TTSPubHex) != cfg.TTSPubHex) {" || rc=1

run_mutation "J-14 an issuer key is generated even though one was supplied" \
  "TestGenerate_ExternalIssuerWritesNoIssuerPrivateKey" \
  "	if selfIssued {
		var err error
		ttsPub, ttsPriv, err = ed25519.GenerateKey(g.rand)" \
  "	if true {
		var err error
		ttsPub, ttsPriv, err = ed25519.GenerateKey(g.rand)" || rc=1

run_mutation "J-15 the issuer key is left inside the deployment" \
  "TestGenerate_IssuerKeyIsPlacedBesideTheDeployment" \
  "	if issuerKey != \"\" {
		staged := filepath.Join(tmp, fileIssuerKey)" \
  "	if issuerKey != \"\" && false {
		staged := filepath.Join(tmp, fileIssuerKey)" || rc=1

run_mutation "J-16 the issuer key path is overwritten instead of refused" \
  "TestGenerate_RefusesAnOccupiedIssuerKeyPath" \
  "		if _, err := os.Lstat(issuerKey); err == nil {" \
  "		if _, err := os.Lstat(issuerKey); err == nil && false {" \
  "		if err := os.Link(staged, issuerKey); err != nil {" \
  "		if err := os.Rename(staged, issuerKey); err != nil {" || rc=1

run_mutation "J-17 run.sh cds into the deployment again" \
  "TestRunScript_DoesNotChangeTheWorkingDirectory" \
  "	b.WriteString(\"HERE=\$(cd \\\"\$(dirname \\\"\$0\\\")\\\" && pwd)\\n\")" \
  "	b.WriteString(\"cd \\\"\$(dirname \\\"\$0\\\")\\\"\\n\")" \
  "	b.WriteString(pepFlags(cfg, \"\\\"\$PINNED\\\"\", policyHash,
		\"\\\"\$HERE/\"+fileLogKey+\"\\\"\", \"\\\"\$HERE/\"+auditLog+\"\\\"\"))" \
  "	b.WriteString(pepFlags(cfg, \"\\\"\$PINNED\\\"\", policyHash, fileLogKey, shellQuote(auditLog)))" || rc=1

run_mutation "J-18 run.sh stops checking issuer.pub against the pin" \
  "TestRunScript_RefusesWhenIssuerPubDoesNotMatchThePin" \
  "	fmt.Fprintf(&b, \"if [ \\\"\$(tr -d '[:space:]' < \\\"\$HERE/%s\\\")\\\" != \\\"\$PINNED\\\" ]; then\\n\", fileIssuerPub)" \
  "	fmt.Fprintf(&b, \"if [ \\\"\$(tr -d '[:space:]' < \\\"\$HERE/%s\\\")\\\" = \\\"\$PINNED\\\" ] && false; then\\n\", fileIssuerPub)" || rc=1

if [ "$rc" -eq 0 ]; then
  echo
  echo "all mutations killed"
else
  echo
  echo "at least one mutation survived or failed to apply -- see above"
fi
exit "$rc"
