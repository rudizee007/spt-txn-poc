#!/usr/bin/env python3
"""
Independently verify an SPT-Txn x402 payment on the XRP Ledger.

Given the raw transaction JSON, this recomputes the spt_txn_context_hash that
the payment carries in its own `spt-txn/contextHash` memo, from nothing but
public ledger fields plus the anchor the payment also carries. If they agree,
the payment is cryptographically bound to that human anchor: the amount, the
destination, the payer and the anchor cannot be changed without breaking the
commitment that is already on the ledger.

Standard library only. No network, no dependencies, nothing to trust but the
ledger and this file.

    python3 verify-xrpl-loop.py tx.json
    xrpl_rpc ... | python3 verify-xrpl-loop.py -

The one input that is not on the ledger is the gate's issuance timestamp, which
is committed in the preimage but never transmitted. It is recovered by scanning
a window around the validation time (default +/- 48h); the recovered value is
printed, and it should sit a few seconds BEFORE validation.
"""
import sys, json, hashlib, binascii, datetime, argparse

RIPPLE_EPOCH = 946684800
US, RS = "\x1f", "\x1e"
ANCHOR_MEMO = "spt-txn/humanAnchor"
CTXHASH_MEMO = "spt-txn/contextHash"


def canonical(ordered, extra):
    """Mirror of internal/ledger canonicalEncode: k US v RS, then sorted x:extra."""
    out = []
    for k, v in ordered:
        if any(c in k + v for c in (US, RS)):
            raise ValueError("field %r contains a reserved separator byte" % k)
        out.append(k + US + v + RS)
    for k in sorted(extra):
        out.append("x:" + k + US + extra[k] + RS)
    return "".join(out).encode()


def context_hash(ordered, extra):
    return hashlib.sha256(canonical(ordered, extra)).hexdigest()


def unhex(h):
    return binascii.unhexlify(h).decode("utf-8")


def read_memos(tx):
    found = {}
    for entry in tx.get("Memos") or []:
        m = entry.get("Memo", {})
        try:
            found[unhex(m["MemoType"])] = unhex(m["MemoData"])
        except Exception as e:
            print("  ! memo could not be decoded as hex/utf-8: %s" % e)
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="raw transaction JSON, or - for stdin")
    ap.add_argument("-window", type=int, default=172800,
                    help="seconds either side of validation to search for the "
                         "gate's issuance timestamp (default 172800 = 48h)")
    a = ap.parse_args()

    raw = sys.stdin.read() if a.path == "-" else open(a.path).read()
    tx = json.loads(raw)
    tx = tx.get("result", tx)  # tolerate a full JSON-RPC envelope

    print("SPT-Txn - XRPL payment verification")
    print("=" * 60)

    ok = True

    def check(label, good, detail=""):
        nonlocal ok
        print("  %-28s %s%s" % (label, "OK  " if good else "FAIL", detail))
        if not good:
            ok = False

    # ---- 1. the payment itself -------------------------------------------
    check("transaction type", tx.get("TransactionType") == "Payment",
          "  " + str(tx.get("TransactionType")))
    meta = tx.get("meta") or {}
    check("result", meta.get("TransactionResult") == "tesSUCCESS",
          "  " + str(meta.get("TransactionResult")))
    check("validated", bool(tx.get("validated")))

    ctid = tx.get("ctid")
    if ctid:
        c = int(ctid, 16)
        net = c & 0xFFFF
        lgr = (c >> 32) & 0x0FFFFFFF
        check("CTID network id", net == 0,
              "  %d (%s)" % (net, "MAINNET" if net == 0 else "NOT mainnet"))
        check("CTID ledger agrees", lgr == tx.get("ledger_index"),
              "  %d" % lgr)

    date = tx.get("date")
    when = (datetime.datetime.utcfromtimestamp(date + RIPPLE_EPOCH)
            .strftime("%Y-%m-%d %H:%M:%S UTC")) if date is not None else "?"
    print()
    print("  payer        %s" % tx.get("Account"))
    print("  destination  %s" % tx.get("Destination"))
    print("  amount       %s drops   delivered %s" %
          (tx.get("Amount"), meta.get("delivered_amount")))
    print("  SourceTag    %s" % tx.get("SourceTag"))
    print("  ledger       %s   validated %s" % (tx.get("ledger_index"), when))
    print()

    check("delivered == instructed",
          str(meta.get("delivered_amount")) == str(tx.get("Amount")))

    # ---- 2. the memos ----------------------------------------------------
    memos = read_memos(tx)
    anchor = memos.get(ANCHOR_MEMO)
    stamped = memos.get(CTXHASH_MEMO)
    check("humanAnchor memo present", bool(anchor))
    check("contextHash memo present", bool(stamped))
    if not (anchor and stamped):
        print("\n  Without both memos the payment carries no on-ledger binding "
              "and nothing below can be checked.")
        return 1
    print("  anchor       %s" % anchor)
    print("  contextHash  %s" % stamped)
    print()

    # ---- 3. re-derive the commitment -------------------------------------
    # The preimage names the tag field "DestinationTag" while the payment
    # stamps SourceTag; both variants are tried so this script does not
    # depend on that naming being settled.
    base = (date or 0) + RIPPLE_EPOCH
    hit = None
    for tag_key in ("DestinationTag", "SourceTag"):
        extra = {tag_key: str(tx.get("SourceTag")), "Memo": anchor}
        for off in range(-a.window, a.window + 1):
            ordered = [
                ("chain", "xrpl"),
                ("TransactionType", "Payment"),
                ("Account", tx.get("Account")),
                ("Destination", tx.get("Destination")),
                ("Amount", str(tx.get("Amount"))),
                ("Currency", "XRP"),
                ("timestamp", str(base + off)),
            ]
            if context_hash(ordered, extra) == stamped:
                hit = (tag_key, base + off, off)
                break
        if hit:
            break

    if not hit:
        check("contextHash re-derives", False,
              "  no match within +/-%ds" % a.window)
        print("\n  The stamped hash does not reproduce from these ledger fields.")
        return 1

    tag_key, ts, off = hit
    check("contextHash re-derives", True)
    print()
    print("  The hash on the ledger reproduces EXACTLY from:")
    print("    payer, destination, amount, currency, and the anchor in memo 1")
    print("    tag committed as   x:%s = %s" % (tag_key, tx.get("SourceTag")))
    print("    gate issued at     %d  (%s, %+ds vs validation)" %
          (ts, datetime.datetime.utcfromtimestamp(ts)
           .strftime("%Y-%m-%d %H:%M:%S UTC"), off))
    print()
    print("  So the payment is bound to that human anchor. Changing the amount,")
    print("  the destination, the payer or the anchor breaks a commitment that")
    print("  is already in ledger state and cannot be rewritten.")
    print()
    print("VERDICT: " + ("all checks passed" if ok else "SOME CHECKS FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
