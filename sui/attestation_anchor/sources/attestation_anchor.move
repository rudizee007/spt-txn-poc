/// SPT-Txn — Attestation Anchor (Sui / Move)
///
/// Anchors SPT-Txn attestation roots (32-byte values, e.g. the off-chain
/// `spt_txn_context_hash`) on Sui so any party can verify, after the fact, that a
/// given root was anchored, by whom, and when. It mirrors the off-chain
/// `internal/ledger/sui.go` adapter and the Aptos / Cairo / Solidity anchors — but
/// in Sui's object model rather than Aptos global storage.
///
/// Design (Sui-idiomatic):
///   - The log is a single SHARED object `AnchorBook`, created once by the module
///     initializer (`init`) at publish and shared so anyone can append to it.
///   - `anchor` is open: any account may append a root (an append-only public
///     log). The submitter is `tx_context::sender`; the time is the epoch
///     timestamp. Sui has no transaction memo, so this module is the anchoring
///     mechanism; the SUI-native zkLogin/SuiNS humanAnchor binding is grant work.
///
/// 2024 edition: `object`, `transfer`, `tx_context`/`TxContext`, `UID`, and
/// `vector` come from the implicit prelude; only `sui::event` is imported.
module spt_txn::attestation_anchor {
    use sui::event;

    /// Root must be exactly 32 bytes.
    const E_BAD_ROOT: u64 = 1;
    /// Requested anchor index is out of range.
    const E_OUT_OF_RANGE: u64 = 2;

    /// A single anchored record. `vector<u8>` is copyable, so this struct can be
    /// `copy` (the field is reused in the emitted event below).
    public struct Anchor has store, copy, drop {
        root: vector<u8>,
        submitter: address,
        timestamp_ms: u64,
    }

    /// The append-only log — a shared object created at publish.
    public struct AnchorBook has key {
        id: UID,
        anchors: vector<Anchor>,
    }

    /// Emitted on every successful anchor (for off-chain indexers).
    public struct Anchored has copy, drop {
        index: u64,
        submitter: address,
        root: vector<u8>,
        timestamp_ms: u64,
    }

    /// Module initializer: runs once at publish. Creates one empty AnchorBook and
    /// shares it so any account can append.
    fun init(ctx: &mut TxContext) {
        transfer::share_object(AnchorBook {
            id: object::new(ctx),
            anchors: vector[],
        });
    }

    /// Anchor a 32-byte attestation root into the shared book. Anyone may call.
    public fun anchor(book: &mut AnchorBook, root: vector<u8>, ctx: &TxContext) {
        assert!(vector::length(&root) == 32, E_BAD_ROOT);
        let index = vector::length(&book.anchors);
        let who = tx_context::sender(ctx);
        let ts = tx_context::epoch_timestamp_ms(ctx);
        vector::push_back(&mut book.anchors, Anchor { root, submitter: who, timestamp_ms: ts });
        event::emit(Anchored { index, submitter: who, root, timestamp_ms: ts });
    }

    /// Number of anchors recorded.
    public fun get_count(book: &AnchorBook): u64 {
        vector::length(&book.anchors)
    }

    /// Borrow a previously anchored record by index.
    public fun get_anchor(book: &AnchorBook, index: u64): &Anchor {
        assert!(index < vector::length(&book.anchors), E_OUT_OF_RANGE);
        vector::borrow(&book.anchors, index)
    }

    // ── tests (in-module so they can reference the private error consts) ──────

    #[test_only]
    use sui::test_scenario as ts;

    #[test_only]
    fun root_of_len(n: u8): vector<u8> {
        let mut v = vector[];
        let mut i = 0u8;
        while (i < n) { vector::push_back(&mut v, i); i = i + 1; };
        v
    }

    #[test]
    fun anchor_and_read() {
        let owner = @0xA11CE;
        let mut sc = ts::begin(owner);
        init(ts::ctx(&mut sc));
        ts::next_tx(&mut sc, owner);
        {
            let mut book = ts::take_shared<AnchorBook>(&sc);
            assert!(get_count(&book) == 0, 100);
            anchor(&mut book, root_of_len(32), ts::ctx(&mut sc));
            assert!(get_count(&book) == 1, 101);
            let rec = get_anchor(&book, 0);
            assert!(rec.submitter == owner, 102);
            assert!(vector::length(&rec.root) == 32, 103);
            ts::return_shared(book);
        };
        ts::end(sc);
    }

    #[test]
    #[expected_failure(abort_code = E_BAD_ROOT)]
    fun rejects_wrong_length() {
        let owner = @0xA11CE;
        let mut sc = ts::begin(owner);
        init(ts::ctx(&mut sc));
        ts::next_tx(&mut sc, owner);
        {
            let mut book = ts::take_shared<AnchorBook>(&sc);
            anchor(&mut book, root_of_len(31), ts::ctx(&mut sc)); // 31 bytes → abort
            ts::return_shared(book);
        };
        ts::end(sc);
    }
}
