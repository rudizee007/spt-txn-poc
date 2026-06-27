/// SPT-Txn — Attestation Anchor (Aptos / Move)
///
/// Anchors SPT-Txn attestation roots (32-byte SHA-256 values) on Aptos so any
/// party can verify, after the fact, that a given root was anchored, by whom,
/// and when. Mirrors the off-chain `internal/ledger/aptos.go` adapter and the
/// Starknet Cairo `attestation_anchor` contract — here as a first-class Move
/// module.
///
/// A root is the off-chain SPT-Txn `ContextHash` (or any attestation root): a
/// 32-byte value held as `vector<u8>` of length 32. Anchor the same value the
/// off-chain token binds to, so the on-chain record and the token tie together.
///
/// Design notes:
///   - The anchor log lives in an `AnchorBook` resource published under one
///     account (the deployer). `init_book` creates it once.
///   - `anchor` is open: anyone may append a root (an append-only public log).
///     The submitter's address is recorded from their signer. Move lets any
///     function in this module mutate the book via `borrow_global_mut`, so a
///     caller does not need the book owner's signer to append.
///   - Aptos has no native transaction memo; this module is the anchoring
///     mechanism. With Move account abstraction, an agent account can separately
///     enforce its Capability Token scope on-chain (the agentic grant deliverable).
///
/// Scaffolded against current Aptos framework. If the framework API shifts,
/// bump the `rev` in Move.toml to match your `aptos` CLI.
module spt_txn::attestation_anchor {
    use std::signer;
    use std::vector;
    use aptos_framework::timestamp;
    use aptos_framework::event;

    /// An AnchorBook already exists under this account.
    const E_BOOK_EXISTS: u64 = 1;
    /// No AnchorBook exists under the given owner.
    const E_NO_BOOK: u64 = 2;
    /// Root must be exactly 32 bytes (a SHA-256 digest).
    const E_BAD_ROOT: u64 = 3;
    /// Requested anchor index is out of range.
    const E_OUT_OF_RANGE: u64 = 4;

    /// A single anchored record.
    struct Anchor has copy, drop, store {
        root: vector<u8>,
        submitter: address,
        timestamp: u64,
    }

    /// The append-only log, published under the deployer's account.
    struct AnchorBook has key {
        anchors: vector<Anchor>,
    }

    #[event]
    /// Emitted on every successful anchor.
    struct Anchored has drop, store {
        book_owner: address,
        index: u64,
        submitter: address,
        root: vector<u8>,
        timestamp: u64,
    }

    /// Publish an empty AnchorBook under `account`. Call once after deploy.
    public entry fun init_book(account: &signer) {
        let owner = signer::address_of(account);
        assert!(!exists<AnchorBook>(owner), E_BOOK_EXISTS);
        move_to(account, AnchorBook { anchors: vector::empty<Anchor>() });
    }

    /// Anchor a 32-byte attestation root into the book at `book_owner`.
    /// Anyone may call; the submitter address is taken from `submitter`.
    public entry fun anchor(
        submitter: &signer,
        book_owner: address,
        root: vector<u8>,
    ) acquires AnchorBook {
        assert!(exists<AnchorBook>(book_owner), E_NO_BOOK);
        assert!(vector::length(&root) == 32, E_BAD_ROOT);

        let book = borrow_global_mut<AnchorBook>(book_owner);
        let index = vector::length(&book.anchors);
        let who = signer::address_of(submitter);
        let ts = timestamp::now_seconds();

        vector::push_back(&mut book.anchors, Anchor { root, submitter: who, timestamp: ts });
        event::emit(Anchored { book_owner, index, submitter: who, root, timestamp: ts });
    }

    #[view]
    /// Number of anchors recorded in the book at `book_owner`.
    public fun get_count(book_owner: address): u64 acquires AnchorBook {
        assert!(exists<AnchorBook>(book_owner), E_NO_BOOK);
        vector::length(&borrow_global<AnchorBook>(book_owner).anchors)
    }

    #[view]
    /// Read a previously anchored record by index.
    public fun get_anchor(book_owner: address, index: u64): Anchor acquires AnchorBook {
        assert!(exists<AnchorBook>(book_owner), E_NO_BOOK);
        let book = borrow_global<AnchorBook>(book_owner);
        assert!(index < vector::length(&book.anchors), E_OUT_OF_RANGE);
        *vector::borrow(&book.anchors, index)
    }

    #[test_only]
    use aptos_framework::account;

    #[test(fx = @aptos_framework, deployer = @0xA11CE, caller = @0xB0B)]
    fun anchor_and_read(fx: &signer, deployer: &signer, caller: &signer) acquires AnchorBook {
        // timestamp framework needs initialization in tests.
        timestamp::set_time_has_started_for_testing(fx);
        account::create_account_for_test(signer::address_of(deployer));
        account::create_account_for_test(signer::address_of(caller));

        init_book(deployer);
        let owner = signer::address_of(deployer);
        assert!(get_count(owner) == 0, 100);

        // 32-byte root.
        let root = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut root, (i as u8)); i = i + 1; };

        anchor(caller, owner, root);
        assert!(get_count(owner) == 1, 101);

        let rec = get_anchor(owner, 0);
        assert!(rec.submitter == signer::address_of(caller), 102);
        assert!(vector::length(&rec.root) == 32, 103);
    }

    #[test(fx = @aptos_framework, deployer = @0xA11CE, caller = @0xB0B)]
    #[expected_failure(abort_code = E_BAD_ROOT)]
    fun rejects_wrong_length_root(fx: &signer, deployer: &signer, caller: &signer) acquires AnchorBook {
        timestamp::set_time_has_started_for_testing(fx);
        account::create_account_for_test(signer::address_of(deployer));
        account::create_account_for_test(signer::address_of(caller));
        init_book(deployer);
        // 31 bytes — must abort.
        let root = vector::empty<u8>();
        let i = 0;
        while (i < 31) { vector::push_back(&mut root, 0u8); i = i + 1; };
        anchor(caller, signer::address_of(deployer), root);
    }
}
