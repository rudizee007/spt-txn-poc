// SPT-Txn — Attestation Anchor (Starknet / Cairo)
//
// Stores SPT-Txn attestation hashes / audit roots on-chain so any party can
// verify, after the fact, that a given root was anchored, by whom, and when.
// Mirrors the off-chain `internal/ledger/starknet.go` adapter and the Solana /
// Stellar memo-anchor footprints — here as a first-class Cairo contract.
//
// A root is a 32-byte SHA-256 value, held as `u256` (a `felt252` cannot hold a
// full 256-bit hash). Pair with the off-chain SPT-Txn attestation: anchor its
// `ContextHash` here so the on-chain record and the off-chain token bind to the
// same value.
//
// Scaffolded against Cairo 2.x / Scarb 2.x and Starknet — verify against your
// installed `scarb --version`; the storage API has shifted across versions.

use starknet::ContractAddress;

#[derive(Drop, Serde, starknet::Store)]
pub struct Anchor {
    pub root: u256,
    pub submitter: ContractAddress,
    pub timestamp: u64,
}

#[starknet::interface]
pub trait IAttestationAnchor<TContractState> {
    /// Anchor an attestation root; returns its index. Anyone may call.
    fn anchor(ref self: TContractState, root: u256) -> u64;
    /// Total number of anchors recorded.
    fn get_count(self: @TContractState) -> u64;
    /// Read a previously anchored record by index.
    fn get_anchor(self: @TContractState, index: u64) -> Anchor;
}

#[starknet::contract]
mod AttestationAnchor {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use super::Anchor;

    #[storage]
    struct Storage {
        count: u64,
        anchors: Map<u64, Anchor>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Anchored: Anchored,
    }

    #[derive(Drop, starknet::Event)]
    struct Anchored {
        #[key]
        index: u64,
        #[key]
        submitter: ContractAddress,
        root: u256,
        timestamp: u64,
    }

    #[abi(embed_v0)]
    impl AttestationAnchorImpl of super::IAttestationAnchor<ContractState> {
        fn anchor(ref self: ContractState, root: u256) -> u64 {
            let index = self.count.read();
            let submitter = get_caller_address();
            let timestamp = get_block_timestamp();
            self.anchors.entry(index).write(Anchor { root, submitter, timestamp });
            self.count.write(index + 1_u64);
            self.emit(Anchored { index, submitter, root, timestamp });
            index
        }

        fn get_count(self: @ContractState) -> u64 {
            self.count.read()
        }

        fn get_anchor(self: @ContractState, index: u64) -> Anchor {
            self.anchors.entry(index).read()
        }
    }
}
