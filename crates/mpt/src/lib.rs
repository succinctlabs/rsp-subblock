use itertools::Itertools;
use reth_trie::{AccountProof, HashedPostState, TrieAccount};
use revm::primitives::{Address, HashMap, B256};
use rkyv::{
    de,
    with::{Identity, MapKV},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Module containing MPT code adapted from `zeth`.
mod mpt;
pub use mpt::Error;
use mpt::{proofs_to_tries, transition_proofs_to_tries, B256Def, MptNode, MptNodeReference};

/// Ethereum state trie and account storage tries.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct EthereumState {
    pub state_trie: MptNode,
    #[rkyv(with = MapKV<B256Def, Identity>)]
    pub storage_tries: HashMap<B256, MptNode>,
}

impl EthereumState {
    /// Builds Ethereum state tries from relevant proofs before and after a state transition.
    pub fn from_transition_proofs(
        state_root: B256,
        parent_proofs: &HashMap<Address, AccountProof>,
        proofs: &HashMap<Address, AccountProof>,
    ) -> Result<Self, FromProofError> {
        transition_proofs_to_tries(state_root, parent_proofs, proofs)
    }

    /// Builds Ethereum state tries from relevant proofs from a given state.
    pub fn from_proofs(
        state_root: B256,
        proofs: &HashMap<Address, AccountProof>,
    ) -> Result<Self, FromProofError> {
        proofs_to_tries(state_root, proofs)
    }

    /// Mutates state based on diffs provided in [`HashedPostState`].
    pub fn update(&mut self, post_state: &HashedPostState) {
        for (hashed_address, account) in post_state.accounts.iter().sorted_by(|a, b| a.0.cmp(b.0)) {
            println!("hashed_address: {:?}", hashed_address);
            let hashed_address = hashed_address.as_slice();

            match account {
                Some(account) => {
                    println!("inserting account: {:?}", account);
                    let state_storage = &post_state.storages.get(hashed_address).unwrap();
                    let storage_root = {
                        let storage_trie = self.storage_tries.get_mut(hashed_address).unwrap();

                        if state_storage.wiped {
                            println!("clearing storage");
                            storage_trie.clear();
                        }

                        let mut deferred_deletes = Vec::new();
                        for (key, value) in state_storage.storage.iter() {
                            let key = key.as_slice();
                            if value.is_zero() {
                                deferred_deletes.push(key);
                            } else {
                                println!("inserting storage key: {:?}", key);
                                storage_trie.insert_rlp(key, *value).unwrap();
                            }
                            println!("storage_root: {:?}", storage_trie.hash());
                        }
                        for key in deferred_deletes {
                            println!("deleting storage key: {:?}", key);
                            storage_trie.delete(key).unwrap();
                        }
                        println!(
                            "FINAL STORAGE ROOT -------------------------------: {:?}",
                            storage_trie.hash()
                        );
                        storage_trie.hash()
                    };

                    let state_account = TrieAccount {
                        nonce: account.nonce,
                        balance: account.balance,
                        storage_root,
                        code_hash: account.get_bytecode_hash(),
                    };
                    self.state_trie.insert_rlp(hashed_address, state_account).unwrap();
                }
                None => {
                    println!("deleting account: {:?}", hashed_address);
                    self.state_trie.delete(hashed_address).unwrap();
                }
            }
        }
    }

    /// Computes the state root.
    pub fn state_root(&self) -> B256 {
        self.state_trie.hash()
    }

    /// Given a state trie constructed with some storage proofs, prunes it to only include the
    /// necessary hashes for certain addresses / storage slots touched.
    ///
    /// Note: never called in the zkvm, so it's pretty fine that this is not optimized.
    pub fn prune(&mut self, touched_state: &HashedPostState) {
        // Iterate over all of the touched state, marking nodes touched along the way.
        let (touched_account_refs, touched_storage_refs) = self.get_touched_nodes(touched_state);

        // Now, traverse the entire trie, replacing any nodes that are not touched with their
        // digest.
        let prev_state_root = self.state_root();
        self.state_trie.prune_unmarked_nodes(&touched_account_refs);
        let new_state_root = self.state_root();
        assert_eq!(prev_state_root, new_state_root);

        for (hashed_address, storage_refs) in touched_storage_refs {
            let storage_trie = self.storage_tries.get_mut(&hashed_address).unwrap();
            let prev_storage_root = storage_trie.hash();
            storage_trie.prune_unmarked_nodes(&storage_refs);
            let new_storage_root = storage_trie.hash();
            assert_eq!(prev_storage_root, new_storage_root);
        }
    }

    fn get_touched_nodes(
        &self,
        post_state: &HashedPostState,
    ) -> (HashSet<MptNodeReference>, HashMap<B256, HashSet<MptNodeReference>>) {
        let mut touched_account_refs = HashSet::new();
        let mut touched_storage_refs = HashMap::<B256, HashSet<MptNodeReference>>::new();
        for (hashed_address, account) in post_state.accounts.iter().sorted_by(|a, b| a.0.cmp(b.0)) {
            println!("hashed_address: {:?}", hashed_address);
            let hashed_address = hashed_address.as_slice();

            match account {
                Some(account) => {
                    println!("inserting account: {:?}", account);
                    let state_storage = &post_state.storages.get(hashed_address).unwrap();
                    let storage_root = {
                        let storage_trie = self.storage_tries.get_mut(hashed_address).unwrap();

                        if state_storage.wiped {
                            println!("clearing storage");
                            storage_trie.clear();
                        }

                        let mut deferred_deletes = Vec::new();
                        for (key, value) in state_storage.storage.iter() {
                            let key = key.as_slice();
                            if value.is_zero() {
                                deferred_deletes.push(key);
                            } else {
                                println!("inserting storage key: {:?}", key);
                                let (_gotten, touched) =
                                    storage_trie.get_with_touched(key).unwrap();
                                touched_storage_refs
                                    .entry(hashed_address)
                                    .or_default()
                                    .insert(touched);
                            }
                            println!("storage_root: {:?}", storage_trie.hash());
                        }
                        for key in deferred_deletes {
                            println!("deleting storage key: {:?}", key);
                            storage_trie.delete(key).unwrap();
                        }
                        println!(
                            "FINAL STORAGE ROOT -------------------------------: {:?}",
                            storage_trie.hash()
                        );
                        storage_trie.hash()
                    };

                    let state_account = TrieAccount {
                        nonce: account.nonce,
                        balance: account.balance,
                        storage_root,
                        code_hash: account.get_bytecode_hash(),
                    };
                    self.state_trie.insert_rlp(hashed_address, state_account).unwrap();
                }
                None => {
                    println!("deleting account: {:?}", hashed_address);
                    self.state_trie.delete(hashed_address).unwrap();
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromProofError {
    #[error("Node {} is not found by hash", .0)]
    NodeNotFoundByHash(usize),
    #[error("Node {} refrences invalid successor", .0)]
    NodeHasInvalidSuccessor(usize),
    #[error("Node {} cannot have children and is invalid", .0)]
    NodeCannotHaveChildren(usize),
    #[error("Found mismatched storage root after reconstruction \n account {}, found {}, expected {}", .0, .1, .2)]
    MismatchedStorageRoot(Address, B256, B256),
    #[error("Found mismatched staet root after reconstruction \n found {}, expected {}", .0, .1)]
    MismatchedStateRoot(B256, B256),
    // todo: Should decode return a decoder error?
    #[error("Error decoding proofs from bytes, {}", .0)]
    DecodingError(#[from] Error),
}
