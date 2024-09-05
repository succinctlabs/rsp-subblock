use std::collections::{BTreeMap, HashSet};

use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use itertools::Either;
use reth_execution_types::ExecutionOutcome;
use reth_primitives::{Account, B256};
use reth_storage_errors::db::DatabaseError;
use reth_trie::{
    forward_cursor::ForwardInMemoryCursor,
    hashed_cursor::{
        HashedCursor, HashedCursorFactory, HashedPostStateCursorFactory, HashedStorageCursor,
    },
    trie_cursor::{TrieCursor, TrieCursorFactory},
    AccountProof, BranchNodeCompact, HashBuilder, HashedPostStateSorted, Nibbles, StateRoot,
    TrieNode, CHILD_INDEX_RANGE, EMPTY_ROOT_HASH,
};
use revm_primitives::{keccak256, HashMap, U256};

#[derive(Clone)]
struct InMemoryTrieCursorFactory<'a> {
    account_entries: &'a Vec<(Nibbles, BranchNodeCompact)>,
    storage_entries: &'a HashMap<B256, Vec<(Nibbles, BranchNodeCompact)>>,
}

struct InMemoryAccountTrieCursor<'a> {
    cursor: ForwardInMemoryCursor<'a, Nibbles, BranchNodeCompact>,
}

struct InMemoryStorageTrieCursor<'a> {
    cursor: ForwardInMemoryCursor<'a, Nibbles, BranchNodeCompact>,
}

#[derive(Clone)]
struct InMemoryHashedCursorFactory<'a> {
    account_entries: &'a Vec<(B256, Account)>,
    storage_entries: &'a HashMap<B256, Vec<(B256, U256)>>,
}

struct InMemoryHashedAccountCursor<'a> {
    cursor: ForwardInMemoryCursor<'a, B256, Account>,
}

struct InMemoryHashedStorageCursor<'a> {
    cursor: ForwardInMemoryCursor<'a, B256, U256>,
}

impl<'a> TrieCursorFactory for InMemoryTrieCursorFactory<'a> {
    type AccountTrieCursor = InMemoryAccountTrieCursor<'a>;
    type StorageTrieCursor = InMemoryStorageTrieCursor<'a>;

    fn account_trie_cursor(&self) -> Result<Self::AccountTrieCursor, DatabaseError> {
        Ok(InMemoryAccountTrieCursor { cursor: ForwardInMemoryCursor::new(self.account_entries) })
    }

    fn storage_trie_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageTrieCursor, DatabaseError> {
        Ok(InMemoryStorageTrieCursor {
            cursor: ForwardInMemoryCursor::new(self.storage_entries.get(&hashed_address).unwrap()),
        })
    }
}

impl<'a> TrieCursor for InMemoryAccountTrieCursor<'a> {
    #[doc = " Move the cursor to the key and return if it is an exact match."]
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let in_memory = self.cursor.seek(&key);
        if in_memory.as_ref().map_or(false, |entry| entry.0 == key) {
            return Ok(in_memory);
        }

        unreachable!();
    }

    #[doc = " Move the cursor to the key and return a value matching of greater than the key."]
    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        Ok(self.cursor.seek(&key))
    }

    #[doc = " Move the cursor to the next key."]
    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        unreachable!();
    }

    #[doc = " Get the current entry."]
    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        Ok(self.cursor.current_key().cloned())
    }
}

impl<'a> TrieCursor for InMemoryStorageTrieCursor<'a> {
    #[doc = " Move the cursor to the key and return if it is an exact match."]
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let in_memory = self.cursor.seek(&key);
        if in_memory.as_ref().map_or(false, |entry| entry.0 == key) {
            return Ok(in_memory);
        }

        // Is this correct?
        Ok(None)
    }

    #[doc = " Move the cursor to the key and return a value matching of greater than the key."]
    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        Ok(self.cursor.seek(&key))
    }

    #[doc = " Move the cursor to the next key."]
    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        unreachable!();
    }

    #[doc = " Get the current entry."]
    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        Ok(self.cursor.current_key().cloned())
    }
}

impl<'a> HashedCursorFactory for InMemoryHashedCursorFactory<'a> {
    type AccountCursor = InMemoryHashedAccountCursor<'a>;
    type StorageCursor = InMemoryHashedStorageCursor<'a>;

    fn hashed_account_cursor(&self) -> Result<Self::AccountCursor, DatabaseError> {
        Ok(InMemoryHashedAccountCursor { cursor: ForwardInMemoryCursor::new(self.account_entries) })
    }

    fn hashed_storage_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageCursor, DatabaseError> {
        Ok(InMemoryHashedStorageCursor {
            cursor: ForwardInMemoryCursor::new(self.storage_entries.get(&hashed_address).unwrap()),
        })
    }
}

impl<'a> HashedCursor for InMemoryHashedAccountCursor<'a> {
    type Value = Account;

    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(self.cursor.seek(&key))
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(self.cursor.next())
    }
}

impl<'a> HashedCursor for InMemoryHashedStorageCursor<'a> {
    type Value = U256;

    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(self.cursor.seek(&key))
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(self.cursor.next())
    }
}

impl<'a> HashedStorageCursor for InMemoryHashedStorageCursor<'a> {
    fn is_storage_empty(&mut self) -> Result<bool, DatabaseError> {
        Ok(self.cursor.is_empty())
    }
}

#[allow(clippy::type_complexity)]
fn proofs_to_stuff<T: Decodable + Default>(
    proofs: Vec<(B256, Vec<Bytes>)>,
) -> eyre::Result<(Vec<(Nibbles, BranchNodeCompact)>, Vec<(B256, T)>)> {
    let mut my_entries: HashMap<Nibbles, BranchNodeCompact> = HashMap::new();

    let mut trie_nodes = BTreeMap::default();
    let mut ignored_keys = HashSet::<Nibbles>::default();

    let mut leaves = BTreeMap::default();

    // Hack to make sure the node iter doesn't prematurely ends. THIS CAUSES WRONG TRIE ROOT.
    leaves.insert(
        B256::from_slice(&reth_primitives::hex!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )),
        T::default(),
    );

    for (hashed_key, proof) in proofs.iter() {
        let key = Nibbles::unpack(hashed_key);

        let mut path = Nibbles::default();
        let mut proof_iter = proof.iter().peekable();

        while let Some(encoded) = proof_iter.next() {
            let mut next_path = path.clone();
            match TrieNode::decode(&mut &encoded[..])? {
                TrieNode::Branch(branch) => {
                    next_path.push(key[path.len()]);

                    let mut children = vec![];

                    let mut stack_ptr = branch.as_ref().first_child_index();
                    for index in CHILD_INDEX_RANGE {
                        let mut branch_child_path = path.clone();
                        branch_child_path.push(index);

                        if branch.state_mask.is_bit_set(index) {
                            children.push(B256::from_slice(&branch.stack[stack_ptr][1..]));

                            if !key.starts_with(&branch_child_path) {
                                let child = &branch.stack[stack_ptr];
                                if child.len() == B256::len_bytes() + 1 {
                                    // The child node is referred to by hash.
                                    trie_nodes.insert(
                                        branch_child_path,
                                        Either::Left(B256::from_slice(&child[1..])),
                                    );
                                } else {
                                    // The child node is encoded in-place. Temporarily ignored for
                                    // cycle tracking.
                                    todo!()
                                }
                            }
                            stack_ptr += 1;
                        }
                    }

                    my_entries.insert(
                        path.clone(),
                        BranchNodeCompact::new(
                            branch.state_mask,
                            0,
                            branch.state_mask,
                            children,
                            None,
                        ),
                    );
                }
                TrieNode::Extension(extension) => {
                    next_path.extend_from_slice(&extension.key);

                    // Add the extended branch node if this is the last proof item. This can happen
                    // when proving the previous absence of a new node that shares the prefix with
                    // the extension node.
                    if proof_iter.peek().is_none() {
                        let child = &extension.child;
                        if child.len() == B256::len_bytes() + 1 {
                            // The extension child is referenced by hash.
                            trie_nodes.insert(
                                next_path.clone(),
                                Either::Left(B256::from_slice(&child[1..])),
                            );
                        } else {
                            // An extension's child can only be a branch. Since here it's also not a
                            // hash, it can only be a branch node encoded in place. This could
                            // happen in theory when two leaf nodes share a very long common prefix
                            // and both have very short values.
                            //
                            // In practice, since key paths are Keccak hashes, it's extremely
                            // difficult to get two slots like this for testing. Since this cannot
                            // be properly tested, it's more preferable to leave it unimplemented to
                            // be alerted when this is hit (which is extremely unlikely).
                            //
                            // Using `unimplemented!` instead of `todo!` because of this.
                            //
                            // To support this, the underlying `alloy-trie` crate (which is
                            // currently faulty for not supported in-place encoded nodes) must first
                            // be patched to support adding in-place nodes to the hash builder.
                            // Relevant PR highlighting the issue:
                            //
                            // https://github.com/alloy-rs/trie/pull/27
                            unimplemented!("extension child is a branch node encoded in place")
                        }
                    }
                }
                TrieNode::Leaf(leaf) => {
                    next_path.extend_from_slice(&leaf.key);
                    trie_nodes.insert(next_path.clone(), Either::Right(leaf.value.clone()));

                    let storage_value = T::decode(&mut leaf.value.as_slice()).unwrap();

                    leaves.insert(B256::from_slice(&next_path.pack()), storage_value);
                }
            };
            path = next_path;
        }
    }

    // Ignore branch child hashes in the path of leaves or lower child hashes.
    let mut keys = trie_nodes.keys().peekable();
    while let Some(key) = keys.next() {
        if keys.peek().map_or(false, |next| next.starts_with(key)) {
            ignored_keys.insert(key.clone());
        }
    }

    // Build the hash tree.
    let mut hash_builder = HashBuilder::default().with_updates(true);
    for (path, value) in trie_nodes.into_iter().filter(|(path, _)| !ignored_keys.contains(path)) {
        match value {
            Either::Left(branch_hash) => {
                hash_builder.add_branch(path, branch_hash, true);
            }
            Either::Right(leaf_value) => {
                hash_builder.add_leaf(path, &leaf_value);
            }
        }
    }

    // Forces the last item to be updated by calculating root.
    hash_builder.root();

    let (_, updates) = hash_builder.split();

    for (key, value) in updates.into_iter() {
        my_entries.insert(key, value);
    }

    let mut entries: Vec<_> = my_entries.into_iter().collect();
    entries.sort_by_key(|item| item.0.clone());

    let leaves: Vec<_> = leaves.into_iter().collect();

    Ok((entries, leaves))
}

pub fn compute_state_root(
    execution_outcome: &ExecutionOutcome,
    storage_proofs: &[AccountProof],
) -> eyre::Result<B256> {
    let mut storage_trie_entries = HashMap::new();
    let mut hashed_storage_entries = HashMap::new();

    let (account_trie_entries, hashed_account_entries) = {
        let (entries, leaves) = proofs_to_stuff::<alloy_rpc_types::Account>(
            storage_proofs
                .iter()
                .map(|proof| (keccak256(proof.address), proof.proof.clone()))
                .collect(),
        )
        .unwrap();

        // We have to do this because when Account does not come with inline storage hash, so
        // the hasher always attempts to walk the storage trie.
        //
        // It's okay to always insert here, as it gets overwritten by the code below if we actually
        // have access to the storage.
        for leaf in leaves.iter() {
            storage_trie_entries.insert(
                leaf.0,
                vec![(
                    Nibbles::default(),
                    BranchNodeCompact::new(
                        0b1111111111111111_u16,
                        0,
                        0,
                        vec![],
                        Some(leaf.1.storage_root),
                    ),
                )],
            );

            hashed_storage_entries.insert(
                leaf.0,
                if leaf.1.storage_root == EMPTY_ROOT_HASH {
                    vec![]
                } else {
                    // This is to prevent the empty cursor short circuit
                    vec![(
                        B256::from(reth_primitives::hex!(
                            "1111111111111111111111111111111111111111111111111111111111111111"
                        )),
                        U256::from(2),
                    )]
                },
            );
        }

        (
            entries,
            leaves
                .into_iter()
                .map(|(key, value)| {
                    (
                        key,
                        Account {
                            nonce: value.nonce,
                            balance: value.balance,
                            bytecode_hash: if value.code_hash == keccak256([]) {
                                None
                            } else {
                                Some(value.code_hash)
                            },
                        },
                    )
                })
                .collect::<Vec<_>>(),
        )
    };

    for proof in storage_proofs.iter() {
        let hashed_address = keccak256(proof.address);
        let (entries, leaves) = proofs_to_stuff::<U256>(
            proof
                .storage_proofs
                .iter()
                .map(|proof| (keccak256(proof.key), proof.proof.clone()))
                .collect(),
        )
        .unwrap();

        storage_trie_entries.insert(hashed_address, entries);
        hashed_storage_entries.insert(hashed_address, leaves);
    }

    println!("cycle-tracker-start: reth-root");

    println!("cycle-tracker-start: prep");

    let in_memory_trie_cursor_factory = InMemoryTrieCursorFactory {
        account_entries: &account_trie_entries,
        storage_entries: &storage_trie_entries,
    };
    let in_memory_hashed_cursor_factory = InMemoryHashedCursorFactory {
        account_entries: &hashed_account_entries,
        storage_entries: &hashed_storage_entries,
    };

    println!("cycle-tracker-end: prep");

    println!("cycle-tracker-start: hash");
    let hashed_post_state = execution_outcome.hash_state_slow();
    println!("cycle-tracker-end: hash");

    println!("cycle-tracker-start: prefix");
    let prefix_sets = hashed_post_state.construct_prefix_sets().freeze();
    println!("cycle-tracker-end: prefix");

    println!("cycle-tracker-start: sort");
    let sorted_stated: HashedPostStateSorted = hashed_post_state.into_sorted();
    println!("cycle-tracker-end: sort");

    println!("cycle-tracker-start: factory");
    let hashed_post_state_cursor_factory =
        HashedPostStateCursorFactory::new(in_memory_hashed_cursor_factory, &sorted_stated);
    println!("cycle-tracker-end: factory");

    println!("cycle-tracker-start: root");
    let root = StateRoot::new(in_memory_trie_cursor_factory, hashed_post_state_cursor_factory)
        .with_prefix_sets(prefix_sets)
        .root()
        .unwrap();
    println!("cycle-tracker-end: root");

    println!("cycle-tracker-end: reth-root");

    Ok(root)
}
