use std::{collections::HashMap, iter::once};

use itertools::Itertools;
use reth_errors::ProviderError;
use reth_execution_types::ExecutionOutcome;
use reth_primitives::{
    revm_primitives::AccountInfo, Address, Block, Bloom, Header, Receipt, Receipts, Request, B256,
    U256,
};
use reth_trie::{TrieAccount, EMPTY_ROOT_HASH};
use revm::{db::WrapDatabaseRef, DatabaseRef};
use revm_primitives::{keccak256, Bytecode};
use rsp_mpt::EthereumState;
use serde::{Deserialize, Serialize};

use rkyv::util::AlignedVec;

use crate::{error::ClientError, EthereumVariant, Variant};

/// The input for the client to execute a block and fully verify the STF (state transition
/// function).
///
/// Instead of passing in the entire state, we only pass in the state roots along with merkle proofs
/// for the storage slots that were modified and accessed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientExecutorInput {
    /// The current block (which will be executed inside the client).
    pub current_block: Block,
    /// The previous block headers starting from the most recent. There must be at least one header
    /// to provide the parent state root.
    pub ancestor_headers: Vec<Header>,
    /// Network state as of the parent block.
    pub parent_state: EthereumState,
    /// Requests to account state and storage slots.
    pub state_requests: HashMap<Address, Vec<U256>>,
    /// Account bytecodes.
    pub bytecodes: Vec<Bytecode>,
}

/// Input to the subblock program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubblockInput {
    /// The current block (which will be executed inside the client).
    pub current_block: Block,
    /// The blockhashes used by the subblock.
    ///
    /// Right now, this is just the blockhashes used by every subblock. In the future, we can
    /// probably shrink this down to just the blockhashes used by the current subblock.
    pub block_hashes: HashMap<u64, B256>,
    /// The bytecodes used by the subblock
    pub bytecodes: Vec<Bytecode>,
    /// Whether this is the first subblock (do we need to do pre-execution transactions?)
    pub is_first_subblock: bool,
    /// Whether this is the last subblock (do we need to do post-execution transactions?)
    pub is_last_subblock: bool,
    /// The starting gas used for the subblock.
    pub starting_gas_used: u64,
}

/// Everything needed to run the subblock task e2e.
///
/// Necessary data for subblock stdin and agg stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubblockHostOutput {
    pub subblock_inputs: Vec<SubblockInput>,
    pub subblock_parent_states: Vec<Vec<u8>>,
    pub subblock_outputs: Vec<SubblockOutput>,
    pub agg_input: AggregationInput,
    pub agg_parent_state: Vec<u8>,
}

impl SubblockHostOutput {
    /// Validates the output of the host executor, by running all of the subblocks natively and
    /// checking their consistency.
    pub fn validate(&self) -> Result<(), ClientError> {
        let current_block = self.agg_input.current_block.clone();
        let executor_difficulty = current_block.header.difficulty;
        for (i, subblock_input) in self.subblock_inputs.iter().enumerate() {
            let mut subblock_parent_state = rkyv::from_bytes::<EthereumState, rkyv::rancor::Error>(
                &self.subblock_parent_states[i],
            )
            .unwrap();

            let subblock_output = self.subblock_outputs[i].clone();
            let debug_subblock_input = subblock_input.clone();
            let mut input = debug_subblock_input
                .current_block
                .with_recovered_senders()
                .expect("failed to recover senders");
            input.is_first_subblock = subblock_input.is_first_subblock;
            input.is_last_subblock = subblock_input.is_last_subblock;

            tracing::debug!("is first subblock: {:?}", input.is_first_subblock);
            tracing::debug!("is last subblock: {:?}", input.is_last_subblock);

            let bytecode_by_hash =
                subblock_input.bytecodes.iter().map(|b| (b.hash_slow(), b)).collect();
            let trie_db = TrieDB::new(
                &subblock_parent_state,
                subblock_input.block_hashes.clone(),
                bytecode_by_hash,
            );
            let wrap_ref = WrapDatabaseRef(trie_db);
            let debug_execution_output =
                EthereumVariant::execute(&input, executor_difficulty, wrap_ref)?;
            let receipts = debug_execution_output.receipts.clone();
            let requests = debug_execution_output.requests.clone();
            let outcome = ExecutionOutcome::new(
                debug_execution_output.state,
                Receipts::from(debug_execution_output.receipts),
                current_block.header.number,
                vec![debug_execution_output.requests.into()],
            );

            let mut logs_bloom = Bloom::default();
            receipts.iter().for_each(|r| {
                logs_bloom.accrue_bloom(&r.bloom_slow());
            });
            let old_state_root = subblock_parent_state.state_root();
            subblock_parent_state.update(&outcome.hash_state_slow());
            let debug_subblock_output = SubblockOutput {
                receipts,
                logs_bloom,
                output_state_root: subblock_parent_state.state_root(),
                input_state_root: old_state_root,
                requests,
            };

            if debug_subblock_output != subblock_output {
                eprintln!(
                    "output state root: {:?} {:?}",
                    debug_subblock_output.output_state_root, subblock_output.output_state_root
                );
                eprintln!(
                    "input state root: {:?} {:?}",
                    debug_subblock_output.input_state_root, subblock_output.input_state_root
                );
                return Err(ClientError::InvalidSubblockOutput);
            }
        }
        Ok(())
    }
}

/// The input for the client to execute a block and fully verify the STF (state transition
/// function).
///
/// Instead of passing in the entire state, we only pass in the state roots along with merkle proofs
/// for the storage slots that were modified and accessed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregationInput {
    /// The current block (which will be executed inside the client).
    pub current_block: Block,
    /// The previous block headers starting from the most recent. There must be at least one header
    /// to provide the parent state root.
    pub ancestor_headers: Vec<Header>,
    /// Account bytecodes.
    pub bytecodes: Vec<Bytecode>,
}

impl AggregationInput {
    pub fn parent_header(&self) -> &Header {
        &self.ancestor_headers[0]
    }
}

impl ClientExecutorInput {
    /// Gets the immediate parent block's header.
    #[inline(always)]
    pub fn parent_header(&self) -> &Header {
        &self.ancestor_headers[0]
    }

    /// Creates a [`WitnessDb`].
    pub fn witness_db(&self) -> Result<TrieDB<'_>, ClientError> {
        <Self as WitnessInput>::witness_db(self)
    }
}

impl WitnessInput for ClientExecutorInput {
    #[inline(always)]
    fn state(&self) -> &EthereumState {
        &self.parent_state
    }

    #[inline(always)]
    fn state_anchor(&self) -> B256 {
        self.parent_header().state_root
    }

    #[inline(always)]
    fn state_requests(&self) -> impl Iterator<Item = (&Address, &Vec<U256>)> {
        self.state_requests.iter()
    }

    #[inline(always)]
    fn bytecodes(&self) -> impl Iterator<Item = &Bytecode> {
        self.bytecodes.iter()
    }

    #[inline(always)]
    fn headers(&self) -> impl Iterator<Item = &Header> {
        once(&self.current_block.header).chain(self.ancestor_headers.iter())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SubblockOutput {
    /// The new state root after executing this subblock.
    pub output_state_root: B256,
    /// The logs bloom.
    pub logs_bloom: Bloom,
    /// The transaction receipts.
    pub receipts: Vec<Receipt>,
    /// The state root before executing this subblock.
    pub input_state_root: B256,
    /// EIP 7685 Requests.
    pub requests: Vec<Request>,
}

impl SubblockOutput {
    /// This is intended to ONLY be called by consecutive subblocks of the same block.
    /// `self` is the current cumulative subblock output, and `other` is the new subblock output.
    pub fn extend(&mut self, other: Self) {
        // Get the gas used so far, and add it to all of the new receipts.
        let cumulative_gas_used = match self.receipts.last() {
            Some(receipt) => receipt.cumulative_gas_used,
            None => 0,
        };

        // Make sure that the current output state root lines up with the next input state root.
        assert_eq!(self.output_state_root, other.input_state_root);
        self.output_state_root = other.output_state_root;
        self.logs_bloom.accrue_bloom(&other.logs_bloom);

        // Add the cumulative gas used to the receipts.
        let mut receipts = other.receipts;
        receipts.iter_mut().for_each(|receipt| {
            receipt.cumulative_gas_used += cumulative_gas_used;
        });

        // Add other receipts to the current receipts.
        self.receipts.extend(receipts);

        // Add other requests to the current requests.
        self.requests.extend(other.requests);
    }
}

#[derive(Debug, Clone)]
pub struct TrieDB<'a> {
    inner: &'a EthereumState,
    block_hashes: HashMap<u64, B256>,
    bytecode_by_hash: HashMap<B256, &'a Bytecode>,
}

impl<'a> TrieDB<'a> {
    pub fn new(
        inner: &'a EthereumState,
        block_hashes: HashMap<u64, B256>,
        bytecode_by_hash: HashMap<B256, &'a Bytecode>,
    ) -> Self {
        Self { inner, block_hashes, bytecode_by_hash }
    }

    pub fn get_account_from_hashed_address(
        &self,
        hashed_address: &[u8],
    ) -> Result<Option<AccountInfo>, <Self as DatabaseRef>::Error> {
        let account_in_trie = self.inner.state_trie.get_rlp::<TrieAccount>(hashed_address).unwrap();

        let account = account_in_trie.map(|account_in_trie| AccountInfo {
            balance: account_in_trie.balance,
            nonce: account_in_trie.nonce,
            code_hash: account_in_trie.code_hash,
            code: None,
        });

        Ok(account)
    }

    pub fn get_storage_from_hashed_address(
        &self,
        hashed_address: &[u8],
        index: U256,
    ) -> Result<U256, <Self as DatabaseRef>::Error> {
        let storage_trie = self
            .inner
            .storage_tries
            .get(hashed_address)
            .expect("A storage trie must be provided for each account");

        Ok(storage_trie
            .get_rlp::<U256>(keccak256(index.to_be_bytes::<32>()).as_slice())
            .expect("Can get from MPT")
            .unwrap_or_default())
    }
}

impl DatabaseRef for TrieDB<'_> {
    /// The database error type.
    type Error = ProviderError;

    /// Get basic account information.
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let hashed_address = keccak256(address);

        self.get_account_from_hashed_address(hashed_address.as_slice())
    }

    /// Get account code by its hash.
    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.bytecode_by_hash.get(&hash).map(|code| (*code).clone()).unwrap())
    }

    /// Get storage value of address at index.
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let hashed_address = keccak256(address);
        let hashed_address = hashed_address.as_slice();

        self.get_storage_from_hashed_address(hashed_address, index)
    }

    /// Get block hash by block number.
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(*self
            .block_hashes
            .get(&number)
            .expect("A block hash must be provided for each block number"))
    }
}

/// A trait for constructing [`TrieDB`].
pub trait WitnessInput {
    /// Gets a reference to the state from which account info and storage slots are loaded.
    fn state(&self) -> &EthereumState;

    /// Gets the state trie root hash that the state referenced by
    /// [state()](trait.WitnessInput#tymethod.state) must conform to.
    fn state_anchor(&self) -> B256;

    /// Gets an iterator over address state requests. For each request, the account info and storage
    /// slots are loaded from the relevant tries in the state returned by
    /// [state()](trait.WitnessInput#tymethod.state).
    fn state_requests(&self) -> impl Iterator<Item = (&Address, &Vec<U256>)>;

    /// Gets an iterator over account bytecodes.
    fn bytecodes(&self) -> impl Iterator<Item = &Bytecode>;

    /// Gets an iterator over references to a consecutive, reverse-chronological block headers
    /// starting from the current block header.
    fn headers(&self) -> impl Iterator<Item = &Header>;

    /// Creates a [`WitnessDb`] from a [`WitnessInput`] implementation. To do so, it verifies the
    /// state root, ancestor headers and account bytecodes, and constructs the account and
    /// storage values by reading against state tries.
    ///
    /// NOTE: For some unknown reasons, calling this trait method directly from outside of the type
    /// implementing this trait causes a zkVM run to cost over 5M cycles more. To avoid this, define
    /// a method inside the type that calls this trait method instead.
    #[inline(always)]
    fn witness_db(&self) -> Result<TrieDB<'_>, ClientError> {
        let state = self.state();

        if self.state_anchor() != state.state_root() {
            return Err(ClientError::MismatchedStateRoot);
        }

        // Verify the storage tries.
        for (hashed_address, storage_trie) in state.storage_tries.iter() {
            let account =
                state.state_trie.get_rlp::<TrieAccount>(hashed_address.as_slice()).unwrap();
            let storage_root = account.map_or(EMPTY_ROOT_HASH, |a| a.storage_root);
            if storage_root != storage_trie.hash() {
                return Err(ClientError::MismatchedStorageRoot);
            }
        }

        let bytecodes_by_hash =
            self.bytecodes().map(|code| (code.hash_slow(), code)).collect::<HashMap<_, _>>();

        // Verify and build block hashes
        let mut block_hashes: HashMap<u64, B256> = HashMap::new();
        for (child_header, parent_header) in self.headers().tuple_windows() {
            if parent_header.number != child_header.number - 1 {
                return Err(ClientError::InvalidHeaderBlockNumber(
                    parent_header.number + 1,
                    child_header.number,
                ));
            }

            let parent_header_hash = parent_header.hash_slow();
            if parent_header_hash != child_header.parent_hash {
                return Err(ClientError::InvalidHeaderParentHash(
                    parent_header_hash,
                    child_header.parent_hash,
                ));
            }

            block_hashes.insert(parent_header.number, child_header.parent_hash);
        }

        Ok(TrieDB::new(state, block_hashes, bytecodes_by_hash))
    }
}

/// Read a buffer of bytes aligned to N from the SP1 zkVM input stream.
///
/// Note:  Since `u8` is the smallest alignment, any alignment with N % 4 == 0 is a valid alignment.
///
/// # Panics
///  - If N is not a multiple of 4.
///  - If the size hinted is 0.
pub fn read_aligned_vec<const N: usize>() -> AlignedVec<N> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "zkvm")] {
            use sp1_zkvm::syscalls::{syscall_hint_len, syscall_hint_read};
            assert!(N % align_of::<u8>() == 0, "SP1 zkVM alignment must be a multiple of 4");

            // Round up to the nearest multiple of 4 so that the memory allocated is in whole words
            let len = syscall_hint_len();
            let capacity = (len + 3) / 4 * 4;

            // Allocate a buffer of the required length that is 4 byte aligned
            let mut vec = AlignedVec::<N>::with_capacity(capacity);

            // Read the vec into uninitialized memory. The syscall assumes the memory is uninitialized,
            // which should be true because the allocator does not dealloc, so a new alloc should be fresh.
            unsafe {
                syscall_hint_read(vec.as_mut_ptr(), len);
                vec.set_len(len);
            }
            vec
        } else {
            unimplemented!()
        }
    }
}
