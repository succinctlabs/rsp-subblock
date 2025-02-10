use std::{collections::HashMap, iter::once};

use itertools::Itertools;
use reth_errors::ProviderError;
use reth_primitives::{
    revm_primitives::AccountInfo, Address, Block, Bloom, Header, Receipt, B256, U256,
};
use reth_trie::{HashedPostState, TrieAccount};
use revm_primitives::{keccak256, Bytecode};
use rsp_mpt::EthereumState;
//use rsp_witness_db::WitnessDb;
use revm::DatabaseRef;
use serde::{Deserialize, Serialize};
use std::io::Write;

use sp1_sdk::{HashableKey, SP1Stdin, SP1VerifyingKey};

use crate::{error::ClientError, hash_transactions};

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubblockInput {
    /// The current block (which will be executed inside the client).
    pub current_block: Block,
    /// Simple DB
    pub simple_db: SimpleDB,
    /// Whether this is the first subblock (do we need to do pre-execution transactions?)
    pub is_first_subblock: bool,
    /// Whether this is the last subblock (do we need to do post-execution transactions?)
    pub is_last_subblock: bool,
}

/// TODO: needs a better name
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllSubblockOutputs {
    pub subblock_inputs: Vec<SubblockInput>,
    pub subblock_outputs: Vec<SubblockOutput>,
    pub agg_input: AggregationInput,
}

impl AllSubblockOutputs {
    /// Constructs the aggregation stdin, sans the subblock proofs.
    pub fn to_aggregation_stdin(&self, subblock_vk: &SP1VerifyingKey) -> SP1Stdin {
        let mut stdin = SP1Stdin::new();

        assert_eq!(self.subblock_inputs.len(), self.subblock_outputs.len());
        let mut public_values = Vec::new();
        for i in 0..self.subblock_inputs.len() {
            let mut current_public_values = Vec::new();
            let transaction_hash = hash_transactions(&self.subblock_inputs[i].current_block.body);
            bincode::serialize_into(&mut current_public_values, &transaction_hash).unwrap();

            let serialized = rkyv::to_bytes::<rkyv::rancor::BoxedError>(&self.subblock_outputs[i])
                .expect("failed to serialize state diff")
                .to_vec();
            current_public_values.write_all(&serialized).unwrap();

            public_values.push(current_public_values);
        }
        stdin.write::<Vec<Vec<u8>>>(&public_values);
        stdin.write::<[u32; 8]>(&subblock_vk.hash_u32());
        let buffer = bincode::serialize(&self.agg_input).unwrap();
        stdin.write_vec(buffer);
        stdin
    }
}

/// The input for the client to execute a block and fully verify the STF (state transition
/// function).
///
/// Instead of passing in the entire state, we only pass in the state roots along with merkle proofs
/// for the storage slots that were modified and accessed.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    /* rkyv::Archive,
     * rkyv::Serialize,
     * rkyv::Deserialize, */
)]
pub struct AggregationInput {
    /// The current block (which will be executed inside the client).
    pub current_block: Block,
    /// The previous block headers starting from the most recent. There must be at least one header
    /// to provide the parent state root.
    pub ancestor_headers: Vec<Header>,
    /// Network state as of the parent block.
    pub parent_state: EthereumState,
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

#[derive(
    Debug, Clone, Serialize, Deserialize, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct SubblockOutput {
    pub state_diff: HashedPostState,
    pub logs_bloom: Bloom,
    pub receipts: Vec<Receipt>,
    // pub requests: Vec<Request>, // This is only needed for pectra.
}

impl SubblockOutput {
    pub fn extend(&mut self, other: Self) {
        let cumulative_gas_used = match self.receipts.last() {
            Some(receipt) => receipt.cumulative_gas_used,
            None => 0,
        };

        self.state_diff.extend(other.state_diff);
        self.logs_bloom.accrue_bloom(&other.logs_bloom);
        let mut receipts = other.receipts;
        receipts.iter_mut().for_each(|receipt| {
            receipt.cumulative_gas_used += cumulative_gas_used;
        });
        self.receipts.extend(receipts);
        // self.requests.extend(other.requests);
    }
}

#[derive(Debug)]
pub struct TrieDB<'a> {
    inner: &'a EthereumState,
    block_hashes: HashMap<u64, B256>,
    bytecode_by_hash: HashMap<B256, &'a Bytecode>,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    /* rkyv::Archive,
     * rkyv::Serialize,
     * rkyv::Deserialize, */
)]
pub struct SimpleDB {
    /// The cached accounts.
    pub accounts: HashMap<Address, AccountInfo>,
    /// The cached storage.
    pub storage: HashMap<Address, HashMap<U256, U256>>,
    /// The cached block hashes.
    pub block_hashes: HashMap<u64, B256>,
}

impl SimpleDB {
    pub fn new(
        accounts: HashMap<Address, AccountInfo>,
        storage: HashMap<Address, HashMap<U256, U256>>,
        block_hashes: HashMap<u64, B256>,
    ) -> Self {
        Self { accounts, storage, block_hashes }
    }
}

impl<'a> TrieDB<'a> {
    pub fn new(
        inner: &'a EthereumState,
        block_hashes: HashMap<u64, B256>,
        bytecode_by_hash: HashMap<B256, &'a Bytecode>,
    ) -> Self {
        Self { inner, block_hashes, bytecode_by_hash }
    }
}

impl<'a> DatabaseRef for TrieDB<'a> {
    /// The database error type.
    type Error = ProviderError;

    /// Get basic account information.
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let hashed_address = keccak256(address);
        let hashed_address = hashed_address.as_slice();

        let account_in_trie = self.inner.state_trie.get_rlp::<TrieAccount>(hashed_address).unwrap();

        let account = account_in_trie.map(|account_in_trie| AccountInfo {
            balance: account_in_trie.balance,
            nonce: account_in_trie.nonce,
            code_hash: account_in_trie.code_hash,
            code: None,
        });

        Ok(account)
    }

    /// Get account code by its hash.
    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.bytecode_by_hash.get(&hash).map(|code| (*code).clone()).unwrap())
    }

    /// Get storage value of address at index.
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let hashed_address = keccak256(address);
        let hashed_address = hashed_address.as_slice();

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

    /// Get block hash by block number.
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(*self
            .block_hashes
            .get(&number)
            .expect("A block hash must be provided for each block number"))
    }
}

impl DatabaseRef for SimpleDB {
    /// The database error type.
    type Error = ProviderError;

    /// Get basic account information.
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }

    /// Get account code by its hash.
    fn code_by_hash_ref(&self, _hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
        // Ok(self.bytecode_by_hash.get(&hash).map(|code| (*code).clone()).unwrap())
    }

    /// Get storage value of address at index.
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(*self.storage.get(&address).unwrap().get(&index).unwrap())
    }

    /// Get block hash by block number.
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(*self
            .block_hashes
            .get(&number)
            .expect("A block hash must be provided for each block number"))
    }
}

/// A trait for constructing [`WitnessDb`].
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
