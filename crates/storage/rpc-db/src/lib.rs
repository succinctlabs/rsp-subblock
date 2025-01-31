use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use alloy_provider::{network::AnyNetwork, Provider};
use alloy_rpc_types::BlockId;
use alloy_transport::Transport;
use reth_primitives::{
    revm_primitives::{AccountInfo, Bytecode},
    Address, B256, U256,
};
use reth_revm::db::BundleState;
use reth_revm::DatabaseRef;
use reth_storage_errors::{db::DatabaseError, provider::ProviderError};
use revm_primitives::HashMap;

/// A database that fetches data from a [Provider] over a [Transport].
#[derive(Debug, Clone)]
pub struct RpcDb<T, P> {
    /// The provider which fetches data.
    pub provider: P,
    /// The block to fetch data from.
    pub block: BlockId,
    /// The subblock's accounts.
    pub subblock_accounts: RefCell<HashMap<Address, AccountInfo>>,
    /// The subblock's storage.
    pub subblock_storage: RefCell<HashMap<Address, HashMap<U256, U256>>>,
    /// The cached accounts.
    pub accounts: RefCell<HashMap<Address, AccountInfo>>,
    /// The cached storage.
    pub storage: RefCell<HashMap<Address, HashMap<U256, U256>>>,
    /// The oldest block whose header/hash has been requested.
    pub oldest_ancestor: RefCell<u64>,
    /// A phantom type to make the struct generic over the transport.
    pub _phantom: PhantomData<T>,
}

/// Errors that can occur when interacting with the [RpcDb].
#[derive(Debug, Clone, thiserror::Error)]
pub enum RpcDbError {
    #[error("failed to fetch data: {0}")]
    RpcError(String),
    #[error("failed to find block")]
    BlockNotFound,
    #[error("failed to find trie node preimage")]
    PreimageNotFound,
}

impl<T: Transport + Clone, P: Provider<T, AnyNetwork> + Clone> RpcDb<T, P> {
    /// Create a new [`RpcDb`].
    pub fn new(provider: P, block: u64) -> Self {
        RpcDb {
            provider,
            block: block.into(),
            subblock_accounts: RefCell::new(HashMap::new()),
            subblock_storage: RefCell::new(HashMap::new()),
            accounts: RefCell::new(HashMap::new()),
            storage: RefCell::new(HashMap::new()),
            oldest_ancestor: RefCell::new(block),
            _phantom: PhantomData,
        }
    }

    /// Fetch the [AccountInfo] for an [Address].
    pub async fn fetch_account_info(&self, address: Address) -> Result<AccountInfo, RpcDbError> {
        tracing::debug!("fetching account info for address: {}", address);

        // Prioritize fetching from the cache.
        if self.accounts.borrow().contains_key(&address) {
            return Ok(self.accounts.borrow().get(&address).unwrap().clone());
        }

        // Fetch the proof for the account.
        let proof = self
            .provider
            .get_proof(address, vec![])
            .block_id(self.block)
            .await
            .map_err(|e| RpcDbError::RpcError(e.to_string()))?;

        // Fetch the code of the account.
        let code = self
            .provider
            .get_code_at(address)
            .block_id(self.block)
            .await
            .map_err(|e| RpcDbError::RpcError(e.to_string()))?;

        // Construct the account info & write it to the log.
        let bytecode = Bytecode::new_raw(code);
        let account_info = AccountInfo {
            nonce: proof.nonce,
            balance: proof.balance,
            code_hash: proof.code_hash,
            code: Some(bytecode.clone()),
        };

        // Record the account info to the state.
        self.subblock_accounts.borrow_mut().insert(address, account_info.clone());

        Ok(account_info)
    }

    /// Fetch the storage value at an [Address] and [U256] index.
    pub async fn fetch_storage_at(
        &self,
        address: Address,
        index: U256,
    ) -> Result<U256, RpcDbError> {
        tracing::debug!("fetching storage value at address: {}, index: {}", address, index);

        // Prioritize fetching from the cache.
        if let Some(storage_map) = self.storage.borrow().get(&address) {
            if let Some(value) = storage_map.get(&index) {
                return Ok(*value);
            }
        }

        // Fetch the storage value.
        let value = self
            .provider
            .get_storage_at(address, index)
            .block_id(self.block)
            .await
            .map_err(|e| RpcDbError::RpcError(e.to_string()))?;

        // Record the storage value to the state.
        let mut storage_values = self.subblock_storage.borrow_mut();
        let entry = storage_values.entry(address).or_default();
        entry.insert(index, value);

        Ok(value)
    }

    /// Fetch the block hash for a block number.
    pub async fn fetch_block_hash(&self, number: u64) -> Result<B256, RpcDbError> {
        tracing::info!("fetching block hash for block number: {}", number);

        // Fetch the block.
        let block = self
            .provider
            .get_block_by_number(number.into(), false)
            .await
            .map_err(|e| RpcDbError::RpcError(e.to_string()))?;

        // Record the block hash to the state.
        let block = block.ok_or(RpcDbError::BlockNotFound)?;
        let hash = block.header.hash;

        let mut oldest_ancestor = self.oldest_ancestor.borrow_mut();
        *oldest_ancestor = number.min(*oldest_ancestor);

        Ok(hash)
    }

    /// Gets all the state keys used. The client uses this to read the actual state data from tries.
    pub fn get_state_requests(&self) -> HashMap<Address, Vec<U256>> {
        let accounts = self.subblock_accounts.borrow();
        let storage = self.subblock_storage.borrow();

        accounts
            .keys()
            .chain(storage.keys())
            .map(|&address| {
                let storage_keys_for_address: BTreeSet<U256> = storage
                    .get(&address)
                    .map(|storage_map| storage_map.keys().cloned().collect())
                    .unwrap_or_default();

                (address, storage_keys_for_address.into_iter().collect())
            })
            .collect()
    }

    /// Advances the subblock.
    pub fn advance_subblock(&self) {
        self.subblock_accounts.borrow_mut().clear();
        self.subblock_storage.borrow_mut().clear();
    }

    pub fn update_state_diffs(&mut self, state_diffs: &BundleState) {
        for (address, account) in state_diffs.state.iter() {
            match &account.info {
                Some(info) => self.accounts.borrow_mut().insert(*address, info.clone()),
                None => self.accounts.borrow_mut().insert(*address, AccountInfo::default()),
            };
        }
        for (address, storage) in state_diffs.state.iter() {
            let storage_map =
                storage.storage.iter().map(|(k, v)| (*k, v.present_value())).collect();
            self.storage.borrow_mut().insert(*address, storage_map);
        }
    }

    /// Gets all account bytecodes.
    pub fn get_bytecodes(&self) -> Vec<Bytecode> {
        let accounts = self.accounts.borrow();

        accounts
            .values()
            .flat_map(|account| account.code.clone())
            .map(|code| (code.hash_slow(), code))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect::<Vec<_>>()
    }
}

impl<T: Transport + Clone, P: Provider<T, AnyNetwork> + Clone> DatabaseRef for RpcDb<T, P> {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".to_string()))
        })?;
        let result =
            tokio::task::block_in_place(|| handle.block_on(self.fetch_account_info(address)));
        let account_info =
            result.map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))?;
        Ok(Some(account_info))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".to_string()))
        })?;
        let result =
            tokio::task::block_in_place(|| handle.block_on(self.fetch_storage_at(address, index)));
        let value =
            result.map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))?;
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".to_string()))
        })?;
        let result = tokio::task::block_in_place(|| handle.block_on(self.fetch_block_hash(number)));
        let value =
            result.map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))?;
        Ok(value)
    }
}
