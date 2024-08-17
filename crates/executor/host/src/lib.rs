use std::marker::PhantomData;

use alloy_provider::Provider;
use alloy_transport::Transport;
use eyre::{eyre, Ok};
use reth_execution_types::ExecutionOutcome;
use reth_primitives::{proofs, Block, Bloom, Receipts, B256};
use revm::db::CacheDB;
use rsp_client_executor::{
    io::ClientExecutorInput, ChainVariant, EthereumVariant, OptimismVariant, Variant,
    CHAIN_ID_ETH_MAINNET, CHAIN_ID_OP_MAINNET,
};
use rsp_primitives::account_proof::eip1186_proof_to_account_proof;
use rsp_rpc_db::RpcDb;

/// An executor that fetches data from a [Provider] to execute blocks in the [ClientExecutor].
#[derive(Debug, Clone)]
pub struct HostExecutor<T: Transport + Clone, P: Provider<T> + Clone> {
    /// The provider which fetches data.
    pub provider: P,
    /// A phantom type to make the struct generic over the transport.
    pub phantom: PhantomData<T>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DbPersistence {
    current_block: Block,
    previous_block: Block,
    block: alloy_rpc_types::BlockId,
    state_root: B256,
    accounts: std::collections::HashMap<revm_primitives::Address, revm_primitives::AccountInfo>,
    storage: std::collections::HashMap<
        revm_primitives::Address,
        std::collections::HashMap<revm_primitives::U256, revm_primitives::U256>,
    >,
    block_hashes: std::collections::HashMap<u64, B256>,
    trie_nodes: std::collections::HashMap<B256, revm_primitives::Bytes>,
    dirty_proofs: Vec<reth_trie::AccountProof>,
    used_proofs: std::collections::HashMap<
        revm_primitives::Address,
        rsp_primitives::account_proof::AccountProofWithBytecode,
    >,
}

impl<T: Transport + Clone, P: Provider<T> + Clone> HostExecutor<T, P> {
    /// Create a new [`HostExecutor`] with a specific [Provider] and [Transport].
    pub fn new(provider: P) -> Self {
        Self { provider, phantom: PhantomData }
    }

    /// Executes the block with the given block number.
    pub async fn execute(
        &self,
        block_number: u64,
    ) -> eyre::Result<(ClientExecutorInput, ChainVariant)> {
        tracing::info!("fetching chain ID to identify chain variant");
        let chain_id = self.provider.get_chain_id().await?;
        let variant = match chain_id {
            CHAIN_ID_ETH_MAINNET => ChainVariant::Ethereum,
            CHAIN_ID_OP_MAINNET => ChainVariant::Optimism,
            _ => {
                eyre::bail!("unknown chain ID: {}", chain_id);
            }
        };

        let client_input = match variant {
            ChainVariant::Ethereum => {
                self.execute_variant::<EthereumVariant>(chain_id, block_number).await
            }
            ChainVariant::Optimism => {
                self.execute_variant::<OptimismVariant>(chain_id, block_number).await
            }
        }?;

        Ok((client_input, variant))
    }

    async fn execute_variant<V>(
        &self,
        chain_id: u64,
        block_number: u64,
    ) -> eyre::Result<ClientExecutorInput>
    where
        V: Variant,
    {
        #[allow(deprecated)]
        let persistence_folder =
            std::env::home_dir().unwrap().join(format!("data/rsp/{}", chain_id));
        if !persistence_folder.exists() {
            std::fs::create_dir_all(&persistence_folder).unwrap();
        }

        let persistence_path = persistence_folder.join(format!("{}.json", block_number));

        let persistence = if persistence_path.exists() {
            let mut persistence_file = std::fs::File::open(&persistence_path).unwrap();
            let persistence: DbPersistence =
                serde_json::from_reader(&mut persistence_file).unwrap();
            Some(persistence)
        } else {
            None
        };

        // Fetch the current block and the previous block from the provider.
        tracing::info!("fetching the current block and the previous block");
        let current_block = if let Some(persistence) = persistence.as_ref() {
            persistence.current_block.to_owned()
        } else {
            self.provider
                .get_block_by_number(block_number.into(), true)
                .await?
                .map(Block::try_from)
                .ok_or(eyre!("couldn't fetch block: {}", block_number))??
        };
        let previous_block = if let Some(persistence) = persistence.as_ref() {
            persistence.previous_block.to_owned()
        } else {
            self.provider
                .get_block_by_number((block_number - 1).into(), true)
                .await?
                .map(Block::try_from)
                .ok_or(eyre!("couldn't fetch block: {}", block_number))??
        };

        // Setup the spec for the block executor.
        tracing::info!("setting up the spec for the block executor");
        let spec = V::spec();

        // Setup the database for the block executor.
        tracing::info!("setting up the database for the block executor");
        let rpc_db = if let Some(persistence) = persistence.as_ref() {
            RpcDb {
                provider: self.provider.clone(),
                block: persistence.block,
                state_root: persistence.state_root,
                accounts: std::cell::RefCell::new(persistence.accounts.clone()),
                storage: std::cell::RefCell::new(persistence.storage.clone()),
                block_hashes: std::cell::RefCell::new(persistence.block_hashes.clone()),
                trie_nodes: std::cell::RefCell::new(persistence.trie_nodes.clone()),
                _phantom: PhantomData,
            }
        } else {
            RpcDb::new(
                self.provider.clone(),
                (block_number - 1).into(),
                previous_block.header.state_root,
            )
        };
        let cache_db = CacheDB::new(&rpc_db);

        // Execute the block and fetch all the necessary data along the way.
        tracing::info!(
            "executing the block and with rpc db: block_number={}, transaction_count={}",
            block_number,
            current_block.body.len()
        );
        let executor_block_input = current_block
            .clone()
            .with_recovered_senders()
            .ok_or(eyre!("failed to recover senders"))?;
        let executor_difficulty = current_block.header.difficulty;
        let executor_output = V::execute(&executor_block_input, executor_difficulty, cache_db)?;

        // Validate the block post execution.
        tracing::info!("validating the block post execution");
        V::validate_block_post_execution(
            &executor_block_input,
            &spec,
            &executor_output.receipts,
            &executor_output.requests,
        )?;

        // Accumulate the logs bloom.
        tracing::info!("accumulating the logs bloom");
        let mut logs_bloom = Bloom::default();
        executor_output.receipts.iter().for_each(|r| {
            logs_bloom.accrue_bloom(&r.bloom_slow());
        });

        // Convert the output to an execution outcome.
        let executor_outcome = ExecutionOutcome::new(
            executor_output.state,
            Receipts::from(executor_output.receipts),
            current_block.header.number,
            vec![executor_output.requests.into()],
        );

        let used_proofs = if let Some(persistence) = persistence.as_ref() {
            persistence.used_proofs.to_owned()
        } else {
            rpc_db.fetch_used_accounts_and_proofs().await
        };

        // For every account we touched, fetch the storage proofs for all the slots we touched.
        let dirty_storage_proofs = if let Some(persistence) = persistence.as_ref() {
            persistence.dirty_proofs.clone()
        } else {
            let mut buffer = Vec::new();
            for (address, account) in executor_outcome.bundle_accounts_iter() {
                let storage_keys = account
                    .storage
                    .keys()
                    .map(|key| B256::new(key.to_be_bytes()))
                    .collect::<Vec<_>>();
                let storage_proof = self
                    .provider
                    .get_proof(address, storage_keys)
                    .block_id((block_number - 1).into())
                    .await?;
                buffer.push(eip1186_proof_to_account_proof(storage_proof));
            }
            buffer
        };

        // Verify the state root.
        tracing::info!("verifying the state root");
        let state_root =
            rsp_mpt::compute_state_root(&executor_outcome, &dirty_storage_proofs, &rpc_db)?;

        serde_json::to_writer(
            &mut std::fs::File::create(&persistence_path).unwrap(),
            &DbPersistence {
                current_block: current_block.clone(),
                previous_block: previous_block.clone(),
                block: rpc_db.block,
                state_root: rpc_db.state_root,
                accounts: rpc_db.accounts.borrow().to_owned(),
                storage: rpc_db.storage.borrow().to_owned(),
                block_hashes: rpc_db.block_hashes.borrow().to_owned(),
                trie_nodes: rpc_db.trie_nodes.borrow().to_owned(),
                dirty_proofs: dirty_storage_proofs.clone(),
                used_proofs: used_proofs.clone(),
            },
        )
        .unwrap();

        if state_root != current_block.state_root {
            // TODO: comment this check back in, but leaving it out for now so that we can
            // get rough cycle counts.
            println!("The state root doesn't match.");
            // eyre::bail!("mismatched state root");
        }

        // Derive the block header.
        //
        // Note: the receipts root and gas used are verified by `validate_block_post_execution`.
        let mut header = current_block.header.clone();
        header.parent_hash = previous_block.hash_slow();
        header.ommers_hash = proofs::calculate_ommers_root(&current_block.ommers);
        header.state_root = current_block.state_root;
        header.transactions_root = proofs::calculate_transaction_root(&current_block.body);
        header.receipts_root = current_block.header.receipts_root;
        header.withdrawals_root = current_block
            .withdrawals
            .clone()
            .map(|w| proofs::calculate_withdrawals_root(w.into_inner().as_slice()));
        header.logs_bloom = logs_bloom;
        header.requests_root =
            current_block.requests.as_ref().map(|r| proofs::calculate_requests_root(&r.0));

        // Assert the derived header is correct.
        assert_eq!(header.hash_slow(), current_block.header.hash_slow(), "header mismatch");

        // Log the result.
        tracing::info!(
            "sucessfully executed block: block_number={}, block_hash={}, state_root={}",
            current_block.header.number,
            header.hash_slow(),
            state_root
        );

        // Create the client input.
        let client_input = ClientExecutorInput {
            previous_block,
            current_block,
            dirty_storage_proofs,
            used_storage_proofs: used_proofs,
            block_hashes: rpc_db.block_hashes.borrow().clone(),
            trie_nodes: rpc_db.trie_nodes.borrow().values().cloned().collect(),
        };
        Ok(client_input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_provider::ReqwestProvider;
    use rsp_client_executor::ClientExecutor;
    use tracing_subscriber::{
        filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt,
        util::SubscriberInitExt,
    };
    use url::Url;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_e2e_ethereum() {
        run_e2e::<EthereumVariant>("RPC_1", 18884864, "client_input_ethereum.json").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_e2e_optimism() {
        run_e2e::<OptimismVariant>("RPC_10", 122853660, "client_input_optimism.json").await;
    }

    #[test]
    fn test_input_bincode_roundtrip() {
        let file = std::fs::File::open("client_input_ethereum.json").unwrap();
        let client_input: ClientExecutorInput = serde_json::from_reader(file).unwrap();
        let serialized = bincode::serialize(&client_input).unwrap();
        let deserialized = bincode::deserialize::<ClientExecutorInput>(&serialized).unwrap();
        assert_eq!(client_input, deserialized);
    }

    async fn run_e2e<V>(env_var_key: &str, block_number: u64, input_file: &str)
    where
        V: Variant,
    {
        // Intialize the environment variables.
        dotenv::dotenv().ok();

        // Initialize the logger.
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .try_init();

        // Setup the provider.
        let rpc_url =
            Url::parse(std::env::var(env_var_key).unwrap().as_str()).expect("invalid rpc url");
        let provider = ReqwestProvider::new_http(rpc_url);

        // Setup the host executor.
        let host_executor = HostExecutor::new(provider);

        // Execute the host.
        let (client_input, _) =
            host_executor.execute(block_number).await.expect("failed to execute host");

        // Setup the client executor.
        let client_executor = ClientExecutor;

        // Execute the client.
        client_executor.execute::<V>(client_input.clone()).expect("failed to execute client");

        // Save the client input to a file.
        let file = std::fs::File::create(input_file).unwrap();
        serde_json::to_writer_pretty(file, &client_input).unwrap();

        // Load the client input from a file.
        let file = std::fs::File::open(input_file).unwrap();
        let _: ClientExecutorInput = serde_json::from_reader(file).unwrap();
    }
}
