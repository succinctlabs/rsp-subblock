mod error;
pub use error::Error as HostError;
use reth_trie::HashedPostState;
use std::{
    collections::{BTreeSet, HashMap},
    marker::PhantomData,
};

use alloy_provider::{network::AnyNetwork, Provider};
use alloy_transport::Transport;
use reth_execution_types::ExecutionOutcome;
use reth_primitives::{proofs, Block, Bloom, Receipts, B256, U256};
use revm::db::{CacheDB, WrapDatabaseRef};
use revm_primitives::Address;
use rsp_client_executor::{
    io::{
        AggregationInput, BufferedTrieDB, ClientExecutorInput, SubblockHostOutput, SubblockInput,
        SubblockOutput,
    },
    ChainVariant, EthereumVariant, LineaVariant, OptimismVariant, SepoliaVariant, Variant,
};
use rsp_mpt::EthereumState;
use rsp_primitives::account_proof::eip1186_proof_to_account_proof;
use rsp_rpc_db::RpcDb;

/// An executor that fetches data from a [Provider] to execute blocks in the [ClientExecutor].
#[derive(Debug, Clone)]
pub struct HostExecutor<T: Transport + Clone, P: Provider<T, AnyNetwork> + Clone> {
    /// The provider which fetches data.
    pub provider: P,
    /// A phantom type to make the struct generic over the transport.
    pub phantom: PhantomData<T>,
}
lazy_static::lazy_static! {
    /// Number of transactions per subblock.
    pub static ref TRANSACTIONS_PER_SUBBLOCK: u64 = std::env::var("TRANSACTIONS_PER_SUBBLOCK")
        .map(|s| s.parse().unwrap())
        .unwrap_or(32);
}

fn merge_state_requests(
    state_requests: &mut HashMap<Address, Vec<U256>>,
    subblock_state_requests: &HashMap<Address, Vec<U256>>,
) {
    for (address, keys) in subblock_state_requests.iter() {
        state_requests.entry(*address).or_default().extend(keys.iter().cloned());
    }
}

impl<T: Transport + Clone, P: Provider<T, AnyNetwork> + Clone> HostExecutor<T, P> {
    /// Create a new [`HostExecutor`] with a specific [Provider] and [Transport].
    pub fn new(provider: P) -> Self {
        Self { provider, phantom: PhantomData }
    }

    /// Executes the block with the given block number.
    pub async fn execute(
        &self,
        block_number: u64,
        variant: ChainVariant,
    ) -> Result<ClientExecutorInput, HostError> {
        match variant {
            ChainVariant::Ethereum => self.execute_variant::<EthereumVariant>(block_number).await,
            ChainVariant::Optimism => self.execute_variant::<OptimismVariant>(block_number).await,
            ChainVariant::Linea => self.execute_variant::<LineaVariant>(block_number).await,
            ChainVariant::Sepolia => self.execute_variant::<SepoliaVariant>(block_number).await,
        }
    }

    /// Executes the block with the given block number and returns the client input for each
    /// subblock.
    ///
    /// TODO: all variants
    pub async fn execute_subblock(
        &self,
        block_number: u64,
    ) -> Result<SubblockHostOutput, HostError> {
        self.execute_variant_subblocks::<EthereumVariant>(block_number).await
    }

    async fn execute_variant<V>(&self, block_number: u64) -> Result<ClientExecutorInput, HostError>
    where
        V: Variant,
    {
        // Fetch the current block and the previous block from the provider.
        tracing::info!("fetching the current block and the previous block");

        let current_block = self
            .provider
            .get_block_by_number(block_number.into(), true)
            .await?
            .ok_or(HostError::ExpectedBlock(block_number))
            .map(|block| Block::try_from(block.inner))??;

        let previous_block = self
            .provider
            .get_block_by_number((block_number - 1).into(), true)
            .await?
            .ok_or(HostError::ExpectedBlock(block_number))
            .map(|block| Block::try_from(block.inner))??;

        // Setup the spec for the block executor.
        tracing::info!("setting up the spec for the block executor");
        let spec = V::spec();

        // Setup the database for the block executor.
        tracing::info!("setting up the database for the block executor");
        let rpc_db = RpcDb::new(self.provider.clone(), block_number - 1);
        let cache_db = CacheDB::new(&rpc_db);

        // Execute the block and fetch all the necessary data along the way.
        tracing::info!(
            "executing the block and with rpc db: block_number={}, transaction_count={}",
            block_number,
            current_block.body.len()
        );

        let executor_block_input = V::pre_process_block(&current_block)
            .with_recovered_senders()
            .ok_or(HostError::FailedToRecoverSenders)?;

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

        let state_requests = rpc_db.get_state_requests();

        // For every account we touched, fetch the storage proofs for all the slots we touched.
        tracing::info!("fetching storage proofs");
        let mut before_storage_proofs = Vec::new();
        let mut after_storage_proofs = Vec::new();

        for (address, used_keys) in state_requests.iter() {
            let modified_keys = executor_outcome
                .state()
                .state
                .get(address)
                .map(|account| {
                    account.storage.keys().map(|key| B256::from(*key)).collect::<BTreeSet<_>>()
                })
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();

            let keys = used_keys
                .iter()
                .map(|key| B256::from(*key))
                .chain(modified_keys.clone().into_iter())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();

            let storage_proof = self
                .provider
                .get_proof(*address, keys.clone())
                .block_id((block_number - 1).into())
                .await?;
            before_storage_proofs.push(eip1186_proof_to_account_proof(storage_proof));

            let storage_proof = self
                .provider
                .get_proof(*address, modified_keys)
                .block_id((block_number).into())
                .await?;
            after_storage_proofs.push(eip1186_proof_to_account_proof(storage_proof));
        }

        let state = EthereumState::from_transition_proofs(
            previous_block.state_root,
            &before_storage_proofs.iter().map(|item| (item.address, item.clone())).collect(),
            &after_storage_proofs.iter().map(|item| (item.address, item.clone())).collect(),
        )?;

        // Verify the state root.
        tracing::info!("verifying the state root");
        let state_root = {
            let mut mutated_state = state.clone();
            mutated_state.update(&executor_outcome.hash_state_slow());
            mutated_state.state_root()
        };
        if state_root != current_block.state_root {
            return Err(HostError::StateRootMismatch(state_root, current_block.state_root));
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
        let constructed_header_hash = header.hash_slow();
        let target_hash = current_block.header.hash_slow();
        if constructed_header_hash != target_hash {
            return Err(HostError::HeaderMismatch(constructed_header_hash, target_hash));
        }

        // Log the result.
        tracing::info!(
            "successfully executed block: block_number={}, block_hash={}, state_root={}",
            current_block.header.number,
            header.hash_slow(),
            state_root
        );

        // Fetch the parent headers needed to constrain the BLOCKHASH opcode.
        let oldest_ancestor = *rpc_db.oldest_ancestor.borrow();
        let mut ancestor_headers = vec![];
        tracing::info!("fetching {} ancestor headers", block_number - oldest_ancestor);
        for height in (oldest_ancestor..=(block_number - 1)).rev() {
            let block = self
                .provider
                .get_block_by_number(height.into(), false)
                .await?
                .ok_or(HostError::ExpectedBlock(height))?;

            ancestor_headers.push(block.inner.header.try_into()?);
        }

        // Create the client input.
        let client_input = ClientExecutorInput {
            current_block: V::pre_process_block(&current_block),
            ancestor_headers,
            parent_state: state,
            state_requests,
            bytecodes: rpc_db.get_bytecodes(),
        };
        tracing::info!("successfully generated client input");

        Ok(client_input)
    }

    async fn execute_variant_subblocks<V>(
        &self,
        block_number: u64,
    ) -> Result<SubblockHostOutput, HostError>
    where
        V: Variant,
    {
        // Fetch the current block and the previous block from the provider.
        tracing::info!("fetching the current block and the previous block");
        let current_block = self
            .provider
            .get_block_by_number(block_number.into(), true)
            .await?
            .ok_or(HostError::ExpectedBlock(block_number))
            .map(|block| Block::try_from(block.inner))??;

        let previous_block = self
            .provider
            .get_block_by_number((block_number - 1).into(), true)
            .await?
            .ok_or(HostError::ExpectedBlock(block_number))
            .map(|block| Block::try_from(block.inner))??;

        let total_transactions = current_block.body.len() as u64;

        let previous_block_hash = previous_block.hash_slow();

        // Setup the spec for the block executor.
        tracing::info!("setting up the spec for the block executor");

        // Setup the database for the block executor.
        tracing::info!("setting up the database for the block executor");
        let mut rpc_db = RpcDb::new(self.provider.clone(), block_number - 1);

        // Execute the block and fetch all the necessary data along the way.
        tracing::info!(
            "executing the block and with rpc db: block_number={}, transaction_count={}",
            block_number,
            total_transactions
        );

        let executor_block_input = V::pre_process_block(&current_block)
            .with_recovered_senders()
            .ok_or(HostError::FailedToRecoverSenders)?;

        let executor_difficulty = current_block.header.difficulty;

        let mut all_executor_outcomes = ExecutionOutcome::default();

        let mut all_state_requests = HashMap::new();

        let mut num_transactions_completed: u64 = 0;

        let mut result = Vec::new();
        let mut global_logs_bloom = Bloom::default();

        let mut subblock_outputs = Vec::new();

        while current_block.body.len() as u64 > num_transactions_completed {
            tracing::info!("executing subblock");
            let cache_db = CacheDB::new(&rpc_db);
            let upper = std::cmp::min(
                current_block.body.len() as u64,
                num_transactions_completed + *TRANSACTIONS_PER_SUBBLOCK,
            );
            let mut subblock_input = executor_block_input.clone();
            subblock_input.body =
                subblock_input.body[num_transactions_completed as usize..upper as usize].to_vec();
            subblock_input.senders = subblock_input.senders
                [num_transactions_completed as usize..upper as usize]
                .to_vec();

            let is_first_subblock = num_transactions_completed == 0;
            let is_last_subblock = upper == current_block.body.len() as u64;
            subblock_input.is_first_subblock = is_first_subblock;
            subblock_input.is_last_subblock = is_last_subblock;
            let subblock_output = V::execute(&subblock_input, executor_difficulty, cache_db)?;

            tracing::info!(
                "successfully executed subblock: num_transactions_completed={}, upper={}",
                num_transactions_completed,
                upper
            );

            // Accumulate the logs bloom.
            tracing::info!("accumulating the logs bloom");
            let mut logs_bloom = Bloom::default();
            subblock_output.receipts.iter().for_each(|r| {
                logs_bloom.accrue_bloom(&r.bloom_slow());
            });
            global_logs_bloom.accrue_bloom(&logs_bloom);

            // Using the diffs from the bundle, update the RPC DB.
            rpc_db.update_state_diffs(&subblock_output.state);

            let receipts = subblock_output.receipts.clone();

            // Convert the output to an execution outcome.
            let executor_outcome = ExecutionOutcome::new(
                subblock_output.state,
                Receipts::from(subblock_output.receipts),
                current_block.header.number,
                vec![subblock_output.requests.into()],
            );

            // Save the subblock's `HashedPostState` for debugging.
            let target_post_state = executor_outcome.hash_state_slow();

            let subblock_output =
                SubblockOutput { receipts, logs_bloom, state_diff: target_post_state.clone() };
            subblock_outputs.push(subblock_output);

            // Accumulate this subblock's `ExecutionOutcome` into `all_executor_outcomes`.
            all_executor_outcomes.extend(executor_outcome);

            // Merge the state requests from the subblock into `all_state_requests`.
            let subblock_state_requests = rpc_db.get_state_requests();
            merge_state_requests(&mut all_state_requests, &subblock_state_requests);

            let mut subblock_input = SubblockInput {
                current_block: V::pre_process_block(&current_block),
                parent_state_bytes: Vec::new(),
                state_diff_bytes: Vec::new(),
                block_hashes: HashMap::new(),
                bytecodes: rpc_db.get_bytecodes(),
                is_first_subblock,
                is_last_subblock,
            };

            // Slice the correct transactions for this subblock
            subblock_input.current_block.body = subblock_input.current_block.body
                [num_transactions_completed as usize..upper as usize]
                .to_vec();

            #[cfg(debug_assertions)]
            {
                // // Reconstruct the subblock input exactly as it would be in the client.
                // let debug_subblock_input = subblock_input.clone();
                // let mut input = debug_subblock_input
                //     .current_block
                //     .with_recovered_senders()
                //     .expect("failed to recover senders");
                // input.is_first_subblock = subblock_input.is_first_subblock;
                // input.is_last_subblock = subblock_input.is_last_subblock;

                // tracing::debug!("is first subblock: {:?}", input.is_first_subblock);
                // tracing::debug!("is last subblock: {:?}", input.is_last_subblock);
                // let wrap_ref = WrapDatabaseRef(debug_subblock_input.simple_db);
                // let debug_execution_output = V::execute(&input, executor_difficulty, wrap_ref)?;
                // let receipts = debug_execution_output.receipts.clone();
                // let outcome = ExecutionOutcome::new(
                //     debug_execution_output.state,
                //     Receipts::from(debug_execution_output.receipts),
                //     current_block.header.number,
                //     vec![debug_execution_output.requests.into()],
                // );

                // let mut logs_bloom = Bloom::default();
                // receipts.iter().for_each(|r| {
                //     logs_bloom.accrue_bloom(&r.bloom_slow());
                // });
                // let debug_subblock_output =
                //     SubblockOutput { receipts, logs_bloom, state_diff: outcome.hash_state_slow() };

                // tracing::info!(
                //     "Is the debug subblock output equal to the constructed subblock output? {:?}",
                //     debug_subblock_output == *subblock_outputs.last().unwrap()
                // );
                // tracing::info!(
                //     "Does the reconstructed subblock output match the target post state? {:?}",
                //     outcome.hash_state_slow() == target_post_state
                // );
            }

            // Advance subblock
            num_transactions_completed = upper;
            rpc_db.advance_subblock();

            result.push(subblock_input);
        }

        // Commented this out for now, since gas used won't line up.
        // need to check this at the end.
        // Validate the block post execution.
        // tracing::info!("validating the block post execution");
        // V::validate_block_post_execution(
        //     &subblock_input,
        //     &spec,
        //     &subblock_output.receipts,
        //     &subblock_output.requests,
        // )?;

        // Build parent state from modified keys and used keys from this subblock
        let mut before_storage_proofs = Vec::new();
        let mut after_storage_proofs = Vec::new();

        for (address, used_keys) in all_state_requests.iter() {
            let modified_keys = all_executor_outcomes
                .state()
                .state
                .get(address)
                .map(|account| {
                    account.storage.keys().map(|key| B256::from(*key)).collect::<BTreeSet<_>>()
                })
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();

            let keys = used_keys
                .iter()
                .map(|key| B256::from(*key))
                .chain(modified_keys.clone().into_iter())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();

            let storage_proof = self
                .provider
                .get_proof(*address, keys.clone())
                .block_id((block_number - 1).into())
                .await?;
            before_storage_proofs.push(eip1186_proof_to_account_proof(storage_proof));

            let storage_proof = self
                .provider
                .get_proof(*address, modified_keys)
                .block_id((block_number).into())
                .await?;
            after_storage_proofs.push(eip1186_proof_to_account_proof(storage_proof));
        }

        let parent_state = EthereumState::from_transition_proofs(
            previous_block.state_root,
            &before_storage_proofs.iter().map(|item| (item.address, item.clone())).collect(),
            &after_storage_proofs.iter().map(|item| (item.address, item.clone())).collect(),
        )?;

        // Update the parent state with the cumulative state diffs from all subblocks.
        let mut mutated_state = parent_state.clone();
        mutated_state.update(&all_executor_outcomes.hash_state_slow());

        // Verify the state root.
        let state_root = mutated_state.state_root();
        if state_root != current_block.state_root {
            return Err(HostError::StateRootMismatch(state_root, current_block.state_root));
        }

        // Derive the block header.
        //
        // Note: the receipts root and gas used are verified by `validate_block_post_execution`.
        let mut header = current_block.header.clone();
        header.parent_hash = previous_block_hash;
        header.ommers_hash = proofs::calculate_ommers_root(&current_block.ommers);
        header.state_root = current_block.state_root;
        header.transactions_root = proofs::calculate_transaction_root(&current_block.body);
        header.receipts_root = current_block.header.receipts_root;
        header.withdrawals_root = current_block
            .withdrawals
            .clone()
            .map(|w| proofs::calculate_withdrawals_root(w.into_inner().as_slice()));
        header.logs_bloom = global_logs_bloom;
        header.requests_root =
            current_block.requests.as_ref().map(|r| proofs::calculate_requests_root(&r.0));

        // Assert the derived header is correct.
        let constructed_header_hash = header.hash_slow();
        let target_hash = current_block.header.hash_slow();
        if constructed_header_hash != target_hash {
            return Err(HostError::HeaderMismatch(constructed_header_hash, target_hash));
        }

        // Log the result.
        tracing::info!(
            "successfully executed block: block_number={}, block_hash={}, state_root={}",
            current_block.header.number,
            header.hash_slow(),
            current_block.state_root
        );

        // Fetch the parent headers needed to constrain the BLOCKHASH opcode.
        let oldest_ancestor = *rpc_db.oldest_ancestor.borrow();
        let mut ancestor_headers = vec![];
        let mut block_hashes = HashMap::new();
        tracing::info!("fetching {} ancestor headers", block_number - oldest_ancestor);
        for height in (oldest_ancestor..=(block_number - 1)).rev() {
            let block = self
                .provider
                .get_block_by_number(height.into(), false)
                .await?
                .ok_or(HostError::ExpectedBlock(height))?;

            block_hashes.insert(height, block.inner.header.hash);
            ancestor_headers.push(block.inner.header.try_into()?);
        }

        let aggregation_input = AggregationInput {
            current_block: V::pre_process_block(&current_block),
            ancestor_headers,
            parent_state: parent_state.clone(),
            bytecodes: rpc_db.get_bytecodes(),
        };

        let parent_state_bytes =
            rkyv::to_bytes::<rkyv::rancor::Error>(&parent_state).unwrap().to_vec();

        let mut cumulative_state_diff = HashedPostState::default();

        for i in 0..result.len() {
            let subblock_input = &mut result[i];
            let state_diff_bytes =
                rkyv::to_bytes::<rkyv::rancor::Error>(&cumulative_state_diff).unwrap();
            subblock_input.state_diff_bytes = state_diff_bytes.to_vec();
            subblock_input.parent_state_bytes = parent_state_bytes.clone();
            subblock_input.block_hashes = block_hashes.clone();

            cumulative_state_diff.extend_ref(&subblock_outputs[i].state_diff);
        }

        let all_subblock_outputs = SubblockHostOutput {
            subblock_inputs: result,
            subblock_outputs,
            agg_input: aggregation_input,
        };

        Ok(all_subblock_outputs)
    }
}
