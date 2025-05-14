mod error;
pub use error::Error as HostError;
use reth_trie::AccountProof;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    marker::PhantomData,
    sync::Arc,
    time::Duration,
};

use alloy_provider::{network::AnyNetwork, Provider};
use alloy_transport::Transport;
use itertools::Itertools;
use reth_execution_types::ExecutionOutcome;
use reth_primitives::{proofs, Block, Bloom, Receipts, B256, U256};
use revm::db::CacheDB;
use revm_primitives::{keccak256, Address};
use rsp_client_executor::{
    io::{
        AggregationInput, ClientExecutorInput, SubblockHostOutput, SubblockInput, SubblockOutput,
    },
    ChainVariant, EthereumVariant, Variant,
};
use rsp_mpt::EthereumState;
use rsp_primitives::account_proof::eip1186_proof_to_account_proof;
use rsp_rpc_db::RpcDb;
use tokio::{task::JoinSet, time::sleep};

/// The maximum number of times to retry fetching a proof.
const MAX_PROOF_RETRIES: u32 = 3;
/// The initial backoff duration for proof fetching retries.
const INITIAL_RETRY_BACKOFF: Duration = Duration::from_millis(100);

/// An executor that fetches data from a [Provider] to execute blocks in the [ClientExecutor].
#[derive(Debug, Clone)]
pub struct HostExecutor<T: Transport + Clone, P: Provider<T, AnyNetwork> + Clone> {
    /// The provider which fetches data.
    pub provider: Arc<P>,
    /// A phantom type to make the struct generic over the transport.
    pub phantom: PhantomData<T>,
}
lazy_static::lazy_static! {
    /// Amount of gas used per subblock.
    pub static ref SUBBLOCK_GAS_LIMIT: u64 = std::env::var("SUBBLOCK_GAS_LIMIT")
        .map(|s| s.parse().unwrap())
        .unwrap_or(1_000_000);
}

fn merge_state_requests(
    state_requests: &mut HashMap<Address, Vec<U256>>,
    subblock_state_requests: &HashMap<Address, Vec<U256>>,
) {
    for (address, keys) in subblock_state_requests.iter() {
        state_requests.entry(*address).or_default().extend(keys.iter().cloned());
    }
}

impl<T: Transport + Clone, P: Provider<T, AnyNetwork> + Clone + 'static> HostExecutor<T, P> {
    /// Create a new [`HostExecutor`] with a specific [Provider] and [Transport].
    pub fn new(provider: P) -> Self {
        Self { provider: Arc::new(provider), phantom: PhantomData }
    }

    async fn get_proof(
        provider: Arc<P>,
        address: Address,
        keys: Vec<B256>,
        block_number: u64,
    ) -> Result<AccountProof, HostError> {
        let mut attempts = 0;
        let mut backoff = INITIAL_RETRY_BACKOFF;

        loop {
            match provider.get_proof(address, keys.clone()).block_id((block_number).into()).await {
                Ok(proof) => return Ok(eip1186_proof_to_account_proof(proof)),
                Err(e) => {
                    attempts += 1;
                    if attempts >= MAX_PROOF_RETRIES {
                        tracing::error!(
                            "Failed to get proof for address {} at block {} after {} attempts: {:?}",
                            address,
                            block_number,
                            attempts,
                            e
                        );
                        // Consider returning a more specific error if needed
                        return Err(HostError::Transport(e));
                    }
                    tracing::warn!(
                        "Attempt {} failed to get proof for address {} at block {}. Retrying in {:?}...",
                        attempts,
                        address,
                        block_number,
                        backoff
                    );
                    sleep(backoff).await;
                    // Exponential backoff
                    backoff *= 2;
                }
            }
        }
    }

    /// Executes the block with the given block number.
    pub async fn execute(
        &self,
        block_number: u64,
        variant: ChainVariant,
    ) -> Result<ClientExecutorInput, HostError> {
        match variant {
            ChainVariant::Ethereum => self.execute_variant::<EthereumVariant>(block_number).await,
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

        // These accumulate across multiple subblocks.
        let mut cumulative_executor_outcomes = ExecutionOutcome::default();
        let mut cumulative_state_requests = HashMap::new();

        // These store individual state requests, executor outcomes, and state diffs for each subblock.
        let mut all_state_requests = Vec::new();
        let mut all_executor_outcomes = Vec::new();
        let mut state_diffs = Vec::new();

        // The number of transactions completed so far.
        let mut num_transactions_completed: u64 = 0;

        // The amount of gas used so far.
        let mut cumulative_gas_used = 0;

        // The accumulated logs bloom, across subblocks.
        let mut global_logs_bloom = Bloom::default();

        // These store the inputs, outputs, and parent states for each subblock.
        // These are eventually fed into the zkvm.
        let mut subblock_inputs = Vec::new();
        let mut subblock_outputs = Vec::new();
        let mut subblock_parent_states = Vec::new();

        loop {
            tracing::info!("executing subblock");
            let cache_db = CacheDB::new(&rpc_db);

            // Slice the block to only include the transactions that have not been executed yet.
            let mut subblock_input = executor_block_input.clone();
            subblock_input.body =
                subblock_input.body[num_transactions_completed as usize..].to_vec();
            subblock_input.senders =
                subblock_input.senders[num_transactions_completed as usize..].to_vec();

            // Set the subblock configuration. In the host, we set `subblock_gas_limit` to the
            // `SUBBLOCK_GAS_LIMIT` environment variable. Then, even though many transactions may
            // be included in the executor input, the subblock will only execute up to the
            // `subblock_gas_limit`.
            let is_first_subblock = num_transactions_completed == 0;
            subblock_input.is_first_subblock = is_first_subblock;
            subblock_input.is_last_subblock = false;
            subblock_input.subblock_gas_limit = *SUBBLOCK_GAS_LIMIT + cumulative_gas_used;
            subblock_input.starting_gas_used = cumulative_gas_used;
            let starting_gas_used = cumulative_gas_used;

            tracing::info!("num transactions left: {}", subblock_input.body.len());

            // Execute the subblock.
            let subblock_output = V::execute(&subblock_input, executor_difficulty, cache_db)?;

            let num_executed_transactions = subblock_output.receipts.len();
            let upper = num_transactions_completed + num_executed_transactions as u64;
            let is_last_subblock = upper == current_block.body.len() as u64;

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
            // This way, the next subblock will see the state changes from the current subblock.
            rpc_db.update_state_diffs(&subblock_output.state);

            // Update the cumulative gas used.
            let receipts = subblock_output.receipts.clone();
            cumulative_gas_used +=
                receipts.last().map(|r| r.cumulative_gas_used - starting_gas_used).unwrap_or(0);

            // Convert the output to an execution outcome.
            let executor_outcome = ExecutionOutcome::new(
                subblock_output.state,
                Receipts::from(subblock_output.receipts),
                current_block.header.number,
                vec![subblock_output.requests.into()],
            );
            all_executor_outcomes.push(executor_outcome.clone());

            // Save the subblock's `HashedPostState` for debugging.
            let target_post_state = executor_outcome.hash_state_slow();
            state_diffs.push(target_post_state);

            // Initialize and set part of the subblock output. The rest will be set later.
            let subblock_output = SubblockOutput {
                receipts,
                logs_bloom,
                output_state_root: B256::default(),
                input_state_root: B256::default(),
                requests: vec![],
            };
            subblock_outputs.push(subblock_output);

            // Accumulate this subblock's `ExecutionOutcome` into `cumulative_executor_outcomes`.
            cumulative_executor_outcomes.extend(executor_outcome);

            // Record the state requests for this subblock.
            let subblock_state_requests = rpc_db.get_state_requests();

            // Merge the state requests from the subblock into `cumulative_state_requests`.
            merge_state_requests(&mut cumulative_state_requests, &subblock_state_requests);
            all_state_requests.push(subblock_state_requests);

            let mut subblock_input = SubblockInput {
                current_block: V::pre_process_block(&current_block),
                block_hashes: BTreeMap::new(),
                bytecodes: rpc_db.get_bytecodes(),
                is_first_subblock,
                is_last_subblock,
                starting_gas_used,
            };

            // Slice the correct transactions for this subblock
            subblock_input.current_block.body = subblock_input.current_block.body
                [num_transactions_completed as usize..upper as usize]
                .to_vec();

            // Advance subblock.
            num_transactions_completed = upper;
            rpc_db.advance_subblock();

            subblock_inputs.push(subblock_input);

            if num_transactions_completed >= current_block.body.len() as u64 {
                break;
            }
        }

        // Build parent state from modified keys and used keys from this subblock
        let mut before_storage_proofs = Vec::new();
        let mut after_storage_proofs = Vec::new();

        for chunk in cumulative_state_requests.into_iter().chunks(10).into_iter() {
            let mut before_handles = JoinSet::new();
            let mut after_handles = JoinSet::new();
            for (address, used_keys) in chunk {
                let modified_keys = cumulative_executor_outcomes
                    .state()
                    .state
                    .get(&address)
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

                let provider_clone = self.provider.clone();

                before_handles.spawn(async move {
                    Self::get_proof(provider_clone, address, keys, block_number - 1).await.unwrap()
                });

                let provider_clone = self.provider.clone();
                after_handles.spawn(async move {
                    Self::get_proof(provider_clone, address, modified_keys, block_number)
                        .await
                        .unwrap()
                });
            }
            before_storage_proofs.extend(before_handles.join_all().await);
            after_storage_proofs.extend(after_handles.join_all().await);
        }

        let parent_state = EthereumState::from_transition_proofs(
            previous_block.state_root,
            &before_storage_proofs.iter().map(|item| (item.address, item.clone())).collect(),
            &after_storage_proofs.iter().map(|item| (item.address, item.clone())).collect(),
        )?;

        let cumulative_state_diffs = cumulative_executor_outcomes.hash_state_slow();

        // Update the parent state with the cumulative state diffs from all subblocks.
        let mut mutated_state = parent_state.clone();
        mutated_state.update(&cumulative_state_diffs);

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
        let mut block_hashes = BTreeMap::new();
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
            bytecodes: rpc_db.get_bytecodes(),
        };

        let parent_state_bytes =
            rkyv::to_bytes::<rkyv::rancor::Error>(&parent_state).unwrap().to_vec();

        let mut big_state = parent_state.clone();
        for i in 0..subblock_inputs.len() {
            let input_root = big_state.state_root();
            // Get the touched addresses / storage slots in this subblock.
            let mut touched_state = HashMap::new();
            for (address, used_keys) in all_state_requests[i].iter() {
                let modified_keys = all_executor_outcomes[i]
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
                    .map(keccak256)
                    .collect::<Vec<_>>();

                touched_state.insert(keccak256(address), keys);
            }

            // Generate the subblock parent state by taking the state diff of the subblock and all
            // touched addresses, and then pruning the big state.
            let mut subblock_parent_state = big_state.clone();

            let serialized_size =
                rkyv::to_bytes::<rkyv::rancor::Error>(&subblock_parent_state).unwrap().len();
            let prev_root = subblock_parent_state.state_root();

            subblock_parent_state.prune(&state_diffs[i], &touched_state);

            // Assert that pruning did not change the state root.
            let new_root = subblock_parent_state.state_root();
            assert_eq!(prev_root, new_root);

            let new_serialized_size =
                rkyv::to_bytes::<rkyv::rancor::Error>(&subblock_parent_state).unwrap().len();
            tracing::info!(
                "Pruned state compression ratio: {}",
                new_serialized_size as f64 / serialized_size as f64
            );
            subblock_parent_states.push(
                rkyv::to_bytes::<rkyv::rancor::Error>(&subblock_parent_state).unwrap().to_vec(),
            );

            // Update the big state with the state diff of this subblock, and set the fields of this
            // subblock's input/output accordingly.
            big_state.update(&state_diffs[i]);
            let output_root = big_state.state_root();

            subblock_outputs[i].input_state_root = input_root;
            subblock_outputs[i].output_state_root = output_root;

            let subblock_input = &mut subblock_inputs[i];
            subblock_input.block_hashes = block_hashes.clone();
        }

        let all_subblock_outputs = SubblockHostOutput {
            subblock_inputs,
            subblock_parent_states,
            subblock_outputs,
            agg_input: aggregation_input,
            agg_parent_state: parent_state_bytes,
        };

        #[cfg(debug_assertions)]
        {
            all_subblock_outputs.validate().map_err(HostError::ClientValidation)?;
        }

        Ok(all_subblock_outputs)
    }
}
