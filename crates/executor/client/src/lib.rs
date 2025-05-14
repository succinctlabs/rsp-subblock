/// Client program input data types.
pub mod io;
#[macro_use]
mod utils;
pub mod custom;
pub mod error;

use std::{borrow::BorrowMut, fmt::Display, io::Cursor};

use cfg_if::cfg_if;
use custom::CustomEvmConfig;
use error::ClientError;
use io::{AggregationInput, ClientExecutorInput, SubblockInput, SubblockOutput, TrieDB};
use reth_chainspec::ChainSpec;
use reth_errors::{ConsensusError, ProviderError};
use reth_ethereum_consensus::{
    validate_block_post_execution as validate_block_post_execution_ethereum,
    validate_subblock_post_execution as validate_subblock_post_execution_ethereum,
};
use reth_evm::execute::{
    BlockExecutionError, BlockExecutionOutput, BlockExecutorProvider, Executor,
};
use reth_evm_ethereum::execute::EthExecutorProvider;
use reth_evm_optimism::OpExecutorProvider;
use reth_execution_types::ExecutionOutcome;
use reth_optimism_consensus::validate_block_post_execution as validate_block_post_execution_optimism;
use reth_primitives::{
    proofs, Block, BlockWithSenders, Bloom, Header, Receipt, Receipts, Request, TransactionSigned,
};
use revm::{db::WrapDatabaseRef, Database};
use revm_primitives::{address, B256, U256};
use rsp_mpt::EthereumState;
use sha2::{Digest, Sha256};

/// Chain ID for Ethereum Mainnet.
pub const CHAIN_ID_ETH_MAINNET: u64 = 0x1;

/// Chain ID for OP Mainnnet.
pub const CHAIN_ID_OP_MAINNET: u64 = 0xa;

/// Chain ID for Linea Mainnet.
pub const CHAIN_ID_LINEA_MAINNET: u64 = 0xe708;

/// Chain ID for Sepolia.
pub const CHAIN_ID_SEPOLIA: u64 = 0xaa36a7;

/// An executor that executes a block inside a zkVM.
#[derive(Debug, Clone, Default)]
pub struct ClientExecutor;

/// Trait for representing different execution/validation rules of different chain variants. This
/// allows for dead code elimination to minimize the ELF size for each variant.
pub trait Variant {
    fn spec() -> ChainSpec;

    fn execute<DB>(
        executor_block_input: &BlockWithSenders,
        executor_difficulty: U256,
        cache_db: DB,
    ) -> Result<BlockExecutionOutput<Receipt>, BlockExecutionError>
    where
        DB: Database<Error: Into<ProviderError> + Display>;

    fn validate_block_post_execution(
        block: &BlockWithSenders,
        chain_spec: &ChainSpec,
        receipts: &[Receipt],
        requests: &[Request],
    ) -> Result<(), ConsensusError>;

    fn validate_subblock_aggregation(
        _header: &Header,
        _chain_spec: &ChainSpec,
        _receipts: &[Receipt],
        _requests: &[Request],
    ) -> Result<(), ConsensusError> {
        unimplemented!()
    }

    fn pre_process_block(block: &Block) -> Block {
        block.clone()
    }
}

/// Implementation for Ethereum-specific execution/validation logic.
#[derive(Debug)]
pub struct EthereumVariant;

/// Implementation for Optimism-specific execution/validation logic.
#[derive(Debug)]
pub struct OptimismVariant;

/// Implementation for Linea-specific execution/validation logic.
#[derive(Debug)]
pub struct LineaVariant;

/// Implementation for Sepolia-specific execution/validation logic.
#[derive(Debug)]
pub struct SepoliaVariant;

/// EVM chain variants that implement different execution/validation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainVariant {
    /// Ethereum networks.
    Ethereum,
    /// OP stack networks.
    Optimism,
    /// Linea networks.
    Linea,
    /// Testnets
    Sepolia,
}

impl ChainVariant {
    /// Returns the chain ID for the given variant.
    pub fn chain_id(&self) -> u64 {
        match self {
            ChainVariant::Ethereum => CHAIN_ID_ETH_MAINNET,
            ChainVariant::Optimism => CHAIN_ID_OP_MAINNET,
            ChainVariant::Linea => CHAIN_ID_LINEA_MAINNET,
            ChainVariant::Sepolia => CHAIN_ID_SEPOLIA,
        }
    }
}

impl ClientExecutor {
    pub fn execute<V>(&self, mut input: ClientExecutorInput) -> Result<Header, ClientError>
    where
        V: Variant,
    {
        // Initialize the witnessed database with verified storage proofs.
        let wrap_ref = profile!("initialize witness db", {
            let trie_db = input.witness_db().unwrap();
            WrapDatabaseRef(trie_db)
        });

        // Execute the block.
        let spec = V::spec();
        let executor_block_input = profile!("recover senders", {
            input
                .current_block
                .clone()
                .with_recovered_senders()
                .ok_or(ClientError::SignatureRecoveryFailed)
        })?;
        let executor_difficulty = input.current_block.header.difficulty;
        let executor_output = profile!("execute", {
            V::execute(&executor_block_input, executor_difficulty, wrap_ref)
        })?;

        // Validate the block post execution.
        profile!("validate block post-execution", {
            V::validate_block_post_execution(
                &executor_block_input,
                &spec,
                &executor_output.receipts,
                &executor_output.requests,
            )
        })?;

        // Accumulate the logs bloom.
        let mut logs_bloom = Bloom::default();
        profile!("accrue logs bloom", {
            executor_output.receipts.iter().for_each(|r| {
                logs_bloom.accrue_bloom(&r.bloom_slow());
            })
        });

        // Convert the output to an execution outcome.
        let executor_outcome = ExecutionOutcome::new(
            executor_output.state,
            Receipts::from(executor_output.receipts),
            input.current_block.header.number,
            vec![executor_output.requests.into()],
        );

        // Verify the state root.
        let state_root = profile!("compute state root", {
            input.parent_state.update(&executor_outcome.hash_state_slow());
            input.parent_state.state_root()
        });

        if state_root != input.current_block.state_root {
            return Err(ClientError::MismatchedStateRoot);
        }

        // Derive the block header.
        //
        // Note: the receipts root and gas used are verified by `validate_block_post_execution`.
        let mut header = input.current_block.header.clone();
        header.parent_hash = input.parent_header().hash_slow();
        header.ommers_hash = proofs::calculate_ommers_root(&input.current_block.ommers);
        header.state_root = input.current_block.state_root;
        header.transactions_root = proofs::calculate_transaction_root(&input.current_block.body);
        header.receipts_root = input.current_block.header.receipts_root;
        header.withdrawals_root = input
            .current_block
            .withdrawals
            .take()
            .map(|w| proofs::calculate_withdrawals_root(w.into_inner().as_slice()));
        header.logs_bloom = logs_bloom;
        header.requests_root =
            input.current_block.requests.as_ref().map(|r| proofs::calculate_requests_root(&r.0));

        Ok(header)
    }

    pub fn execute_subblock<V>(
        &self,
        input: SubblockInput,
        input_state: &mut EthereumState,
    ) -> Result<SubblockOutput, ClientError>
    where
        V: Variant,
    {
        // Initialize the database.
        println!("cycle-tracker-start: initialize db");
        // First deserialize the parent state, and calculate the parent state root.
        let input_state_root = input_state.state_root();

        println!("cycle-tracker-start: construct buffered trie db");
        // Finally, construct the database.
        // TODO: verify the parent block hashes????
        let bytecode_by_hash = input.bytecodes.iter().map(|b| (b.hash_slow(), b)).collect();
        let trie_db = TrieDB::new(input_state, input.block_hashes, bytecode_by_hash);
        let wrap_ref = WrapDatabaseRef(trie_db);
        println!("cycle-tracker-end: construct buffered trie db");

        println!("cycle-tracker-end: initialize db");

        // Execute the block.
        let mut executor_block_input = profile!("recover senders", {
            input
                .current_block
                .clone()
                .with_recovered_senders()
                .ok_or(ClientError::SignatureRecoveryFailed)
        })?;
        executor_block_input.is_first_subblock = input.is_first_subblock;
        executor_block_input.is_last_subblock = input.is_last_subblock;
        executor_block_input.starting_gas_used = input.starting_gas_used;

        let executor_difficulty = input.current_block.header.difficulty;
        let executor_output = profile!("execute", {
            V::execute(&executor_block_input, executor_difficulty, wrap_ref)
        })?;

        let requests = executor_output.requests.clone();
        let receipts = executor_output.receipts.clone();

        let mut logs_bloom = Bloom::default();
        profile!("accrue logs bloom", {
            executor_output.receipts.iter().for_each(|r| {
                logs_bloom.accrue_bloom(&r.bloom_slow());
            })
        });

        let subblock_output = profile!("finalize output", {
            // Convert the output to an execution outcome.
            let executor_outcome = ExecutionOutcome::new(
                executor_output.state,
                Receipts::from(executor_output.receipts),
                input.current_block.header.number,
                vec![executor_output.requests.into()],
            );

            let hash_state = executor_outcome.hash_state_slow();

            // Get the output state root by applying the diff to the input state.
            input_state.update(&hash_state);
            let output_state_root = input_state.state_root();

            SubblockOutput { output_state_root, logs_bloom, receipts, input_state_root, requests }
        });

        Ok(subblock_output)
    }

    pub fn execute_aggregation<V: Variant>(
        &self,
        public_values: Vec<Vec<u8>>,
        vkey: [u32; 8],
        mut aggregation_input: AggregationInput,
        parent_state_root: B256,
    ) -> Result<Header, ClientError> {
        let mut cumulative_state_diff =
            SubblockOutput { output_state_root: parent_state_root, ..Default::default() };
        let mut transaction_body: Vec<TransactionSigned> = Vec::new();
        profile!("aggregate", {
            for (i, public_value) in public_values.iter().enumerate() {
                let public_values_digest = Sha256::digest(&public_value);
                cfg_if! {
                    if #[cfg(target_os = "zkvm")] {
                        sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &public_values_digest.into());
                    }
                }
                println!("cycle-tracker-start: deserialize subblock input");
                let mut reader = Cursor::new(&public_value);
                let subblock_input: SubblockInput = bincode::deserialize_from(&mut reader).unwrap();

                println!("cycle-tracker-end: deserialize subblock input");

                // Check that the starting gas used is the same as the last cumulative gas used.
                assert_eq!(
                    subblock_input.starting_gas_used,
                    cumulative_state_diff
                        .receipts
                        .last()
                        .map(|r| r.cumulative_gas_used)
                        .unwrap_or(0)
                );

                // Consistency checks on the subblock input's first/last subblock flags.
                if i == 0 {
                    assert!(subblock_input.is_first_subblock);
                }
                if i == public_values.len() - 1 {
                    assert!(subblock_input.is_last_subblock);
                }
                if i > 0 && i < public_values.len() - 1 {
                    assert!(!subblock_input.is_first_subblock);
                    assert!(!subblock_input.is_last_subblock);
                }

                assert_eq!(
                    subblock_input.current_block.header,
                    aggregation_input.current_block.header
                );
                println!("cycle-tracker-start: deserialize subblock output");

                let subblock_output: SubblockOutput =
                    bincode::deserialize_from(&mut reader).unwrap();
                println!("cycle-tracker-end: deserialize subblock output");

                println!("cycle-tracker-start: extend state");

                // Accumulate subblock's output into the cumulative state diff.
                // This function also contains consistency checks between the cumulative state diff
                // and the subblock output.
                cumulative_state_diff.extend(subblock_output);

                // Also add this subblock's transaction body to the transaction body.
                transaction_body.extend(subblock_input.current_block.body);
                println!("cycle-tracker-end: extend state");
            }
        });

        // Check that the subblock transactions match the main block transactions.
        assert_eq!(
            transaction_body, aggregation_input.current_block.body,
            "subblock transactions do not match main block transactions"
        );

        profile!("validate subblock aggregation", {
            // Check that the accumulated logs bloom is the same as the main block logs bloom.
            assert_eq!(
                cumulative_state_diff.logs_bloom,
                aggregation_input.current_block.header.logs_bloom
            );
            V::validate_subblock_aggregation(
                &aggregation_input.current_block.header,
                &V::spec(),
                &cumulative_state_diff.receipts,
                &cumulative_state_diff.requests,
            )
            .expect("failed to validate subblock aggregation")
        });

        // The final state root of the entire block is the cumulative output state root.
        let state_root = cumulative_state_diff.output_state_root;
        if state_root != aggregation_input.current_block.state_root {
            panic!(
                "mismatched state root: {state_root} != {:?}",
                aggregation_input.current_block.state_root
            );
        }

        // Derive the block header.
        //
        // Note: the receipts root and gas used are verified by `validate_block_post_execution`.
        let mut header = aggregation_input.current_block.header.clone();
        header.parent_hash = aggregation_input.parent_header().hash_slow();
        header.ommers_hash = proofs::calculate_ommers_root(&aggregation_input.current_block.ommers);
        header.state_root = aggregation_input.current_block.state_root;
        header.transactions_root =
            proofs::calculate_transaction_root(&aggregation_input.current_block.body);
        header.receipts_root = aggregation_input.current_block.header.receipts_root;
        header.withdrawals_root = aggregation_input
            .current_block
            .withdrawals
            .take()
            .map(|w| proofs::calculate_withdrawals_root(w.into_inner().as_slice()));
        header.logs_bloom = cumulative_state_diff.logs_bloom;
        header.requests_root = aggregation_input
            .current_block
            .requests
            .as_ref()
            .map(|r| proofs::calculate_requests_root(&r.0));

        Ok(header)
    }
}

impl Variant for EthereumVariant {
    fn spec() -> ChainSpec {
        rsp_primitives::chain_spec::mainnet()
    }

    fn execute<DB>(
        executor_block_input: &BlockWithSenders,
        executor_difficulty: U256,
        cache_db: DB,
    ) -> Result<BlockExecutionOutput<Receipt>, BlockExecutionError>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        EthExecutorProvider::new(
            Self::spec().into(),
            CustomEvmConfig::from_variant(ChainVariant::Ethereum),
        )
        .executor(cache_db)
        .execute((executor_block_input, executor_difficulty).into())
    }

    fn validate_block_post_execution(
        block: &BlockWithSenders,
        chain_spec: &ChainSpec,
        receipts: &[Receipt],
        requests: &[Request],
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution_ethereum(block, chain_spec, receipts, requests)
    }

    fn validate_subblock_aggregation(
        header: &Header,
        chain_spec: &ChainSpec,
        receipts: &[Receipt],
        requests: &[Request],
    ) -> Result<(), ConsensusError> {
        validate_subblock_post_execution_ethereum(header, chain_spec, receipts, requests)
    }
}

impl Variant for OptimismVariant {
    fn spec() -> ChainSpec {
        rsp_primitives::chain_spec::op_mainnet()
    }

    fn execute<DB>(
        executor_block_input: &BlockWithSenders,
        executor_difficulty: U256,
        cache_db: DB,
    ) -> Result<BlockExecutionOutput<Receipt>, BlockExecutionError>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        OpExecutorProvider::new(
            Self::spec().into(),
            CustomEvmConfig::from_variant(ChainVariant::Optimism),
        )
        .executor(cache_db)
        .execute((executor_block_input, executor_difficulty).into())
    }

    fn validate_block_post_execution(
        block: &BlockWithSenders,
        chain_spec: &ChainSpec,
        receipts: &[Receipt],
        _requests: &[Request],
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution_optimism(block, chain_spec, receipts)
    }
}

impl Variant for LineaVariant {
    fn spec() -> ChainSpec {
        rsp_primitives::chain_spec::linea_mainnet()
    }

    fn execute<DB>(
        executor_block_input: &BlockWithSenders,
        executor_difficulty: U256,
        cache_db: DB,
    ) -> Result<BlockExecutionOutput<Receipt>, BlockExecutionError>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        EthExecutorProvider::new(
            Self::spec().into(),
            CustomEvmConfig::from_variant(ChainVariant::Linea),
        )
        .executor(cache_db)
        .execute((executor_block_input, executor_difficulty).into())
    }

    fn validate_block_post_execution(
        block: &BlockWithSenders,
        chain_spec: &ChainSpec,
        receipts: &[Receipt],
        requests: &[Request],
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution_ethereum(block, chain_spec, receipts, requests)
    }

    fn pre_process_block(block: &Block) -> Block {
        // Linea network uses clique consensus, which is not implemented in reth.
        // The main difference for the execution part is the block beneficiary:
        // reth will credit the block reward to the beneficiary address (coinbase)
        // whereas in clique, the block reward is credited to the signer.

        // We extract the clique beneficiary address from the genesis extra data.
        // - vanity: 32 bytes
        // - address: 20 bytes
        // - seal: 65 bytes
        // we extract the address from the 32nd to 52nd byte.
        let addr = address!("8f81e2e3f8b46467523463835f965ffe476e1c9e");

        // We hijack the beneficiary address here to match the clique consensus.
        let mut block = block.clone();
        block.header.borrow_mut().beneficiary = addr;
        block
    }
}

impl Variant for SepoliaVariant {
    fn spec() -> ChainSpec {
        rsp_primitives::chain_spec::sepolia()
    }

    fn execute<DB>(
        executor_block_input: &BlockWithSenders,
        executor_difficulty: U256,
        cache_db: DB,
    ) -> Result<BlockExecutionOutput<Receipt>, BlockExecutionError>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        EthExecutorProvider::new(
            Self::spec().into(),
            CustomEvmConfig::from_variant(ChainVariant::Ethereum),
        )
        .executor(cache_db)
        .execute((executor_block_input, executor_difficulty).into())
    }

    fn validate_block_post_execution(
        block: &BlockWithSenders,
        chain_spec: &ChainSpec,
        receipts: &[Receipt],
        requests: &[Request],
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution_ethereum(block, chain_spec, receipts, requests)
    }
}
