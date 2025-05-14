//! Subblock executor.
//!
//! This is a standalone program that can be used to execute a subblock, and optionally dump the
//! elf/stdin pairs to a directory.

use alloy_provider::ReqwestProvider;
use clap::Parser;
use rkyv::util::AlignedVec;
use rsp_client_executor::io::SubblockHostOutput;
use rsp_host_executor::HostExecutor;
use rsp_mpt::EthereumState;
use sp1_sdk::{
    include_elf, HashableKey, Prover, ProverClient, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::{io::Cursor, path::PathBuf};
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

mod cli;
use cli::ProviderArgs;

/// The arguments for the host executable.
#[derive(Debug, Clone, Parser)]
struct HostArgs {
    /// The block number of the block to execute.
    #[clap(long)]
    block_number: u64,
    #[clap(flatten)]
    provider: ProviderArgs,
    /// Whether to pre-execute the block.
    #[clap(long)]
    execute: bool,
    /// Where to dump the elf and stdin for the files.
    #[clap(long)]
    dump_dir: Option<PathBuf>,
    /// Optional path to the directory containing cached client input. A new cache file will be
    /// created from RPC data if it doesn't already exist.
    #[clap(long)]
    cache_dir: Option<PathBuf>,
    /// Optional path to the proof cache
    #[clap(long)]
    proof_cache_dir: Option<PathBuf>,
    /// The path to the CSV file containing the execution data.
    #[clap(long, default_value = "report.csv")]
    report_path: PathBuf,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Intialize the environment variables.
    dotenv::dotenv().ok();

    // Initialize the logger.
    tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::from_default_env()).init();

    // Parse the command line arguments.
    let args = HostArgs::parse();

    let provider_config = args.provider.clone().into_provider().await?;

    let cache_data = try_load_input_from_cache(
        args.cache_dir.as_ref(),
        provider_config.chain_id,
        args.block_number,
    )?;

    let client_input = match (cache_data, provider_config.rpc_url) {
        (Some(cache_data), _) => cache_data,
        (None, Some(rpc_url)) => {
            // Cache not found but we have RPC
            // Setup the provider.
            let provider = ReqwestProvider::new_http(rpc_url);

            // Setup the host executor.
            let host_executor = HostExecutor::new(provider);

            // Execute the host.
            let cache_data = host_executor
                .execute_subblock(args.block_number)
                .await
                .expect("failed to execute host");

            if let Some(ref cache_dir) = args.cache_dir {
                let input_folder = cache_dir.join(format!("input/{}", provider_config.chain_id));
                if !input_folder.exists() {
                    std::fs::create_dir_all(&input_folder)?;
                }

                let input_path = input_folder.join(format!("{}.bin", args.block_number));
                let mut cache_file = std::fs::File::create(input_path)?;

                bincode::serialize_into(&mut cache_file, &cache_data)?;
            }

            cache_data
        }
        (None, None) => {
            eyre::bail!("cache not found and RPC URL not provided")
        }
    };

    // Generate the proof.
    let client =
        tokio::task::spawn_blocking(|| ProverClient::builder().cpu().build()).await.unwrap();

    // Setup the proving key and verification key.
    let (subblock_pk, _subblock_vk) = client.setup(include_elf!("rsp-client-eth-subblock")).await;

    let (agg_pk, _agg_vk) = client.setup(include_elf!("rsp-client-eth-agg")).await;

    // Todo: rename
    schedule_task(
        subblock_pk,
        args.block_number,
        agg_pk,
        client_input,
        args.execute,
        args.dump_dir,
    )
    .await?;

    Ok(())
}

async fn schedule_task(
    subblock_pk: SP1ProvingKey,
    block_number: u64,
    agg_pk: SP1ProvingKey,
    inputs: SubblockHostOutput,
    execute: bool,
    dump_dir: Option<PathBuf>,
) -> eyre::Result<()> {
    let (subblock_elf, subblock_vk) = (subblock_pk.elf, subblock_pk.vk);
    let agg_elf = agg_pk.elf;

    let dump_dir = dump_dir.map(|d| d.join(format!("{}", block_number)));

    if let Some(dump_dir) = dump_dir.as_ref() {
        std::fs::create_dir_all(dump_dir)?;
        std::fs::write(dump_dir.join("subblock_elf.bin"), subblock_elf.as_ref())?;
        std::fs::write(dump_dir.join("subblock_vk.bin"), bincode::serialize(&subblock_vk)?)?;
        std::fs::write(dump_dir.join("agg_elf.bin"), agg_elf.as_ref())?;
    }

    let client =
        tokio::task::spawn_blocking(|| ProverClient::builder().cpu().build()).await.unwrap();

    let aggregation_stdin = to_aggregation_stdin(inputs.clone(), &subblock_vk);
    if let Some(dump_dir) = dump_dir.as_ref() {
        let stdin_path = dump_dir.join("agg_stdin.bin");
        std::fs::write(stdin_path, bincode::serialize(&aggregation_stdin)?)?;
    }

    for i in 0..inputs.subblock_inputs.len() {
        let input = &inputs.subblock_inputs[i];
        let parent_state = &inputs.subblock_parent_states[i];

        let mut stdin = SP1Stdin::new();
        stdin.write(input);
        stdin.write_vec(parent_state.clone());

        // Save the elf/stdin pair to the dump directory.
        if let Some(dump_dir) = dump_dir.as_ref() {
            let stdin_dir_path = dump_dir.join("subblock_stdins");
            std::fs::create_dir_all(&stdin_dir_path)?;
            let stdin_path = stdin_dir_path.join(format!("{}.bin", i));
            std::fs::write(stdin_path, bincode::serialize(&stdin)?)?;
        }

        if execute {
            let (_public_values, report) = client.execute(&subblock_elf, &stdin).run().unwrap();
            let subblock_instruction_count = report.total_instruction_count();
            tracing::info!("Subblock {} instruction count: {}", i, subblock_instruction_count);
        }
    }

    if execute {
        // Execute the aggregation program with deferred proof verification off, since we don't have the proof yet.
        let (_public_values, report) = client
            .execute(&agg_elf, &aggregation_stdin)
            .deferred_proof_verification(false)
            .run()
            .unwrap();
        let agg_instruction_count = report.total_instruction_count();
        tracing::info!("Aggregation program instruction count: {}", agg_instruction_count);
    }

    Ok(())
}

/// Constructs the aggregation stdin, sans the subblock proofs.
pub fn to_aggregation_stdin(
    subblock_host_output: SubblockHostOutput,
    subblock_vk: &SP1VerifyingKey,
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();

    assert_eq!(
        subblock_host_output.subblock_inputs.len(),
        subblock_host_output.subblock_outputs.len()
    );
    let mut public_values = Vec::new();
    for i in 0..subblock_host_output.subblock_inputs.len() {
        let mut current_public_values = Vec::new();
        let input = &subblock_host_output.subblock_inputs[i];
        bincode::serialize_into(&mut current_public_values, input).unwrap();
        bincode::serialize_into(
            &mut current_public_values,
            &subblock_host_output.subblock_outputs[i],
        )
        .unwrap();

        // let serialized = bincode::serialize(&subblock_host_output.subblock_outputs[i])
        //     .expect("failed to serialize subblock output")
        //     .to_vec();

        // current_public_values.write_all(&serialized).unwrap();

        public_values.push(current_public_values);
    }

    let mut aligned_vec = AlignedVec::<16>::new();
    let mut reader = Cursor::new(&subblock_host_output.agg_parent_state);
    aligned_vec.extend_from_reader(&mut reader).unwrap();
    let parent_state =
        rkyv::from_bytes::<EthereumState, rkyv::rancor::BoxedError>(&aligned_vec).unwrap();
    let parent_state_root = parent_state.state_root();

    stdin.write::<Vec<Vec<u8>>>(&public_values);
    stdin.write::<[u32; 8]>(&subblock_vk.hash_u32());
    stdin.write(&subblock_host_output.agg_input);
    stdin.write(&parent_state_root);
    stdin
}

fn try_load_input_from_cache(
    cache_dir: Option<&PathBuf>,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<SubblockHostOutput>> {
    Ok(if let Some(cache_dir) = cache_dir {
        let cache_path =
            cache_dir.join(format!("subblock-input/{}/{}.bin", chain_id, block_number));

        if cache_path.exists() {
            // TODO: prune the cache if invalid instead
            let mut cache_file = std::fs::File::open(cache_path)?;
            let cache_data: SubblockHostOutput = bincode::deserialize_from(&mut cache_file)?;

            Some(cache_data)
        } else {
            None
        }
    } else {
        None
    })
}
