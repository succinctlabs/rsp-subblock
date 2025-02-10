//! Cluster subblock execution.
//!
//! Directly creates an aggregation task.

use alloy_provider::ReqwestProvider;
use clap::Parser;
use reth_primitives::B256;
use rsp_client_executor::io::{
    AggregationInput, AllSubblockOutputs, SubblockInput, SubblockOutput,
};
use rsp_host_executor::HostExecutor;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1Proof, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

use sp1_worker::{
    client::ClusterClient,
    proto::{Artifact, TaskType},
};

use std::sync::Arc;

mod execute;

mod cli;
use cli::ProviderArgs;

mod eth_proofs;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheData {
    pub subblock_inputs: Vec<SubblockInput>,
    pub agg_input: AggregationInput,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Intialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

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
    let client = ProverClient::from_env();

    // Setup the proving key and verification key.
    let (subblock_pk, subblock_vk) = client.setup(include_elf!("rsp-client-eth-subblock"));

    let (agg_pk, agg_vk) = client.setup(include_elf!("rsp-client-eth-agg"));

    let agg_stdin = client_input.to_aggregation_stdin(&subblock_vk);

    // println!("Block hash: {}", block_hash);

    Ok(())
}

async fn upload_artifact<T: Serialize + Send + Sync>(
    client: &ClusterClient,
    name: &str,
    data: T,
) -> eyre::Result<Artifact> {
    let artifact = client
        .create_artifact_blocking(name, 0)
        .map_err(|e| eyre::eyre!("Failed to create artifact: {}", e))?;
    artifact
        .upload(&client.http, &data)
        .await
        .map_err(|e| eyre::eyre!("Failed to upload artifact: {}", e))?;

    Ok(artifact)
}

async fn schedule_task(
    subblock_pk: SP1ProvingKey,
    agg_pk: SP1ProvingKey,
    inputs: AllSubblockOutputs,
) -> eyre::Result<()> {
    let (subblock_elf, subblock_vk) = (subblock_pk.elf, subblock_pk.vk);
    let (agg_elf, agg_vk) = (agg_pk.elf, agg_pk.vk);

    let aggregation_stdin = inputs.to_aggregation_stdin(&subblock_vk);

    let cluster_client = Arc::new(ClusterClient::new());

    // Create artifacts for the subblock stuff.
    let subblock_elf_artifact: Artifact =
        upload_artifact(&cluster_client, "subblock_elf", subblock_elf).await?;

    let subblock_vk_artifact: Artifact =
        upload_artifact(&cluster_client, "subblock_vk", subblock_vk).await?;

    // Create artifacts for the aggregation stuff.
    let agg_elf_artifact: Artifact = upload_artifact(&cluster_client, "agg_elf", agg_elf).await?;

    let agg_vk_artifact: Artifact = upload_artifact(&cluster_client, "agg_vk", agg_vk).await?;

    let agg_stdin_artifact: Artifact =
        upload_artifact(&cluster_client, "agg_stdin", aggregation_stdin).await?;

    let proof_id = "yuwen".to_string();

    let task = cluster_client.create_task(
        TaskType::Sp1AggregationTask,
        vec![subblock_elf_artifact, subblock_vk_artifact],
        vec![agg_elf_artifact, agg_vk_artifact, agg_stdin_artifact],
        proof_id,
        None,
        None,
    );

    Ok(())
}

fn try_load_input_from_cache(
    cache_dir: Option<&PathBuf>,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<AllSubblockOutputs>> {
    Ok(if let Some(cache_dir) = cache_dir {
        let cache_path = cache_dir.join(format!("input/{}/{}.bin", chain_id, block_number));

        if cache_path.exists() {
            // TODO: prune the cache if invalid instead
            let mut cache_file = std::fs::File::open(cache_path)?;
            let cache_data: AllSubblockOutputs = bincode::deserialize_from(&mut cache_file)?;

            Some(cache_data)
        } else {
            None
        }
    } else {
        None
    })
}
