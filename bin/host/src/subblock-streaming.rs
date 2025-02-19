//! Streaming subblock execution.
//!
//! Directly creates an aggregation task.

use alloy_provider::ReqwestProvider;
use clap::Parser;
use reth_primitives::B256;
use rsp_client_executor::{
    hash_transactions,
    io::{AggregationInput, SubblockHostOutput, SubblockInput},
};
use rsp_host_executor::HostExecutor;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey,
    SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::io::Write;
use std::path::PathBuf;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

use sp1_worker::{
    artifact::ArtifactType,
    client::ClusterClient,
    proto::{Artifact, TaskType},
};

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
    let (subblock_pk, _subblock_vk) = client.setup(include_elf!("rsp-client-eth-subblock"));

    let (agg_pk, _agg_vk) = client.setup(include_elf!("rsp-client-eth-agg"));

    let mut proof = schedule_task(subblock_pk, agg_pk, client_input).await?;
    let block_hash = proof.public_values.read::<B256>();

    println!("block hash: {}", block_hash);

    Ok(())
}

async fn upload_artifact<T: Serialize + Send + Sync>(
    client: &ClusterClient,
    name: &str,
    data: T,
    artifact_type: ArtifactType,
) -> eyre::Result<Artifact> {
    let artifact = client
        .create_artifact_blocking(name, 0)
        .map_err(|e| eyre::eyre!("Failed to create artifact: {}", e))?;
    artifact
        .upload_with_type(artifact_type, data)
        .await
        .map_err(|e| eyre::eyre!("Failed to upload artifact: {}", e))?;

    Ok(artifact)
}

async fn schedule_task(
    subblock_pk: SP1ProvingKey,
    agg_pk: SP1ProvingKey,
    inputs: SubblockHostOutput,
) -> eyre::Result<SP1ProofWithPublicValues> {
    let (subblock_elf, subblock_vk) = (subblock_pk.elf, subblock_pk.vk);
    let agg_elf = agg_pk.elf;
    let cluster_client = ClusterClient::new();
    let mut subblock_input_artifacts: Vec<Artifact> =
        Vec::with_capacity(inputs.subblock_inputs.len());

    let aggregation_stdin = to_aggregation_stdin(inputs.clone(), &subblock_vk);

    for i in 0..inputs.subblock_inputs.len() {
        let input = &inputs.subblock_inputs[i];
        let parent_state = &inputs.subblock_parent_states[i];
        let input_state_diff = &inputs.subblock_input_diffs[i];

        let mut stdin = SP1Stdin::new();
        stdin.write(input);
        stdin.write_vec(parent_state.clone());
        stdin.write_vec(input_state_diff.clone());
        let artifact =
            upload_artifact(&cluster_client, "subblock_input", stdin, ArtifactType::Stdin).await?;
        subblock_input_artifacts.push(artifact);
    }

    // Create an artifact index for the subblock inputs.
    let subblock_input_index =
        subblock_input_artifacts.iter().map(|a| a.id.clone()).collect::<Vec<_>>();
    let subblock_input_index_artifact: Artifact = upload_artifact(
        &cluster_client,
        "subblock_input_index",
        subblock_input_index,
        ArtifactType::UnspecifiedArtifactType,
    )
    .await?;

    // Create artifacts for the subblock stuff.
    let subblock_elf_artifact: Artifact =
        upload_artifact(&cluster_client, "subblock_elf", subblock_elf, ArtifactType::Program)
            .await?;

    let subblock_vk_artifact: Artifact = upload_artifact(
        &cluster_client,
        "subblock_vk",
        subblock_vk,
        ArtifactType::UnspecifiedArtifactType,
    )
    .await?;

    // Create artifacts for the aggregation stuff.
    let agg_elf_artifact: Artifact =
        upload_artifact(&cluster_client, "agg_elf", agg_elf, ArtifactType::Program).await?;

    let agg_stdin_artifact: Artifact =
        upload_artifact(&cluster_client, "agg_stdin", aggregation_stdin, ArtifactType::Stdin)
            .await?;

    // Create an empty artifact for the output
    let output_artifact: Artifact = cluster_client
        .create_artifact_blocking("agg_output", 0)
        .map_err(|e| eyre::eyre!("Failed to create output artifact: {}", e))?;

    // TODO: make a random proof id.
    let proof_id = "yuwen".to_string();

    let input_ids = vec![
        subblock_elf_artifact.id,
        subblock_input_index_artifact.id,
        subblock_vk_artifact.id,
        agg_elf_artifact.id,
        agg_stdin_artifact.id,
    ];

    let task_id = cluster_client
        .create_task(
            TaskType::Sp1AggregationTask,
            &input_ids,
            &[output_artifact.id.clone()],
            proof_id,
            None,
            None,
        )
        .await
        .map_err(|e| eyre::eyre!("Failed to create task: {}", e))?;

    println!("Task created: {}", task_id);

    cluster_client
        .wait_tasks(&[task_id])
        .await
        .map_err(|e| eyre::eyre!("Failed to wait for task: {}", e))?;

    let result: SP1ProofWithPublicValues = output_artifact
        .download_proof(&cluster_client.http)
        .await
        .map_err(|e| eyre::eyre!("Failed to download output: {}", e))?;

    Ok(result)
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
        let transactions = &subblock_host_output.subblock_inputs[i].current_block.body;
        bincode::serialize_into(&mut current_public_values, transactions).unwrap();

        let serialized =
            rkyv::to_bytes::<rkyv::rancor::BoxedError>(&subblock_host_output.subblock_outputs[i])
                .expect("failed to serialize state diff")
                .to_vec();

        // for _ in 0..100 {
        //     let tmp = serialized.clone();

        //     let deserialized_2 =
        //         rkyv::from_bytes::<SubblockOutput, rkyv::rancor::BoxedError>(&serialized).unwrap();

        //     assert_eq!(subblock_host_output.subblock_outputs[i], deserialized_2);
        //     serialized = rkyv::to_bytes::<rkyv::rancor::BoxedError>(&deserialized_2)
        //         .expect("failed to serialize state diff")
        //         .to_vec();
        //     assert_eq!(tmp, serialized, "inconsistent serialized representation");
        //     println!("success");
        // }

        // println!("yuwen_serialized: {:?}", serialized);

        current_public_values.write_all(&serialized).unwrap();

        let sp1_pv = SP1PublicValues::from(&current_public_values);

        println!("sp1_pv: {:?}", sp1_pv.hash());
        public_values.push(current_public_values);
    }
    stdin.write::<Vec<Vec<u8>>>(&public_values);
    stdin.write::<[u32; 8]>(&subblock_vk.hash_u32());
    stdin.write(&subblock_host_output.agg_input);
    stdin.write_vec(subblock_host_output.agg_parent_state);
    stdin
}

fn try_load_input_from_cache(
    cache_dir: Option<&PathBuf>,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<SubblockHostOutput>> {
    Ok(if let Some(cache_dir) = cache_dir {
        let cache_path = cache_dir.join(format!("input/{}/{}.bin", chain_id, block_number));

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
