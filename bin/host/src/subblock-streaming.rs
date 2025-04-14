//! Streaming subblock execution.
//!
//! Directly creates an aggregation task.

use alloy_provider::ReqwestProvider;
use api2::{conn::ClusterClientV2, worker::CreateDummyProofRequest};
use clap::Parser;
use rsp_client_executor::io::{AggregationInput, SubblockHostOutput, SubblockInput};
use rsp_host_executor::HostExecutor;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin,
    SP1VerifyingKey,
};
use std::{
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

use sp1_worker::{
    artifact::{ArtifactClient, ArtifactType},
    proto::{Artifact, TaskType},
    redis::RedisArtifactClient,
    V2Client,
};

mod execute;

mod cli;
use cli::{upload_artifact, ProviderArgs};

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
    /// Whether we are running in a simulator or not.
    #[clap(long)]
    simulate: bool,
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

lazy_static::lazy_static! {
    static ref DEBUG_LOG_FILE: PathBuf = PathBuf::from("debug.csv");
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Intialize the environment variables.
    dotenv::dotenv().ok();

    // if std::env::var("RUST_LOG").is_err() {
    //     std::env::set_var("RUST_LOG", "info");
    // }

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

    let (duration, proof_id) =
        schedule_task(subblock_pk, args.block_number, agg_pk, client_input, args.execute).await?;

    let mut debug_log_file =
        std::fs::OpenOptions::new().create(true).append(true).open(DEBUG_LOG_FILE.clone()).unwrap();
    debug_log_file
        .write_all(format!("{}, {}, {}\n", args.block_number, proof_id, duration).as_bytes())
        .unwrap();

    Ok(())
}

async fn schedule_task(
    subblock_pk: SP1ProvingKey,
    block_number: u64,
    agg_pk: SP1ProvingKey,
    inputs: SubblockHostOutput,
    execute: bool,
) -> eyre::Result<(String, String)> {
    let (subblock_elf, subblock_vk) = (subblock_pk.elf, subblock_pk.vk);
    let agg_elf = agg_pk.elf;
    let addr = std::env::var("CLUSTER_V2_RPC").expect("CLUSTER_V2_RPC must be set");
    let mut cluster_client = ClusterClientV2::connect(addr.clone(), "rsp".to_string()).await?;
    let artifact_client = RedisArtifactClient::new(
        std::env::var("REDIS_NODES")
            .expect("REDIS_NODES is not set")
            .split(',')
            .map(|s| s.to_string())
            .collect(),
        std::env::var("REDIS_POOL_MAX_SIZE").unwrap_or("16".to_string()).parse().unwrap(),
    );

    let now: std::time::Duration =
        SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");

    let proof_id = format!("rsp_{}", now.as_secs());

    let worker_id = format!("worker_{}", now.as_secs());

    println!("proof_id: {}", proof_id);

    cluster_client
        .client
        .client
        .create_dummy_proof(CreateDummyProofRequest {
            worker_id: worker_id.clone(),
            proof_id: proof_id.clone(),
            requester: "yuwens_mac".to_string(),
            expires_at: 0,
        })
        .await?;

    let mut subblock_input_artifacts: Vec<Artifact> =
        Vec::with_capacity(inputs.subblock_inputs.len());

    let client = ProverClient::from_env();

    let aggregation_stdin = to_aggregation_stdin(inputs.clone(), &subblock_vk);
    let mut total_cycles = 0;
    let mut max_cycles = 0;

    for i in 0..inputs.subblock_inputs.len() {
        let input = &inputs.subblock_inputs[i];
        let parent_state = &inputs.subblock_parent_states[i];

        let mut stdin = SP1Stdin::new();
        stdin.write(input);
        stdin.write_vec(parent_state.clone());
        #[cfg(debug_assertions)]
        {
            // Save the elf/stdin pair to the dump directory.
            let dump_dir = PathBuf::from(std::env::var("DUMP_DIR").unwrap_or("./dump".to_string()));
            let elf_path = dump_dir.join(format!("subblock_elf_{}.bin", i));
            let stdin_path = dump_dir.join(format!("subblock_stdin_{}.bin", i));
            std::fs::write(elf_path, &subblock_elf)?;
            std::fs::write(stdin_path, bincode::serialize(&stdin)?)?;
        }
        let artifact_handle =
            upload_artifact(&artifact_client, "subblock_input", &stdin, ArtifactType::Stdin);

        if execute {
            let (_public_values, report) = client.execute(&subblock_elf, &stdin).run().unwrap();
            let mut debug_log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(DEBUG_LOG_FILE.clone())
                .unwrap();
            debug_log_file
                .write_all(format!("subblock, {}\n", report.total_instruction_count()).as_bytes())
                .unwrap();

            // Write the subblock stdin and elf to subblock_{i}/program.bin and
            // subblock_{i}/stdin.bin
            let subblock_input_dir = format!("{}_subblock_{}", block_number, i);
            std::fs::create_dir_all(&subblock_input_dir).unwrap();
            std::fs::write(format!("{}/program.bin", subblock_input_dir), &subblock_elf).unwrap();
            let stdin = bincode::serialize(&stdin).unwrap();
            std::fs::write(format!("{}/stdin.bin", subblock_input_dir), stdin).unwrap();
        }

        let artifact = artifact_handle.await?;
        subblock_input_artifacts.push(artifact);
    }

    // Create an artifact index for the subblock inputs.
    let subblock_input_index =
        subblock_input_artifacts.iter().map(|a| a.id.clone()).collect::<Vec<_>>();
    let subblock_input_index_artifact: Artifact = upload_artifact(
        &artifact_client,
        "subblock_input_index",
        subblock_input_index,
        ArtifactType::UnspecifiedArtifactType,
    )
    .await?;

    // Create artifacts for the subblock stuff.
    let subblock_elf_artifact: Artifact =
        upload_artifact(&artifact_client, "subblock_elf", subblock_elf, ArtifactType::Program)
            .await?;

    let subblock_vk_artifact: Artifact = upload_artifact(
        &artifact_client,
        "subblock_vk",
        subblock_vk,
        ArtifactType::UnspecifiedArtifactType,
    )
    .await?;

    // Create artifacts for the aggregation stuff.
    let agg_elf_artifact: Artifact =
        upload_artifact(&artifact_client, "agg_elf", &agg_elf, ArtifactType::Program).await?;

    let agg_stdin_artifact: Artifact =
        upload_artifact(&artifact_client, "agg_stdin", &aggregation_stdin, ArtifactType::Stdin)
            .await?;

    if execute {
        let (_public_values, report) = client
            .execute(&agg_elf, &aggregation_stdin)
            .deferred_proof_verification(false)
            .run()
            .unwrap();
        let agg_instruction_count = report.total_instruction_count();
        total_cycles += agg_instruction_count;
        max_cycles =
            if max_cycles < agg_instruction_count { agg_instruction_count } else { max_cycles };
    }

    // Create an empty artifact for the output
    let output_artifact: Artifact = artifact_client
        .create_artifact_blocking("agg_output", 0)
        .map_err(|e| eyre::eyre!("Failed to create output artifact: {}", e))?;

    // Create an empty artifact for the duration
    let duration_artifact: Artifact =
        artifact_client
            .create_artifact_blocking("agg_duration", 0)
            .map_err(|e| eyre::eyre!("Failed to create duration artifact: {}", e))?;

    let input_ids = vec![
        subblock_elf_artifact.id,
        subblock_input_index_artifact.id,
        subblock_vk_artifact.id,
        agg_elf_artifact.id,
        agg_stdin_artifact.id,
    ];

    let task_id = cluster_client
        .client
        .create_task(
            TaskType::Sp1SubblockAggregator,
            &input_ids,
            &[output_artifact.id.clone(), duration_artifact.id.clone()],
            proof_id.clone(),
            None,
            None,
        )
        .await
        .map_err(|e| eyre::eyre!("Failed to create task: {}", e))?;

    println!("Task created: {}", task_id);

    cluster_client
        .client
        .wait_tasks(proof_id.clone(), &[task_id.clone()])
        .await
        .map_err(|e| eyre::eyre!("Failed to wait for task: {}", e))?;

    let duration: String = artifact_client
        .download_with_type(&duration_artifact, ArtifactType::UnspecifiedArtifactType)
        .await
        .map_err(|e| eyre::eyre!("Failed to download duration: {}", e))?;

    let result: SP1ProofWithPublicValues = artifact_client
        .download_with_type(&output_artifact, ArtifactType::Proof)
        .await
        .map_err(|e| eyre::eyre!("Failed to download output: {}", e))?;

    client.verify(&result, &agg_pk.vk)?;

    println!("total cycles: {}", total_cycles);
    println!("max cycles: {}", max_cycles);

    // This is the easiest way to find out how long it takes to run the subblock without setup time.
    // YUWEN TODO: change the task ui somehow to accept preprocessed setup.
    // println!("run again, this time setup is cached.");
    // cluster_client
    //     .update_task_status(&task_id, sp1_worker::proto::TaskStatus::Pending)
    //     .await
    //     .map_err(|e| eyre::eyre!("Failed to update task status: {}", e))?;

    Ok((duration, proof_id))
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
                .expect("failed to serialize subblock output")
                .to_vec();

        current_public_values.write_all(&serialized).unwrap();

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
