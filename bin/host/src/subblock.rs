//! Serial subblock execution. Use this one for debugging.

use alloy_provider::ReqwestProvider;
use clap::Parser;
use reth_primitives::B256;
use rsp_client_executor::io::SubblockHostOutput;
use rsp_host_executor::HostExecutor;
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
};
use sp1_worker::{
    artifact::ArtifactType,
    client::ClusterClient,
    proto::{Artifact, TaskType},
    ProofOptions,
};
use std::path::PathBuf;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

mod cli;
use cli::{upload_artifact, ProviderArgs};

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

    let cluster_client = ClusterClient::new();

    // Setup the proving key and verification key.
    let (subblock_pk, subblock_vk) = client.setup(include_elf!("rsp-client-eth-subblock"));

    let elf_artifact = upload_artifact(
        &cluster_client,
        "subblock_elf",
        subblock_pk.elf.clone(),
        ArtifactType::Program,
    )
    .await?;

    let mut public_values = Vec::new();
    let mut agg_stdin = SP1Stdin::new();
    for i in 0..client_input.subblock_inputs.len() {
        let input = &client_input.subblock_inputs[i];
        let parent_state = &client_input.subblock_parent_states[i];
        let input_state_diff = &client_input.subblock_input_diffs[i];

        // Execute the block inside the zkVM.
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);
        stdin.write_vec(parent_state.clone());
        stdin.write_vec(input_state_diff.clone());

        if args.execute {
            let (_public_values, execution_report) =
                client.execute(&subblock_pk.elf, &stdin).run().unwrap();
            println!(
                "total instructions for subblock: {}",
                execution_report.total_instruction_count()
            );
        }
        // Generate the subblock proof.
        let proof =
            schedule_controller(elf_artifact.clone(), stdin, &cluster_client, args.execute).await?;

        // Write the output to the public values.
        public_values.push(proof.public_values.clone());

        println!("public values: {:?}", proof.public_values.hash());
        // println!("is_last_subblock: {}", input.is_last_subblock);

        let SP1Proof::Compressed(proof) = proof.proof else { panic!() };
        agg_stdin.write_proof(*proof, subblock_vk.vk.clone());
    }
    println!("subblock proofs generated");

    let (pk, _agg_vk) = client.setup(include_elf!("rsp-client-eth-agg"));

    let agg_elf_artifact =
        upload_artifact(&cluster_client, "agg_elf", &pk.elf, ArtifactType::Program).await?;

    let public_values = public_values.iter().map(|p| p.to_vec()).collect::<Vec<_>>();
    agg_stdin.write::<Vec<Vec<u8>>>(&public_values);
    agg_stdin.write::<[u32; 8]>(&subblock_vk.hash_u32());
    agg_stdin.write(&client_input.agg_input);
    agg_stdin.write_vec(client_input.agg_parent_state);

    // if args.execute {
    //     let (_public_values, execution_report) = client.execute(&pk.elf, &agg_stdin).run().unwrap();
    //     println!("total instructions for agg: {}", execution_report.total_instruction_count());
    // }
    // let mut proof = client.prove(&pk, &agg_stdin).compressed().run().unwrap();

    let client = ProverClient::from_env();
    if args.execute {
        let (_public_values, execution_report) =
            client.execute(&pk.elf, &agg_stdin).deferred_proof_verification(false).run().unwrap();
        println!("total instructions for agg: {}", execution_report.total_instruction_count());
    }
    let mut proof =
        schedule_controller(agg_elf_artifact.clone(), agg_stdin, &cluster_client, args.execute)
            .await?;
    let block_hash = proof.public_values.read::<B256>();
    println!("Block hash: {}", block_hash);

    Ok(())
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

async fn schedule_controller(
    elf_artifact: Artifact,
    stdin: SP1Stdin,
    cluster_client: &ClusterClient,
    _execute: bool,
) -> eyre::Result<SP1ProofWithPublicValues> {
    let stdin_artifact: Artifact =
        upload_artifact(cluster_client, "subblock_stdin", stdin, ArtifactType::Stdin).await?;

    let proof_options = ProofOptions::subblock();
    let proof_options_artifact: Artifact = upload_artifact(
        cluster_client,
        "subblock_proof_options",
        proof_options,
        ArtifactType::UnspecifiedArtifactType,
    )
    .await?;
    // Create an empty artifact for the output
    let output_artifact: Artifact =
        cluster_client
            .create_artifact_blocking("subblock_output", 0)
            .map_err(|e| eyre::eyre!("Failed to create output artifact: {}", e))?;

    let proof_id = "yuwen".to_string();

    let input_ids = vec![elf_artifact.id, stdin_artifact.id, proof_options_artifact.id];

    let task_id = cluster_client
        .create_task(
            TaskType::Sp1Controller,
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
        .wait_tasks(&[task_id.clone()])
        .await
        .map_err(|e| eyre::eyre!("Failed to wait for task: {}", e))?;

    let result: SP1ProofWithPublicValues = output_artifact
        .download_proof(&cluster_client.http)
        .await
        .map_err(|e| eyre::eyre!("Failed to download output: {}", e))?;

    // println!("run again, this time setup is cached.");
    // cluster_client
    //     .update_task_status(&task_id, sp1_worker::proto::TaskStatus::Pending)
    //     .await
    //     .map_err(|e| eyre::eyre!("Failed to update task status: {}", e))?;

    // cluster_client
    //     .wait_tasks(&[task_id])
    //     .await
    //     .map_err(|e| eyre::eyre!("Failed to wait for task: {}", e))?;

    Ok(result)
}
