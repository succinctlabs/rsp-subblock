//! Serial subblock execution. Use this one for debugging.

use alloy_provider::ReqwestProvider;
use api2::conn::ClusterClientV2;
use clap::Parser;
use reth_primitives::{Block, B256};
use rkyv::util::AlignedVec;
use rsp_client_executor::io::SubblockHostOutput;
use rsp_host_executor::HostExecutor;
use rsp_mpt::EthereumState;
use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient, SP1Proof, SP1Stdin};
use sp1_worker::{artifact::ArtifactType, redis::RedisArtifactClient};
use std::{io::Cursor, path::PathBuf};
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

mod cli;
use cli::{schedule_controller, upload_artifact, ProviderArgs};

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
        (Some(cache_data), _) => {
            #[cfg(debug_assertions)]
            {
                cache_data.validate()?;
            }
            cache_data
        }
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

    let addr = std::env::var("CLUSTER_V2_RPC").expect("CLUSTER_V2_RPC must be set");
    let mut cluster_client = ClusterClientV2::connect(addr.clone(), "rsp".to_string()).await?;

    cfg_if::cfg_if! {
        if #[cfg(feature = "s3")] {
            let artifact_client = sp1_worker::artifact::S3ArtifactClient::new(
                std::env::var("S3_REGION").unwrap_or("us-east-2".to_string()),
                std::env::var("S3_BUCKET").unwrap(),
                std::env::var("S3_CONCURRENCY")
                    .map(|s| s.parse().unwrap_or(32))
                    .unwrap_or(32),
            )
            .await;
        } else {
            let artifact_client = RedisArtifactClient::new(
                std::env::var("REDIS_NODES")
            .expect("REDIS_NODES is not set")
            .split(',')
            .map(|s| s.to_string())
            .collect(),
                std::env::var("REDIS_POOL_MAX_SIZE")
                    .unwrap_or("16".to_string())
                    .parse()
                    .unwrap(),
            );
        }
    }

    // Setup the proving key and verification key.
    let (subblock_pk, subblock_vk) = client.setup(include_elf!("rsp-client-eth-subblock")).await;

    let elf_artifact =
        upload_artifact(&artifact_client, "subblock_elf", &subblock_pk.elf, ArtifactType::Program)
            .await?;

    let mut public_values = Vec::new();
    let mut agg_stdin = SP1Stdin::new();
    for i in 0..client_input.subblock_inputs.len() {
        let input = &client_input.subblock_inputs[i];
        let parent_state = &client_input.subblock_parent_states[i];

        // Execute the block inside the zkVM.
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);
        stdin.write_vec(parent_state.clone());

        if args.execute {
            let (_public_values, execution_report) =
                client.execute(&subblock_pk.elf, &stdin).run().unwrap();
            println!(
                "total instructions for subblock: {}",
                execution_report.total_instruction_count()
            );
        }

        // Write the elf and stdin to the dump directory.
        if let Ok(dump_dir) = std::env::var("DUMP_DIR") {
            let dump_dir = PathBuf::from(dump_dir);
            let elf_path = dump_dir.join(format!("subblock_elf_{}.bin", i));
            let stdin_path = dump_dir.join(format!("subblock_stdin_{}.bin", i));
            std::fs::write(elf_path, subblock_pk.elf.as_ref())?;
            std::fs::write(stdin_path, bincode::serialize(&stdin)?)?;
        }

        // Generate the subblock proof.
        let proof = schedule_controller(
            elf_artifact.clone(),
            stdin,
            &mut cluster_client,
            &artifact_client,
            args.execute,
        )
        .await?;
        // Write the output to the public values.
        public_values.push(proof.public_values.clone());

        let SP1Proof::Compressed(proof) = proof.proof else { panic!() };
        agg_stdin.write_proof(*proof, subblock_vk.vk.clone());
    }
    println!("subblock proofs generated");

    let (pk, agg_vk) = client.setup(include_elf!("rsp-client-eth-agg")).await;

    let agg_elf_artifact =
        upload_artifact(&artifact_client, "agg_elf", &pk.elf, ArtifactType::Program).await?;

    let mut aligned_vec = AlignedVec::<16>::new();
    let mut reader = Cursor::new(&client_input.agg_parent_state);
    aligned_vec.extend_from_reader(&mut reader).unwrap();
    let parent_state =
        rkyv::from_bytes::<EthereumState, rkyv::rancor::BoxedError>(&aligned_vec).unwrap();
    let parent_state_root = parent_state.state_root();

    let public_values = public_values.iter().map(|p| p.to_vec()).collect::<Vec<_>>();
    agg_stdin.write::<Vec<Vec<u8>>>(&public_values);
    agg_stdin.write::<[u32; 8]>(&subblock_vk.hash_u32());
    agg_stdin.write(&client_input.agg_input);
    agg_stdin.write(&parent_state_root);

    if args.execute {
        let (_public_values, execution_report) = client.execute(&pk.elf, &agg_stdin).run().unwrap();
        println!("total instructions for agg: {}", execution_report.total_instruction_count());
    }

    println!("starting agg proof");

    let mut proof = schedule_controller(
        agg_elf_artifact.clone(),
        agg_stdin,
        &mut cluster_client,
        &artifact_client,
        args.execute,
    )
    .await?;

    client.verify(&proof, &agg_vk)?;

    let _parent_state_root = proof.public_values.read::<B256>();
    let _block = proof.public_values.read::<Block>();
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
