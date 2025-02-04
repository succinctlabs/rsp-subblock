use alloy_provider::ReqwestProvider;
use clap::Parser;
use reth_primitives::B256;
use rsp_client_executor::io::{AggregationInput, SubblockInput, SubblockOutput};
use rsp_host_executor::HostExecutor;
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Proof, SP1Stdin};
use std::path::PathBuf;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
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
            let (subblock_inputs, agg_input) = host_executor
                .execute_subblock(args.block_number)
                .await
                .expect("failed to execute host");

            let cache_data = CacheData { subblock_inputs, agg_input };

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
    let (pk, subblock_vk) = client.setup(include_elf!("rsp-client-eth-subblock"));

    let mut public_values = Vec::new();
    let mut agg_stdin = SP1Stdin::new();
    for input in client_input.subblock_inputs {
        // Execute the block inside the zkVM.
        let mut stdin = SP1Stdin::new();
        let buffer = bincode::serialize(&input).unwrap();
        stdin.write_vec(buffer);

        // if args.execute {
        //     let (_, execution_report) = client.execute(&pk.elf, &stdin).run().unwrap();
        //     println!(
        //         "total instructions for subblock: {}",
        //         execution_report.total_instruction_count()
        //     );
        // }
        // Generate the subblock proof.
        let proof = client.prove(&pk, &stdin).compressed().run().unwrap();
        // Read the block hash.
        public_values.push(proof.public_values);
        let SP1Proof::Compressed(proof) = proof.proof else { panic!() };
        agg_stdin.write_proof(*proof, subblock_vk.vk.clone());
    }
    println!("subblock proofs generated");

    let (pk, agg_vk) = client.setup(include_elf!("rsp-client-eth-agg"));

    let public_values = public_values.iter().map(|p| p.to_vec()).collect::<Vec<_>>();
    let buffer = bincode::serialize(&public_values).unwrap();
    agg_stdin.write_vec(buffer);
    agg_stdin.write(&subblock_vk.hash_u32());
    let buffer = bincode::serialize(&client_input.agg_input).unwrap();
    agg_stdin.write_vec(buffer);

    if args.execute {
        let (_public_values, execution_report) = client.execute(&pk.elf, &agg_stdin).run().unwrap();
        println!("total instructions for agg: {}", execution_report.total_instruction_count());
    }
    let mut proof = client.prove(&pk, &agg_stdin).compressed().run().unwrap();
    let block_hash = proof.public_values.read::<B256>();
    println!("Block hash: {}", block_hash);

    Ok(())
}

fn try_load_input_from_cache(
    cache_dir: Option<&PathBuf>,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<CacheData>> {
    Ok(if let Some(cache_dir) = cache_dir {
        let cache_path = cache_dir.join(format!("input/{}/{}.bin", chain_id, block_number));

        if cache_path.exists() {
            // TODO: prune the cache if invalid instead
            let mut cache_file = std::fs::File::open(cache_path)?;
            let cache_data: CacheData = bincode::deserialize_from(&mut cache_file)?;

            Some(cache_data)
        } else {
            None
        }
    } else {
        None
    })
}
