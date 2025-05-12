use alloy_provider::ReqwestProvider;
use clap::Parser;
use eth_proofs::EthProofsClient;
use rsp_client_executor::{
    io::ClientExecutorInput, ChainVariant, CHAIN_ID_ETH_MAINNET, CHAIN_ID_LINEA_MAINNET,
    CHAIN_ID_OP_MAINNET, CHAIN_ID_SEPOLIA,
};
use rsp_host_executor::HostExecutor;
use sp1_sdk::{include_elf, Prover, ProverClient, SP1Stdin};
use std::path::PathBuf;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};
mod cli;
use cli::ProviderArgs;

mod execute;

mod eth_proofs;

// const FIB_ELF: &[u8] = include_bytes!("fib-elf.bin");
// const FIB_STDIN: &[u8] = include_bytes!("fib-stdin.bin");

/// The arguments for the host executable.
#[derive(Debug, Clone, Parser)]
struct HostArgs {
    /// The block number of the block to execute.
    #[clap(long)]
    block_number: u64,
    #[clap(flatten)]
    provider: ProviderArgs,
    /// Whether to generate a proof or just execute the block.
    #[clap(long)]
    prove: bool,

    /// Where to dump the elf and stdin.
    #[clap(long)]
    dump_dir: Option<PathBuf>,
    /// Optional path to the directory containing cached client input. A new cache file will be
    /// created from RPC data if it doesn't already exist.
    #[clap(long)]
    cache_dir: Option<PathBuf>,
    /// The path to the CSV file containing the execution data.
    #[clap(long, default_value = "report.csv")]
    report_path: PathBuf,

    /// Optional ETH proofs endpoint.
    #[clap(long, env, requires("eth_proofs_api_token"))]
    eth_proofs_endpoint: Option<String>,

    /// Optional ETH proofs API token.
    #[clap(long, env)]
    eth_proofs_api_token: Option<String>,

    /// Optional ETH proofs cluster ID.
    #[clap(long, default_value_t = 1)]
    eth_proofs_cluster_id: u64,
}

#[tokio::main(flavor = "multi_thread")]
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
    let eth_proofs_client = EthProofsClient::new(
        args.eth_proofs_cluster_id,
        args.eth_proofs_endpoint,
        args.eth_proofs_api_token,
    );

    if let Some(eth_proofs_client) = &eth_proofs_client {
        eth_proofs_client.queued(args.block_number).await?;
    }

    let variant = match provider_config.chain_id {
        CHAIN_ID_ETH_MAINNET => ChainVariant::Ethereum,
        CHAIN_ID_OP_MAINNET => ChainVariant::Optimism,
        CHAIN_ID_LINEA_MAINNET => ChainVariant::Linea,
        CHAIN_ID_SEPOLIA => ChainVariant::Sepolia,
        _ => {
            eyre::bail!("unknown chain ID: {}", provider_config.chain_id);
        }
    };

    let client_input_from_cache = try_load_input_from_cache(
        args.cache_dir.as_ref(),
        provider_config.chain_id,
        args.block_number,
    )?;

    let client_input = match (client_input_from_cache, provider_config.rpc_url) {
        (Some(client_input_from_cache), _) => client_input_from_cache,
        (None, Some(rpc_url)) => {
            // Cache not found but we have RPC
            // Setup the provider.
            let provider = ReqwestProvider::new_http(rpc_url);

            // Setup the host executor.
            let host_executor = HostExecutor::new(provider);

            // Execute the host.
            let client_input = host_executor
                .execute(args.block_number, variant)
                .await
                .expect("failed to execute host");

            if let Some(ref cache_dir) = args.cache_dir {
                let input_folder = cache_dir.join(format!("input/{}", provider_config.chain_id));
                if !input_folder.exists() {
                    std::fs::create_dir_all(&input_folder)?;
                }

                let input_path = input_folder.join(format!("{}.bin", args.block_number));
                let mut cache_file = std::fs::File::create(input_path)?;

                bincode::serialize_into(&mut cache_file, &client_input)?;
            }

            client_input
        }
        (None, None) => {
            eyre::bail!("cache not found and RPC URL not provided")
        }
    };

    // Generate the proof.
    let client =
        tokio::task::spawn_blocking(|| ProverClient::builder().cpu().build()).await.unwrap();

    // Setup the proving key and verification key.
    let (pk, _vk) = client
        .setup(match variant {
            ChainVariant::Ethereum => include_elf!("rsp-client-eth"),
            _ => panic!("other chain variants not supported for subblocks: {:?}", variant),
        })
        .await;

    // Execute the block inside the zkVM.
    let mut stdin = SP1Stdin::new();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);

    // let (pk, vk) = client.setup(FIB_ELF).await;
    // let stdin: SP1Stdin = bincode::deserialize(FIB_STDIN).unwrap();
    // Only execute the program.
    let (_public_values, execution_report) = client.execute(&pk.elf, &stdin).run().unwrap();

    println!("execution_report: {}", execution_report);
    // // Read the block hash.
    // let block_hash = public_values.read::<B256>();
    // println!("success: block_hash={block_hash}");

    // if eth_proofs_client.is_none() {
    //     // Process the execute report, print it out, and save data to a CSV specified by
    //     // report_path.
    //     process_execution_report(
    //         variant,
    //         client_input,
    //         &execution_report,
    //         args.report_path.clone(),
    //     )?;
    // }

    if args.prove {
        println!("Starting proof generation.");

        if let Some(eth_proofs_client) = &eth_proofs_client {
            eth_proofs_client.proving(args.block_number).await?;
        }

        // let proof = client.prove(&pk, &stdin).compressed().run().expect("Proving should work.");
        // let proof_bytes = bincode::serialize(&proof.proof).unwrap();

        if let Some(dump_dir) = args.dump_dir {
            let dump_dir = dump_dir.join(format!("{}", args.block_number));
            let elf_path = dump_dir.join("basic_elf.bin");
            let stdin_path = dump_dir.join("basic_stdin.bin");
            std::fs::write(elf_path, pk.elf.as_ref())?;
            std::fs::write(stdin_path, bincode::serialize(&stdin)?)?;
        }

        // Generate the subblock proof.
        // let proof = schedule_controller(
        //     elf_artifact.clone(),
        //     stdin,
        //     &mut cluster_client,
        //     &artifact_client,
        //     false,
        // )
        // .await?;
        // client.verify(&proof, &vk).unwrap();
        // let elapsed = start.elapsed().as_secs_f32();

        // println!("elapsed: {}", elapsed);

        // if let Some(eth_proofs_client) = &eth_proofs_client {
        //     eth_proofs_client
        //         .proved(&proof_bytes, args.block_number, &execution_report, elapsed, &vk)
        //         .await?;
        // }
    }

    Ok(())
}

fn try_load_input_from_cache(
    cache_dir: Option<&PathBuf>,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<ClientExecutorInput>> {
    Ok(if let Some(cache_dir) = cache_dir {
        let cache_path = cache_dir.join(format!("input/{}/{}.bin", chain_id, block_number));

        if cache_path.exists() {
            // TODO: prune the cache if invalid instead
            let mut cache_file = std::fs::File::open(cache_path)?;
            let client_input: ClientExecutorInput = bincode::deserialize_from(&mut cache_file)?;

            Some(client_input)
        } else {
            None
        }
    } else {
        None
    })
}
