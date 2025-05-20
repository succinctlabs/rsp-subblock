# Reth Succinct Processor (RSP): Subblock POC

> [!CAUTION]
>
> This repository is still an active work-in-progress and is not formally audited or meant for production usage.

## Overview

A proof of concept system for generating zero-knowledge proofs of EVM block execution using [Reth](https://github.com/paradigmxyz/reth) in real time (Sub 12 seconds). Intended for use with Succinct's Prover Network, for ultra low-latency proofs.

In order to minimize latency, Ethereum blocks are split up by transaction into several subblocks.
Each subblock proof can be generated in parallel, and then aggregated into a single proof.

## Getting Started

To build and execute a monolithic SP1 program for a given block, run:

```bash
cargo run --release --bin rsp -- --block-number <block_number> --chain-id 1 
```

To build and execute the subblock and aggregation SP1 programs for a given block, run:

```bash
cargo run --release --bin subblock -- --block-number <block_number> --chain-id 1 
```

Note that neither of these commands will actually generate proofs. They will only build the executables
and optionally execute them in the SP1 zkVM.

Run the following command for more details on the CLI.

```bash
cargo run --release --bin subblock -- --help
```

## Subblock constraint overview

Each subblock uses the SP1 program in [`bin/client-eth-subblock`](bin/client-eth-subblock). The subblock program takes as input:

1. The subblock to execute. This takes the form of a normal block, except only the transactions contained in the subblock are included.
2. The parent state. This contains all the state that is needed to execute the subblock, including any state modified from previous subblocks.
3. Other metadata about the subblock.

The subblock program then executes the subblock and returns the new state root, logs bloom, and transaction receipts.

The aggregation program takes as input:

1. Proofs for all the subblocks.
2. The parent state root.
3. The current block header.
4. The current block body.

The aggregation program then verifies the proofs and asserts that the public values of all the subblocks are consistent with the block passed into the aggregation program. It then commits the current block hash, the parent block hash, and the current block's body as public values.
