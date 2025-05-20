#!/usr/bin/env python3
"""
Analyzes the gas usage of transactions in specific blocks listed in a CSV file.

Reads block numbers from 'evaluation_blocks.csv' and outputs analysis to
'evaluation_blocks_gas_analysis.csv'.
"""

import sys
import os
import csv
from web3 import Web3
from dotenv import load_dotenv

def main():
    # Load environment variables from .env file
    load_dotenv()

    # Define the input CSV filename
    input_csv_filename = "evaluation_blocks.csv"
    blocks_to_process = []

    # Read block numbers from the input CSV file
    try:
        with open(input_csv_filename, 'r', newline='') as infile:
            reader = csv.reader(infile)
            header = next(reader) # Skip header row
            print(f"Reading blocks from {input_csv_filename}, skipping header: {header}")
            for row in reader:
                if row: # Ensure row is not empty
                    try:
                        # Assuming block number is in the first column
                        block_number = int(row[0])
                        blocks_to_process.append(block_number)
                    except (ValueError, IndexError):
                        print(f"Warning: Skipping invalid row in {input_csv_filename}: {row}", file=sys.stderr)
        if not blocks_to_process:
            print(f"Error: No valid block numbers found in {input_csv_filename}.")
            sys.exit(1)
        print(f"Found {len(blocks_to_process)} blocks to process.")

    except FileNotFoundError:
        print(f"Error: Input file '{input_csv_filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading {input_csv_filename}: {e}")
        sys.exit(1)

    # Get Ethereum RPC URL from .env file
    ethereum_rpc_url = os.environ.get('RPC_SLOW')
    if not ethereum_rpc_url:
        print("Error: RPC_SLOW variable not found in .env file.")
        print("Please create a .env file with RPC_SLOW=your_ethereum_node_url")
        print("Example: RPC_SLOW=https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY")
        sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(ethereum_rpc_url))

    # Check if connected to Ethereum node
    if not w3.is_connected():
        print("Error: Failed to connect to Ethereum node.")
        print("Please check that the RPC_SLOW in your .env file contains a valid Ethereum node URL.")
        sys.exit(1)

    # Create CSV file for output
    csv_filename = "evaluation_blocks_gas_analysis.csv" # Updated filename
    with open(csv_filename, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        
        # Write CSV header
        csv_writer.writerow(['Block Number', 'Transaction Hash', 'Gas Limit', 'Gas Used'])
        
        # Process each block from the list
        process_blocks(w3, blocks_to_process, csv_writer) # Updated call
    
    print(f"Analysis complete. Results saved to {csv_filename}") # Updated message

def get_transactions(block):
    """Extract transactions from a block, handling different block formats."""
    if hasattr(block, 'transactions'):
        return block.transactions
    elif isinstance(block, dict) and 'transactions' in block:
        return block['transactions']
    return []

def get_transaction_gas_limit(tx):
    """Extract the gas limit from a transaction, handling different transaction formats."""
    if hasattr(tx, 'gas'):
        return tx.gas
    elif isinstance(tx, dict) and 'gas' in tx:
        return tx['gas']
    return 0

def get_transaction_hash(tx):
    """Extract the transaction hash, handling different transaction formats."""
    if hasattr(tx, 'hash'):
        return tx.hash
    elif isinstance(tx, dict) and 'hash' in tx:
        return tx['hash']
    return None

def process_blocks(w3, block_numbers, csv_writer): # Updated signature
    """Process each block in the provided list and output the transaction that used the most gas to CSV."""
    total_blocks = len(block_numbers)
    for i, block_number in enumerate(block_numbers): # Iterate over the list
        print(f"Processing block {block_number} ({i+1}/{total_blocks})")
        try:
            # Get the block with full transaction details
            block = w3.eth.get_block(block_number, full_transactions=True)
            
            # Get transactions from the block
            transactions = get_transactions(block)
            
            # Check if there are any transactions
            if not transactions:
                csv_writer.writerow([block_number, 'No transactions', 0, 0])
                continue
            
            # Find the transaction that used the most gas
            max_gas_used = 0
            max_gas_limit = 0
            max_tx_hash = None
            
            for tx in transactions:
                # Get transaction hash
                tx_hash = get_transaction_hash(tx)
                if not tx_hash:
                    continue
                
                # Get gas limit from transaction
                gas_limit = get_transaction_gas_limit(tx)
                
                # Get the receipt to find actual gas used
                try:
                    receipt = w3.eth.get_transaction_receipt(tx_hash)
                    gas_used = receipt.gasUsed
                    
                    if gas_used > max_gas_used:
                        max_gas_used = gas_used
                        max_gas_limit = gas_limit
                        max_tx_hash = tx_hash
                except Exception as e:
                    # Skip transactions with receipt issues
                    continue
            
            # Write the result to CSV
            if max_tx_hash:
                # Convert hash to hex string if it's not already a string
                tx_hash_str = max_tx_hash.hex() if hasattr(max_tx_hash, 'hex') else str(max_tx_hash)
                csv_writer.writerow([block_number, tx_hash_str, max_gas_limit, max_gas_used])
            else:
                csv_writer.writerow([block_number, 'No valid transactions', 0, 0])
        
        except Exception as e:
            csv_writer.writerow([block_number, f'Error: {str(e)}', 0, 0])
            print(f"Error processing block {block_number}: {str(e)}", file=sys.stderr)

if __name__ == "__main__":
    main()