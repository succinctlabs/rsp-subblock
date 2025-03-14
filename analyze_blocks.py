#!/usr/bin/env python3

import sys
import os
import csv
from web3 import Web3
from dotenv import load_dotenv

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # Check if the correct number of arguments are provided
    if len(sys.argv) != 3:
        print("Usage: python3 analyze_blocks.py <start_block> <end_block>")
        sys.exit(1)

    # Parse command line arguments
    try:
        start_block = int(sys.argv[1])
        end_block = int(sys.argv[2])
    except ValueError:
        print("Error: Block numbers must be integers.")
        sys.exit(1)

    # Ensure start_block is less than or equal to end_block
    if start_block > end_block:
        print("Error: Start block must be less than or equal to end block.")
        sys.exit(1)

    # Get Ethereum RPC URL from .env file
    ethereum_rpc_url = os.environ.get('RPC_1')
    if not ethereum_rpc_url:
        print("Error: RPC_1 variable not found in .env file.")
        print("Please create a .env file with RPC_1=your_ethereum_node_url")
        print("Example: RPC_1=https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY")
        sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(ethereum_rpc_url))

    # Check if connected to Ethereum node
    if not w3.is_connected():
        print("Error: Failed to connect to Ethereum node.")
        print("Please check that the RPC_1 in your .env file contains a valid Ethereum node URL.")
        sys.exit(1)

    # Create CSV file for output
    csv_filename = f"blocks_{start_block}_to_{end_block}_gas_analysis.csv"
    with open(csv_filename, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        
        # Write CSV header
        csv_writer.writerow(['Block Number', 'Transaction Hash', 'Gas Limit', 'Gas Used'])
        
        # Process each block in the range
        process_blocks(w3, start_block, end_block, csv_writer)
    
    print(f"Analysis complete. Results saved to {csv_filename}")

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

def process_blocks(w3, start_block, end_block, csv_writer):
    """Process each block in the range and output the transaction that used the most gas to CSV."""
    for block_number in range(start_block, end_block + 1):
        print(f"Processing block {block_number}")
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