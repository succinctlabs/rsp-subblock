#!/usr/bin/env python3
import os
import csv
import subprocess
import argparse
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor

def run_subblock_command(block_number):
    """Run the subblock command for a specific block number and return the block number."""
    debug_file = f"debug_{block_number}.csv"
    
    cmd = [
        "cargo", "run", 
        "--profile", "release-with-debug", 
        "--bin", "subblock", 
        "--", 
        "--block-number", str(block_number),
        "--chain-id", "1",
        "--cache-dir", "subblock-cache-gassplit-2m",
        "--execute"
    ]
    
    # Set the DEBUG_FILE environment variable
    env = os.environ.copy()
    env["DEBUG_FILE"] = debug_file
    
    try:
        subprocess.run(cmd, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return block_number, debug_file
    except subprocess.CalledProcessError as e:
        print(f"Error processing block {block_number}: {e}")
        return block_number, None

def process_debug_file(block_number, debug_file):
    """Process a debug file and return data in the format [block_number, type, count]."""
    if not debug_file or not os.path.exists(debug_file):
        return []
    
    results = []
    
    with open(debug_file, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) == 2:
                entry_type, count = row
                results.append([block_number, entry_type, count])
    
    # Clean up the temporary debug file
    os.remove(debug_file)
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Aggregate subblock debug outputs for a range of blocks.')
    parser.add_argument('start_block', type=int, help='Starting block number')
    parser.add_argument('end_block', type=int, help='Ending block number')
    parser.add_argument('output_file', type=str, help='Output aggregation file')
    parser.add_argument('--workers', type=int, default=4, help='Number of worker processes (default: 4)')
    
    args = parser.parse_args()
    
    # Create a list of block numbers to process
    block_numbers = range(args.start_block, args.end_block + 1)
    
    print(f"Processing blocks {args.start_block} to {args.end_block}...")
    
    all_results = []
    
    # Process blocks in parallel
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        # First run all the subblock commands
        future_to_block = {executor.submit(run_subblock_command, block_num): block_num for block_num in block_numbers}
        
        for future in future_to_block:
            block_num, debug_file = future.result()
            if debug_file:
                results = process_debug_file(block_num, debug_file)
                all_results.extend(results)
    
    # Write aggregated results to the output file
    with open(args.output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['block_number', 'type', 'count'])  # Header row
        writer.writerows(all_results)
    
    print(f"Aggregation complete. Results written to {args.output_file}")
    print(f"Processed {len(block_numbers)} blocks with {len(all_results)} total entries")

if __name__ == "__main__":
    main()