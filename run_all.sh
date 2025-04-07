#!/usr/bin/env bash

# runs all of the subblock streaming runs for the given cache directory

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
CACHE_DIR="subblock-cache-8m"
CHAIN_ID="1"
CARGO_BIN="subblock-streaming"
CSV_FILE="evaluation_blocks.csv"
# --- End Configuration ---

echo "Script started. Current working directory: $(pwd)"
echo "Checking cache directory: '$CACHE_DIR'"

# Check if the cache directory exists
if [ ! -d "$CACHE_DIR" ]; then
    echo "Error: Cache directory '$CACHE_DIR' not found."
    exit 1
fi
echo "Cache directory '$CACHE_DIR' exists."

# Check if the CSV file exists and is readable
if [ ! -f "$CSV_FILE" ]; then
    echo "Error: CSV file '$CSV_FILE' not found."
    exit 1
fi
if [ ! -r "$CSV_FILE" ]; then
    echo "Error: CSV file '$CSV_FILE' is not readable."
    exit 1
fi
echo "CSV file '$CSV_FILE' found and is readable."

# Explicitly check directory permissions from script perspective
echo "Directory permissions:"
ls -ld "$CACHE_DIR"

echo "-------------------------------------"
echo "Starting subblock streaming runs from CSV file: $CSV_FILE"
echo "Using cache directory: $CACHE_DIR"
echo "-------------------------------------"

# Keep track of how many blocks we process
processed_count=0

# Read the CSV file line by line, skipping the header
tail -n +2 "$CSV_FILE" | while IFS= read -r block_number; do
    # Remove potential carriage returns if the file came from Windows
    block_number=$(echo "$block_number" | tr -d '\r')

    # Basic validation: Check if block_number looks like a valid number
    if ! [[ "$block_number" =~ ^[0-9]+$ ]]; then
        echo "Warning: Skipping line. Extracted value '$block_number' does not look like a valid number."
        continue # Skip to the next line
    fi

    echo "Processing Block Number: $block_number"

    # Construct and run the command
    cargo run --profile release --bin "$CARGO_BIN" -- \
        --block-number "$block_number" \
        --chain-id "$CHAIN_ID" \
        --cache-dir "$CACHE_DIR"

    echo "Finished processing block $block_number."
    echo "-------------------------------------"
    processed_count=$((processed_count + 1))
done

# Report final status
if [ "$processed_count" -eq 0 ]; then
    echo "No valid block numbers found in '$CSV_FILE' to process."
else
    echo "All processing complete. Processed $processed_count blocks from '$CSV_FILE'."
fi

exit 0