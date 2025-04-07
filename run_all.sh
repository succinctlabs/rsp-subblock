#!/usr/bin/env bash

# runs all of the subblock streaming runs for the given cache directory

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
CACHE_DIR="subblock-cache-8m"
CHAIN_ID="1"
CARGO_BIN="subblock-streaming"
# --- End Configuration ---

echo "Script started. Current working directory: $(pwd)"
echo "Checking cache directory: '$CACHE_DIR'"

# Check if the cache directory exists
if [ ! -d "$CACHE_DIR" ]; then
    echo "Error: Cache directory '$CACHE_DIR' not found."
    exit 1
fi
echo "Cache directory '$CACHE_DIR' exists."

# Explicitly check directory permissions from script perspective
echo "Directory permissions:"
ls -ld "$CACHE_DIR"

echo "Attempting to list .bin files in '$CACHE_DIR' using ls:"
# Use ls to explicitly test the glob pattern BEFORE the loop. Capture output/errors.
# Using || true to prevent set -e from exiting if ls finds nothing
ls -l "$CACHE_DIR"/input/1/*.bin || echo "ls command found no .bin files or failed."
echo "-------------------------------------"


echo "Starting subblock streaming runs..."
echo "Using cache directory: $CACHE_DIR"
echo "Scanning for .bin files with bash glob..."
echo "-------------------------------------"

# Keep track of how many files we process
processed_count=0

# Loop through all files ending in .bin in the specified directory
# Using nullglob ensures the loop doesn't run if no files match
shopt -s nullglob
for filepath in "$CACHE_DIR"/input/1/*.bin; do
    # Extract the filename from the full path
    filename=$(basename "$filepath")

    # Extract the block number by removing the '.bin' extension
    block_number="${filename%.bin}"

    # Basic validation: Check if block_number looks like a valid number
    if ! [[ "$block_number" =~ ^[0-9]+$ ]]; then
        echo "Warning: Skipping file '$filename'. Extracted name '$block_number' does not look like a valid number."
        continue # Skip to the next file
    fi

    echo "Processing file: $filename --> Block Number: $block_number"

    # Construct and run the command
    cargo run --profile release --bin "$CARGO_BIN" -- \
        --block-number "$block_number" \
        --chain-id "$CHAIN_ID" \
        --cache-dir "$CACHE_DIR"

    echo "Finished processing block $block_number."
    echo "-------------------------------------"
    processed_count=$((processed_count + 1))
done

# Turn nullglob off again (good practice)
shopt -u nullglob

# Report final status
if [ "$processed_count" -eq 0 ]; then
    echo "Bash glob loop did not find any .bin files to process in '$CACHE_DIR'."
else
    echo "All processing complete. Processed $processed_count files."
fi

exit 0