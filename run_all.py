import os
import subprocess
import sys
import csv
import concurrent.futures
import signal # For signal handling
import threading # For locks and events
import time # For potential sleep
import itertools # For the counter

# --- Configuration ---
CACHE_DIR = "subblock-bench-8m"
CHAIN_ID = "1"
CARGO_BIN = "subblock-streaming"
CSV_FILE = "evaluation_blocks.csv"
NUM_WORKERS = 1 # Number of parallel processes to run
START_ROW = 20 # 1-based index for the *data* row to start processing from (after header)
# --- End Configuration ---

# --- Globals for Signal Handling & Progress ---
# Store active Popen objects
running_processes = []
# Lock to protect access to the running_processes list
process_lock = threading.Lock()
# Event to signal shutdown across threads
shutdown_requested = threading.Event()
# Store the executor instance to shut it down from the signal handler
executor_instance = None
# Add a thread-safe counter for progress
# Using itertools.count is naturally thread-safe for incrementing
progress_counter = itertools.count(start=1)
# --- End Globals ---

def signal_handler(sig, frame):
    """Handles SIGINT (Ctrl+C) to initiate graceful shutdown."""
    global executor_instance
    if shutdown_requested.is_set():
        print("\nShutdown already in progress. Force killing remaining processes...", file=sys.stderr)
        force_kill = True # Second Ctrl+C might trigger force kill
    else:
        print("\nCtrl+C received. Initiating graceful shutdown...", file=sys.stderr)
        force_kill = False

    shutdown_requested.set() # Signal all threads to stop

    terminated_count = 0
    killed_count = 0

    # Terminate running subprocesses
    # Iterate over a copy in case the list is modified concurrently (though lock helps)
    with process_lock:
        procs_to_terminate = list(running_processes) # Make a copy

    print(f"Attempting to terminate {len(procs_to_terminate)} running cargo processes...")
    for proc in procs_to_terminate:
        try:
            if force_kill:
                 print(f"Force killing PID {proc.pid}...")
                 proc.kill() # Send SIGKILLn 
                 killed_count += 1
            else:
                print(f"Terminating PID {proc.pid}...")
                proc.terminate() # Send SIGTERM (more graceful)
                terminated_count += 1
        except ProcessLookupError:
            print(f"Process PID {proc.pid} already finished.")
        except Exception as e:
            print(f"Error terminating process PID {proc.pid}: {e}", file=sys.stderr)

    print(f"Sent terminate signal to {terminated_count} processes.")
    if killed_count > 0:
        print(f"Sent kill signal to {killed_count} processes.")

    # Optionally, give processes a moment to terminate before killing if not force_kill
    # if not force_kill:
    #    time.sleep(2)
    #    with process_lock:
    #        # Check again which are still alive and kill them
    #        # ... implementation ...

    # Shutdown the executor - prevent new tasks, cancel pending ones
    if executor_instance:
        print("Shutting down thread pool executor...")
        # cancel_futures requires Python 3.9+
        if sys.version_info >= (3, 9):
             executor_instance.shutdown(wait=False, cancel_futures=True)
        else:
             executor_instance.shutdown(wait=False) # cancel_futures not available

    # The KeyboardInterrupt will likely be raised in the main thread after this handler returns
    # Or we can exit here directly if preferred:
    # print("Exiting script.")
    # sys.exit(1)


def run_cargo_for_block(block_number, total_blocks):
    """Constructs and runs the cargo command, handling specific errors and showing progress."""
    global running_processes, process_lock, shutdown_requested, CACHE_DIR, CHAIN_ID, progress_counter

    # Get the current progress count before checking for shutdown
    current_count = next(progress_counter)

    if shutdown_requested.is_set():
        # Decrement counter if skipped? Or let it represent attempts? Let's keep it as attempts.
        print(f"Skipping block {block_number} (Task {current_count}/{total_blocks}) due to shutdown request.")
        return block_number, "skipped", None

    # Print progress here
    print(f"Starting processing for Block Number: {block_number} (Task {current_count}/{total_blocks})")
    command = [
        "cargo", "run", "--profile", "release-with-debug", "--bin", CARGO_BIN, "--",
        "--block-number", str(block_number),
        "--chain-id", CHAIN_ID,
        "--cache-dir", CACHE_DIR,
        "--execute"
    ]

    proc = None
    try:
        # Start the process without waiting
        proc = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Add to list of running processes under lock
        with process_lock:
            if shutdown_requested.is_set(): # Check again after acquiring lock
                 print(f"Shutdown requested immediately after starting {block_number}. Terminating...")
                 proc.terminate()
                 return block_number, "cancelled", None
            running_processes.append(proc)

        # Wait for the process to complete. This will be interrupted if the process is terminated externally.
        # Capture output after completion
        stdout, stderr = proc.communicate()
        return_code = proc.returncode

        # Remove from list once completed (or terminated)
        with process_lock:
            try:
                running_processes.remove(proc)
            except ValueError:
                pass # Already removed or never added properly

        if shutdown_requested.is_set() and return_code != 0:
             # If shutdown was requested and process exited non-zero, likely terminated by us
             print(f"Processing for block {block_number} (Task {current_count}/{total_blocks}) cancelled (exit code {return_code}).")
             # Optionally print stderr if needed: print(f"Stderr for cancelled {block_number}:\n{stderr}", file=sys.stderr)
             return block_number, "cancelled", return_code
        elif return_code == 0:
            print(f"Finished processing block {block_number} (Task {current_count}/{total_blocks}). Success.")
            # print(f"Output for {block_number}:\n{stdout}") # Uncomment to see output
            return block_number, "success", None
        else:
            # --- Failure Handling ---
            print(f"Error running command for block {block_number} (Task {current_count}/{total_blocks}). Exit code: {return_code}", file=sys.stderr)
            print(f"Stderr for {block_number}:\n{stderr}", file=sys.stderr)

            # Check for the specific error message in stderr
            error_string_to_check = "Error: io error: failed to fill whole buffer"
            if error_string_to_check in stderr:
                print(f"Detected '{error_string_to_check}' for block {block_number}.")
                # Construct the file path
                file_to_delete = os.path.join(CACHE_DIR, "input", CHAIN_ID, f"{block_number}.bin")
                print(f"Attempting to delete potentially corrupted file: {file_to_delete}")
                try:
                    os.remove(file_to_delete)
                    print(f"Successfully deleted {file_to_delete}")
                except FileNotFoundError:
                    print(f"File not found, could not delete: {file_to_delete}", file=sys.stderr)
                except OSError as e:
                    print(f"Error deleting file {file_to_delete}: {e}", file=sys.stderr)
                except Exception as e:
                    print(f"Unexpected error during file deletion for {file_to_delete}: {e}", file=sys.stderr)
            # --- End Failure Handling ---

            return block_number, "failed", return_code

    except FileNotFoundError:
         print(f"Error: 'cargo' command not found. Is Rust installed and in PATH?", file=sys.stderr)
         # Signal shutdown immediately if cargo isn't found
         shutdown_requested.set()
         # Remove proc if it was added, though Popen likely failed earlier
         if proc:
             with process_lock:
                 try: running_processes.remove(proc)
                 except ValueError: pass
         return block_number, "failed", "Cargo not found" # Special error case
    except Exception as e:
        print(f"An unexpected error occurred processing block {block_number} (Task {current_count}/{total_blocks}): {e}", file=sys.stderr)
        # Ensure removal from list on unexpected error
        if proc:
            with process_lock:
                 try: running_processes.remove(proc)
                 except ValueError: pass
        return block_number, "failed", e


def main():
    """Main function to execute the subblock streaming process in parallel."""
    global executor_instance, START_ROW # Allow assignment to the global

    # Register the signal handler for SIGINT
    original_sigint_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal_handler)

    print(f"Script started. Current working directory: {os.getcwd()}")
    print(f"Running with {NUM_WORKERS} parallel workers.")
    print(f"Starting processing from CSV data row: {START_ROW}") # Log start row
    print("Press Ctrl+C to initiate graceful shutdown.")

    # --- Pre-run Checks ---
    print(f"Checking cache directory: '{CACHE_DIR}'")
    if not os.path.isdir(CACHE_DIR):
        print(f"Error: Cache directory '{CACHE_DIR}' not found.", file=sys.stderr)
        sys.exit(1)
    print(f"Cache directory '{CACHE_DIR}' exists.")

    print(f"Checking CSV file: '{CSV_FILE}'")
    if not os.path.isfile(CSV_FILE):
        print(f"Error: CSV file '{CSV_FILE}' not found.", file=sys.stderr)
        sys.exit(1)
    if not os.access(CSV_FILE, os.R_OK):
         print(f"Error: CSV file '{CSV_FILE}' is not readable.", file=sys.stderr)
         sys.exit(1)
    print(f"CSV file '{CSV_FILE}' found and is readable.")

    print("-" * 37)
    print(f"Reading block numbers from CSV file: {CSV_FILE}")

    # --- Read and Validate Block Numbers ---
    block_numbers_to_process = []
    skipped_rows_count = 0
    total_rows_in_file = 0 # Count total data rows for context
    try:
        with open(CSV_FILE, 'r', newline='') as infile:
            reader = csv.reader(infile)
            try:
                header = next(reader) # Read header row (Row 1 overall)
                print(f"Skipped header: {header}")
            except StopIteration:
                print("Error: CSV file is empty.", file=sys.stderr)
                sys.exit(1)

            # Iterate through data rows (starting from overall row 2)
            for i, row in enumerate(reader, start=1): # i is now 1-based data row index
                total_rows_in_file += 1
                if not row:
                    print(f"Warning: Skipping empty data row {i}.")
                    continue # Skip empty rows regardless of start row

                # Skip rows before the desired start row
                if i < START_ROW:
                    skipped_rows_count += 1
                    continue

                # Validate and add block number
                block_number_str = row[0].strip()
                if not block_number_str.isdigit():
                    print(f"Warning: Skipping data row {i}. Value '{block_number_str}' is not a valid number.")
                    continue
                block_numbers_to_process.append(block_number_str)

    except FileNotFoundError:
        print(f"Error: Failed to open CSV file '{CSV_FILE}'.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred reading CSV: {e}", file=sys.stderr)
        sys.exit(1)

    if skipped_rows_count > 0:
        print(f"Skipped {skipped_rows_count} data rows before row {START_ROW}.")

    if not block_numbers_to_process:
        print(f"No valid block numbers found in CSV file at or after data row {START_ROW}. Exiting.")
        sys.exit(0)

    # --- Get Total Count for Progress ---
    total_blocks_to_process = len(block_numbers_to_process) # This is now the count of blocks *actually* being processed
    print(f"Found {total_blocks_to_process} valid block numbers to process (out of {total_rows_in_file} total data rows).")
    print("-" * 37)
    print(f"Starting parallel processing using cache directory: {CACHE_DIR}")
    print("-" * 37)

    # --- Parallel Processing ---
    results = {"success": 0, "failed": 0, "cancelled": 0, "skipped": 0}
    futures = []

    try:
        # Use ThreadPoolExecutor to run tasks concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
            executor_instance = executor # Store instance for signal handler

            # Submit tasks only if shutdown hasn't been requested already
            if not shutdown_requested.is_set():
                for bn in block_numbers_to_process:
                    if shutdown_requested.is_set(): # Check before submitting each task
                        results["skipped"] += 1
                        continue
                    # Pass total_blocks_to_process to the worker function
                    future = executor.submit(run_cargo_for_block, bn, total_blocks_to_process)
                    futures.append(future)

            print(f"Submitted {len(futures)} tasks to the executor.")

            # Process results as they complete
            # This loop will be interrupted by KeyboardInterrupt if Ctrl+C is pressed
            for future in concurrent.futures.as_completed(futures):
                try:
                    # Get the result from the future
                    _block, status, _error_info = future.result()
                    if status in results:
                        results[status] += 1
                    else: # Should not happen if run_cargo_for_block is correct
                         print(f"Warning: Unknown status '{status}' received.", file=sys.stderr)
                         results["failed"] += 1

                except concurrent.futures.CancelledError:
                     # Future was cancelled before it ran (likely during shutdown)
                     print("A task was cancelled before execution.")
                     results["cancelled"] += 1
                except Exception as exc:
                    # Handle exceptions raised within the task function itself if not caught internally
                    print(f'A task generated an unexpected exception: {exc}', file=sys.stderr)
                    results["failed"] += 1

                # Optional: Check shutdown flag here too to break early,
                # but as_completed might handle this okay after shutdown.
                # if shutdown_requested.is_set():
                #    break

    except KeyboardInterrupt:
        print("\nMain thread caught KeyboardInterrupt. Finalizing shutdown...")
        # Signal handler should have already run or is running.
        # Ensure remaining futures that might not have been waited on are accounted for.
        # Note: This might double-count if as_completed already processed them.
        # A more robust approach might involve tracking submitted vs completed futures.
        pass # Signal handler manages shutdown

    finally:
        # Restore original signal handler
        signal.signal(signal.SIGINT, original_sigint_handler)

        # Ensure executor is definitely shut down if it was created
        if executor_instance and not executor_instance._shutdown:
             print("Ensuring executor is shut down in finally block...")
             if sys.version_info >= (3, 9):
                 executor_instance.shutdown(wait=True, cancel_futures=True)
             else:
                 executor_instance.shutdown(wait=True)


    # --- Final Report ---
    print("-" * 37)
    total_attempted = len(block_numbers_to_process)
    # Adjust counts based on futures processed vs total submitted if needed
    processed_count = results["success"]
    failed_count = results["failed"]
    cancelled_count = results["cancelled"]
    skipped_count = results["skipped"] + (total_attempted - len(futures)) # Add blocks skipped before submission

    print("Processing finished or interrupted.")
    print(f"Summary:")
    print(f"  Total data rows in CSV: {total_rows_in_file}")
    print(f"  Data rows skipped at start: {skipped_rows_count}")
    print(f"  Blocks attempted:       {total_attempted}")
    print(f"  Tasks submitted:        {len(futures)}")
    print(f"  Successfully processed: {processed_count}")
    print(f"  Failed:                 {failed_count}")
    print(f"  Cancelled (Ctrl+C):     {cancelled_count}")
    print(f"  Skipped (during run):   {skipped_count}")
    print("-" * 37)

    # Exit with error code if any tasks failed or were cancelled unexpectedly
    if failed_count > 0 or (shutdown_requested.is_set() and cancelled_count == 0 and processed_count != total_attempted):
         # Exit error if failures OR if shutdown was requested but nothing seems cancelled (unexpected state)
        sys.exit(1)
    elif shutdown_requested.is_set():
         sys.exit(1) # Standard practice to exit non-zero if interrupted
    else:
        sys.exit(0) # Exit successfully only if all submitted tasks succeeded


if __name__ == "__main__":
    main() 