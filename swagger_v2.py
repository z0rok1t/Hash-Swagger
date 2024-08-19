#!/usr/bin/python3
import argparse
import hashlib
import re
import pyfiglet 
import sys
import time
import itertools
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# ASCII art banner
ascii_banner = pyfiglet.figlet_format("Hash Swagger")
print(ascii_banner)
print("Algorithms Available: MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | SHA3_224 | SHA3_256 | SHA3_384 | SHA3_512 | BLAKE2s | BLAKE2b\n")

# Spinner animation class for visual feedback during long operations
class Spinner:
    def __init__(self):
        self.spinner = itertools.cycle(['-', '/', '|', '\\'])
        self.busy = False
        self.spinner_thread = None

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(next(self.spinner))
            sys.stdout.flush()
            sys.stdout.write('\b')
            time.sleep(0.1)

    def start(self):
        self.busy = True
        self.spinner_thread = threading.Thread(target=self.spinner_task)
        self.spinner_thread.start()

    def stop(self):
        self.busy = False
        self.spinner_thread.join()

# Function to identify hash algorithm based on hash length and pattern
def identify_hash_algorithm(hash_string):
    # Dictionary mapping regex patterns to hash algorithms
    hash_patterns = {
        r"^[a-f0-9]{32}$": "MD5",
        r"^[a-f0-9]{40}$": "SHA1",
        r"^[a-f0-9]{56}$": "SHA224",
        r"^[a-f0-9]{64}$": ["SHA256", "SHA3_256", "BLAKE2s"],
        r"^[a-f0-9]{96}$": ["SHA384", "SHA3_384"],
        r"^[a-f0-9]{128}$": ["SHA512", "SHA3_512", "BLAKE2b"]
    }

    for pattern, algorithms in hash_patterns.items():
        if re.match(pattern, hash_string):
            if isinstance(algorithms, list):
                # For ambiguous cases, we'll return all possibilities
                return "/".join(algorithms)
            else:
                return algorithms
    return "Unknown"

# Function to crack a single hash
def crack_hash(hash_string, algorithm, wordlist):
    if not os.path.exists(wordlist):
        return f"\033[91mWordlist file not found: {wordlist}"
    
    with open(wordlist, 'rb') as f:
        for line_bytes in f:
            try:
                word = line_bytes.decode('utf-8').strip()
                hashed_word = hashlib.new(algorithm.lower(), word.encode()).hexdigest()
                if hashed_word == hash_string:
                    return word
            except UnicodeDecodeError:
                continue
    return "Hash Not Found"

# Function to crack a hash using multi-threading
def crack_hash_threaded(hash_string, algorithm, wordlist, chunk_size=1000):
    if not os.path.exists(wordlist):
        return f"\033[91mWordlist file not found: {wordlist}"

    def process_chunk(chunk):
        for word in chunk:
            hashed_word = hashlib.new(algorithm.lower(), word.encode()).hexdigest()
            if hashed_word == hash_string:
                return word
        return None

    with open(wordlist, 'rb') as f:
        words = [line.decode('utf-8', errors='ignore').strip() for line in f]

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = []
        for i in range(0, len(words), chunk_size):
            chunk = words[i:i+chunk_size]
            futures.append(executor.submit(process_chunk, chunk))

        for future in as_completed(futures):
            result = future.result()
            if result:
                return result

    return "Hash Not Found"

# Function to identify and crack hashes from a file
def identify_and_crack_hashes_in_file(file_path, wordlist, use_threading=False):
    if not os.path.exists(file_path):
        return [f"\033[91mHash file not found: {file_path}"]

    results = []
    with open(file_path, 'r') as file:
        for line in file:
            hash_string = line.strip()
            algorithm = identify_hash_algorithm(hash_string)
            if algorithm == "Unknown":
                results.append(f"\033[93mUnable to identify hash algorithm for: {hash_string}")
            else:
                if use_threading:
                    cracked = crack_hash_threaded(hash_string, algorithm.split('/')[0], wordlist)
                else:
                    cracked = crack_hash(hash_string, algorithm.split('/')[0], wordlist)
                
                if cracked == "Hash Not Found":
                    results.append(f"\033[91m{hash_string} ({algorithm}): {cracked}")
                else:
                    results.append(f"\033[1;32m{hash_string} ({algorithm}): {cracked}")
    return results

# Main function
def main():
    parser = argparse.ArgumentParser(description="Advanced Hash Cracking Tool")
    parser.add_argument("-i", metavar="HASH", type=str, help="Identify hash algorithm")
    parser.add_argument("-d", metavar="HASH", type=str, help="Crack a single hash")
    parser.add_argument("-f", metavar="FILE", type=str, help="Identify and crack hashes stored in a file")
    parser.add_argument("-w", metavar="WORDLIST", type=str, help="Specify the wordlist file for dictionary attack")
    parser.add_argument("-t", action="store_true", help="Use threading for faster cracking (may use more CPU)")
    args = parser.parse_args()

    spinner = Spinner()

    if args.i:
        algorithm = identify_hash_algorithm(args.i)
        if algorithm == "Unknown":
            print("\033[93mUnable to identify hash algorithm")
        elif "/" in algorithm:
            print(f"\033[93mAmbiguous hash type. Could be one of: {algorithm}")
        else:
            print(f"\033[1;32mIdentified hash algorithm: {algorithm}")

    if args.d:
        if not args.w:
            print("\033[91mError: Wordlist (-w) is required when using -d option.")
            return
        algorithm = identify_hash_algorithm(args.d)
        if algorithm == "Unknown":
            print("\033[93mUnable to identify hash algorithm")
        else:
            if "/" in algorithm:
                print(f"\033[93mAmbiguous hash type. Attempting to crack as: {algorithm.split('/')[0]}")
                algorithm = algorithm.split('/')[0]
            else:
                print(f"Attempting to crack {algorithm} hash...")
            spinner.start()
            start_time = time.time()
            result = crack_hash_threaded(args.d, algorithm, args.w) if args.t else crack_hash(args.d, algorithm, args.w)
            end_time = time.time()
            spinner.stop()
            if result == "Hash Not Found":
                print(f"\033[91m{result}")
            else:
                print(f"\033[1;32mHash cracked: {result}")
            print(f"Time taken: {end_time - start_time:.2f} seconds")

    if args.f:
        if not args.w:
            print("\033[91mError: Wordlist (-w) is required when using -f option.")
            return
        print("Processing hashes from file...")
        spinner.start()
        start_time = time.time()
        results = identify_and_crack_hashes_in_file(args.f, args.w, args.t)
        end_time = time.time()
        spinner.stop()
        for result in results:
            print(result)
        print(f"Time taken: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()