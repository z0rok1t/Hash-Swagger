#!/usr/bin/python3

import argparse
import hashlib
import re
import pyfiglet 
import sys
import time

ascii_banner = pyfiglet.figlet_format("Hash Swagger")
print(ascii_banner)

print("Algorithms Available: MD5 | SHA1 | SHA256 | SHA384 | SHA512 \n")

def identify_hash_algorithm(hash_string):
    
    # Dictionary mapping hash regex patterns to hash algorithm
    hash_patterns = {
        r"^[a-f0-9]{32}$": "MD5",
        r"^[a-f0-9]{40}$": "SHA1",
        r"^[a-f0-9]{64}$": "SHA256",
        r"^[a-f0-9]{96}$": "SHA384",
        r"^[a-f0-9]{128}$": "SHA512"
    }

    # Check if the hash string matches known hash patterns
    for pattern, algorithm in hash_patterns.items():
        if re.match(pattern, hash_string):
            return algorithm

    # If the hash string does not match any known patterns, return "Unknown"
    return "Unknown"

def crack_hash(hash_string, algorithm, wordlist=None):
    
    if wordlist is None:
        return "Wordlist not specified"

    # Open the wordlist file and read each line
    with open(wordlist, 'rb') as f:
        for line_bytes in f:
            try:
                line = line_bytes.decode('utf-8').strip()
            except UnicodeDecodeError:
                continue

            word = line.strip()
            hashed_word = hashlib.new(algorithm, word.encode()).hexdigest()

            # Compare the hashed word with the provided hash
            if hashed_word == hash_string:
                return word  # Return the cracked plaintext
                    
    # If no match is found in the wordlist, return "Not cracked"
    return "Hash Not Found"

def identify_and_crack_hashes_in_file(file_path, hash_string):
    
    # Identify the hash algorithm of the provided hash string
    algorithm = identify_hash_algorithm(hash_string)
    if algorithm == "Unknown":
        return "Unable to identify hash algorithm"

    # Attempt to crack the hash using the identified algorithm and provided wordlist file
    return crack_hash(hash_string, algorithm, file_path)

# def spinner_animation():
#     while ongoing:
#         for char in '|/-\\+':
#             sys.stdout.write('\r' + char)
#             sys.stdout.flush()
#             time.sleep(0.1)
# # Call the spinning_bar function to show the animation
# spinner_animation()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hash cracking tool")
    parser.add_argument("-i", metavar="HASH", type=str, help="Identify hash algorithm")
    parser.add_argument("-d", metavar="HASH", type=str, help="Crack a single hash")
    parser.add_argument("-f", metavar="FILE", type=str, help="Identify and crack hashes stored in a file")
    parser.add_argument("-w", metavar="WORDLIST", type=str, help="Specify the wordlist file for dictionary attack")

    args = parser.parse_args()

    if args.i:
        if identify_hash_algorithm(args.i) == "Unknown":
            print(f"\033[91m Identified hash algorithm:", identify_hash_algorithm(args.i))
        else:
            print(f"\033[1;32m Identified hash algorithm:", identify_hash_algorithm(args.i))

    if args.d:
        algorithm = identify_hash_algorithm(args.d)
        if algorithm == "Unknown":
            print("Unable to identify hash algorithm")
        else:
            result = crack_hash(args.d, algorithm, args.w)
            if result == "Hash Not Found":
                print(f"\033[91m", result)
            else:
                print(f"\033[1;32m Hash:", result)

    if args.f:
        with open(args.f, 'r') as file:
            for line in file:
                hash_string = line.strip()
                result = identify_and_crack_hashes_in_file(args.f, hash_string)
                print(f"\033[1;32m Hashes:", result)
