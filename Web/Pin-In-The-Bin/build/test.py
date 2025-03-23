import string
from hashlib import sha256
import secrets
import time
import math
from concurrent.futures import ThreadPoolExecutor, as_completed

def pow_challenge(length=8):
    """Generate a random PoW challenge string (hex)."""
    return secrets.token_hex(length)

def check_pow(challenge_str, user_solution, difficulty=2):
    """Verify PoW solution by checking the SHA256."""
    
    target = '0' * difficulty
    h = sha256((challenge_str + user_solution).encode()).hexdigest()
    return h.startswith(target)

def _search_chunk(challenge_str, difficulty, charset, chunk_start, chunk_size):
    """
    Worker function: searches [chunk_start, chunk_start + chunk_size)
    within the total search space, converting integer -> candidate string.
    
    Returns the solution string if found, or None otherwise.
    """
    target = '0' * difficulty
    # Precompute boundaries
    space_size = len(charset) ** 8
    chunk_end = min(chunk_start + chunk_size, space_size)

    for idx in range(chunk_start, chunk_end):
        # Convert 'idx' to base-len(charset) => 8-char string
        # We build the string by repeated modulus
        candidate_chars = []
        tmp = idx
        for _ in range(8):
            candidate_chars.append(charset[tmp % len(charset)])
            tmp //= len(charset)
        candidate = ''.join(candidate_chars)

        # Check if the hash meets the difficulty
        h = sha256((challenge_str + candidate).encode()).hexdigest()
        if h.startswith(target):
            return candidate
    return None

def solve_pow(challenge_str, difficulty=2, num_threads=4):
    """
    Solve the PoW for 'challenge_str' by searching the 8-char space
    using 'num_threads' in parallel. Then return the first valid solution
    found.
    
    The search is done in chunk_size blocks to avoid massive overhead
    from enqueuing the entire space at once.
    """
    # We'll search 8-character solutions from:
    #  - total combos = len(charset)^8
    charset = string.ascii_letters + string.digits
    space_size = len(charset) ** 8
    chunk_size = 100_000  # number of candidates per chunk

    start_time = time.perf_counter()
    found_solution = None
    chunk_start = 0

    # We create a ThreadPool for concurrency
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # We'll keep requesting chunks until we either:
        #  - find a valid solution, or
        #  - exhaust the search space
        while chunk_start < space_size and found_solution is None:
            futures = []
            # Submit up to num_threads chunks concurrently
            for _ in range(num_threads):
                if chunk_start >= space_size:
                    break

                future = executor.submit(
                    _search_chunk,
                    challenge_str,
                    difficulty,
                    charset,
                    chunk_start,
                    chunk_size
                )
                futures.append(future)
                chunk_start += chunk_size

            # As each thread finishes, check if it found something
            for f in as_completed(futures):
                result = f.result()
                if result is not None:
                    found_solution = result
                    # Break out of checking other futures
                    break

    if found_solution:
        elapsed = time.perf_counter() - start_time
        print(f"[solve_pow] Found solution in {elapsed:.2f} seconds.")
    else:
        print("[solve_pow] No solution found (very unlikely with difficulty=6).")

    return found_solution

def main():
    """
    - Generate 5 random PoW challenges
    - Solve each challenge (one at a time) using solve_pow
    - Print the solution and the time taken
    """
    import sys
    challenge = sys.argv[1] if len(sys.argv) > 1 else print("No challenge provided")
    print(f"Solving challenge: {challenge}")
    solution = solve_pow(challenge)
    print(f"Solution: {solution}")

if __name__ == "__main__":
    main()
