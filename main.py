import hashlib
import time
from itertools import product
from multiprocessing import Pool, cpu_count
from typing import Optional


def check_args(args):
    """Top-level worker: args = (candidate_bytes, target_hash_str)"""
    candidate, target_hash = args
    if hash_message_bytes(candidate) == target_hash:
        return candidate
    return None


def hash_message_bytes(message: bytes) -> str:
    return hashlib.sha512(message).hexdigest()


def check_one_password(candidate: bytes, target: str) -> Optional[bytes]:
    if hash_message_bytes(candidate) == target:
        return candidate
    return None


def try_length(length: int, charset: bytes, target_hash: str, cores: int) -> Optional[bytes]:
    if length == 0:
        if hash_message_bytes(b"") == target_hash:
            return b""
        return None

    print(f"  → length {length} ({len(charset)**length:,} candidates) ... ", end="", flush=True)
    start = time.time()

    # Build task list (picklable)
    task_list = [(bytes(tup), target_hash) for tup in product(charset, repeat=length)]

    with Pool(processes=cores) as pool:
        try:
            for result in pool.imap_unordered(check_args, task_list, chunksize=200):
                if result is not None:
                    elapsed = time.time() - start
                    print(f"FOUND in {elapsed:.2f}s")
                    pool.terminate()
                    pool.join()
                    return result
        except:
            pool.terminate()
            pool.join()
            raise

    elapsed = time.time() - start
    print(f"not found ({elapsed:.1f}s)")
    return None

    elapsed = time.time() - start
    print(f"not found ({elapsed:.1f}s)")
    return None


def bruteforce_incremental(
    charset: bytes,
    target_hash: str,
    start_len: int = 1,
    max_len: int = 12,
    cores: Optional[int] = None,
) -> tuple[Optional[bytes], int]:

    if cores is None:
        cores = max(1, cpu_count() - 1)   # leave one core free

    print(f"Charset size: {len(charset)}  |  Using ≈ {cores} cores")
    print(f"Target: {target_hash[:16]}…{target_hash[-8:]}")
    print("-" * 70)

    for length in range(start_len, max_len + 1):
        result = try_length(length, charset, target_hash, cores)
        if result is not None:
            return result, length
        time.sleep(0.3)  # small breathing room between lengths

    print("\nNot found up to length", max_len)
    return None, -1


if __name__ == "__main__":
    # Use small charset for quick testing
    chars = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    # Replace with your real hash
    example_secret = b"passw"
    target = hash_message_bytes(example_secret)

    print("Testing with:", example_secret.decode(), "→", target[:18] + "...")

    found, length = bruteforce_incremental(
        charset=chars,
        target_hash=target,
        start_len=1,
        max_len=8,
        cores=None
    )

    if found:
        print("\n" + "═"*60)
        print(f" PASSWORD FOUND at length {length}")
        print("bytes :", found)
        print("string:", found.decode(errors="replace"))
        print("hash :", hash_message_bytes(found))