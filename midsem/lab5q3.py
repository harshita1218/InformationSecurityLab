import hashlib
import random
import string
import time

def generate_random_string(length):
    """Generate a random string of fixed length."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def compute_md5(data):
    """Compute MD5 hash of the given data."""
    return hashlib.md5(data.encode()).hexdigest()

def compute_sha1(data):
    """Compute SHA-1 hash of the given data."""
    return hashlib.sha1(data.encode()).hexdigest()

def compute_sha256(data):
    """Compute SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode()).hexdigest()

def measure_hash_time(hash_func, data):
    """Measure time taken to compute the hash."""
    start_time = time.time()
    hash_value = hash_func(data)
    end_time = time.time()
    return hash_value, end_time - start_time

def detect_collisions(hashes):
    """Detect any collisions in the hash dataset."""
    collisions = {}
    for hash_value in hashes:
        if hash_value in collisions:
            collisions[hash_value] += 1
        else:
            collisions[hash_value] = 1
    return {k: v for k, v in collisions.items() if v > 1}

def main():
    num_strings = 100
    strings = [generate_random_string(random.randint(10, 20)) for _ in range(num_strings)]

    md5_hashes = []
    sha1_hashes = []
    sha256_hashes = []

    # Compute hashes and measure time
    for s in strings:
        md5_hash, md5_time = measure_hash_time(compute_md5, s)
        sha1_hash, sha1_time = measure_hash_time(compute_sha1, s)
        sha256_hash, sha256_time = measure_hash_time(compute_sha256, s)

        md5_hashes.append(md5_hash)
        sha1_hashes.append(sha1_hash)
        sha256_hashes.append(sha256_hash)

        print(f"String: {s}")
        print(f"MD5: {md5_hash}, Time: {md5_time:.6f} seconds")
        print(f"SHA-1: {sha1_hash}, Time: {sha1_time:.6f} seconds")
        print(f"SHA-256: {sha256_hash}, Time: {sha256_time:.6f} seconds")
        print("-" * 50)

    # Detect collisions
    md5_collisions = detect_collisions(md5_hashes)
    sha1_collisions = detect_collisions(sha1_hashes)
    sha256_collisions = detect_collisions(sha256_hashes)

    # Output collision results
    print("\nCollision Detection Results:")
    print(f"MD5 Collisions: {md5_collisions}")
    print(f"SHA-1 Collisions: {sha1_collisions}")
    print(f"SHA-256 Collisions: {sha256_collisions}")

if __name__ == "__main__":
    main()
