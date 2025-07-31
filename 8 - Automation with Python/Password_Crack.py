import hashlib
import itertools
import string
import time

def hash_password(password: str) -> str:
    # Hash a password using SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

def brute_force_crack(hashed_password: str, max_length: int) -> str:
    chars = string.ascii_lowercase + string.digits
    for length in range(1, max_length + 1):
        for guess in itertools.product(chars, repeat=length):
            guess_password = ''.join(guess)
            if hash_password(guess_password) == hashed_password:
                return guess_password
    return None

def main():
    # Define the target password and hash it
    target_password = "abc123"  # You can change this to any short password
    hashed_password = hash_password(target_password)
    
    # Print the hashed password
    print(f"Hashed password: {hashed_password}")
    
    # Start the brute-force attack
    max_length = 6  # Limit the scope to short passwords
    start_time = time.time()
    cracked_password = brute_force_crack(hashed_password, max_length)
    end_time = time.time()
    
    # Display results
    if cracked_password:
        print(f"Password found: {cracked_password}")
    else:
        print("Password not found within the given length limit.")
    
    print(f"Time taken: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
