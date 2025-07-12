import hashlib
import itertools
import bcrypt
import sys # Import sys for potential exit

def generate_hash(password, algorithm='sha256'):
    """Generates a hash for a given password using the specified algorithm (MD5, SHA1, SHA256, SHA512)."""
    try:
        if algorithm.lower() == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif algorithm.lower() == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif algorithm.lower() == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif algorithm.lower() == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        else:
            # This case should ideally be caught by the main function's input validation
            print(f"Error: Unsupported hashing algorithm '{algorithm}' for direct hash generation.")
            return None
    except Exception as e:
        print(f"Error generating hash: {e}")
        return None

def generate_bcrypt_hash(password):
    """Generates a bcrypt hash for a given password (for testing/setup)."""
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8') # Return as string for display/storage
    except Exception as e:
        print(f"Error generating bcrypt hash: {e}")
        return None

def check_bcrypt_password(password, hashed_password_bytes):
    """Checks if a given cleartext password matches a bcrypt hash.
    hashed_password_bytes must be bytes (e.g., b'$2b$12$...')
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password_bytes)
    except Exception as e:
        # This catch is mostly for malformed hashes or unexpected errors,
        # bcrypt.checkpw returns False if passwords don't match, without raising an exception.
        print(f"Error during bcrypt check: {e}")
        return False

def dictionary_attack(target_hash, hash_algo, dictionary_path="rockyou.txt"):
    """Attempts to crack a hash using a dictionary attack."""
    print(f"\n[+] Starting dictionary attack for {target_hash} using {hash_algo.upper()}...")

    target_hash_bytes = None
    if hash_algo.lower() == 'bcrypt':
        try:
            target_hash_bytes = target_hash.encode('utf-8')
            # Basic validation for bcrypt hash format (starts with $2a$, $2b$, or $2y$)
            if not (target_hash_bytes.startswith(b'$2a$') or
                    target_hash_bytes.startswith(b'$2b$') or
                    target_hash_bytes.startswith(b'$2y$')):
                print("Error: Target bcrypt hash format seems incorrect. It should start with $2a$, $2b$, or $2y$.")
                return None
        except Exception as e:
            print(f"Error preparing target bcrypt hash: {e}")
            return None

    try:
        # Use 'latin-1' or 'utf-8' with error handling, as dictionary files can have varied encodings
        with open(dictionary_path, 'r', encoding='latin-1', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                word = line.strip()
                if not word:
                    continue # Skip empty lines

                if hash_algo.lower() == 'bcrypt':
                    if target_hash_bytes is None: # Exit if bcrypt hash was invalid
                        return None
                    if check_bcrypt_password(word, target_hash_bytes):
                        print(f"[*] Password found via dictionary attack: '{word}' (Hash: {target_hash})")
                        return word
                else: # For MD5, SHA1, SHA256, SHA512
                    hashed_word = generate_hash(word, hash_algo)
                    if hashed_word and hashed_word == target_hash:
                        print(f"[*] Password found via dictionary attack: '{word}' (Hash: {hashed_word})")
                        return word

                # Optional: Print progress for large dictionaries (uncomment to enable)
                # if line_num % 100000 == 0:
                #     print(f"  [-] Tested {line_num} words...")

        print("[-] Password not found in dictionary.")
        return None
    except FileNotFoundError:
        print(f"Error: Dictionary file not found at '{dictionary_path}'. Please ensure it exists.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during dictionary attack: {e}")
        return None

def brute_force_attack(target_hash, hash_algo, charset, max_length):
    """Attempts to crack a hash using a brute-force attack."""
    print(f"\n[+] Starting brute-force attack for {target_hash} using {hash_algo.upper()}...")

    target_hash_bytes = None
    if hash_algo.lower() == 'bcrypt':
        try:
            target_hash_bytes = target_hash.encode('utf-8')
            # Basic validation for bcrypt hash format
            if not (target_hash_bytes.startswith(b'$2a$') or
                    target_hash_bytes.startswith(b'$2b$') or
                    target_hash_bytes.startswith(b'$2y$')):
                print("Error: Target bcrypt hash format seems incorrect. It should start with $2a$, $2b$, or $2y$.")
                return None
        except Exception as e:
            print(f"Error preparing target bcrypt hash: {e}")
            return None

    for length in range(1, max_length + 1):
        print(f"  [-] Trying passwords of length {length}...")
        for attempt_tuple in itertools.product(charset, repeat=length):
            word = "".join(attempt_tuple)

            if hash_algo.lower() == 'bcrypt':
                if target_hash_bytes is None: # Exit if bcrypt hash was invalid
                    return None
                if check_bcrypt_password(word, target_hash_bytes):
                    print(f"[*] Password found via brute-force: '{word}' (Hash: {target_hash})")
                    return word
            else: # For MD5, SHA1, SHA256, SHA512
                hashed_word = generate_hash(word, hash_algo)
                if hashed_word and hashed_word == target_hash:
                    print(f"[*] Password found via brute-force: '{word}' (Hash: {hashed_word})")
                    return word
    print(f"[-] Password not found via brute-force within max length {max_length}.")
    return None

def main():
    print("--- Hashed Password Cracker ---")

    # Offer to generate or crack
    action_choice = input("Do you want to (1) crack a hash or (2) generate a hash for testing? (1/2): ").strip()

    if action_choice == '2':
        # --- GENERATE HASH MODE ---
        test_password = input("Enter password to generate hash for: ")
        
        print("\nAvailable Hashing Algorithms for Generation: MD5, SHA1, SHA256, SHA512, BCRYPT")
        generate_algo = input("Enter the hashing algorithm for generation (e.g., sha256 or bcrypt): ").strip().lower()

        generated_hash = None
        if generate_algo == 'md5':
            generated_hash = generate_hash(test_password, 'md5')
        elif generate_algo == 'sha1':
            generated_hash = generate_hash(test_password, 'sha1')
        elif generate_algo == 'sha256':
            generated_hash = generate_hash(test_password, 'sha256')
        elif generate_algo == 'sha512':
            generated_hash = generate_hash(test_password, 'sha512')
        elif generate_algo == 'bcrypt':
            generated_hash = generate_bcrypt_hash(test_password)
        else:
            print("Invalid or unsupported hashing algorithm for generation. Please choose from MD5, SHA1, SHA256, SHA512, BCRYPT.")
        
        if generated_hash:
            print(f"Generated {generate_algo.upper()} hash for '{test_password}': {generated_hash}")
        
        # We return here, as the user chose to only generate a hash
        return # Use return to terminate the script cleanly after generation

    elif action_choice != '1':
        print("Invalid choice. Exiting.")
        sys.exit() # Use sys.exit() for a clean exit

    # --- CRACK HASH MODE (Existing Logic) ---
    target_hash = input("Enter the hashed password to crack: ").strip() # Removed .lower() here to preserve bcrypt case
    if not target_hash:
        print("Target hash cannot be empty. Exiting.")
        sys.exit()

    print("\nAvailable Hashing Algorithms for Cracking: MD5, SHA1, SHA256, SHA512, BCRYPT") # Clarified prompt
    hash_algo = input("Enter the hashing algorithm (e.g., sha256 or bcrypt): ").strip().lower()
    if hash_algo not in ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt']:
        print("Invalid or unsupported hashing algorithm. Exiting.")
        sys.exit()

    print("\nChoose attack type:")
    print("1. Dictionary Attack")
    print("2. Brute-Force Attack")
    attack_choice = input("Enter your choice (1 or 2): ").strip()

    if attack_choice == '1':
        dictionary_path = input("Enter path to dictionary file (default: rockyou.txt): ").strip()
        if not dictionary_path:
            dictionary_path = "rockyou.txt"
        dictionary_attack(target_hash, hash_algo, dictionary_path)
    elif attack_choice == '2':
        charset_input = input("Enter character set for brute-force (e.g., abcdefghijklmnopqrstuvwxyz0123456789!@#$): ").strip()
        if not charset_input:
            print("Character set cannot be empty. Exiting.")
            sys.exit()
        try:
            max_length = int(input("Enter maximum password length for brute-force: ").strip())
            if max_length <= 0:
                raise ValueError
        except ValueError:
            print("Maximum length must be a positive integer. Exiting.")
            sys.exit()
        brute_force_attack(target_hash, hash_algo, charset_input, max_length)
    else:
        print("Invalid attack choice. Exiting.")
        sys.exit()

if __name__ == "__main__":
    main()