import hashlib
import os
import json

# File to store hashes
HASH_FILE = "file_hashes.json"

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None

def load_hashes():
    """Load saved hashes from a JSON file."""
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    """Save hashes to a JSON file."""
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=4)

def check_integrity(directory):
    """Check for changes in files by comparing hash values."""
    stored_hashes = load_hashes()
    current_hashes = {}

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path)
            if file_hash:
                current_hashes[file_path] = file_hash
                if file_path in stored_hashes:
                    if stored_hashes[file_path] != file_hash:
                        print(f"[WARNING] File changed: {file_path}")
                else:
                    print(f"[NEW] New file detected: {file_path}")

    # Check for deleted files
    for file_path in stored_hashes:
        if file_path not in current_hashes:
            print(f"[DELETED] File missing: {file_path}")

    save_hashes(current_hashes)
    print("[INFO] Integrity check completed.")

def main():
    directory = input("Enter the directory to monitor: ").strip()
    if not os.path.exists(directory):
        print("[ERROR] Directory does not exist!")
        return
    check_integrity(directory)

if __name__ == "__main__":
    main()
