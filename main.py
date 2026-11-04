import hashlib
import json

def hash_data(data: str) -> str:
    """Hashes a string using SHA-256."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def build_merkle_tree(leaves: list[str]) -> str:
    """Builds a simple Merkle Tree and returns the Root Hash."""
    if not leaves:
        return hash_data("")
    
    hashes = [hash_data(leaf) for leaf in leaves]
    
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        
        new_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i+1]
            new_level.append(hash_data(combined))
        hashes = new_level
        
    return hashes[0]

if __name__ == "__main__":
    print("Aegis-Audit: Basic Merkle Tree Logic Test")
    test_logs = ["User login", "AI read file.txt", "AI executed rm -rf"]
    root = build_merkle_tree(test_logs)
    print(f"Test Merkle Root: {root}")