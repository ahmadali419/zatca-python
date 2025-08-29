#!/usr/bin/env python3
"""
Debug script to see what's happening with the private key.
"""

import json

def debug_private_key():
    """Debug the private key loading issue."""
    
    # Load the private key from certificate info
    with open("Certificates/certificateInfo.json", "r") as f:
        cert_info = json.load(f)
    
    private_key = cert_info["privateKey"]
    
    print("🔍 Debugging private key...")
    print(f"Private key length: {len(private_key)}")
    print(f"Private key: '{private_key}'")
    print(f"Private key type: {type(private_key)}")
    print(f"Private key stripped: '{private_key.strip()}'")
    print(f"Private key stripped length: {len(private_key.strip())}")
    
    # Check if it's empty or whitespace
    if not private_key:
        print("❌ Private key is empty")
    elif not private_key.strip():
        print("❌ Private key is only whitespace")
    else:
        print("✅ Private key has content")

if __name__ == "__main__":
    debug_private_key()
