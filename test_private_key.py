#!/usr/bin/env python3
"""
Test script to verify the new private key works correctly with ZATCA requirements.
"""

from utilities.einvoice_signer import einvoice_signer
import json

def test_private_key():
    """Test if the new private key can be loaded correctly."""
    
    # Load the private key from certificate info
    with open("Certificates/certificateInfo.json", "r") as f:
        cert_info = json.load(f)
    
    private_key = cert_info["privateKey"]
    
    print("🔍 Testing private key compatibility with ZATCA...")
    print(f"Private key: {private_key[:50]}...")
    print()
    
    try:
        # Try to load the private key using the same function that was failing
        key = einvoice_signer._load_ec_private_key_any_format(private_key)
        
        print("✅ SUCCESS: Private key loaded successfully!")
        print(f"   Curve: {key.curve.name}")
        print(f"   Key size: {key.key_size} bits")
        
        if isinstance(key.curve, einvoice_signer.ec.SECP256R1):
            print("✅ SUCCESS: Private key uses the correct secp256r1 curve (P-256)")
        else:
            print("❌ ERROR: Private key does not use the correct curve")
            return False
            
        # Test signing a simple message
        test_message = b"test message"
        signature = key.sign(test_message, einvoice_signer.ec.ECDSA(einvoice_signer.hashes.SHA256()))
        print("✅ SUCCESS: Private key can sign messages")
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR: Failed to load private key: {e}")
        return False

if __name__ == "__main__":
    success = test_private_key()
    
    if success:
        print("\n🎉 All tests passed! The private key is now compatible with ZATCA.")
        print("\n⚠️  IMPORTANT: You still need to:")
        print("1. Generate a new CSR with this private key")
        print("2. Re-onboard with ZATCA using the new CSR")
        print("3. Update the certificate info with the new certificate from ZATCA")
    else:
        print("\n❌ Tests failed. Please check the error messages above.")
