import base64
from OpenSSL import crypto

def get_digital_signature(xml_hashing, private_key_content):
    try:
        hash_bytes = base64.b64decode(xml_hashing)
        if hash_bytes is None:
            raise Exception("Failed to decode the base64-encoded XML hashing.")
        
        private_key_content = private_key_content.replace("\n", "").replace("\t", "")
        if "-----BEGIN EC PRIVATE KEY-----" not in private_key_content and "-----END EC PRIVATE KEY-----" not in private_key_content:
            private_key_content = f"-----BEGIN EC PRIVATE KEY-----\n{private_key_content}\n-----END EC PRIVATE KEY-----"

        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_content)
        if private_key is None:
            raise Exception("Failed to read private key.")
        
        signature = crypto.sign(private_key, hash_bytes, 'sha256')
        return base64.b64encode(signature).decode()
    except Exception as e:
        raise Exception(f"Failed to process signature: {e}")

# Example usage
xml_hashing = "57h8U6238qUEeG99CsVAyhBQsOC49AW08xLA3nm9//c="  # Replace with your base64-encoded XML hashing
private_key_content = "MHQCAQEEICe8m3XKx7SavYsUZRId63p5IKiuoDTZ+4y8t4xqdrDZoAcGBSuBBAAKoUQDQgAE6Pf4gOoP2d3kEy6THelTPElwpDTbIkqjCmVw7T7fwRRzom0KhJ9k+804uCtr6hb/2NTpPzX39SnMUhcVpSciPg==" # Replace with your EC private key content

try:
    signature = get_digital_signature(xml_hashing, private_key_content)
    print("Digital Signature:", signature)
except Exception as e:
    print("Error:", e)
