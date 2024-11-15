import base64
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def get_public_key_from_certificate(certificate_content):
    # Pastikan format PEM yang benar
    if not certificate_content.startswith("-----BEGIN CERTIFICATE-----"):
        certificate_content = f"-----BEGIN CERTIFICATE-----\n{certificate_content}\n-----END CERTIFICATE-----\n"
    
    # Membaca sertifikat X.509
    certificate = x509.load_pem_x509_certificate(certificate_content.encode('utf-8'))
    print("Sertifikat berhasil dimuat.")
    
    # Ekstrak kunci publik
    public_key = certificate.public_key()
    print("Kunci publik berhasil diekstrak.")
    
    # Konversi kunci publik ke format PEM
    public_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    print("Kunci publik dalam format PEM:")
    print(public_key_pem.decode('utf-8'))
    
    return public_key_pem.decode('utf-8')

def print_public_key_details(public_key_pem):
    public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
    pub_numbers = public_key.public_numbers()
    
    # Cetak detail kunci
    print(f"Jenis Kunci Publik: {type(public_key)}")
    print(f"Ukuran Kunci: {public_key.key_size} bits")
    print(f"Angka Kunci Publik: {pub_numbers}")

def verify_signature(hash_to_verify, signature, public_key_content):
    # Decode the base64 signature
    signature = base64.b64decode(signature)
    print("Signature decoded successfully.")
    
    # Ensure public key content is in proper PEM format
    if not public_key_content.startswith("-----BEGIN PUBLIC KEY-----"):
        public_key_content = f"-----BEGIN PUBLIC KEY-----\n{public_key_content}\n-----END PUBLIC KEY-----\n"
    
    # Load the public key
    public_key = load_pem_public_key(public_key_content.encode('utf-8'))
    print("Public key loaded successfully.")
    
    # Verify the signature using the original data hash
    try:
        # Convert hash_to_verify from base64 to binary if required
        hash_to_verify_binary = base64.b64decode(hash_to_verify)  # Decode if hash is base64
        
        # Verifikasi menggunakan hash binary
        public_key.verify(
            signature,
            hash_to_verify_binary,  # Use binary hash directly
            ec.ECDSA(hashes.SHA256())
        )
        print("Signature verification succeeded.")
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Contoh penggunaan
if __name__ == "__main__":
    invoice_hash = ("HAQHJtkf26inGt3FSEH+a9nsfwym2+E+USHMQsQ7LRQ=")
    x509_certificate = ("MIID3jCCA4SgAwIBAgITEQAAOAPF90Ajs/xcXwABAAA4AzAKBggqhkjOPQQDAjBiMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZFgNnb3YxFzAVBgoJkiaJk/IsZAEZFgdleHRnYXp0MRswGQYDVQQDExJQUlpFSU5WT0lDRVNDQTQtQ0EwHhcNMjQwMTExMDkxOTMwWhcNMjkwMTA5MDkxOTMwWjB1MQswCQYDVQQGEwJTQTEmMCQGA1UEChMdTWF4aW11bSBTcGVlZCBUZWNoIFN1cHBseSBMVEQxFjAUBgNVBAsTDVJpeWFkaCBCcmFuY2gxJjAkBgNVBAMTHVRTVC04ODY0MzExNDUtMzk5OTk5OTk5OTAwMDAzMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEoWCKa0Sa9FIErTOv0uAkC1VIKXxU9nPpx2vlf4yhMejy8c02XJblDq7tPydo8mq0ahOMmNo8gwni7Xt1KT9UeKOCAgcwggIDMIGtBgNVHREEgaUwgaKkgZ8wgZwxOzA5BgNVBAQMMjEtVFNUfDItVFNUfDMtZWQyMmYxZDgtZTZhMi0xMTE4LTliNTgtZDlhOGYxMWU0NDVmMR8wHQYKCZImiZPyLGQBAQwPMzk5OTk5OTk5OTAwMDAzMQ0wCwYDVQQMDAQxMTAwMREwDwYDVQQaDAhSUlJEMjkyOTEaMBgGA1UEDwwRU3VwcGx5IGFjdGl2aXRpZXMwHQYDVR0OBBYEFEX+YvmmtnYoDf9BGbKo7ocTKYK1MB8GA1UdIwQYMBaAFJvKqqLtmqwskIFzVvpP2PxT+9NnMHsGCCsGAQUFBwEBBG8wbTBrBggrBgEFBQcwAoZfaHR0cDovL2FpYTQuemF0Y2EuZ292LnNhL0NlcnRFbnJvbGwvUFJaRUludm9pY2VTQ0E0LmV4dGdhenQuZ292LmxvY2FsX1BSWkVJTlZPSUNFU0NBNC1DQSgxKS5jcnQwDgYDVR0PAQH/BAQDAgeAMDwGCSsGAQQBgjcVBwQvMC0GJSsGAQQBgjcVCIGGqB2E0PsShu2dJIfO+xnTwFVmh/qlZYXZhD4CAWQCARIwHQYDVR0lBBYwFAYIKwYBBQUHAwMGCCsGAQUFBwMCMCcGCSsGAQQBgjcVCgQaMBgwCgYIKwYBBQUHAwMwCgYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIhALE/ichmnWXCUKUbca3yci8oqwaLvFdHVjQrveI9uqAbAiA9hC4M8jgMBADPSzmd2uiPJA6gKR3LE03U75eqbC/rXA==")
    base64_signature = ("MEUCIQD0BivmlaJSr+MhDDEaVtfpDcB6md+0GTXPZRIELIbctgIgQYt277kWx3T5MqHBWQzwyrndHl1ixPFOTs3vr/21gjc=")
    
    public_key = get_public_key_from_certificate(x509_certificate)
    print_public_key_details(public_key)

    is_valid = verify_signature(invoice_hash, base64_signature, public_key)
    print(f"Signature valid: {is_valid}")
