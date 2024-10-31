import tempfile
import os
import base64
import re
from OpenSSL import crypto

def get_public_key_and_signature(certificate_base64):
    try:
        # Step 1: Create a temporary file for the certificate
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.pem') as temp_file:
            cert_content = "-----BEGIN CERTIFICATE-----\n"
            cert_content += "\n".join([certificate_base64[i:i+64] for i in range(0, len(certificate_base64), 64)])
            cert_content += "\n-----END CERTIFICATE-----\n"
            temp_file.write(cert_content)
            temp_file_path = temp_file.name

        # Step 2: Read the certificate
        with open(temp_file_path, 'r') as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Step 3: Extract the public key
        pub_key = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())

        # Step 4: Parse the public key details
        pub_key_details = crypto.load_publickey(crypto.FILETYPE_ASN1, pub_key)
        pub_key_data = pub_key_details.to_cryptography_key().public_numbers()

        # Step 5: Construct raw public key from x and y components
        x = pub_key_data.x.to_bytes(32, byteorder='big')
        y = pub_key_data.y.to_bytes(32, byteorder='big')

        # Ensure x and y are 32 bytes long for secp256k1
        x = x.rjust(32, b'\0')
        y = y.rjust(32, b'\0')

        # Prepare the raw public key in uncompressed DER format
        public_key_der = b'\x30\x56\x30\x10\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x05\x2B\x81\x04\x00\x0A\x03\x42\x00\x04' + x + y

        # Step 6: Extract the ECDSA signature from DER data
        cert_pem = open(temp_file_path, 'r').read()
        matches = re.search(r'-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----', cert_pem, re.DOTALL)

        if not matches:
            raise Exception("Error extracting DER data from certificate.")

        der_data = base64.b64decode(matches.group(1).replace('\n', ''))
        sequence_pos = der_data.rfind(b'\x30', -72)
        signature = der_data[sequence_pos:]

        # Return the correctly extracted details
        return {
            'public_key': public_key_der,  # Raw public key in DER format
            'signature': signature  # Raw ECDSA signature bytes
        }
    except Exception as e:
        raise Exception("[Error] Failed to process certificate: " + str(e))
    finally:
        # Clean up resources
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def format_hex(data):
    hex_str = data.hex()
    return ':'.join(a + b for a, b in zip(hex_str[::2], hex_str[1::2]))

# Example certificate_base64 for testing
certificate_base64 = "MIID3jCCA4SgAwIBAgITEQAAOAPF90Ajs/xcXwABAAA4AzAKBggqhkjOPQQDAjBiMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZFgNnb3YxFzAVBgoJkiaJk/IsZAEZFgdleHRnYXp0MRswGQYDVQQDExJQUlpFSU5WT0lDRVNDQTQtQ0EwHhcNMjQwMTExMDkxOTMwWhcNMjkwMTA5MDkxOTMwWjB1MQswCQYDVQQGEwJTQTEmMCQGA1UEChMdTWF4aW11bSBTcGVlZCBUZWNoIFN1cHBseSBMVEQxFjAUBgNVBAsTDVJpeWFkaCBCcmFuY2gxJjAkBgNVBAMTHVRTVC04ODY0MzExNDUtMzk5OTk5OTk5OTAwMDAzMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEoWCKa0Sa9FIErTOv0uAkC1VIKXxU9nPpx2vlf4yhMejy8c02XJblDq7tPydo8mq0ahOMmNo8gwni7Xt1KT9UeKOCAgcwggIDMIGtBgNVHREEgaUwgaKkgZ8wgZwxOzA5BgNVBAQMMjEtVFNUfDItVFNUfDMtZWQyMmYxZDgtZTZhMi0xMTE4LTliNTgtZDlhOGYxMWU0NDVmMR8wHQYKCZImiZPyLGQBAQwPMzk5OTk5OTk5OTAwMDAzMQ0wCwYDVQQMDAQxMTAwMREwDwYDVQQaDAhSUlJEMjkyOTEaMBgGA1UEDwwRU3VwcGx5IGFjdGl2aXRpZXMwHQYDVR0OBBYEFEX+YvmmtnYoDf9BGbKo7ocTKYK1MB8GA1UdIwQYMBaAFJvKqqLtmqwskIFzVvpP2PxT+9NnMHsGCCsGAQUFBwEBBG8wbTBrBggrBgEFBQcwAoZfaHR0cDovL2FpYTQuemF0Y2EuZ292LnNhL0NlcnRFbnJvbGwvUFJaRUludm9pY2VTQ0E0LmV4dGdhenQuZ292LmxvY2FsX1BSWkVJTlZPSUNFU0NBNC1DQSgxKS5jcnQwDgYDVR0PAQH/BAQDAgeAMDwGCSsGAQQBgjcVBwQvMC0GJSsGAQQBgjcVCIGGqB2E0PsShu2dJIfO+xnTwFVmh/qlZYXZhD4CAWQCARIwHQYDVR0lBBYwFAYIKwYBBQUHAwMGCCsGAQUFBwMCMCcGCSsGAQQBgjcVCgQaMBgwCgYIKwYBBQUHAwMwCgYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIhALE/ichmnWXCUKUbca3yci8oqwaLvFdHVjQrveI9uqAbAiA9hC4M8jgMBADPSzmd2uiPJA6gKR3LE03U75eqbC/rXA=="

result = get_public_key_and_signature(certificate_base64)
print("public_key")
print(format_hex(result['public_key']))
print("signature")
print(format_hex(result['signature']))
