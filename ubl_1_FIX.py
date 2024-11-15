import hashlib
import base64

def get_signed_properties_hash(signing_time, digest_value, x509_issuer_name, x509_serial_number):
    # Construct the XML string with exactly 36 spaces in front of <xades:SignedSignatureProperties>
    xml_string = (
        '<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">\n'
        '                                    <xades:SignedSignatureProperties>\n'
        '                                        <xades:SigningTime>{}</xades:SigningTime>\n'.format(signing_time) +
        '                                        <xades:SigningCertificate>\n'
        '                                            <xades:Cert>\n'
        '                                                <xades:CertDigest>\n'
        '                                                    <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>\n'
        '                                                    <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{}</ds:DigestValue>\n'.format(digest_value) +
        '                                                </xades:CertDigest>\n'
        '                                                <xades:IssuerSerial>\n'
        '                                                    <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{}</ds:X509IssuerName>\n'.format(x509_issuer_name) +
        '                                                    <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{}</ds:X509SerialNumber>\n'.format(x509_serial_number) +
        '                                                </xades:IssuerSerial>\n'
        '                                            </xades:Cert>\n'
        '                                        </xades:SigningCertificate>\n'
        '                                    </xades:SignedSignatureProperties>\n'
        '                                </xades:SignedProperties>'
    )

    # Clean up the XML string (normalize newlines and trim extra spaces)
    xml_string = xml_string.replace("\r\n", "\n").strip()

    # Generate the SHA256 hash of the XML string in binary format
    hash_bytes = hashlib.sha256(xml_string.encode('utf-8')).digest()

    # Convert the hash to hex and then base64 encode the result
    hash_hex = hash_bytes.hex()
    return base64.b64encode(hash_hex.encode('utf-8')).decode('utf-8')

# Test inputs
signing_time = "2024-01-17T19:06:11"
digest_value = "ZDMwMmI0MTE1NzVjOTU2NTk4YzVlODhhYmI0ODU2NDUyNTU2YTVhYjhhMDFmN2FjYjk1YTA2OWQ0NjY2MjQ4NQ=="
x509_issuer_name = "CN=PRZEINVOICESCA4-CA, DC=extgazt, DC=gov, DC=local"
x509_serial_number = "379112742831380471835263969587287663520528387"

# Calculate and print the Signed Properties Hash
signed_properties_hash = get_signed_properties_hash(signing_time, digest_value, x509_issuer_name, x509_serial_number)
print("Signed Properties Hash:", signed_properties_hash)
