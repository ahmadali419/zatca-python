import base64
import hashlib
import json
import os
import re
import tempfile
from lxml import etree
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
from utilities.qr_code_generator import qr_code_generator

class einvoice_signer:
    
    @staticmethod
    def get_request_api_from_file(xml_file_path, x509_certificate_content, private_key_content):
        # Open XML document with preserveWhiteSpace = true
        parser = etree.XMLParser(remove_blank_text=False)
        xml = etree.parse(xml_file_path, parser)
        return einvoice_signer.get_request_api(xml, x509_certificate_content, private_key_content)

    @staticmethod
    def get_request_api(xml, x509_certificate_content, private_key_content):
        # Resource files
        xsl_file_path = 'resources/xslfile.xsl'
        ubl_template_path = 'resources/zatca_ubl.xml'
        signature_path = 'resources/zatca_signature.xml'
        xml_declaration = '<?xml version="1.0" encoding="utf-8"?>'

        # Get UUID from element <cbc:UUID>
        uuid_nodes = xml.xpath('//cbc:UUID', namespaces={'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
        if len(uuid_nodes) == 0:
            raise Exception("UUID not found in the XML document.")
        uuid = uuid_nodes[0].text

        # Check if it is a simplified invoice
        is_simplified_invoice = False
        invoice_type_code_nodes = xml.xpath('//cbc:InvoiceTypeCode', namespaces={'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
        if len(invoice_type_code_nodes) > 0:
            name_attribute = invoice_type_code_nodes[0].get('name')
            is_simplified_invoice = name_attribute.startswith("02")

        # Apply XSL transform
        xsl = etree.parse(xsl_file_path)
        transform = etree.XSLT(xsl)
        transformed_xml = transform(xml)
        if transformed_xml is None:
            raise Exception("XSL Transformation failed.")

        # Canonicalize (C14N) transformed document
        canonical_xml = etree.tostring(transformed_xml, method='c14n').decode()

        #print(canonical_xml)
        # Get byte hash256 from transformed document
        hash = hashlib.sha256(canonical_xml.encode('utf-8')).digest()
       
        # Encode hash to Base64
        base64_hash = base64.b64encode(hash).decode()
        #print(base64_hash)
        # Encode canonicalized XML to Base64
        updated_xml = xml_declaration + "\n" + canonical_xml
        encoded_bytes = base64.b64encode(updated_xml.encode('utf-8'))
        base64_invoice = encoded_bytes.decode('utf-8')

        #base64_invoice = base64.b64encode((xml_declaration + "\n" + canonical_xml).encode('utf-8').strip()).decode()

        # Return early for non-simplified invoices
        if not is_simplified_invoice:
            result = {
                "invoiceHash": base64_hash,
                "uuid": uuid,
                "invoice": base64_invoice
            }
            return json.dumps(result)

        # Sign the simplified invoice
        return einvoice_signer.sign_simplified_invoice(canonical_xml, base64_hash, x509_certificate_content, private_key_content, ubl_template_path, signature_path, uuid)

    
    @staticmethod
    def sign_simplified_invoice(canonical_xml, base64_hash, x509_certificate_content, private_key_content, ubl_template_path, signature_path, uuid):
        xml_declaration = f'<?xml version="1.0" encoding="utf-8"?>'
        # Signing Simplified Invoice Document
        signature_timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        
        # Wrap the certificate content with PEM headers and footers
        pem_certificate = "-----BEGIN CERTIFICATE-----\n" + \
                          "\n".join([x509_certificate_content[i:i+64] for i in range(0, len(x509_certificate_content), 64)]) + \
                          "\n-----END CERTIFICATE-----"


        #print(f"Type of x509_certificate_content: {type(x509_certificate_content)}")

        #print(f"Content of x509_certificate_content ==: {x509_certificate_content}")  # Print first 100 characters for a quick check

        # Decode the X.509 certificate
        #certificate_bytes = base64.b64decode(x509_certificate_content)

        # Generate public key hashing from the decoded certificate
        #hash_bytes = hashlib.sha256(certificate_bytes).digest()

        #print(f"Content of hash_bytes: {hash_bytes}")
        
        #public_key_hashing = base64.b64encode(hash_bytes).decode()

        #print(f"Content of public_key_hashing: {public_key_hashing}")

        # Decode sertifikat dari base64
        #certificate_bytes = base64.b64decode(x509_certificate_content)

        # Generate public key hashing
        hash_bytes = hashlib.sha256(x509_certificate_content.encode('utf-8')).digest()
        hash_hex = hash_bytes.hex()
        public_key_hashing = base64.b64encode(hash_hex.encode('utf-8')).decode(('utf-8'))
        print(f"Content of public_key_hashing: {public_key_hashing}")

        # Parse the X.509 certificate
        certificate = x509.load_pem_x509_certificate(pem_certificate.encode(), default_backend())

        # Extract certificate information
        issuer_name = einvoice_signer.get_issuer_name(certificate)
        serial_number = einvoice_signer.get_serial_number(certificate)
        signed_properties_hash = einvoice_signer.get_signed_properties_hash(signature_timestamp, public_key_hashing, issuer_name, serial_number)
        signature_value = einvoice_signer.get_digital_signature(base64_hash, private_key_content)

        ecdsa_result = einvoice_signer.get_public_key_and_signature(x509_certificate_content)
        #qr_tag8 = ecdsa_result['public_key']
        #qr_tag9 = ecdsa_result['signature']

        # Populate UBLExtension Template
        with open(ubl_template_path, 'r') as ubl_file:
            ubl_content = ubl_file.read()
            ubl_content = ubl_content.replace("INVOICE_HASH", base64_hash)
            ubl_content = ubl_content.replace("SIGNED_PROPERTIES", signed_properties_hash)
            ubl_content = ubl_content.replace("SIGNATURE_VALUE", signature_value)
            ubl_content = ubl_content.replace("CERTIFICATE_CONTENT", x509_certificate_content)
            ubl_content = ubl_content.replace("SIGNATURE_TIMESTAMP", signature_timestamp)
            ubl_content = ubl_content.replace("PUBLICKEY_HASHING", public_key_hashing)
            ubl_content = ubl_content.replace("ISSUER_NAME", issuer_name)
            ubl_content = ubl_content.replace("SERIAL_NUMBER", str(serial_number))

        #print(ubl_content)

        # Insert UBL into XML
        insert_position = canonical_xml.find('>') + 1  # Find position after the first '>'
        updated_xml_string = canonical_xml[:insert_position] + ubl_content + canonical_xml[insert_position:]

        # Generate QR Code (Assuming qr_code_generator is defined elsewhere)
        qr_code = qr_code_generator.generate_qr_code(canonical_xml, base64_hash, signature_value, ecdsa_result)

        # Load signature template content
        with open(signature_path, 'r') as signature_file:
            signature_content = signature_file.read()
            signature_content = signature_content.replace("BASE64_QRCODE", qr_code)

        # Insert signature string before <cac:AccountingSupplierParty>
        insert_position_signature = updated_xml_string.find('<cac:AccountingSupplierParty>')
        if insert_position_signature != -1:
            updated_xml_string = updated_xml_string[:insert_position_signature] + signature_content + updated_xml_string[insert_position_signature:]
        else:
            raise Exception("The <cac:AccountingSupplierParty> tag was not found in the XML.")

        updated_xml = xml_declaration + "\n" + updated_xml_string
        encoded_bytes = base64.b64encode(updated_xml.encode('utf-8'))
        base64_invoice = encoded_bytes.decode('utf-8')

        #base64_invoice = base64.b64encode((xml_declaration + updated_xml_string).encode('utf-8').strip()).decode()

        #decoded_xml = base64.b64decode(base64_invoice.encode('utf-8')).decode('utf-8')
        
        #print(decoded_xml)

        # Generate Array Result
        result = {
            "invoiceHash": base64_hash,
            "uuid": uuid,
            "invoice": base64_invoice,
        }

        # Convert Array to JSON string
        return json.dumps(result)

    @staticmethod
    def get_issuer_name(certificate):
        issuer = certificate.issuer
        issuer_name_parts = []

        # Convert issuer to a dictionary-like structure
        issuer_dict = {}
        for attr in issuer:
            key = attr.oid._name
            if key in issuer_dict:
                if isinstance(issuer_dict[key], list):
                    issuer_dict[key].append(attr.value)
                else:
                    issuer_dict[key] = [issuer_dict[key], attr.value]
            else:
                issuer_dict[key] = attr.value

        # Debug: Print the issuer_dict to see all key-value pairs
        # print("Issuer Dictionary:", issuer_dict)

        # Check for 'CN' and add to the issuer name parts
        if 'commonName' in issuer_dict:
            issuer_name_parts.append(f"CN={issuer_dict['commonName']}")

        # Check for 'DC' (Domain Component) if it exists
        if 'domainComponent' in issuer_dict:
            dc_list = issuer_dict['domainComponent']
            if isinstance(dc_list, list):
                # Reverse the DC list to get them in the required order
                dc_list.reverse()
                for dc in dc_list:
                    if dc:  # Check if the DC is not empty
                        issuer_name_parts.append(f"DC={dc}")
            #else:
                #issuer_name_parts.append(f"DC={dc_list}")

        # Join the parts with a comma and return
        return ", ".join(issuer_name_parts)

    @staticmethod
    def get_serial_number(certificate):
        return certificate.serial_number

    @staticmethod
    def get_signed_properties_hash(signing_time, digest_value, x509_issuer_name, x509_serial_number):
    # Construct the XML string with exact formatting
        xml_string = (
            '<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">\n'
            '                                    <xades:SignedSignatureProperties>\n'
            '                                        <xades:SigningTime>{}</xades:SigningTime>\n'
            '                                        <xades:SigningCertificate>\n'
            '                                            <xades:Cert>\n'
            '                                                <xades:CertDigest>\n'
            '                                                    <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>\n'
            '                                                    <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{}</ds:DigestValue>\n'
            '                                                </xades:CertDigest>\n'
            '                                                <xades:IssuerSerial>\n'
            '                                                    <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{}</ds:X509IssuerName>\n'
            '                                                    <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{}</ds:X509SerialNumber>\n'
            '                                                </xades:IssuerSerial>\n'
            '                                            </xades:Cert>\n'
            '                                        </xades:SigningCertificate>\n'
            '                                    </xades:SignedSignatureProperties>\n'
            '</xades:SignedProperties>'
        ).format(signing_time, digest_value, x509_issuer_name, x509_serial_number)

        # Compute the SHA-256 hash
        hash_bytes = hashlib.sha256(xml_string.encode()).digest()
    
        # Return the Base64 encoded hash
        return base64.b64encode(hash_bytes).decode()


    @staticmethod
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
        
    @staticmethod
    def get_public_key_and_signature(certificate_base64):
        try:
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.pem') as temp_file:
                cert_content = "-----BEGIN CERTIFICATE-----\n"
                cert_content += "\n".join([certificate_base64[i:i+64] for i in range(0, len(certificate_base64), 64)])
                cert_content += "\n-----END CERTIFICATE-----\n"
                temp_file.write(cert_content)
                temp_file_path = temp_file.name

            with open(temp_file_path, 'r') as f:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

            pub_key = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())
            pub_key_details = crypto.load_publickey(crypto.FILETYPE_ASN1, pub_key).to_cryptography_key().public_numbers()

            x = pub_key_details.x.to_bytes(32, byteorder='big').rjust(32, b'\0')
            y = pub_key_details.y.to_bytes(32, byteorder='big').rjust(32, b'\0')

            public_key_der = b'\x30\x56\x30\x10\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x05\x2B\x81\x04\x00\x0A\x03\x42\x00\x04' + x + y

            cert_pem = open(temp_file_path, 'r').read()
            matches = re.search(r'-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----', cert_pem, re.DOTALL)
            if not matches:
                raise Exception("Error extracting DER data from certificate.")
            
            der_data = base64.b64decode(matches.group(1).replace('\n', ''))
            sequence_pos = der_data.rfind(b'\x30', -72)
            signature = der_data[sequence_pos:]

            return {
                'public_key': public_key_der,
                'signature': signature
            }
        except Exception as e:
            raise Exception("[Error] Failed to process certificate: " + str(e))
        finally:
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    @staticmethod
    def decode_base64(data, altchars=b'+/'):
        data = re.sub(rb'[^a-zA-Z0-9%s]+' % altchars, b'', data)  # normalize
        missing_padding = len(data) % 4
        if missing_padding:
            data += b'=' * (4 - missing_padding)
        return base64.b64decode(data, altchars)
