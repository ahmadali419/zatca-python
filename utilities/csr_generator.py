import os
import subprocess
import base64

def generate_csr_and_privatekey(cert_info, config_file_path):
    environment_type = cert_info['environmentType']

    # Define Output file paths
    config_path = 'certificates/config.cnf'
    private_key_file = 'certificates/PrivateKey.pem'
    csr_file = 'certificates/taxpayer.csr'
    public_key_file = 'certificates/PublicKey.pem'

    # Read dynamic data from csr.config
    data = read_config_file(config_file_path)

    # Generate the config content and write to config.cnf file
    generate_cnf_content(data, environment_type, config_path)

    # Generate EC private key
    generate_ec_private_key(private_key_file)
    
    # Generate CSR
    cert_info['csr'] = generate_csr(private_key_file, config_path, csr_file)

    # Generate Public Key
    generate_public_key(private_key_file, public_key_file)

    # Clean up the private key
    cert_info['privateKey'] = clean_private_key(private_key_file)

    # Output success message
    print(f"\nPrivate Key (cleaned), CSR (Base64), and Public Key generated successfully.")

    return cert_info

def read_config_file(file_path):
    config_data = {}
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Config file not found: {file_path}")
    
    with open(file_path, 'r') as file:
        for line in file:
            if '=' in line:
                key, value = line.split('=', 1)
                config_data[key.strip()] = value.strip()

    # Organize data into the structure expected by the generateCnfContent function
    data = {
        'csr': {
            'common_name': config_data['csr.common.name'],
            'serial_number': config_data['csr.serial.number'],
            'organization_identifier': config_data['csr.organization.identifier'],
            'organization_unit_name': config_data['csr.organization.unit.name'],
            'organization_name': config_data['csr.organization.name'],
            'country_name': config_data['csr.country.name'],
            'invoice_type': config_data['csr.invoice.type'],
            'location_address': config_data['csr.location.address'],
            'industry_business_category': config_data['csr.industry.business.category']
        }
    }
    return data

def generate_cnf_content(data, environment_type, file_path):

    asn_template = "TSTZATCA-Code-Signing"

    if environment_type == 'NonProduction':
        asn_template = 'TSTZATCA-Code-Signing'
    elif environment_type == 'Simulation':
        asn_template = 'PREZATCA-Code-Signing'
    elif environment_type == 'Production':
        asn_template = 'ZATCA-Code-Signing'

    cnf_content = []
    
    # OID Section
    cnf_content.append("oid_section = OIDs")
    cnf_content.append("[OIDs]")
    cnf_content.append("certificateTemplateName=1.3.6.1.4.1.1311.20.2\n")
    
    # req Section
    cnf_content.append("[req]")
    cnf_content.append("default_bits = 2048")
    cnf_content.append("emailAddress = email@email.com")
    cnf_content.append("req_extensions = v3_req")
    cnf_content.append("x509_extensions = v3_ca")
    cnf_content.append("prompt = no")
    cnf_content.append("default_md = sha256")
    cnf_content.append("req_extensions = req_ext")
    cnf_content.append("distinguished_name = dn\n")
    
    # dn Section
    cnf_content.append("[dn]")
    for key, value in data['csr'].items():
        if key == 'common_name':
            cnf_content.append(f"CN={value}")
        elif key == 'country_name':
            cnf_content.append(f"C={value}")
        elif key == 'organization_unit_name':
            cnf_content.append(f"OU={value}")
        elif key == 'organization_name':
            cnf_content.append(f"O={value}")
    
    # v3_req Section
    cnf_content.append("\n[v3_req]")
    cnf_content.append("basicConstraints = CA:FALSE")
    cnf_content.append("keyUsage = digitalSignature, nonRepudiation, keyEncipherment")
    
    # req_ext Section
    cnf_content.append("\n[req_ext]")
    cnf_content.append(f"certificateTemplateName = ASN1:PRINTABLESTRING:{asn_template}\n" )
    cnf_content.append("subjectAltName = dirName:alt_names")
    
    # alt_names Section
    cnf_content.append("\n[alt_names]")
    cnf_content.append(f"SN={data['csr']['serial_number']}")
    cnf_content.append(f"UID={data['csr']['organization_identifier']}")
    cnf_content.append(f"title={data['csr']['invoice_type']}")
    cnf_content.append(f"registeredAddress={data['csr']['location_address']}")
    cnf_content.append(f"businessCategory={data['csr']['industry_business_category']}")
    
    content = "\n".join(cnf_content)
    with open(file_path, 'w') as file:
        file.write(content)

def execute_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {result.stderr.strip()}")

def generate_ec_private_key(output_file_path):
    command = f"openssl ecparam -name secp256k1 -genkey -noout -out {output_file_path}"
    execute_command(command)

def generate_csr(private_key_file_path, config_path, csr_output_file_path):
    command = f"openssl req -new -sha256 -key {private_key_file_path} -config {config_path} -out {csr_output_file_path}"
    execute_command(command)

    with open(csr_output_file_path, 'rb') as csr_file:
        csr_content = csr_file.read()
    
    # Encode CSR content in Base64
    csr_content_base64 = base64.b64encode(csr_content).decode('utf-8')
    with open(csr_output_file_path, 'w') as csr_file:
        csr_file.write(csr_content_base64)

    return csr_content_base64

def generate_public_key(private_key_file_path, public_key_file_path):
    command = f"openssl ec -in {private_key_file_path} -pubout -conv_form compressed -out {public_key_file_path}"
    execute_command(command)

def clean_private_key(private_key_file_path):
    with open(private_key_file_path, 'r') as file:
        private_key_content = file.read()
    
    cleaned_key = ''.join(private_key_content.splitlines()[1:-1])  # Remove header/footer
    with open(private_key_file_path, 'w') as private_key_file:
        private_key_file.write(cleaned_key)

    return cleaned_key


if __name__ == "__main__":
    generate_csr_and_privatekey('NonProduction', 'certificates/csr-config-example-EN.properties')