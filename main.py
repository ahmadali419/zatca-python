from csr_generator import (
    read_config_file,
    generate_cnf_content,
    write_to_file,
    generate_ec_private_key,
    generate_csr,
    generate_public_key,
    clean_private_key
)

def main():
    # Define file paths
    config_file_path = 'Certificates/csr-config-example-EN.properties'
    config_path = 'Certificates/config.cnf'
    private_key_file = 'Certificates/PrivateKey.pem'
    csr_file = 'Certificates/taxpayer.csr'
    public_key_file = 'Certificates/PublicKey.pem'

    # Read dynamic data from csr.config
    data = read_config_file(config_file_path)

    # Generate the config content and write to config.cnf file
    cnf_content = generate_cnf_content(data)
    write_to_file(config_path, cnf_content)

    # Generate EC private key
    generate_ec_private_key(private_key_file)

    # Generate CSR
    generate_csr(private_key_file, config_path, csr_file)

    # Generate Public Key
    generate_public_key(private_key_file, public_key_file)

    # Clean up the private key
    clean_private_key(private_key_file)

    # Output success message
    print("Private Key (cleaned), CSR (Base64), and Public Key generated successfully.")

if __name__ == "__main__":
    main()
