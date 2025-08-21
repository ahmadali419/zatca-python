# csr_generator.py
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
import base64
import os
import re

class CsrGenerator:
    def __init__(self, config, environment_type,api_path):
        self.config = config
        self.environment_type = environment_type
        self.api_path=api_path
        self.asn_template = self.get_asn_template()
        self.open_ssl=self.ensure_openssl()

    def get_asn_template(self):
        if self.environment_type == 'NonProduction':
            return 'TSTZATCA-Code-Signing'
        elif self.environment_type == 'Simulation':
            return 'PREZATCA-Code-Signing'
        elif self.environment_type == 'Production':
            return 'ZATCA-Code-Signing'
        else:
            raise ValueError("Invalid environment type specified.")

    # def generate_private_key(self):
    #     return ec.generate_private_key(ec.SECP256K1(), default_backend())

    # def generate_csr(self):
    #     private_key = self.generate_private_key()
        
    #     # Build the CSR
    #     csr_builder = x509.CertificateSigningRequestBuilder()
    #     csr_builder = csr_builder.subject_name(x509.Name([
    #         x509.NameAttribute(NameOID.COUNTRY_NAME, self.config.get('csr.country.name', 'SA')),
    #         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.config.get('csr.organization.unit.name', '')),
    #         x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config.get('csr.organization.name', '')),
    #         x509.NameAttribute(NameOID.COMMON_NAME, self.config.get('csr.common.name', ''))
    #     ]))
        
    #     # Add ASN.1 extension
    #     csr_builder = csr_builder.add_extension(
    #         x509.UnrecognizedExtension(
    #             ObjectIdentifier("1.3.6.1.4.1.311.20.2"), 
    #             self.asn_template.encode()
    #         ),
    #         critical=False
    #     )
        
    #     # Add SAN extension
    #     csr_builder = csr_builder.add_extension(
    #         x509.SubjectAlternativeName([
    #             x509.DirectoryName(x509.Name([
    #                 x509.NameAttribute(ObjectIdentifier("2.5.4.4"), self.config.get('csr.serial.number', '')),
    #                 x509.NameAttribute(ObjectIdentifier("0.9.2342.19200300.100.1.1"), self.config.get('csr.organization.identifier', '')),
    #                 x509.NameAttribute(ObjectIdentifier("2.5.4.12"), self.config.get('csr.invoice.type', '')),
    #                 x509.NameAttribute(ObjectIdentifier("2.5.4.26"), self.config.get('csr.location.address', '')),
    #                 x509.NameAttribute(ObjectIdentifier("2.5.4.15"), self.config.get('csr.industry.business.category', ''))
    #             ]))
    #         ]),
    #         critical=False
    #     )

    #     # Sign the CSR with the private key
    #     csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

    #     # Serialize private key and CSR
    #     private_key_pem = private_key.private_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PrivateFormat.TraditionalOpenSSL,
    #         encryption_algorithm=serialization.NoEncryption()
    #     )
    #     csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    #     # Strip header/footer from private key
    #     private_key_content = re.sub(
    #         r'-----BEGIN .* PRIVATE KEY-----|-----END .* PRIVATE KEY-----|\n', '', 
    #         private_key_pem.decode('utf-8')
    #     )

    #     # Encode CSR in Base64
    #     csr_base64 = base64.b64encode(csr_pem).decode('utf-8')

    #     return private_key_content, csr_base64

    # def save_to_files(self, private_key_pem, csr_pem):
    #     os.makedirs("certificates", exist_ok=True)
    #     private_key_file = 'certificates/PrivateKey.pem'
    #     csr_file = 'certificates/taxpayer.csr'
        
    #     with open(private_key_file, "wb") as key_file:
    #         key_file.write(private_key_pem)
        
    #     with open(csr_file, "wb") as csr_file:
    #         csr_file.write(csr_pem)
        
    #     print(f"\nPrivate key and CSR have been saved to {private_key_file} and {csr_file}, respectively.")

# ---------- Find/OpenSSL ----------
    def ensure_openssl(self) -> str:
        exe = shutil.which("openssl")
        if exe:
            return exe

        candidates = [
            r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            r"C:\Program Files\OpenSSL-Win32\bin\openssl.exe",
            r"C:\Program Files\Git\usr\bin\openssl.exe",
        ]
        for p in candidates:
            if Path(p).exists():
                return p

        raise FileNotFoundError("OpenSSL not found. Install it or add to PATH.")

    def run(self,cmd, cwd=None):
        r = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"Command failed: {' '.join(cmd)}\nSTDERR:\n{r.stderr}"
            )
        return r.stdout

    def make_cnf(self,tmpdir: Path) -> Path:
            is_sim = self.api_path in {"sandbox", "simulation"}
            tmpl = f"""
        oid_section = my_oids

        [ my_oids ]
        certificateTemplateName = 1.3.6.1.4.1.311.20.2

        [ req ]
        default_md = sha256
        prompt = no
        string_mask = utf8only
        distinguished_name = dn
        req_extensions = v3_req

        [ dn ]
        C  = {self.config.get("csr.country.name")}
        O  = {self.config.get('csr.organization.name', '')}
        OU = {self.config.get('csr.organization.unit.name', '')}
        CN = {self.config.get('csr.common.name', '')}

        [ v3_req ]
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment
        subjectAltName = dirName:alt_names
        {"certificateTemplateName = ASN1:PRINTABLESTRING:PREZATCA-Code-Signing" if is_sim else ""}

        [ alt_names ]
        SN = {self.config.get('csr.common.name', '')}
        UID = {self.config.get('csr.organization.identifier', '')}
        title = {self.config.get('csr.invoice.type', '')}
        registeredAddress = {self.config.get('csr.location.address', '')}
        businessCategory = {self.config.get('csr.industry.business.category', '')}
        """
            cnf = tmpdir / "config.cnf"
            cnf.write_text(tmpl.strip() + "\n", encoding="utf-8")
            return cnf



    def csr_generator(self):
        vat = self.config.get('csr.organization.identifier', '')
        if not (vat.isdigit() and len(vat) == 15):
            print(
                f"WARNING: VAT should be 15 digits. Provided: {vat}",
                file=sys.stderr
            )

        out_dir = Path.cwd()
        key_path = out_dir / "private_key.pem"
        csr_path = out_dir / "request.csr"
        b64_path = out_dir / "request.csr.base64"
        uuid_path = out_dir / "egs_uuid.txt"

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cnf = self.make_cnf(tmp)

            # 1) Generate EC private key (secp256k1)
            self.run([
                self.open_ssl, "ecparam", "-name", "secp256k1",
                "-genkey", "-noout", "-out", str(key_path)
            ])

            # 2) CSR using our CNF
            self.run([
                self.open_ssl, "req", "-new", "-sha256",
                "-key", str(key_path),
                "-config", str(cnf),
                "-extensions", "v3_req",
                "-out", str(csr_path)
            ])

        pem_lines = csr_path.read_text(encoding="utf-8").splitlines()
        body = "".join(pem_lines)

        csr_base64_content = base64.b64encode(body.encode("utf-8")).decode("utf-8")        
        b64_path.write_text(csr_base64_content + "\n", encoding="utf-8")

        # Save UUID
        uuid_path.write_text(str(uuid.uuid4()) + "\n", encoding="utf-8")

        # Strip headers/footers from private key
        private_key_pem = key_path.read_text(encoding="utf-8").splitlines()
        private_key_content = "".join(line for line in private_key_pem if not line.startswith("-----"))

        return {"private_key": private_key_content, "csr_base64": csr_base64_content}
