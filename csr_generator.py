import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

# ---------- Your details ----------
ENV = "simulation"
C = "SA"
O = "SME"
OU = "SME"
CN = "SME"
VAT = "310724367700003"   # Organization Identifier from your PHP
CRN = "3-83f5993c-2113-434b-a66a-9b2fcc1313f3"  # Must be your actual CRN
ADDRESS = "Riyadh 1234 Street"
CATEGORY = "Technology"
TITLE = "1100"  # Simplified invoices only

# Build the SN field required by ZATCA: 1-VAT | 2-CRN | 3-UUID
EGS_UUID = str(uuid.uuid4())
SN = f"1-{VAT}|2-{CRN}|3-{EGS_UUID}"


# ---------- Find/OpenSSL ----------
def ensure_openssl() -> str:
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


OPENSSL = ensure_openssl()


def run(cmd, cwd=None):
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


# ---------- Build OpenSSL config (ZATCA) ----------
def make_cnf(tmpdir: Path) -> Path:
    is_sim = ENV.lower() in {"sandbox", "simulation"}
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
C  = {C}
O  = {O}
OU = {OU}
CN = {CN}

[ v3_req ]
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
subjectAltName = dirName:alt_names
{"certificateTemplateName = ASN1:PRINTABLESTRING:PREZATCA-Code-Signing" if is_sim else ""}

[ alt_names ]
SN = {SN}
UID = {VAT}
title = {TITLE}
registeredAddress = {ADDRESS}
businessCategory = {CATEGORY}
"""
    cnf = tmpdir / "config.cnf"
    cnf.write_text(tmpl.strip() + "\n", encoding="utf-8")
    return cnf


def main():
    if not (VAT.isdigit() and len(VAT) == 15):
        print(
            f"WARNING: VAT should be 15 digits. Provided: {VAT}",
            file=sys.stderr
        )

    out_dir = Path.cwd()
    key_path = out_dir / "private_key.pem"
    csr_path = out_dir / "request.csr"
    b64_path = out_dir / "request.csr.base64"
    uuid_path = out_dir / "egs_uuid.txt"

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        cnf = make_cnf(tmp)

        # 1) Generate EC private key (secp256k1)
        run([
            OPENSSL, "ecparam", "-name", "secp256k1",
            "-genkey", "-noout", "-out", str(key_path)
        ])

        # 2) CSR using our CNF
        run([
            OPENSSL, "req", "-new", "-sha256",
            "-key", str(key_path),
            "-config", str(cnf),
            "-extensions", "v3_req",
            "-out", str(csr_path)
        ])

    # Emit base64 (headerless) CSR for API usage
    pem_lines = csr_path.read_text(encoding="utf-8").splitlines()
    body = "".join(line for line in pem_lines if not line.startswith("-----"))
    b64_path.write_text(body + "\n", encoding="utf-8")
    uuid_path.write_text(EGS_UUID + "\n", encoding="utf-8")

    print("Private Key  ->", key_path)
    print("CSR          ->", csr_path)
    print("CSR (BASE64) ->", b64_path)
    print("EGS UUID     ->", uuid_path)
    print("\n--- CSR BASE64 (copy into API) ---\n" + body)


    return {key_path,b64_path}

if __name__ == "__main__":
    main()

