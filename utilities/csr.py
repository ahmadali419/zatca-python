# utilities/csr.py
import shutil, subprocess, sys, tempfile, uuid
from pathlib import Path

def _ensure_openssl() -> str:
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

def _run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nSTDERR:\n{r.stderr}")
    return r.stdout

def _make_cnf(tmpdir: Path, *, env: str, C: str, O: str, OU: str, CN: str,
              VAT: str, CRN: str, EGS_UUID: str, ADDRESS: str,
              CATEGORY: str, TITLE: str) -> Path:
    is_sim = env.lower() in {"sandbox", "simulation"}
    SN = f"1-{VAT}|2-{CRN}|3-{EGS_UUID}"
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

def generate_csr(*, env: str, C: str, O: str, OU: str, CN: str,
                 VAT: str, CRN: str, ADDRESS: str,
                 CATEGORY: str, TITLE: str):
    """
    Returns: dict with keys:
      private_key_pem, csr_pem, csr_base64, egs_uuid
    """
    if not (VAT.isdigit() and len(VAT) == 15):
        print(f"WARNING: VAT should be 15 digits. Provided: {VAT}", file=sys.stderr)

    openssl = _ensure_openssl()
    egs_uuid = str(uuid.uuid4())

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        cnf = _make_cnf(tmp, env=env, C=C, O=O, OU=OU, CN=CN,
                        VAT=VAT, CRN=CRN, EGS_UUID=egs_uuid,
                        ADDRESS=ADDRESS, CATEGORY=CATEGORY, TITLE=TITLE)

        key_path = tmp / "private_key.pem"
        csr_path = tmp / "request.csr"

        # 1) EC private key (secp256k1)
        _run([openssl, "ecparam", "-name", "secp256k1", "-genkey", "-noout", "-out", str(key_path)])

        # 2) CSR
        _run([openssl, "req", "-new", "-sha256",
              "-key", str(key_path),
              "-config", str(cnf),
              "-extensions", "v3_req",
              "-out", str(csr_path)])

        csr_pem = csr_path.read_text(encoding="utf-8")
        pem_lines = csr_pem.splitlines()
        csr_base64 = "".join(line for line in pem_lines if not line.startswith("-----"))
        private_key_pem = key_path.read_text(encoding="utf-8")

    return {
        "private_key_pem": private_key_pem,
        "csr_pem": csr_pem,
        "csr_base64": csr_base64,
        "egs_uuid": egs_uuid,
    }
