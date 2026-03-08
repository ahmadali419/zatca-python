from lxml import etree
from lxml.etree import QName
import base64
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# -----------------------------
# Helpers (ZATCA / Phase-2)
# -----------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def tlv_encode(tags_in_order):
    """
    Phase-2 QR TLV:
    Tag(1 byte) + Length(1 byte) + Value(bytes)
    Tags 1..5 UTF-8 text, tag 6 is 32-byte SHA256, tags 7..9 are binary signatures/keys (usually base64-decoded bytes).
    Spec describes TLV + base64 final output. :contentReference[oaicite:8]{index=8}
    """
    out = bytearray()
    for tag, raw_bytes in tags_in_order:
        if not (0 < tag < 256):
            raise ValueError("Tag must fit 1 byte")
        if len(raw_bytes) > 255:
            raise ValueError("Value too long for 1 byte length")
        out.append(tag)
        out.append(len(raw_bytes))
        out.extend(raw_bytes)
    return bytes(out)

def canonicalize_for_hash(xml_root: etree._Element, qr_node_xpath: str):
    """
    ZATCA: sign/hash the whole XML EXCEPT the QR-code data element. :contentReference[oaicite:9]{index=9}
    Easiest practical approach: clone, remove QR AdditionalDocumentReference, then C14N.
    """
    clone = etree.fromstring(etree.tostring(xml_root))
    # remove QR ADR node(s)
    qr_nodes = clone.xpath(qr_node_xpath, namespaces=clone.nsmap)
    for n in qr_nodes:
        parent = n.getparent()
        if parent is not None:
            parent.remove(n)

    # Canonical XML (C14N 1.1 is commonly used in implementations; ZATCA validators are sensitive to formatting)
    return etree.tostring(clone, method="c14n", exclusive=True, with_comments=False)

def ecdsa_sign_b64(private_key_pem: str, data_to_sign: bytes) -> str:
    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("Private key must be EC key (P-256)")
    sig = key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))
    return b64(sig)

# -----------------------------
# Main: Credit Note Generator
# -----------------------------

def create_zatca_phase2_credit_note_xml(data: dict, output_path: str,
                                       private_key_pem: str,
                                       cert_der_b64: str,
                                       public_key_der_b64: str,
                                       previous_invoice_hash_b64: str,
                                       invoice_counter_value: int,
                                       zatca_technical_ca_signature_b64: str | None = None):
    """
    data: your existing dict but:
      - data["InvoiceTypeCode"] should be 381 for credit note
      - data["InvoiceTypeCodeName"] should be KSA-2 transaction code string like "0100000" (tax credit note) :contentReference[oaicite:10]{index=10}
      - data["BillingReference"] MUST exist for credit note :contentReference[oaicite:11]{index=11}

    previous_invoice_hash_b64: PIH (base64 SHA256 hash of previous document in chain)
    invoice_counter_value: ICV (sequential integer)
    """

    NSMAP = {
        None: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
        "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
        "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
        "xades": "http://uri.etsi.org/01903/v1.3.2#",
    }

    def make_element(tag, text=None, parent=None, **attributes):
        if ":" in tag:
            prefix, local_name = tag.split(":", 1)
            namespace = NSMAP[prefix]
            el = etree.Element(QName(namespace, local_name), **attributes)
        else:
            el = etree.Element(QName(NSMAP[None], tag), **attributes)
        if text is not None:
            el.text = str(text)
        if parent is not None:
            parent.append(el)
        return el

    # -----------------------------
    # 1) Build UBL Invoice root (Credit Note via InvoiceTypeCode=381)
    # -----------------------------
    invoice = etree.Element(QName(NSMAP[None], "Invoice"), nsmap=NSMAP)

    # --- UBLExtensions placeholder (Signature goes here)
    ubl_exts = make_element("ext:UBLExtensions", parent=invoice)
    ubl_ext = make_element("ext:UBLExtension", parent=ubl_exts)
    make_element("ext:ExtensionURI", "urn:oasis:names:specification:ubl:dsig:enveloped:xades", ubl_ext)
    ext_content = make_element("ext:ExtensionContent", parent=ubl_ext)

    # --- Header (keep your order rules)
    make_element("cbc:ProfileID", data["ProfileID"], invoice)
    make_element("cbc:ID", data["ID"], invoice)
    make_element("cbc:UUID", data["UUID"], invoice)
    make_element("cbc:IssueDate", data["IssueDate"], invoice)
    make_element("cbc:IssueTime", data["IssueTime"], invoice)

    # Credit Note via InvoiceTypeCode = 381, subtype in @name (KSA-2)
    make_element("cbc:InvoiceTypeCode", "381", invoice, name=data["InvoiceTypeCodeName"])  # e.g. "0100000" :contentReference[oaicite:12]{index=12}

    make_element("cbc:DocumentCurrencyCode", data["DocumentCurrencyCode"], invoice)
    if data.get("TaxCurrencyCode"):
        make_element("cbc:TaxCurrencyCode", data["TaxCurrencyCode"], invoice)

    # BillingReference is mandatory for credit note 381 :contentReference[oaicite:13]{index=13}
    if not data.get("BillingReference"):
        raise ValueError("BillingReference (original invoice ID) is mandatory for credit note (381).")
    br = make_element("cac:BillingReference", parent=invoice)
    invref = make_element("cac:InvoiceDocumentReference", parent=br)
    make_element("cbc:ID", data["BillingReference"], invref)

    # -----------------------------
    # 2) AdditionalDocumentReference: ICV, PIH, QR
    # -----------------------------
    # ICV
    adr_icv = make_element("cac:AdditionalDocumentReference", parent=invoice)
    make_element("cbc:ID", "ICV", adr_icv)
    make_element("cbc:UUID", str(invoice_counter_value), adr_icv)

    # PIH (Previous Invoice Hash)
    adr_pih = make_element("cac:AdditionalDocumentReference", parent=invoice)
    make_element("cbc:ID", "PIH", adr_pih)
    att_pih = make_element("cac:Attachment", parent=adr_pih)
    make_element("cbc:EmbeddedDocumentBinaryObject", previous_invoice_hash_b64, att_pih,
                 mimeCode="text/plain", characterSetCode="UTF-8")

    # QR placeholder (we fill after we compute invoice hash/signature)
    adr_qr = make_element("cac:AdditionalDocumentReference", parent=invoice)
    make_element("cbc:ID", "QR", adr_qr)
    att_qr = make_element("cac:Attachment", parent=adr_qr)
    qr_bin = make_element("cbc:EmbeddedDocumentBinaryObject", "", att_qr,
                          mimeCode="text/plain", characterSetCode="UTF-8")

    # -----------------------------
    # 3) Parties / totals / lines (reuse your existing blocks)
    # -----------------------------
    # NOTE: Copy-paste your Supplier, Customer, TaxTotal, LegalMonetaryTotal,
    #       and InvoiceLines blocks here unchanged (except it is a credit note business-wise).

    # (For brevity here, we assume you paste your existing blocks.)

    # -----------------------------
    # 4) Build Signature (XAdES enveloped) + compute invoice hash
    # -----------------------------
    # Canonicalize excluding QR ADR (data to be signed) :contentReference[oaicite:14]{index=14}
    # XPath targets the entire AdditionalDocumentReference that has cbc:ID='QR'
    qr_xpath = ".//cac:AdditionalDocumentReference[cbc:ID='QR']"
    c14n_bytes = canonicalize_for_hash(invoice, qr_xpath)
    invoice_hash = sha256(c14n_bytes)
    invoice_hash_b64 = b64(invoice_hash)

    # ECDSA signature of invoice hash (tag 7)
    ecdsa_sig_b64 = ecdsa_sign_b64(private_key_pem, invoice_hash)

    # -----------------------------
    # 5) Phase-2 QR TLV (tags 1..9) :contentReference[oaicite:15]{index=15}
    # -----------------------------
    # Tag 1..5 are UTF-8 strings
    seller_name = data["SupplierName"]
    seller_vat = data["SupplierVAT"]

    # ISO8601 timestamp (ZATCA examples often use Z); ensure consistent
    # If you already have IssueDate/IssueTime, combine:
    ts = f'{data["IssueDate"]}T{data["IssueTime"]}Z' if not data["IssueTime"].endswith("Z") else f'{data["IssueDate"]}T{data["IssueTime"]}'
    total_with_vat = str(data["TaxInclusiveAmount"])
    vat_total = str(data["TaxAmount"])

    # Tag 6 is raw 32 bytes of SHA256 hash :contentReference[oaicite:16]{index=16}
    tag6_raw = invoice_hash  # 32 bytes

    # Tag 7 is signature bytes. Your signature is base64 text; TLV expects bytes -> decode base64 to raw bytes.
    tag7_raw = base64.b64decode(ecdsa_sig_b64)

    # Tag 8 public key bytes (decode base64 DER)
    tag8_raw = base64.b64decode(public_key_der_b64)

    # Tag 9 only required for Simplified invoices/notes; pass if you have it :contentReference[oaicite:17]{index=17}
    tag9_raw = base64.b64decode(zatca_technical_ca_signature_b64) if zatca_technical_ca_signature_b64 else b""

    tags = [
        (1, seller_name.encode("utf-8")),
        (2, seller_vat.encode("utf-8")),
        (3, ts.encode("utf-8")),
        (4, total_with_vat.encode("utf-8")),
        (5, vat_total.encode("utf-8")),
        (6, tag6_raw),
        (7, tag7_raw),
        (8, tag8_raw),
    ]
    if zatca_technical_ca_signature_b64:
        tags.append((9, tag9_raw))

    qr_tlv = tlv_encode(tags)
    qr_base64 = b64(qr_tlv)
    qr_bin.text = qr_base64  # put into QR AdditionalDocumentReference

    # -----------------------------
    # 6) Insert ds:Signature + XAdES under UBLExtensions
    # -----------------------------
    # Minimal structure (validators are strict; keep IDs stable)
    sig = make_element("ds:Signature", parent=ext_content, Id="signature")
    signed_info = make_element("ds:SignedInfo", parent=sig)
    make_element("ds:CanonicalizationMethod", parent=signed_info,
                 Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    make_element("ds:SignatureMethod", parent=signed_info,
                 Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")

    # Reference to the whole document (enveloped), excluding QR is handled by our pre-hash step,
    # but ds:Reference still required structurally.
    ref_doc = make_element("ds:Reference", parent=signed_info, URI="")
    transforms = make_element("ds:Transforms", parent=ref_doc)
    make_element("ds:Transform", parent=transforms, Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    make_element("ds:DigestMethod", parent=ref_doc, Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
    make_element("ds:DigestValue", invoice_hash_b64, ref_doc)

    # SignatureValue (sign the SignedInfo canonically)
    signed_info_c14n = etree.tostring(signed_info, method="c14n", exclusive=True, with_comments=False)
    signature_value_b64 = ecdsa_sign_b64(private_key_pem, sha256(signed_info_c14n))
    make_element("ds:SignatureValue", signature_value_b64, sig)

    # KeyInfo with cert
    key_info = make_element("ds:KeyInfo", parent=sig)
    x509_data = make_element("ds:X509Data", parent=key_info)
    make_element("ds:X509Certificate", cert_der_b64, x509_data)

    # XAdES Object (basic container)
    obj = make_element("ds:Object", parent=sig)
    qp = make_element("xades:QualifyingProperties", parent=obj, Target="#signature")
    sp = make_element("xades:SignedProperties", parent=qp, Id="xadesSignedProperties")
    ssp = make_element("xades:SignedSignatureProperties", parent=sp)

    # SigningTime
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    make_element("xades:SigningTime", now, ssp)

    # NOTE:
    # Full XAdES profile includes SigningCertificateV2, SignedDataObjectProperties, etc.
    # ZATCA validations can be strict; many teams mirror ZATCA SDK output exactly.

    # -----------------------------
    # Write final
    # -----------------------------
    etree.ElementTree(invoice).write(output_path, encoding="UTF-8", xml_declaration=True, pretty_print=True)
    return {
        "invoice_hash_b64": invoice_hash_b64,
        "qr_base64": qr_base64,
        "signature_value_b64": signature_value_b64
    }