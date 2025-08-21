import json
import base64
from utilities.api_helper import api_helper
from utilities.csr_generator import CsrGenerator
from utilities.invoice_helper import invoice_helper
from utilities.einvoice_signer import einvoice_signer
from lxml import etree


def run_onboarding(environment_type: str, otp: str, csr_config: dict):
    """
    Executes the full onboarding process with given OTP and CSR config.
    """

    api_path = "NonProduction"
    if environment_type == "NonProduction":
        api_path = "developer-portal"
    elif environment_type == "Production":
        api_path = "core"

    cert_info = {
        "environmentType": environment_type,
        "csr": "",
        "privateKey": "",
        "OTP": otp,
        "ccsid_requestID": "",
        "ccsid_binarySecurityToken": "",
        "ccsid_secret": "",
        "pcsid_requestID": "",
        "pcsid_binarySecurityToken": "",
        "pcsid_secret": "",
        "lastICV": "0",
        "lastInvoiceHash": "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        "complianceCsidUrl": f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{api_path}/compliance",
        "complianceChecksUrl": f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{api_path}/compliance/invoices",
        "productionCsidUrl": f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{api_path}/production/csids",
        "reportingUrl": f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{api_path}/invoices/reporting/single",
        "clearanceUrl": f"https://gw-fatoora.zatca.gov.sa/e-invoicing/{api_path}/invoices/clearance/single",
    }

    try:
        # 1. Generate CSR and PrivateKey
        csr_gen = CsrGenerator(csr_config, environment_type,api_path)

        
        result = csr_gen.csr_generator()
       
        cert_info["csr"] = result["csr_base64"]
        cert_info["privateKey"] = result["private_key"]

        print("cert info is:")    
        print(json.dumps(cert_info, indent=4))

        api_helper.save_json_to_file("Certificates/certificateInfo.json", cert_info)
        # 2. Get Compliance CSID
        response = api_helper.compliance_csid(cert_info)
        print("hey there")
        json_decoded = json.loads(response)
        cert_info["ccsid_requestID"] = json_decoded["requestID"]
        cert_info["ccsid_binarySecurityToken"] = json_decoded["binarySecurityToken"]
        cert_info["ccsid_secret"] = json_decoded["secret"]
        api_helper.save_json_to_file("Certificates/certificateInfo.json", cert_info)



        # 3. Sending Sample Documents
        xml_template_path = r"templates/invoice.xml"
        private_key = cert_info["privateKey"]
        x509_certificate_content = base64.b64decode(cert_info["ccsid_binarySecurityToken"]).decode('utf-8')

        parser = etree.XMLParser(remove_blank_text=False)
        base_document = etree.parse(xml_template_path, parser)

        icv = 0
        pih = cert_info["lastInvoiceHash"]
        document_types = [
            ["STDSI", "388", "Standard Invoice", ""],
            ["STDCN", "383", "Standard CreditNote", "InstructionNotes for Standard CreditNote"],
            ["STDDN", "381", "Standard DebitNote", "InstructionNotes for Standard DebitNote"],
            ["SIMSI", "388", "Simplified Invoice", ""],
            ["SIMCN", "383", "Simplified CreditNote", "InstructionNotes for Simplified CreditNote"],
            ["SIMDN", "381", "Simplified DebitNote", "InstructionNotes for Simplified DebitNote"]
        ]

        for prefix, type_code, description, note in document_types:
            icv += 1
            is_simplified = prefix.startswith("SIM")

            new_doc = invoice_helper.modify_xml(
                base_document, f"{prefix}-0001",
                "0200000" if is_simplified else "0100000",
                type_code, icv, pih, note
            )

            json_payload = einvoice_signer.get_request_api(new_doc, x509_certificate_content, private_key)
            response = api_helper.compliance_checks(cert_info, json_payload)
            json_decoded_response = json.loads(response)

            status = json_decoded_response.get("reportingStatus") if is_simplified else json_decoded_response.get("clearanceStatus")
            if status not in ["REPORTED", "CLEARED"]:
                raise Exception(f"{description} failed with status {status}")

            # update PIH for next doc
            pih = json.loads(json_payload)["invoiceHash"]

        # 4. Get Production CSID
        response = api_helper.production_csid(cert_info)
        json_decoded = json.loads(response)
        cert_info["pcsid_requestID"] = json_decoded["requestID"]
        cert_info["pcsid_binarySecurityToken"] = json_decoded["binarySecurityToken"]
        cert_info["pcsid_secret"] = json_decoded["secret"]

        api_helper.save_json_to_file("Certificates/certificateInfo.json", cert_info)

        return {"success": True, "message": "Onboarding completed", "cert_info": cert_info}

    except Exception as e:
        return {"success": False, "error": str(e)}
