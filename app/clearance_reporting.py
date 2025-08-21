# app/clearance_reporting.py
import json
import base64
import time
from utilities.api_helper import api_helper
from utilities.invoice_helper import invoice_helper
from utilities.einvoice_signer import einvoice_signer
from lxml import etree 


def run_clearance_reporting(file_name:str):
    """
    Executes Clearance & Reporting for invoices.
    """

    results = []

    cert_info = api_helper.load_json_from_file("Certificates/certificateInfo.json")
    xml_template_path = file_name

    print("Cert is ",cert_info["pcsid_binarySecurityToken"])
    # print(json.dumps(cert_info, indent=4))
    private_key = cert_info["privateKey"]
    x509_certificate_content = base64.b64decode(cert_info["pcsid_binarySecurityToken"]).decode('utf-8')

    parser = etree.XMLParser(remove_blank_text=False)
    base_document = etree.parse(xml_template_path, parser)

    document_types = [
        # ["STDSI", "388", "Standard Invoice", ""],
        # ["STDCN", "383", "Standard CreditNote", "InstructionNotes for Standard CreditNote"],
        # ["STDDN", "381", "Standard DebitNote", "InstructionNotes for Standard DebitNote"],
        ["SIMSI", "388", "Simplified Invoice", ""],
        # ["SIMCN", "383", "Simplified CreditNote", "InstructionNotes for Simplified CreditNote"],
        # ["SIMDN", "381", "Simplified DebitNote", "InstructionNotes for Simplified DebitNote"]
    ]

    icv = 0
    pih = "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="

    for prefix, type_code, description, instruction_note in document_types:
        icv += 1
        is_simplified = prefix.startswith("SIM")

        new_doc = invoice_helper.modify_xml(
            base_document,
            f"{prefix}-0001",
            "0200000" if is_simplified else "0100000",
            type_code,
            icv,
            pih,
            instruction_note
        )

        json_payload = einvoice_signer.get_request_api(new_doc, x509_certificate_content, private_key)

        # Decide API call
        if einvoice_signer.is_simplified_invoice(new_doc):
            response = api_helper.invoice_reporting(cert_info, json_payload)
            request_type = "Reporting Api"
            api_url = cert_info["reportingUrl"]
        else:
            response = api_helper.invoice_clearance(cert_info, json_payload)
            request_type = "Clearance Api"
            api_url = cert_info["clearanceUrl"]

        clean_response = api_helper.clean_up_json(response, request_type, api_url)

        try:
            json_decoded_response = json.loads(response)
        except json.JSONDecodeError:
            raise Exception(f"Invalid JSON Response: {response}")

        status = json_decoded_response["reportingStatus"] if is_simplified else json_decoded_response["clearanceStatus"]

        if status not in ["REPORTED", "CLEARED"]:
            raise Exception(f"Failed to process {description}: status = {status}")

        json_payload = json.loads(json_payload)
        pih = json_payload["invoiceHash"]

        results.append({
            "document": description,
            "status": status,
            "server_response": clean_response
        })

        time.sleep(1)

    return {"success": True, "message": "Clearance & Reporting completed", "results": results}
