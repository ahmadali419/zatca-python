import json
import base64
from utilities.api_helper import api_helper
from utilities.csr_generator import CsrGenerator
from utilities.invoice_helper import invoice_helper
from utilities.einvoice_signer import einvoice_signer
from lxml import etree 

def main():
    
    print("\nPYTHON CODE ONBOARDING\n")

    # Define Variable
    environment_type = 'NonProduction'
    OTP = '123345'  # For Simulation and Production Get OTP from fatooraPortal

    csr_config = {
    "csr.common.name": "SME",
    "csr.serial.number": "1-SME|2-SME|3-3-83f5993c-2113-434b-a66a-9b2fcc1313f3",
    "csr.organization.identifier": "310724367700003",
    "csr.organization.unit.name": "SME",
    "csr.organization.name": "SME",
    "csr.country.name": "SA",
    "csr.invoice.type": "1100",
    "csr.location.address": "Riyadh 1234 Street",
    "csr.industry.business.category": "Technology"
    }

    #config_file_path = 'certificates/csr-config-example-EN.properties'

    api_path = 'Simulation'  # Default value

    # Determine API path based on environment type
    if environment_type == 'NonProduction':
        api_path = 'developer-portal'
    elif environment_type == 'Simulation':
        api_path = 'simulation'
    elif environment_type == 'Production':
        api_path = 'core'

    # Prepare certificate information
    cert_info = {
        "environmentType": environment_type,
        "csr": "",
        "privateKey": "",
        "OTP": OTP,
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

    # 1. Generate CSR and PrivateKey
    print("\n1. Generate CSR and PrivateKey\n")

    #Generate CSR & Private Key
    # csr_gen = CsrGenerator(csr_config, environment_type)
    # private_key_content, csr_base64 = csr_gen.generate_csr()

    # print("\nPrivate Key (without header and footer):")
    # print(private_key_content)
    # print("\nBase64 Encoded CSR:")
    # print(csr_base64)

    cert_info["csr"] = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ0hUQ0NBY1FDQVFBd056RUxNQWtHQTFVRUJoTUNVMEV4RERBS0JnTlZCQW9NQTFOTlJURU1NQW9HQTFVRQpDd3dEVTAxRk1Rd3dDZ1lEVlFRRERBTlRUVVV3VmpBUUJnY3Foa2pPUFFJQkJnVXJnUVFBQ2dOQ0FBUmdSOE00Cnl3YjdEZmlKTUVNaUI2Z1FxMmxYSCsrdGpDQ2l2MWtjS3JGR0hTRFJkUFdFRUNVT2g2TkZhT1BWU2IzVHlobWoKODEvTlQ0MnFmM3hVekJlK29JSUJMRENDQVNnR0NTcUdTSWIzRFFFSkRqR0NBUmt3Z2dFVk1Bc0dBMVVkRHdRRQpBd0lGNERDQjN3WURWUjBSQklIWE1JSFVwSUhSTUlIT01Xb3dhQVlEVlFRRURHRXhMVE14TURjeU5ETTJOemN3Ck1EQXdNM3d5TFRNdE9ETm1OVGs1TTJNdE1qRXhNeTAwTXpSaUxXRTJObUV0T1dJeVptTmpNVE14TTJZemZETXQKWldReU56RXdNV1F0WXpVMk1TMDBNakF4TFdJMk5qa3RNemt5T0RBd01tSmxaREV6TVI4d0hRWUtDWkltaVpQeQpMR1FCQVF3UE16RXdOekkwTXpZM056QXdNREF6TVEwd0N3WURWUVFNREFReE1UQXdNUnN3R1FZRFZRUWFEQkpTCmFYbGhaR2dnTVRJek5DQlRkSEpsWlhReEV6QVJCZ05WQkE4TUNsUmxZMmh1YjJ4dloza3dKQVlKS3dZQkJBR0MKTnhRQ0JCY1RGVkJTUlZwQlZFTkJMVU52WkdVdFUybG5ibWx1WnpBS0JnZ3Foa2pPUFFRREFnTkhBREJFQWlBNAp1NGZaNXB4eWJ5T0hhbFhZdkVXd2hQbmxwQXc0ZE8rWEQyTXdYKzhNbndJZ0JFNTB1UEJrYVdUU2xWUjR5SDAvClQ3OXVkRWZkTXFEWE9RZGt6NW4xam93PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0="
    # cert_info["privateKey"] = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIFmZyN9xXpjL2GOlm9VPHrPeH01NRIqEnmxKK9LEAjZnoAcGBSuBBAAK\noUQDQgAEbm4JB2hLi0Xpa/nKmkztf2ifKU3xgTYIULMF/d3kGxBpVIpm4WnLg2sO\nuLpGbvAjE5kZfDIaXlfhlEnWavpCDw==\n-----END EC PRIVATE KEY-----"
    cert_info["privatekey"]="MHQCAQEEIO7xv9jGODfPVhj0/8SqVUe7RMEJD/35M9EP1bpxEnZRoAcGBSuBBAAKoUQDQgAEYEfDOMsG+w34iTBDIgeoEKtpVx/vrYwgor9ZHCqxRh0g0XT1hBAlDoejRWjj1Um908oZo/NfzU+Nqn98VMwXvg=="
    
    api_helper.save_json_to_file("Certificates/certificateInfo.json", cert_info)

    # 2. Get Compliance CSID
    print("\n2. Get Compliance CSID\n")
    response = api_helper.compliance_csid(cert_info)
    request_type = "Compliance CSID"
    api_url = cert_info["complianceCsidUrl"]

    clean_response = api_helper.clean_up_json(response, request_type, api_url)

    try:
        json_decoded_response = json.loads(response)
        
        cert_info["ccsid_requestID"] = json_decoded_response["requestID"]
        cert_info["ccsid_binarySecurityToken"] = json_decoded_response["binarySecurityToken"]
        cert_info["ccsid_secret"] = json_decoded_response["secret"]

        api_helper.save_json_to_file("Certificates/certificateInfo.json", cert_info)

        print("\ncomplianceCSID Server Response: \n" + clean_response)
        
    except json.JSONDecodeError:
        print("\ncomplianceCSID Server Response: \n" + clean_response)

    # 3: Sending Sample Documents
    print("\n3: Sending Sample Documents\n")

    cert_info = api_helper.load_json_from_file("Certificates/certificateInfo.json")
    xml_template_path = r"templates/invoice.xml"

    private_key = cert_info["privateKey"]
    x509_certificate_content = base64.b64decode(cert_info["ccsid_binarySecurityToken"]).decode('utf-8')

    parser = etree.XMLParser(remove_blank_text=False)
    base_document = etree.parse(xml_template_path, parser)
    document_types = [
        ["STDSI", "388", "Standard Invoice", ""],
        ["STDCN", "383", "Standard CreditNote", "InstructionNotes for Standard CreditNote"],
        ["STDDN", "381", "Standard DebitNote", "InstructionNotes for Standard DebitNote"],
        ["SIMSI", "388", "Simplified Invoice", ""],
        ["SIMCN", "383", "Simplified CreditNote", "InstructionNotes for Simplified CreditNote"],
        ["SIMDN", "381", "Simplified DebitNote", "InstructionNotes for Simplified DebitNote"]
    ]

    icv = 0
    pih = "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="

    for doc_type in document_types:
        prefix, type_code, description, instruction_note = doc_type
        icv += 1
        is_simplified = prefix.startswith("SIM")

        print(f"Processing {description}...\n")

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
        
        #print(json_payload)
        
        response = api_helper.compliance_checks(cert_info, json_payload)
        request_type = "Compliance Checks"
        api_url = cert_info["complianceChecksUrl"]

        clean_response = api_helper.clean_up_json(response, request_type, api_url)

        json_decoded_response = json.loads(response)

        if json_decoded_response:
            print(f"complianceChecks Server Response: \n{clean_response}")
        else:
            print(f"Invalid JSON Response: \n{response}")
            exit(1)

        if response is None:
            print(f"Failed to process {description}: serverResult is null.\n")
            exit(1)

        status = json_decoded_response["reportingStatus"] if is_simplified else json_decoded_response["clearanceStatus"]

        if "REPORTED" in status or "CLEARED" in status:
            json_payload = json.loads(json_payload)
            pih = json_payload["invoiceHash"]
            print(f"\n{description} processed successfully\n\n")
        else:
            print(f"Failed to process {description}: status is {status}\n")
            exit(1)

        #time.sleep(1)  

    # 4. Get Production CSID
    
    print(f"\n\n4. Get Production CSID\n")

    response = api_helper.production_csid(cert_info)
    request_type = "Production CSID"
    api_url = cert_info["productionCsidUrl"]

    clean_response = api_helper.clean_up_json(response, request_type, api_url)

    try:
        json_decoded_response = json.loads(response)

        cert_info["pcsid_requestID"] = json_decoded_response["requestID"]
        cert_info["pcsid_binarySecurityToken"] = json_decoded_response["binarySecurityToken"]
        cert_info["pcsid_secret"] = json_decoded_response["secret"]

        api_helper.save_json_to_file("Certificates/certificateInfo.json", cert_info)

        print(f"Production CSID Server Response: \n{clean_response}")

    except json.JSONDecodeError:
        print(f"Production CSID Server Response: \n{clean_response}")


if __name__ == "__main__":
    main()