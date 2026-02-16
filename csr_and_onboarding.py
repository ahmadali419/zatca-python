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
    environment_type = 'Production'
    OTP = '456057'  # For Simulation and Production Get OTP from fatooraPortal

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

    api_path = 'Production'  # Default value

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

    cert_info["csr"] = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ09EQ0NBZDRDQVFBd09qRUxNQWtHQTFVRUJoTUNVMEV4RFRBTEJnTlZCQW9NQkVsR1VsTXhEVEFMQmdOVgpCQXNNQkVsR1VsTXhEVEFMQmdOVkJBTU1CRWxHVWxNd1ZqQVFCZ2NxaGtqT1BRSUJCZ1VyZ1FRQUNnTkNBQVRnCkVKSG5HSHpubjNsZ2dmSHZYNkdjeEJRYmlRNk93OHRkWXIxZ0N2L0RzbkdEL05NMmdzTHFXTHRmQTNtMy9sY3IKaTkrQ3N4Y2ttUlJGUmlRUUJUZDVvSUlCUXpDQ0FUOEdDU3FHU0liM0RRRUpEakdDQVRBd2dnRXNNQXNHQTFVZApEd1FFQXdJRjREQ0IrUVlEVlIwUkJJSHhNSUh1cElIck1JSG9NV293YUFZRFZRUUVER0V4TFRNeE1qTXpNamc0Ck1USXdNREF3TTN3eUxUTXRaR1k0WVdWak16TXRaak0xWkMwME9UTTBMV0l5Tm1RdE5EUTVNVGhoWkdVd01qYzAKZkRNdE5qTm1ZV0ppWldVdE5qVXdZaTAwTmpGbExXRTNOV1F0T1RBMU0yUXhOR0ZrTkRGaU1SOHdIUVlLQ1pJbQppWlB5TEdRQkFRd1BNekV5TXpNeU9EZ3hNakF3TURBek1RMHdDd1lEVlFRTURBUXhNVEF3TVRZd05BWURWUVFhCkRDMVhZV1JwSUVGc0xVMWhiSE5oYUNBMk5EWTJJRUZzTFU1aGMyVmxiU0JFYVhOMGNtbGpkQ0JTYVhsaFpHZ3gKRWpBUUJnTlZCQThNQ1VaMWNtNXBkSFZ5WlRBaEJna3JCZ0VFQVlJM0ZBSUVGQk1TV2tGVVEwRXRRMjlrWlMxVAphV2R1YVc1bk1Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ29OL3VYM3RMY2Z4U1JFclFSajVvN0VvaGpRREcrCkdjZEV3WGZ1RkZQK253SWdhMW11ajdaS08xcmZUQ2I4MGQzd1Y1RE5uZ1FSZnhlV0V3cHlkZDFkS2VZPQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0="
    # cert_info["privateKey"] = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIFmZyN9xXpjL2GOlm9VPHrPeH01NRIqEnmxKK9LEAjZnoAcGBSuBBAAK\noUQDQgAEbm4JB2hLi0Xpa/nKmkztf2ifKU3xgTYIULMF/d3kGxBpVIpm4WnLg2sO\nuLpGbvAjE5kZfDIaXlfhlEnWavpCDw==\n-----END EC PRIVATE KEY-----"
    cert_info["privatekey"]="MHQCAQEEIAHYdCovSbEN1hKFo8p6IuzlKGZf0to73Q3B+4O126MZoAcGBSuBBAAKoUQDQgAE4BCR5xh85595YIHx71+hnMQUG4kOjsPLXWK9YAr/w7Jxg/zTNoLC6li7XwN5t/5XK4vfgrMXJJkURUYkEAU3eQ=="
    
    api_helper.save_json_to_file("Certificates/certificateInfo.json", cert_info)

    # 2. Get Compliance CSID
    print("\n2. Get Compliance CSID\n")
    # response = api_helper.compliance_csid(cert_info)
    request_type = "Compliance CSID"
    api_url = cert_info["complianceCsidUrl"]

    # clean_response = api_helper.clean_up_json(response, request_type, api_url)

    try:
        # json_decoded_response = json.loads(response)
        
        cert_info["ccsid_requestID"] = "1771237329678"
        cert_info["ccsid_binarySecurityToken"] = "TUlJQ1VEQ0NBZmFnQXdJQkFnSUdBWnhsK01zT01Bb0dDQ3FHU000OUJBTUNNQlV4RXpBUkJnTlZCQU1NQ21WSmJuWnZhV05wYm1jd0hoY05Nall3TWpFMk1UQXlNakEwV2hjTk16RXdNakUxTWpFd01EQXdXakE2TVFzd0NRWURWUVFHRXdKVFFURU5NQXNHQTFVRUNnd0VTVVpTVXpFTk1Bc0dBMVVFQ3d3RVNVWlNVekVOTUFzR0ExVUVBd3dFU1VaU1V6QldNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQUtBMElBQk9BUWtlY1lmT2VmZVdDQjhlOWZvWnpFRkJ1SkRvN0R5MTFpdldBSy84T3ljWVA4MHphQ3d1cFl1MThEZWJmK1Z5dUwzNEt6RnlTWkZFVkdKQkFGTjNtamdnRU9NSUlCQ2pBTUJnTlZIUk1CQWY4RUFqQUFNSUg1QmdOVkhSRUVnZkV3Z2U2a2dlc3dnZWd4YWpCb0JnTlZCQVFNWVRFdE16RXlNek15T0RneE1qQXdNREF6ZkRJdE15MWtaamhoWldNek15MW1NelZrTFRRNU16UXRZakkyWkMwME5Ea3hPR0ZrWlRBeU56UjhNeTAyTTJaaFltSmxaUzAyTlRCaUxUUTJNV1V0WVRjMVpDMDVNRFV6WkRFMFlXUTBNV0l4SHpBZEJnb0praWFKay9Jc1pBRUJEQTh6TVRJek16STRPREV5TURBd01ETXhEVEFMQmdOVkJBd01CREV4TURBeE5qQTBCZ05WQkJvTUxWZGhaR2tnUVd3dFRXRnNjMkZvSURZME5qWWdRV3d0VG1GelpXVnRJRVJwYzNSeWFXTjBJRkpwZVdGa2FERVNNQkFHQTFVRUR3d0pSblZ5Ym1sMGRYSmxNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUNSalBiK1piK2pjOFYvRHp4WjB3RTJBaVdrMFVDUm01WklCWEIrMFlLakRBSWdJTWQ0TVJ0WDJBTERmK2hMeDBnRHY5NU5KN00rRzh6bTQyY3ExaUo2VUhVPQ=="
        cert_info["ccsid_secret"] = "KhbbK3Ltt9tp/u8O/y3XZLQU6shRSlDIZKL/ueuiRyw="

        api_helper.save_json_to_file("Certificates/certificateInfo.json", cert_info)

        print("\ncomplianceCSID Server Response: \n")
        
    except json.JSONDecodeError:
        print("\ncomplianceCSID Server Response: \n")

    # 3: Sending Sample Documents
    print("\n3: Sending Sample Documents\n")

    cert_info = api_helper.load_json_from_file("Certificates/certificateInfo.json")
    xml_template_path = r"templates/invoice.xml"

    private_key = "-----BEGIN EC PRIVATE KEY-----MHQCAQEEIAHYdCovSbEN1hKFo8p6IuzlKGZf0to73Q3B+4O126MZoAcGBSuBBAAKoUQDQgAE4BCR5xh85595YIHx71+hnMQUG4kOjsPLXWK9YAr/w7Jxg/zTNoLC6li7XwN5t/5XK4vfgrMXJJkURUYkEAU3eQ==-----END EC PRIVATE KEY-----"
    x509_certificate_content = base64.b64decode(cert_info["ccsid_binarySecurityToken"]).decode('utf-8')
    print('x509_certificate_content',x509_certificate_content)
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