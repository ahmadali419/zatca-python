# main.py
import base64
import json
import requests
from utilities.csr_generator import CsrGenerator

environment_type = "NonProduction"

config = {
    "csr.common.name": "TST-886431145-399999999900003",
    "csr.serial.number": "1-TST|2-TST|3-ed22f1d8-e6a2-1118-9b58-d9a8f11e445f",
    "csr.organization.identifier": "399999999900003",
    "csr.organization.unit.name": "Riyadh Branch",
    "csr.organization.name": "Maximum Speed Tech Supply LTD",
    "csr.country.name": "SA",
    "csr.invoice.type": "1100",
    "csr.location.address": "RRRD2929",
    "csr.industry.business.category": "Supply activities"
}

csr_gen = CsrGenerator(config, environment_type)
private_key_content, csr_base64 = csr_gen.generate_csr()

print("\nPrivate Key (without header and footer):")
print(private_key_content)
print("\nBase64 Encoded CSR:")
print(csr_base64)

# Test ZATCA Compliance for Generated CSR
print("\n2. Get Compliance CSID")

csr = csr_base64
OTP = '123456'
url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance"

json_payload = json.dumps({
    'csr': csr
})

headers = {
    'accept': 'application/json',
    'accept-language': 'en',
    'OTP': OTP,
    'Accept-Version': 'V2',
    'Content-Type': 'application/json',
}

try:
    response = requests.post(url, headers=headers, data=json_payload)

    # Output server response
    if response.status_code == 200:
        print("\n\nServer Response: \n")
        print(json.dumps(response.json(), indent=4))
    else:
        print("\n\nServer Response: \n" + response.text)

except Exception as e:
    print('Error: ' + str(e))
