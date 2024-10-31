import json
import requests
from requests.auth import HTTPBasicAuth

class api_helper:

    @staticmethod
    def compliance_csid(cert_info):
        csr = cert_info['csr']
        OTP = cert_info['OTP']
        url = cert_info['complianceCsidUrl']

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

        response = requests.post(url, headers=headers, data=json_payload)

        if response.status_code != 200:
            raise Exception(f"HTTP error: {response.status_code} - {response.text}")

        return response.text

    @staticmethod
    def production_csid(cert_info):
        request_id = cert_info['ccsid_requestID']
        id_token = cert_info['ccsid_binarySecurityToken']
        secret = cert_info['ccsid_secret']
        url = cert_info['productionCsidUrl']

        json_payload = json.dumps({
            'compliance_request_id': request_id
        })

        headers = {
            'accept': 'application/json',
            'accept-language': 'en',
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
        }

        response = requests.post(url, headers=headers, data=json_payload, auth=HTTPBasicAuth(id_token, secret))

        if response.status_code != 200:
            raise Exception(f"HTTP error: {response.status_code} - {response.text}")

        return response.text

    @staticmethod
    def compliance_checks(cert_info, json_payload):
        id_token = cert_info['ccsid_binarySecurityToken']
        secret = cert_info['ccsid_secret']
        url = cert_info["complianceChecksUrl"]

        headers = {
            'accept': 'application/json',
            'accept-language': 'en',
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
        }

        response = requests.post(url, headers=headers, data=json_payload, auth=HTTPBasicAuth(id_token, secret))

        if response.status_code != 200:
            raise Exception(f"HTTP error: {response.status_code} - {response.text}")

        return response.text

    @staticmethod
    def invoice_reporting(cert_info, json_payload):
        id_token = cert_info['ccsid_binarySecurityToken']
        secret = cert_info['ccsid_secret']
        url = cert_info["complianceChecksUrl"]

        headers = {
            'accept': 'application/json',
            'accept-language': 'en',
            'Clearance-Status': '1',
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
        }

        response = requests.post(url, headers=headers, data=json_payload, auth=HTTPBasicAuth(id_token, secret))

        if response.status_code != 200:
            raise Exception(f"HTTP error: {response.status_code} - {response.text}")

        return response.text

    @staticmethod
    def invoice_clearance(cert_info, json_payload):
        id_token = cert_info['ccsid_binarySecurityToken']
        secret = cert_info['ccsid_secret']
        url = cert_info["complianceChecksUrl"]

        headers = {
            'accept': 'application/json',
            'accept-language': 'en',
            'Clearance-Status': '1',
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
        }

        response = requests.post(url, headers=headers, data=json_payload, auth=HTTPBasicAuth(id_token, secret))

        if response.status_code != 200:
            raise Exception(f"HTTP error: {response.status_code} - {response.text}")

        return response.text

    @staticmethod
    def load_json_from_file(file_path):
        try:
            with open(file_path, 'r') as file:
                json_data = json.load(file)
                return json_data
        except FileNotFoundError:
            raise Exception(f"File not found: {file_path}")
        except json.JSONDecodeError as e:
            raise Exception(f"Error parsing JSON: {str(e)}")

    @staticmethod
    def save_json_to_file(file_path, data):
        try:
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4, ensure_ascii=False, separators=(',', ': '))
        except Exception as e:
            raise Exception(f"Error saving JSON: {str(e)}")

    @staticmethod
    def clean_up_json(api_response, request_type, api_url):
        array_response = json.loads(api_response)

        # Remove None values from the dictionary
        array_response = {k: v for k, v in array_response.items() if v is not None}

        # Add new fields at the root level
        array_response['requestType'] = request_type
        array_response['apiUrl'] = api_url

        return json.dumps(array_response, indent=4, ensure_ascii=False, separators=(',', ': '))