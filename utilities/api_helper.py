import json
import time
import requests
from requests.auth import HTTPBasicAuth

class api_helper:
    
    @staticmethod
    def post_request_with_retries(url, headers, json_payload, auth=None, retries=3, backoff_factor=1):
        """
        POST with retries.
        - Treats HTTP 200 and 202 as success (returns response.text).
        - Retries on network errors and 5xx responses.
        - Raises on other non-success HTTP codes.
        """
        for attempt in range(retries):
            try:
                print("in post request")
                response = requests.post(url, headers=headers, data=json_payload, auth=auth, timeout=60)

                # Log raw text (truncated for safety if huge)
                raw_text = response.text
                print("response is (raw):")
                try:
                    parsed = json.loads(raw_text or "{}")
                    print(json.dumps(parsed, indent=2, ensure_ascii=False))
                except Exception:
                    # Not JSON or invalid JSON; print raw safely
                    print((raw_text or "")[:1000])

                # Retry on 5xx
                if 500 <= response.status_code <= 599:
                    print(f"Server {response.status_code}. Attempt {attempt + 1} of {retries}.")
                    if attempt < retries - 1:
                        time.sleep(backoff_factor * (2 ** attempt))
                        continue
                    # Exhausted retries -> raise
                    raise Exception(f"HTTP error: {response.status_code} - {response.text}")

                # Success: 200 (validated) or 202 (reported/cleared upstream)
                if response.status_code in (200, 202):
                    print("done with this")
                    return response.text

                # Any other non-success -> raise
                raise Exception(f"HTTP error: {response.status_code} - {response.text}")

            except requests.exceptions.RequestException as e:
                # Network-level issues
                print(f"ConnectionError/RequestException: {e}. Attempt {attempt + 1} of {retries}.")
                if attempt < retries - 1:
                    time.sleep(backoff_factor * (2 ** attempt))
                else:
                    raise  # re-raise after final attempt

    @staticmethod
    def compliance_csid(cert_info, retries=3, backoff_factor=1):
        csr = cert_info['csr']
        OTP = cert_info['OTP']
        url = cert_info['complianceCsidUrl']

        json_payload = json.dumps({'csr': csr})
        
        headers = {
            'accept': 'application/json',
            'accept-language': 'en',
            'OTP': OTP,
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
        }
        print("opt in complaince is ", OTP)

        return api_helper.post_request_with_retries(url, headers, json_payload, retries=retries, backoff_factor=backoff_factor)

    @staticmethod
    def production_csid(cert_info, retries=3, backoff_factor=1):
        request_id = cert_info['ccsid_requestID']
        id_token = cert_info['ccsid_binarySecurityToken']
        secret = cert_info['ccsid_secret']
        url = cert_info['productionCsidUrl']

        json_payload = json.dumps({'compliance_request_id': request_id})

        headers = {
            'accept': 'application/json',
            'accept-language': 'en',
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
        }

        auth = HTTPBasicAuth(id_token, secret)
        return api_helper.post_request_with_retries(url, headers, json_payload, auth=auth, retries=retries, backoff_factor=backoff_factor)

    @staticmethod
    def compliance_checks(cert_info, json_payload, retries=3, backoff_factor=1):
        id_token = cert_info['ccsid_binarySecurityToken']
        secret = cert_info['ccsid_secret']
        url = cert_info["complianceChecksUrl"]

        headers = {
            'accept': 'application/json',
            'accept-language': 'en',
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
        }

        auth = HTTPBasicAuth(id_token, secret)
        return api_helper.post_request_with_retries(url, headers, json_payload, auth=auth, retries=retries, backoff_factor=backoff_factor)

    @staticmethod
    def invoice_reporting(cert_info, json_payload, retries=3, backoff_factor=1):
        id_token = cert_info['pcsid_binarySecurityToken']
        secret = cert_info['pcsid_secret']
        url = cert_info["reportingUrl"]

        headers = {
            'accept': 'application/json',
            'accept-language': 'en',
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
        }

        auth = HTTPBasicAuth(id_token, secret)
        return api_helper.post_request_with_retries(url, headers, json_payload, auth=auth, retries=retries, backoff_factor=backoff_factor)

    @staticmethod
    def invoice_clearance(cert_info, json_payload, retries=3, backoff_factor=1):
        id_token = cert_info['pcsid_binarySecurityToken']
        secret = cert_info['pcsid_secret']
        url = cert_info["clearanceUrl"]

        headers = {
            'accept': 'application/json',
            'accept-language': 'en',
            'Clearance-Status': '1',
            'Accept-Version': 'V2',
            'Content-Type': 'application/json',
        }

        auth = HTTPBasicAuth(id_token, secret)
        return api_helper.post_request_with_retries(url, headers, json_payload, auth=auth, retries=retries, backoff_factor=backoff_factor)

    @staticmethod
    def load_json_from_file(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return json.load(file)
        except FileNotFoundError:
            raise Exception(f"File not found: {file_path}")
        except json.JSONDecodeError as e:
            raise Exception(f"Error parsing JSON: {str(e)}")

    @staticmethod
    def save_json_to_file(file_path, data):
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=4, ensure_ascii=False, separators=(',', ': '))
        except Exception as e:
            raise Exception(f"Error saving JSON: {str(e)}")

    @staticmethod
    def clean_up_json(api_response, request_type, api_url):
        """
        Keeps your existing behavior: takes JSON string, injects requestType/apiUrl,
        removes None values, and reorders fields.
        """
        array_response = json.loads(api_response)
        array_response['requestType'] = request_type
        array_response['apiUrl'] = api_url

        array_response = {k: v for k, v in array_response.items() if v is not None}

        reordered_response = {
            'requestType': array_response.pop('requestType'),
            'apiUrl': array_response.pop('apiUrl'),
            **array_response
        }

        return json.dumps(reordered_response, indent=4, ensure_ascii=False, separators=(',', ': '))
