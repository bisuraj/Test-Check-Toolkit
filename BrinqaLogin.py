import requests
import tempfile
import os
import CertFetcher
# Define the temporary directory for storing the certificate
tempDir = tempfile.gettempdir()

# Credentials for login
username = "reportGenerator"
password = ''  # Replace with the actual password

# API endpoint URL for login
login_url = 'https://bakerhughes.brinqa.net/api/auth/login'

def access_token():
    """
    Authenticate and obtain the access token for API requests.
    
    :return: Dictionary containing headers for API requests with the access token
    """
    # Obtain the certificate and write it to a file
    cert = CertFetcher.getPEMFile('bakerhughes.brinqa.net', 443)
    cert_path = os.path.join(tempDir, 'Brinqa.pem')
    with open(cert_path, 'w') as certFile:
        certFile.write(cert)
    
    print('Certificate written successfully.')

    # Prepare login payload
    login_payload = {
        'username': username,
        'password': password
    }

    # Perform login request
    login_response = requests.post(login_url, json=login_payload, verify=cert_path, timeout=30)
    access_token = login_response.json().get('access_token')

    if access_token:
        # Return headers for authenticated API requests
        return {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json;charset=UTF-8',
            'Accept-Encoding': 'gzip, deflate, br',
        }
    else:
        raise Exception('No access token was generated. Exiting.')
