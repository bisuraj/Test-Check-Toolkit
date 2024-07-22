import requests
import os
import pandas as pd
import tempfile

# Temporary directory
tempDir = tempfile.gettempdir()

def count_export(exportUrl, exportHeaders, query):
    # Prepare the request payload for counting records
    countPacket = {
        'query': query,
        'variables': None, 
        'operationName': 'MyQuery',
    }
    # Send the request and parse the response
    exportResponse = requests.post(exportUrl, headers=exportHeaders, json=countPacket, timeout=30, verify=os.path.join(tempDir, 'Brinqa.pem'))
    exportResponse.raise_for_status()
    exportJson = exportResponse.json()
    # Extract the count from the response
    exportCount = exportJson.get('data', {}).get('countHostVulnerability')
    return exportCount

def fetch_data(exportUrl, exportHeaders, offset, limit, filter_query):
    # Prepare the request payload for fetching data
    dataPacket = {
        'query': f'query MyQuery {{ listHostVulnerability(limit: {limit}, offset: {offset}, filter: "{filter_query}") {{ lastFound targets {{ name domains ipAddresses operatingSystem dnsName fqdn netbiosName }} definition {{ qid cves {{ uid }} exportableSolution name }} exportableOutput internetFacing riskRating ageInDays complianceStatus dueDate firstFound timesFound lastFixed disposition primaryConsolidationKey type status }} }}',
        'variables': None, 
        'operationName': 'MyQuery',
    }
    # Send the request and parse the response
    exportResponse = requests.post(exportUrl, headers=exportHeaders, json=dataPacket, timeout=120, verify=os.path.join(tempDir, 'Brinqa.pem'))
    exportResponse.raise_for_status()
    exportJson = exportResponse.json()
    
    # Convert the JSON response to a DataFrame
    dataList = find_first_list(exportJson)
    if dataList is not None:
        df = pd.json_normalize(dataList, sep='_')
    else:
        df = pd.json_normalize(exportJson, sep='_')

    return df

def find_first_list(data):
    # Recursively find the first list in a nested dictionary
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                return value
            elif isinstance(value, dict):
                result = find_first_list(value)
                if result is not None:
                    return result
    return None
