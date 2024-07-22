import requests
import pandas as pd
import time
import json
from DataProcessor import explode_json

def count_export(exportUrl, headers):
    """
    Fetches the count of vulnerabilities from the API.

    :param exportUrl: URL for the API endpoint
    :param headers: Headers for API requests
    :return: Count of vulnerabilities
    """
    countPacket = {
        'query': 'query MyQuery { countHostVulnerability(filter: "(affectsRunningKernel = True OR affectsRunningKernel NOT_EXISTS) AND lastFound IN_LAST 5d AND status = Active AND targets.osType = Client") }',
        'variables': None, 
        'operationName': 'MyQuery',
    }

    try:
        response = requests.post(exportUrl, headers=headers, json=countPacket, timeout=30)
        response.raise_for_status()  # Raise HTTPError for bad responses
        countJson = response.json()
        exportCount = countJson.get('data', {}).get('countHostVulnerability', 0)
        return exportCount
    except requests.exceptions.RequestException as e:
        print(f'Error fetching count: {e}')
        return 0

def json_data_export(offset, headers, exportUrl, sharedData, retries=3, delay=5):
    """
    Fetches and processes a chunk of data from the API.

    :param offset: Offset for the data chunk
    :param headers: Headers for API requests
    :param exportUrl: URL for the API endpoint
    :param sharedData: Shared list to store fetched data
    :param retries: Number of retry attempts in case of failure
    :param delay: Delay between retry attempts in seconds
    """
    dataPacket = {
        'query': f'''
            query MyQuery {{
                listHostVulnerability(
                    limit: 5000, offset: {offset}, 
                    filter: "(affectsRunningKernel = True OR affectsRunningKernel NOT_EXISTS) AND lastFound IN_LAST 5d AND status = Active AND targets.osType = Client"
                ) {{
                    lastFound 
                    targets {{ 
                        name 
                        domains 
                        ipAddresses 
                        operatingSystem 
                        dnsName 
                        fqdn 
                        netbiosName 
                    }} 
                    definition {{ 
                        qid 
                        cves {{ uid }} 
                        exportableSolution 
                        name
                    }} 
                    exportableOutput 
                    internetFacing 
                    riskRating 
                    ageInDays 
                    complianceStatus 
                    dueDate 
                    firstFound 
                    timesFound 
                    lastFixed 
                    disposition 
                    primaryConsolidationKey 
                    type 
                    status
                }}
            }}
        ''',
        'variables': None, 
        'operationName': 'MyQuery',
    }

    for attempt in range(retries):
        try:
            response = requests.post(exportUrl, headers=headers, json=dataPacket, timeout=120)
            response.raise_for_status()
            dataJson = response.json()
            
            # Find and normalize the data list
            dataList = findFirstList(dataJson)
            if dataList is not None:
                df = pd.json_normalize(dataList, sep='_')
            else:
                df = pd.json_normalize(dataJson, sep='_')
            
            # Process and normalize the JSON data
            df = explode_json(df, 'targets', 'definition_cves')
            
            if 'definition_exportableSolution' in df.columns:
                df['definition_exportableSolution'] = df['definition_exportableSolution'].apply(clean_newlines)
            if 'exportableOutput' in df.columns:
                df['exportableOutput'] = df['exportableOutput'].apply(clean_newlines)
            
            # Ensure all expected columns are present
            column_order = [
                'targets_name', 'targets_domains', 'targets_ipAddresses', 'targets_operatingSystem', 'targets_dnsName',
                'targets_fqdn', 'targets_netbiosName', 'definition_qid', 'type', 'definition_name', 'definition_cves',
                'exportableOutput', 'definition_exportableSolution', 'internetFacing','riskRating', 'ageInDays',
                'complianceStatus', 'dueDate', 'firstFound', 'lastFound', 'timesFound', 'lastFixed', 'disposition',
                'status', 'primaryConsolidationKey'
            ]
            for col in column_order:
                if col not in df.columns:
                    df[col] = None
            df = df[column_order]
            
            sharedData.append(df)
            break  # Exit loop if successful
        
        except requests.exceptions.RequestException as e:
            print(f'Error fetching data: {e}. Retrying in {delay} seconds...')
            time.sleep(delay)
        except Exception as e:
            print(f'Unexpected error: {e}. Retrying in {delay} seconds...')
            time.sleep(delay)
