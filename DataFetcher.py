import requests
import pandas as pd
import time
import tempfile
from DataProcessor import explode_json, clean_newlines, findFirstList

tempDir = tempfile.gettempdir()
def count_export(exportUrl, headers, query):
    """
    Fetches the count of vulnerabilities from the API using a provided query.

    :param exportUrl: URL for the API endpoint
    :param headers: Headers for API requests
    :param query: GraphQL query string to fetch the count
    :return: Count of vulnerabilities
    """
    countPacket = {
        'query': query,
        'variables': None,
        'operationName': 'MyQuery',
    }

    try:
        response = requests.post(exportUrl, headers=headers, json=countPacket, timeout=30,verify=tempDir +'\\Brinqa.pem')
        response.raise_for_status()  # Raise HTTPError for bad responses
        countJson = response.json()
        exportCount = countJson.get('data', {}).get('countHostVulnerability', 0)
        return exportCount
    except requests.exceptions.RequestException as e:
        print(f'Error fetching count: {e}')
        return 0
    
def json_data_export(offset, headers, exportUrl, sharedData, query, column_order, retries=3, delay=5):
    """
    Fetches and processes a chunk of data from the API using a custom query and column order.

    :param offset: Offset for the data chunk
    :param headers: Headers for API requests
    :param exportUrl: URL for the API endpoint
    :param sharedData: Shared list to store fetched data
    :param query: GraphQL query string to fetch data
    :param column_order: List of column names in the desired order
    :param retries: Number of retry attempts in case of failure
    :param delay: Delay between retry attempts in seconds
    """
    dataPacket = {
        'query': query,
        'variables': None, 
        'operationName': 'MyQuery',
    }

    for attempt in range(retries):
        try:
            response = requests.post(exportUrl, headers=headers, json=dataPacket, timeout=120,verify=tempDir +'\\Brinqa.pem')
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
            for col in column_order:
                if col not in df.columns:
                    df[col] = None
            df = df[column_order]
            
            sharedData.append(df)
            break  # Exit loop if successful
        
        except requests.exceptions.RequestException as e:
            print(f'Error: {e}. Rerying in {delay} seconds...')
            time.sleep(delay)
        except requests.exceptions.HTTPError as e:
            print(f'Http error: {e}. Rerying in {delay} seconds...')
            time.sleep(delay)
        except requests.exceptions.ConnectionError as e:
            print(f'Connection error: {e}. Rerying in {delay} seconds...')
            time.sleep(delay)
        except requests.exceptions.Timeout as e:
            print(f'Timeout error: {e}. Rerying in {delay} seconds...')
            time.sleep(delay)
        except Exception as e:
            print(f'Unexpected error: {e}. Rerying in {delay} seconds...')
            time.sleep(delay)
