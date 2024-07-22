import os
import datetime
import pandas as pd
import multiprocessing as mp
import tempfile
from BrinqaLogin import access_token
from DataFetcher import count_export, json_data_export
from DataProcessor import explode_json, clean_newlines, previous_run
from FileHandler import save_to_csv, archive_file, check_existing_file
from ParallelExecutor import parallel_runs

# Define the temporary directory for storing the certificate
tempDir = tempfile.gettempdir()

# Directories and file paths
userHome = os.path.expanduser("~")

# Define the FileName and path depending on your use case
file_name = "WorkStations_AVR"
filename = os.path.join(userHome, f'Documents/{file_name}_{datetime.date.today()}')

csvName = f'{filename}.csv'
archPath = f'{filename}.7z'

exportUrl = 'https://bakerhughes.brinqa.net/graphql/caasm'

def main():
    """
    Main function to run the data fetching, processing, and saving workflow.
    """
    # Initialize shared data storage for multiprocessing
    manager = mp.Manager()
    sharedData = manager.list()
    
    # Authenticate and fetch headers
    exportHeaders = access_token()
    
    # Define the GraphQL query for count
    count_query = '''
        query MyQuery {
            countHostVulnerability(
                filter: "(affectsRunningKernel = True OR affectsRunningKernel NOT_EXISTS) AND lastFound IN_LAST 5d AND status = Active AND targets.osType = Client"
            )
        }
    '''
    
    # Fetch the count using the provided query
    count = count_export(exportUrl, exportHeaders, count_query)
    print(f'Total count: {count}')
    
    # Define the GraphQL query for data export
    data_query = '''
        query MyQuery($offset: Int!) {
            listHostVulnerability(
                limit: 5000, offset: $offset, 
                filter: "(affectsRunningKernel = True OR affectsRunningKernel NOT_EXISTS) AND lastFound IN_LAST 5d AND status = Active AND targets.osType = Client"
            ) {
                lastFound 
                targets { 
                    name 
                    domains 
                    ipAddresses 
                    operatingSystem 
                    dnsName 
                    fqdn 
                    netbiosName 
                } 
                definition { 
                    qid 
                    cves { uid } 
                    exportableSolution 
                    name
                } 
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
            }
        }
    '''
    
    # Define the column order for the final DataFrame
    column_order = [
        'targets_name', 'targets_domains', 'targets_ipAddresses', 'targets_operatingSystem', 'targets_dnsName',
        'targets_fqdn', 'targets_netbiosName', 'definition_qid', 'type', 'definition_name', 'definition_cves',
        'exportableOutput', 'definition_exportableSolution', 'internetFacing', 'riskRating', 'ageInDays',
        'complianceStatus', 'dueDate', 'firstFound', 'lastFound', 'timesFound', 'lastFixed', 'disposition',
        'status', 'primaryConsolidationKey'
    ]
    
    # Check if previous data exists and determine offsets
    if check_existing_file(csvName):
        oldRecords = previous_run(csvName)
        if oldRecords > count:
            print('No new data needed, exiting')
            return
        offsets = list(range(oldRecords, count, 5000))
        writemode = 'a'
    else:
        offsets = list(range(0, count, 5000))
        writemode = 'w'
    
    # Fetch data in parallel
    parallel_runs(offsets, exportHeaders, exportUrl, sharedData, data_query, column_order)
    
    # Combine data and save to CSV
    combinedDf = pd.concat(sharedData, ignore_index=True)
    save_to_csv(combinedDf, csvName, mode=writemode)
    
    # Archive the CSV file
    archive_file(csvName, archPath)
    
    # Clean up temporary files
    os.remove(os.path.join(tempDir, 'Brinqa.pem'))

if __name__ == '__main__':
    main()
