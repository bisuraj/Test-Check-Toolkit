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
filename = os.path.join(userHome, f'Documents/Workstation_AVR_{datetime.date.today()}')
csvName = f'{filename}.csv'
archPath = f'{filename}.7z'
exportUrl = 'https://bakerhughes.brinqa.net/graphql/caasm'

def main():
    """
    Main function to run the data fetching, processing, and saving workflow.
    """
    # Initialize shared data storage
    manager = mp.Manager()
    sharedData = manager.list()
    
    # Authenticate and fetch headers
    exportHeaders = access_token()
    
    # Fetch count of vulnerabilities
    count = count_export(exportUrl, exportHeaders)
    print(f'Total Vulns: {count}')
    
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
    parallel_runs(offsets, exportHeaders, exportUrl, sharedData)
    
    # Combine data and save to CSV
    combinedDf = pd.concat(sharedData, ignore_index=True)
    save_to_csv(combinedDf, csvName, mode=writemode)
    
    # Archive the CSV file
    archive_file(csvName, archPath)
    
    # Clean up temporary files
    os.remove(os.path.join(tempDir, 'Brinqa.pem'))

if __name__ == '__main__':
    main()
