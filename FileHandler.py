import os
import py7zr
import pandas as pd
import csv

def save_to_csv(dataframe, filepath, mode='w'):
    """
    Saves a DataFrame to a CSV file.
    
    :param dataframe: DataFrame to save
    :param filepath: Path to the CSV file
    :param mode: File mode ('w' for overwrite, 'a' for append)
    """
    dataframe.to_csv(filepath, mode=mode, index=False, quoting=csv.QUOTE_ALL)

def archive_file(filepath, archive_path):
    """
    Archives a file into a 7z format and deletes the original file.
    
    :param filepath: Path to the file to archive
    :param archive_path: Path to the output archive file
    """
    with py7zr.SevenZipFile(archive_path, 'w') as archive:
        archive.write(filepath)
    os.remove(filepath)

def check_existing_file(filepath):
    """
    Checks if a file exists.
    
    :param filepath: Path to the file
    :return: True if the file exists, False otherwise
    """
    return os.path.exists(filepath)
