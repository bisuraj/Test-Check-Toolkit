import pandas as pd

def findFirstList(data):
    """
    Recursively searches for the first list in a nested dictionary.
    
    :param data: Nested dictionary to search
    :return: The first list found or None if no list is found
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                return value
            elif isinstance(value, dict):
                result = findFirstList(value)
                if result is not None:
                    return result
    return None

def explode_json(df, column, cve):
    """
    Explodes a DataFrame column containing lists into separate rows and normalizes nested JSON columns.
    
    :param df: DataFrame to process
    :param column: Name of the column with list data to explode
    :param cve: Name of the column with CVE data to process
    :return: DataFrame with exploded and normalized data
    """
    df = df.explode(column).reset_index(drop=True)
    json_norm = pd.json_normalize(df[column])
    json_norm.columns = [f'{column}_{subcol}' for subcol in json_norm.columns]
    df = pd.concat([df.drop(columns=[column]), json_norm], axis=1)
    df[cve] = df[cve].apply(extract_cve)
    return df

def extract_cve(list_cves):
    """
    Extracts CVE 'uid' values from a list of CVE dictionaries.
    
    :param list_cves: List of CVE dictionaries
    :return: List of CVE 'uid' values
    """
    if not list_cves:
        return []
    return [d['uid'] for d in list_cves]

def clean_newlines(text):
    """
    Removes newline characters from a string.
    
    :param text: String with newline characters
    :return: String with newlines replaced by spaces
    """
    if isinstance(text, str):
        return text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    return text

def previous_run(file):
    """
    Returns the number of records in a CSV file.
    
    :param file: Path to the CSV file
    :return: Number of records in the file
    """
    df = pd.read_csv(file)
    return len(df)
