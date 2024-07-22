import multiprocessing as mp
from DataFetcher import json_data_export

def wrapper_json_data_export(queue, headers, exportUrl, sharedData, data_query, column_order):
    """
    Worker function for processing chunks of data in parallel.

    :param queue: Queue containing offsets for data chunks
    :param headers: Headers for API requests
    :param exportUrl: URL for the API endpoint
    :param sharedData: Shared list to store fetched data
    :param data_query: GraphQL query string to fetch data
    :param column_order: List of columns to ensure in the final DataFrame
    """
    while not queue.empty():
        offset = queue.get()
        print(f'Processing chunk with offset {offset}')
        json_data_export(offset, headers, exportUrl, sharedData, data_query, column_order)

def parallel_runs(offsets, headers, exportUrl, sharedData, data_query, column_order):
    """
    Runs data fetching in parallel using multiple processes.

    :param offsets: List of offsets for data chunks
    :param headers: Headers for API requests
    :param exportUrl: URL for the API endpoint
    :param sharedData: Shared list to store fetched data
    :param data_query: GraphQL query string to fetch data
    :param column_order: List of columns to ensure in the final DataFrame
    """
    queue = mp.Queue()
    for offset in offsets:
        queue.put(offset)
    
    processes = []
    for _ in range(int(mp.cpu_count() / 2)):
        p = mp.Process(target=wrapper_json_data_export, args=(queue, headers, exportUrl, sharedData, data_query, column_order))
        processes.append(p)
        p.start()
    
    for p in processes:
        p.join()
