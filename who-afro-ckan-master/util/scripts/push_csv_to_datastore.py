#!/usr/bin/env python3
import ckanapi
import logging
import csv

import argparse
from dotenv import load_dotenv

from helpers import EnvDefault

load_dotenv()
log = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-U", "--ckan-url", action=EnvDefault, envvar="CKAN_URL", required=True,
                        help="CKAN url, can be passed as env CKAN_URL, e.g. https://dev.adr.fjelltopp.org")
    parser.add_argument("-K", "--ckan-apikey", action=EnvDefault, envvar="CKAN_APIKEY", required=True,
                        help="CKAN sysadmin api key, can be passed as env CKAN_APIKEY")
    parser.add_argument("-p", "--param",
                        help="Placeholder param to be used by your script.")
    parser.add_argument("--log-level", default=logging.INFO, type=lambda x: getattr(logging, x),
                        help="Configure the logging level.")
    parser.add_argument("-f", "--csv-file", default="data.csv", help="The filename of the csv file containing records to upload")
    parser.add_argument("-r", "--resource-id", help="The id of the resource to which the records should be pushed")
    parser.add_argument("-s", "--chunk-size", default=1000, help="The size of the chunks to upload", type=int)

    parsed_args = parser.parse_args()
    return parsed_args


def extract_header(file_path):
    """
    Extract the header row of a CSV file into a list of dictionaries
    of the form {"id": "<header_value>", "type": "text"}

    :param file_path: Path to the CSV file.
    :return: List of header column names.
    """
    with open(file_path, mode='r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)

    #  Default extracts everything as text, you may wish to override this in the UI.
    header = [{'id': x, "type": "text"} for x in header]
    return header


def load_csv_in_chunks(file_path, chunk_size):
    """
    Load a CSV file and yield it as chunks of dictionaries.

    :param file_path: Path to the CSV file.
    :param chunk_size: Number of rows per chunk.
    :return: Yields chunks of dictionaries.
    """
    with open(file_path, mode='r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        chunk = []
        for index, row in enumerate(reader):
            chunk.append({**row, "_id": index+2})
            if (index + 1) % chunk_size == 0:
                yield chunk
                chunk = []
        # Yield the last chunk whether it is empty or not
        yield chunk


def work(ckan_url, ckan_apikey, csv_filename, resource_id, chunk_size):

    ckan = ckanapi.RemoteCKAN(ckan_url, apikey=ckan_apikey)

    ckan.action.resource_patch(id=resource_id, url_type="datastore")
    ckan.action.datastore_create(
        resource_id=resource_id,
        fields=extract_header(csv_filename),
        primary_key=""
    )
    for index, chunk in enumerate(load_csv_in_chunks(csv_filename, chunk_size)):
        calculate_record_count = len(chunk) != chunk_size
        ckan.action.datastore_upsert(
            resource_id=resource_id,
            records=chunk,
            calculate_record_count=calculate_record_count
        )
        log.info(f"Pushing chunk {index}")



if __name__ == '__main__':
    args = parse_args()
    logging.basicConfig(level=args.log_level)
    ckan_url = args.ckan_url
    ckan_apikey = args.ckan_apikey
    csv_filename = args.csv_file
    resource_id = args.resource_id
    chunk_size = args.chunk_size
    log.info(ckan_url)
    log.info(ckan_apikey)
    work(ckan_url, ckan_apikey, csv_filename, resource_id, chunk_size)
