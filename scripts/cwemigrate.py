import argparse, json, time, sys, yaml, xml
from src.schemas.vulnerabilities import *
from loguru import logger
from src.utils.tools import *

# Script for migrating data from NVD JSON files to a database
# They can be downloaded from https://nvd.nist.gov/vuln/data-feeds

START_TIME = time.time()

def timestamp_to_date(timestamp: str, lowest: str = 'min'):
    """
    Timestamp to date with lowest being the lowest unit,
    either min or sec
    """
    date = None
    format = '%Y-%m-%dT%H:%MZ'
    if lowest == 'min':
        format = '%Y-%m-%dT%H:%MZ'
    elif lowest == 'sec':
        format = '%Y-%m-%dT%H:%M:%SZ'
    logger.debug(f"Timestamp: {timestamp}")
    date = datetime.datetime.strptime(timestamp, format)
    return date

def migrate_data(data: dict, debug: bool = False, filename: str = '', skip_processed_files: bool = True):
    """
    Migrate the data to the database
    """
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Migrate NVD data to a database')
    parser.add_argument('config', metavar='CONFIG', type=str,
                        help='The configuration file to use')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode (delays)',
                        default=False)
    parser.add_argument('xml_files', metavar='XML_FILES', type=str, nargs='+',
                        help='The XML files to migrate')
    parser.add_argument('-l', '--level',
                        help='Set the logging level', nargs='+',
                        default=['INFO'])
    parser.add_argument('-s', '--skip-processed-files', action='store_true',
                        help='Skip processed files',
                        default=True)
    args = parser.parse_args()

    logger.remove()
    for level in args.level:
        logger.add(sys.stderr, level=level, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level: <8}</level> {name} | <cyan>{function}</cyan> - <level>{message}</level>")
    args.json_files = sorted([os.path.abspath(f) for f in args.json_files], reverse=True)
    with open(args.config, 'r') as file:
        config = yaml.safe_load(file)
    dbconfig = config.get('database', {})
    path, name = get_database_dir_and_name(dbconfig, 'vulnerabilities')

    print(f"Using database at {path}/{name}")
    DB_VULNERABILITIES.set(path, name)

    for f in args.json_files:
        try:
            with open(f, 'r') as file:
                data = json.load(file)
                start_time = time.time()
                fn = os.path.basename(f)
                migrate_data(data, args.debug, filename=fn, skip_processed_files=args.skip_processed_files)
                end_time = time.time()
                print(f"Migration took {end_time - start_time:.2f} seconds")
        except Exception as e:
            print(f"Error migrating {f}: {e}")
            continue