import argparse, json, time, sys, yaml, xmltodict
import src.schemas.cwe as cwe
from src.schemas.nvd import *
from loguru import logger
from src.utils.tools import *
from pprint import pprint

# Script for migrating data from NVD JSON files to a database
# They can be downloaded from https://nvd.nist.gov/vuln/data-feeds

START_TIME = time.time()

def not_none(*values):
    """
    Check if any of the values are None
    """
    for v in values:
        if v is None:
            return False
    return True

def pprint_dict(d: dict, i: int = 0):
    """
    Pretty print a dictionary
    """
    indent = (' ' * i)
    if type(d) not in [dict, list]:
        print(type(d).__name__, end='')
        return
    elif type(d) == list:
        print(f"{indent}[", end='')
        if len(d) > 0:
            pprint_dict(d[0], i + 2)
            print(f"]")
        else:
            print(f"]")
        return
    elif type(d) == dict:
        for k, v in d.items():
            print(f"\n{indent}{k}: ", end='')
            pprint_dict(v, i + 2)


def create_category(cat: dict):
    """
    Create a category
    """
    pass

def create_weakness(weak: dict):
    """
    Create a weakness
    """
    cwe_id = weak.get('@ID')
    cwe_formatted_id = f"CWE-{cwe_id}"

    weakness_db = cwe.Weakness.get_or_none(cwe_id=cwe_formatted_id)
    if weakness_db is not None:
        logger.debug(f"Skipping existing weakness {cwe_formatted_id}")
        return None
    
    logger.debug(f"Got cwe_id: {cwe_formatted_id}")
    if cwe_id is None:
        logger.warning(f"Skipping weakness with no ID")
        return None
    name, abstraction, structure, status = weak.get('@Name'), weak.get('@Abstraction'), weak.get('@Structure'), weak.get('@Status')
    description = weak.get('Description')
    background_details = weak.get('Background_Details')
    likelihood_of_exploit = weak.get('Likelihood_Of_Exploit')
    detection_methods = weak.get('Detection_Methods', {})
    logger.debug(f"Detection methods {type(detection_methods).__name__}")
    # somehow the detection methods are a list of dictionaries or a dictionary
    if type(detection_methods) == dict:
        detection_methods = [ detection_methods ]
    methods = []
    method_ids = set()
    for method in detection_methods:
        detect_ms = method.get('Detection_Method', {})
        # same issue here, some are lists, some are dictionaries
        if type(detect_ms) != list:
            detect_ms = [detect_ms]
        for m in detect_ms:
            mid = m.get('@Detection_Method_ID')
            if mid in method_ids:
                continue
            desc = m.get('Method')
            if mid is not None and desc is not None:
                method_ids.add(mid)
                methods.append(f"{desc} ({mid})")
    if len(methods) > 0:
        methods = sorted(methods)
        methods = ', '.join(methods)
    else:
        methods = None


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
    data = data.get('Weakness_Catalog', {})
    weaknesses = data.get('Weaknesses', {})
    categories = data.get('Categories', {})
    views = data.get('Views', {})
    print(f"------------------------------------")
    print(f"WEAKNESSES SCHEMA: {len(weaknesses)}")
    pprint_dict(weaknesses)
    print(f"------------------------------------")
    print(f"CATEGORIES SCHEMA: {len(categories)}")
    pprint_dict(categories)
    print(f"------------------------------------")
    print(f"VIEWS SCHEMA: {len(views)}")
    pprint_dict(views)
    for category in categories.get('Category', []):
        create_category(category)
    for weak in weaknesses.get('Weakness', []):
        create_weakness(weak)
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
    args.xml_files = sorted([os.path.abspath(f) for f in args.xml_files], reverse=True)
    with open(args.config, 'r') as file:
        config = yaml.safe_load(file)
    dbconfig = config.get('database', {})
    path, name = get_database_dir_and_name(dbconfig, 'weaknesses')

    print(f"Using database at {path}/{name}")
    cwe.CONFIG.set(path, name)

    for f in args.xml_files:
        try:
            with open(f, 'r') as file:
                data = xmltodict.parse(file.read())
                start_time = time.time()
                fn = os.path.basename(f)
                migrate_data(data, args.debug, fn, args.skip_processed_files)
                end_time = time.time()
                print(f"Migration took {end_time - start_time:.2f} seconds")
        except Exception as e:
            print(f"Error migrating {f}: {e}")
            continue