import argparse, json, time, pprint, requests, random
from src.database.schema import *

# Script for migrating data from NVD JSON files to a database
# They can be downloaded from https://nvd.nist.gov/vuln/data-feeds

def prompt_continue(debug: bool = False):
    """
    Prompt the user to continue
    """
    if debug:
        response = input("[DEBUG ENABLED] Continue? (q to quit)")
        if response.lower() == 'q':
            return False
    return True

def is_pypi(package: str):
    """
    Check if package is on PyPI
    """
    time.sleep(random.randint(10, 50) / 1000.0)
    package = package.lower()
    res = requests.get(f"https://pypi.org/pypi/{package}/json")
    res = res.json()
    if 'message' in res and res['message'] == 'Not Found':
        return False
    return True

def parse_cpe(cpe: str, version_start: str, version_end: str):
    """
    Parse the CPE

    Order:
    cpe:x:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    parts = cpe.split(':')
    return {
        'part': parts[2],
        'vendor': parts[3],
        'product': parts[4],
        'version': parts[5],
        'update': parts[6],
        'edition': parts[7],
        'language': parts[8],
        'sw_edition': parts[9],
        'target_sw': parts[10],
        'target_hw': parts[11],
        'other': parts[12],
        'version_start_incl': version_start,
        'version_end_excl': version_end
    }

def process_cpe(match: str, py_cpes: list):
    """
    Process the CPE
    """
    vstart = match.get('versionStartIncluding', None)
    vend = match.get('versionEndExcluding', None)
    cpe = parse_cpe(match['cpe23Uri'], vstart, vend)
    vendor, product, version, language = cpe['vendor'], cpe['product'], cpe['version'], cpe['language']
    cpe_db = CPE.get_or_none(CPE.product == product, CPE.vendor == vendor)
    if cpe_db is not None:
        print(f"[DB HIT] Found CPE: {cpe_db.product} ({cpe_db.vendor})")
        if cpe_db.platform == 'pypi':
            py_cpes.append(cpe)
        else:
            print(f"\t--> {cpe['vendor']}:{cpe['product']} is not on PyPI")
        return
    else:
        print(f"[DB MISS] New CPE: {product} ({vendor})")
        return
        cpe_is_pypi = is_pypi(product)
        cpe_db = CPE.create(
            platform='pypi' if cpe_is_pypi else None,
            vendor=vendor,
            product=product,
            version=version,
            language=language
        )
        cpe_db.save()
        if cpe_is_pypi:
            py_cpes.append(cpe)

def migrate_data(data: dict, debug: bool = False):
    """
    Migrate the data to the database
    """
    print(f"Migrating data for {data['CVE_data_timestamp']}")
    print(f"Number of CVEs: {len(data['CVE_Items'])}")
    for entry in data['CVE_Items']:
        cve = entry.get('cve', {})
        configurations = entry.get('configurations', {})
        nodes = configurations.get('nodes', [])
        py_cpes = []
        for node in nodes:
            cpe_match = node.get('cpe_match', [])
            for match in cpe_match:
                process_cpe(match, py_cpes)
        if not py_cpes:
            continue
        print(f"Vulnerability: {cve.get('CVE_data_meta', {}).get('ID', None)}")
        impact = entry.get('impact', {})
        published_date = entry.get('publishedDate', None)
        last_modified_date = entry.get('lastModifiedDate', None)
        if not prompt_continue(debug):
            return
    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Migrate NVD data to a database')
    parser.add_argument('--db', metavar='DATABASE', type=str, required=True,
                        help='The database to migrate to',
                        default='data/packages.db')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode (delays)',
                        default=False)
    parser.add_argument('json_files', metavar='JSON_FILE', type=str, nargs='+',
                        help='The JSON files to migrate')
    args = parser.parse_args()
    args.json_files = sorted([os.path.abspath(f) for f in args.json_files], reverse=True)
    print(f"Using database: {args.db}")
    DatabaseConfig.set(args.db)
    print(f"Using JSON files: {', '.join(args.json_files)}")
    for f in args.json_files:
        try:
            with open(f, 'r') as file:
                data = json.load(file)
                migrate_data(data, args.debug)
        except Exception as e:
            print(f"Error migrating {f}: {e}")
            continue