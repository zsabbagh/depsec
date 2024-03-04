import argparse, json, time, pprint, requests, random
from src.database.schema import *
from loguru import logger

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
    cpe = match.get('cpe23Uri', None)
    logger.debug(f"Processing CPE: {cpe}")
    return
    cpe = parse_cpe(cpe, vstart, vend)
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

def get_first_eng_value(cve: dict, *keys):
    """
    Get the description from the CVE
    """
    descs = None
    try:
        for i in range(len(keys)):
            cve = cve.get(keys[i], {} if i < len(keys) - 1 else [{}])
        descs = list(filter(lambda d: d.get('lang', '') == 'en', cve))
        return descs[0].get('value', '') if len(descs) > 0 else ''
    except Exception as e:
        logger.error(f"Error getting value: {e}, {descs}")
        return ''

def migrate_data(data: dict, debug: bool = False):
    """
    Migrate the data to the database
    """
    print(f"Migrating data for {data['CVE_data_timestamp']}")
    print(f"Number of CVEs: {len(data['CVE_Items'])}")
    count_processed = 0
    count_skipped = 0
    for entry in data['CVE_Items']:
        count_processed += 1
        logger.info(f"Processing entry {count_processed}/{len(data['CVE_Items'])}")
        time.sleep(0.01)
        cve = entry.get('cve', {})
        configurations = entry.get('configurations', {})
        nodes = configurations.get('nodes', [])
        cve_id = cve.get('CVE_data_meta', {}).get('ID', None)
        # no impact means no CVSS score evaluated, so we skip
        impact = entry.get('impact', {})
        if impact == {}:
            logger.warning(f"No impact for {cve_id}")
            count_skipped += 1
            continue
        cve_db = CVE.get_or_none(CVE.cve_id == cve_id)
        # check for duplicate entry
        if cve_db is not None:
            logger.info(f"EXISTING ENTRY: {cve_id}")
            count_skipped += 1
            continue
        # published and last modified dates
        published_at = cve.get('publishedDate', None)
        last_modified_at = cve.get('lastModifiedDate', None)
        # description of the CVE
        description = get_first_eng_value(cve, 'description', 'description_data')
        base_metrics = impact.get('baseMetricV3', {})
        cvss_expliotability_score = base_metrics.get('exploitabilityScore', None)
        cvss_impact_score = base_metrics.get('impactScore', None)
        cvss = base_metrics.get('cvssV3', {})
        cvss_version = cvss.get('version', None)
        cvss_vector_string = cvss.get('vectorString', None)
        cvss_attack_vector = cvss.get('attackVector', None)
        cvss_attack_complexity = cvss.get('attackComplexity', None)
        cvss_privileges_required = cvss.get('privilegesRequired', None)
        cvss_user_interaction = cvss.get('userInteraction', None)
        cvss_scope = cvss.get('scope', None)
        cvss_confidentiality_impact = cvss.get('confidentialityImpact', None)
        cvss_integrity_impact = cvss.get('integrityImpact', None)
        cvss_availability_impact = cvss.get('availabilityImpact', None)
        cvss_base_score = cvss.get('baseScore', None)
        cvss_base_severity = cvss.get('baseSeverity', None)

        logger.info(f"NEW ENTRY: {cve_id} being added to the database")
        cwe = get_first_eng_value(cve, 'problemtype', 'problemtype_data', 'description')

        cve_db = CVE.create(
            cve_id=cve_id,
            description=description,
            published_at=published_at,
            last_modified_at=last_modified_at,
            cwe=cwe,
            cvss_version=cvss_version,
            cvss_expliotability_score=cvss_expliotability_score,
            cvss_impact_score=cvss_impact_score,
            cvss_vector_string=cvss_vector_string,
            cvss_attack_vector=cvss_attack_vector,
            cvss_attack_complexity=cvss_attack_complexity,
            cvss_privileges_required=cvss_privileges_required,
            cvss_user_interaction=cvss_user_interaction,
            cvss_scope=cvss_scope,
            cvss_confidentiality_impact=cvss_confidentiality_impact,
            cvss_integrity_impact=cvss_integrity_impact,
            cvss_availability_impact=cvss_availability_impact,
            cvss_base_score=cvss_base_score,
            cvss_base_severity=cvss_base_severity
        )
        cve_db.save()

        logger.info(f"Processing CPEs for {cve_id}")



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