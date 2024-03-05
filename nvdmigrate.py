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

def parse_cpe(cpe: str):
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
    }

def get_first_eng_value(cve: dict, *keys):
    """
    Get the description from the CVE
    """
    descs = None
    logger.debug(f"Getting ENG for {keys}")
    try:
        for i in range(len(keys)):
            cve = cve.get(keys[i], {} if i < len(keys) - 1 else [{}])
            if type(cve) == list and i < len(keys) - 1:
                cve = cve[0]
        descs = list(filter(lambda d: d.get('lang', '') == 'en', cve))
        return descs[0].get('value', '') if len(descs) > 0 else ''
    except Exception as e:
        logger.error(f"Error getting value: {e}, {descs}")
        return ''

def create_cve(entry: dict):
    """
    Create a CVE from an entry
    """
    cve = entry.get('cve', {})
    cve_id = cve.get('CVE_data_meta', {}).get('ID', None)
    # no impact means no CVSS score evaluated, so we skip
    impact = entry.get('impact', {})
    if impact == {}:
        logger.warning(f"No impact for {cve_id}")
        return None
    cve_db = CVE.get_or_none(CVE.cve_id == cve_id)
    # check for duplicate entry
    if cve_db is not None:
        logger.info(f"EXISTING ENTRY: {cve_id}")
        return None
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

    return cve_db

def create_nodes(node: dict, cve: CVE,
                 is_root: bool = True,
                 parent: ConfigNode = None,
                 root: ConfigNode = None):
    """
    Process a node and return vulnerable versions
    """
    if node is None or len(node) == 0:
        return None
    operator = node.get('operator', '')
    # Create the node
    node_db = ConfigNode.create(
        cve=cve,
        operator=operator,
        is_root=is_root
    )
    logger.info("Created node {node_db.id}")
    # If there is a parent, create an edge
    if parent is not None:
        ConfigEdge.create(
            parent=parent,
            root=root,
            child=node_db
        ).save()
    for cpe_match in node.get('cpe_match', []):
        cpe = cpe_match.get('cpe23Uri', '')
        vulnerable = cpe_match.get('vulnerable', False)
        if not vulnerable:
            continue
        cpe = parse_cpe(cpe)
        CPE.create(
            node=node_db,
            part=cpe.get('part'),
            vendor=cpe.get('vendor'),
            product=cpe.get('product'),
            version=cpe.get('version'),
            language=cpe.get('language'),
            sw_edition=cpe.get('sw_edition'),
            target_sw=cpe.get('target_sw'),
            target_hw=cpe.get('target_hw'),
            other=cpe.get('other'),
            version_start=cpe_match.get('versionStartIncluding', ''),
            version_end=cpe_match.get('versionEndExcluding', ''),
        ).save()
        logger.debug(f"Created CPE for {node_db.id}: {cpe['vendor']}:{cpe['product']}:{cpe['version']}")
    logger.debug(f"Trying to create children for {node_db.id}")
    for child in node.get('children', []):
        root = node_db if is_root else root
        create_nodes(child, cve, is_root=False, parent=node_db, root=root)

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
        configurations = entry.get('configurations', {})
        cve_id = entry.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
        if configurations == {}:
            logger.warning(f"No configurations for {cve_id}")
            count_skipped += 1
            continue
        nodes = configurations.get('nodes', [])
        if len(nodes) == 0:
            logger.warning(f"No nodes for {cve_id}")
            count_skipped += 1
            continue
        cve_db = create_cve(entry)
        if cve_db is None:
            logger.warning(f"Skipping entry {count_processed}/{len(data['CVE_Items'])}")
            continue
        nodes = configurations.get('nodes', [])
        root_node = ConfigNode.get_or_none(
            ConfigNode.cve == cve_db.cve_id,
            ConfigNode.is_root
        )
        if root_node is not None:
            logger.info(f"Root node already exists for {cve_db.cve_id}, skipping nodes")
            continue
        for node in nodes:
            create_nodes(node, cve_db, is_root=True)
            logger.info(f"Created nodes for {cve_db.cve_id}")


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
                start_time = time.time()
                migrate_data(data, args.debug)
                end_time = time.time()
                print(f"Migration took {end_time - start_time:.2f} seconds")
        except Exception as e:
            print(f"Error migrating {f}: {e}")
            continue