import argparse, json, time, requests, random, sys, yaml, os, re
import src.schemas.nvd as nvd
from loguru import logger
from src.utils.tools import *

parser = argparse.ArgumentParser(description='Migrate NVD data to a database')
parser.add_argument('config', metavar='CONFIG', type=str,
                    help='The configuration file to use')
parser.add_argument('--debug', action='store_true',
                    help='Enable debug mode (delays)',
                    default=False)
parser.add_argument('json_files', metavar='JSON_FILE', type=str, nargs='+',
                    help='The JSON files to migrate')
parser.add_argument('-l', '--level',
                    help='Set the logging level', nargs='+',
                    default=['INFO'])
parser.add_argument('-s', '--skip-processed-files', action='store_true',
                    help='Skip processed files',
                    default=True)
parser.add_argument('-f', '--force', action='store_true',
                    help='Force',
                    default=False)
parser.add_argument('-c', '--count', default=100, help='Number of CVEs to process before reporting progress')
args = parser.parse_args()

if args.count < 1:
    logger.warning("Count must be greater than 0, setting to 100")
    args.count = 100

# Script for migrating data from NVD JSON files to a database
# They can be downloaded from https://nvd.nist.gov/vuln/data-feeds

class Global:

    START_TIME = time.time()
    TOTAL_CVES = 0
    PROCESSED_CVES = 0
    CHECKPOINT = 0
    PROCESSED_SINCE_CHECKPOINT = 0
    CHECKPOINT_TIME = None

def wrap_in_list(obj):
    """
    Wrap an object in a list if it is not already a list
    """
    if type(obj) != list:
        return [obj]
    return obj

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

def prompt_continue():
    """
    Prompt the user to continue
    """
    pmpt = input("Continue? (yes)")
    if pmpt.lower() != 'yes':
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

def create_cve(entry: dict) -> int | nvd.CVE:
    """
    Create a nvd.CVE from an entry
    """
    cve = entry.get('cve', {})
    cve_id = cve.get('CVE_data_meta', {}).get('ID', None)
    # no impact means no CVSS score evaluated, so we skip
    impact = entry.get('impact', {})
    if impact == {}:
        logger.warning(f"No impact for {cve_id}, skipping")
        return 1
    cve_db = nvd.CVE.get_or_none(nvd.CVE.cve_id == cve_id)
    # check for duplicate entry
    if cve_db is not None and not args.force:
        logger.warning(f"{cve_id} already exists")
        return 0
    elif args.force and cve_db is not None:
        cve_db.delete_instance()
    # published and last modified dates
    published_at = entry.get('publishedDate', None)
    if published_at is None:
        logger.warning(f"No published date for {cve_id}, skipping")
        return 1
    published_at = timestamp_to_date(published_at, lowest='min')
    last_modified_at = entry.get('lastModifiedDate', None)
    last_modified_at = timestamp_to_date(last_modified_at, lowest='min')
    # description of the CVE
    description = get_first_eng_value(cve, 'description', 'description_data')
    base_metrics = impact.get('baseMetricV3', {}) if impact.get('baseMetricV3', {}) != {} else impact.get('baseMetricV2', {})
    cvss_expliotability_score = base_metrics.get('exploitabilityScore', None)
    cvss_impact_score = base_metrics.get('impactScore', None)
    # v2 and v3-3.1 share 'version', 'vectorString', 'confidentialityImpact', 'integrityImpact', 'availabilityImpact', 'baseScore'
    cvss = base_metrics.get('cvssV3', {}) if base_metrics.get('cvssV3', {}) != {} else base_metrics.get('cvssV2', {})
    cvss_version = cvss.get('version', None)
    # init these to None
    cvss_attack_complexity, cvss_vector_string = None, None
    cvss_attack_vector, cvss_privileges_required, cvss_user_interaction, cvss_scope, cvss_base_severity = None, None, None, None, None
    if cvss_version == '2.0':
        # version 2 has different fields
        # note 'access' takes the place of 'attack'
        cvss_attack_vector = cvss.get('accessVector', None)
        cvss_attack_complexity = cvss.get('accessComplexity', None)
        cvss_privileges_required = cvss.get('authentication', None)
        cvss_user_interaction = base_metrics.get('userInteractionRequired', None)
        # asserts that scope changes if privileges are obtained
        if impact.get('obtainAllPrivilege', None) is True or impact.get('obtainUserPrivilege', None) is True or impact.get('obtainOtherPrivilege', None) is True:
            cvss_scope = 'CHANGED'
        else:
            cvss_scope = 'UNCHANGED'
    else:
        # version 3-3.1 has these fields
        cvss_vector_string = cvss.get('vectorString', None)
        cvss_attack_vector = cvss.get('attackVector', None)
        cvss_attack_complexity = cvss.get('attackComplexity', None)
        cvss_privileges_required = cvss.get('privilegesRequired', None)
        cvss_user_interaction = cvss.get('userInteraction', None)
        cvss_scope = cvss.get('scope', None)
        cvss_base_severity = cvss.get('baseSeverity', None)

    cvss_confidentiality_impact = cvss.get('confidentialityImpact', None)
    cvss_integrity_impact = cvss.get('integrityImpact', None)
    cvss_availability_impact = cvss.get('availabilityImpact', None)
    cvss_base_score = cvss.get('baseScore', None)

    logger.debug(f"NEW ENTRY: {cve_id} being added to the database")

    cve_db = nvd.CVE.create(
        cve_id=cve_id,
        description=description,
        published_at=published_at,
        last_modified_at=last_modified_at,
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

    if cve_db is not None:
        cve_db.save()

    # CVEs can have more than one CWE
    # e.g., CVE-2021-44228 has more than one CWE
    problemtype = cve.get('problemtype', {})
    problemtype_data = problemtype.get('problemtype_data', [])
    problemtype_data = wrap_in_list(problemtype_data)
    has_cwe = False
    for prob in problemtype_data:
        descriptions = prob.get('description', [])
        descriptions = wrap_in_list(descriptions)
        for desc in descriptions:
            value = desc.get('value', '')
            if re.match(r'^CWE-\d+$', value):
                has_cwe = True
                cwe_db = nvd.CWE.create(
                    cve=cve_db,
                    cwe_id=value
                )
                if cwe_db is not None:
                    cwe_db.save()
    # set has_cwe to True if there is a CWE
    if has_cwe:
        cve_db.has_cwe = True
        cve_db.save()

    return cve_db

def create_nodes(node: dict, cve: nvd.CVE,
                 is_root: bool = True,
                 parent: nvd.ConfigNode = None,
                 root: nvd.ConfigNode = None):
    """
    Process a node and return vulnerable versions
    """
    if node is None or len(node) == 0:
        return None
    operator = node.get('operator', '')
    # Create the node
    node_db = nvd.ConfigNode.create(
        cve=cve,
        operator=operator,
        is_root=is_root
    )
    logger.debug("Created node {node_db.id}")
    # If there is a parent, create an edge
    if parent is not None:
        nvd.ConfigEdge.create(
            parent=parent,
            root=root,
            child=node_db
        ).save()
    for cpe_match in node.get('cpe_match', []):
        cpe_uri = cpe_match.get('cpe23Uri', '')
        vulnerable = cpe_match.get('vulnerable', False)
        if not vulnerable:
            continue
        cpe = parse_cpe(cpe_uri)
        end_exclude = cpe_match.get('versionEndExcluding', False)
        start_exclude = cpe_match.get('versionStartExcluding', False)
        nvd.CPE.create(
            node=node_db,
            uri=cpe_uri,
            part=cpe.get('part'),
            vendor=cpe.get('vendor'),
            product=cpe.get('product'),
            version=cpe.get('version'),
            language=cpe.get('language'),
            sw_edition=cpe.get('sw_edition'),
            target_sw=cpe.get('target_sw'),
            target_hw=cpe.get('target_hw'),
            other=cpe.get('other'),
            version_start=cpe_match.get('versionStartIncluding', None) or cpe_match.get('versionStartExcluding', None),
            version_end=cpe_match.get('versionEndExcluding', None) or cpe_match.get('versionEndIncluding', None),
            exclude_start_version=bool(start_exclude),
            exclude_end_version=bool(end_exclude),
        ).save()
        logger.debug(f"Created CPE for {node_db.id}: {cpe['vendor']}:{cpe['product']}:{cpe['version']}")
    logger.debug(f"Trying to create children for {node_db.id}")
    for child in node.get('children', []):
        root = node_db if is_root else root
        create_nodes(child, cve, is_root=False, parent=node_db, root=root)

def migrate_data(data: dict, debug: bool = False, filename: str = '', skip_processed_files: bool = True):
    """
    Migrate the data to the database
    """
    print(f"Migrating data for {data['CVE_data_timestamp']}")
    print(f"Number of CVEs: {len(data['CVE_Items'])}")
    ts = data['CVE_data_timestamp']
    date = timestamp_to_date(ts)
    number_of_cves = len(data['CVE_Items'])
    if not args.force:
        nvd_file = nvd.NVDFile.get_or_none(nvd.NVDFile.created_at == date, nvd.NVDFile.file == filename)
        logger.info(f"NVD file {filename} has been processed: {nvd_file is not None}")
        if nvd_file is not None and skip_processed_files:
            if nvd_file.cves_processed == number_of_cves:
                logger.info(f"File {filename} already processed with {number_of_cves}/{number_of_cves} CVEs, skipping")
                Global.PROCESSED_CVES += number_of_cves
                return
            else:
                logger.info(f"File {filename} already processed, but not all CVEs processed")
                if not prompt_continue():
                    return
                nvd_file.delete_instance()
        elif nvd_file is not None:
            print(f"File {filename} already processed, but not all CVEs processed, continuing")
            nvd_file.delete_instance()
        
    count_processed = 0
    count_skipped = 0
    if Global.CHECKPOINT_TIME is None:
        Global.CHECKPOINT_TIME = time.time()
    for entry in data['CVE_Items']:
        count_processed += 1
        Global.PROCESSED_CVES += 1
        time_since_start = time.time() - Global.START_TIME
        # round to 2 decimal places
        cve_id = entry.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
        if Global.PROCESSED_CVES // args.count != Global.CHECKPOINT:
            Global.CHECKPOINT = Global.PROCESSED_CVES // args.count
            speed = Global.PROCESSED_SINCE_CHECKPOINT / (time.time() - Global.CHECKPOINT_TIME)
            time_left = (Global.TOTAL_CVES - Global.PROCESSED_CVES) / speed
            # format to minutes
            seconds_left = time_left % 60
            minutes_left = time_left // 60
            logger.info(f"{cve_id} {time_since_start:.1f}s {count_processed}/{len(data['CVE_Items'])} {' in ' + filename if filename != '' else ''}, total progress: {Global.PROCESSED_CVES}/{Global.TOTAL_CVES} (speed: {speed:.2f} CVEs/s, time left: {minutes_left:.0f}:{seconds_left:.2f})")
            Global.CHECKPOINT_TIME = time.time()
            Global.PROCESSED_SINCE_CHECKPOINT = 0
        else:
            Global.PROCESSED_SINCE_CHECKPOINT += 1
        time.sleep(0.01)
        configurations = entry.get('configurations', {})
        if configurations == {}:
            logger.debug(f"No configurations for {cve_id}")
            count_skipped += 1
            continue
        nodes = configurations.get('nodes', [])
        if len(nodes) == 0:
            logger.debug(f"No nodes for {cve_id}")
            count_skipped += 1
            continue
        cve_db = create_cve(entry)
        if type(cve_db) == int:
            count_skipped += cve_db
            continue
        nodes = configurations.get('nodes', [])
        root_node = nvd.ConfigNode.get_or_none(
            nvd.ConfigNode.cve == cve_db.cve_id,
            nvd.ConfigNode.is_root
        )
        if root_node is not None:
            logger.debug(f"Root node already exists for {cve_db.cve_id}, skipping nodes")
            continue
        for node in nodes:
            create_nodes(node, cve_db, is_root=True)
            logger.debug(f"Created nodes for {cve_db.cve_id}")
    nvd_file_db = nvd.NVDFile.create(
        file=filename,
        created_at=date,
        cves_processed=count_processed,
        cves_skipped=count_skipped
    )
    if not debug and nvd_file_db is not None:
        nvd_file_db.save()



if __name__ == '__main__':
    logger.remove()
    for level in args.level:
        logger.add(sys.stderr, level=level, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level: <8}</level> {name} | <cyan>{function}</cyan> - <level>{message}</level>")
    args.json_files = sorted([os.path.abspath(f) for f in args.json_files], reverse=True)
    with open(args.config, 'r') as file:
        config = yaml.safe_load(file)
    dbconfig = config.get('database', {})
    path, name = get_database_dir_and_name(dbconfig, 'vulnerabilities')

    print(f"Using database at {path}/{name}")
    nvd.CONFIG.set(path, name)

    for f in args.json_files:
        try:
            with open(f, 'r') as file:
                data = json.load(file)
                cves = len(data['CVE_Items'])
                logger.info(f"File '{f}' has {cves} CVEs")
                Global.TOTAL_CVES += cves
        except Exception as e:
            print(f"Error counting amount {f}: {e}")
            continue
    
    logger.info(f"Total CVEs: {Global.TOTAL_CVES}")
    time.sleep(1)

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