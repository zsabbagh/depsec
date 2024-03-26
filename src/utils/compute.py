import numpy as np
from copy import deepcopy
from loguru import logger

# This file helps with computing KPIs for certain data structures
KPIS = {
    'base': {
        'default': 'mean',
        'key': 'cvss_base_score',
        'max': 10,
        'source': 'cve',
        'title': 'CVSS Base Score',
        'y_label': 'Score',
    },
    'issues': {
        'default': 'sum',
        'key': lambda *args: args[1].get('bandit_report', {}).get('issues_total'),
        'title': 'Bandit Issues',
        'source': 'release',
        'y_label': 'Count',
    },
    'files': {
        'default': 'sum', # all files for all releases (generalise for dependencies)
        'key': 'counted_files', # TODO: inconsistent naming, should be files_counted
        'source': 'releases',
        'title': 'Number of Files',
        'source': 'release',
        'y_label': 'Count',
    },
    'functions': {
        'default': 'sum',
        'key': 'counted_functions',
        'title': 'Number of Functions',
        'source': 'release',
        'y_label': 'Count',
    },
    'impact': {
        'default': 'mean',
        'key': 'cvss_impact_score',
        'title': 'CVSS Impact Score',
        'max': 10,
        'source': 'cve',
        'y_label': 'Score',
    },
    'exploitability': {
        'default': 'mean',
        'key': 'cvss_exploitability_score',
        'title': 'CVSS Exploitability Score',
        'max': 10,
        'source': 'cve',
        'y_label': 'Score',
    },
    'confidentiality': {
        'default': 'mean', # mean impact of all CVEs
        'key': 'cvss_confidentiality_impact',
        'title': 'CVSS Confidentiality Impact',
        'max': 2,
        'source': 'cve',
        'y_label': 'Impact',
    },
    'integrity': {
        'default': 'mean',
        'key': 'cvss_integrity_impact',
        'title': 'CVSS Integrity Impact',
        'max': 2,
        'source': 'cve',
        'y_label': 'Impact',
    },
    'availability': {
        'default': 'mean',
        'key': 'cvss_availability_impact',
        'title': 'CVSS Availability Impact',
        'max': 2,
        'source': 'cve',
        'y_label': 'Impact',
    },
    'cves': {
        'default': 'sum', # sum of all CVEs for all releases
        # assume that the key is a function that takes (data, elem) as arguments
        'key': lambda *args: len(args[1].get('cves', [])),
        'title': 'Number of CVEs',
        'source': 'entry',
        'y_label': 'Count',
    },
    'nloc': {
        'default': 'sum',
        'key': 'nloc_total',
        'title': 'Number of Lines of Code (NLOC)',
        'source': 'release', # 'entry' or 'release
        'y_label': 'NLOC',
    },
    'cves/nloc': {
        'default': 'mean',
        'key': 'cves_per_10k_nlocs',
        'title': 'CVEs per 10k NLOC',
        'y_label': 'CVEs per 10k NLOC',
    },
    'ccn': {
        'key': 'ccns',
        'title': 'Cyclomatic Complexity (CCN) / Function',
        'y_label': 'CCN',
    },
    'days': {
        'key': 'days',
        'title': 'Days to Patch',
        'y_label': 'Days',
    },
}

def timeline_kpis(data: dict, *kpis: str):
    """
    Computes KPIs for a timeline data structure.
    """
    cves = data.get('cves', {})
    releases = data.get('releases', {})
    timeline = data.get('timeline')
    cves = data.get('cves')
    results = {
        k: deepcopy(KPIS[k]) for k in kpis if k in KPIS
    }
    dates = []
    kpi_args = list(kpis)
    kpi_argset = set(kpi_args)
    # first, we compute release-related KPIs
    previous_non_null = {
        k: {
            'sum': 0,
            'min': 0,
            'max': 0,
            'mean': 0,
            'std': 0,
        } for k in kpi_argset
    }
    for entry in timeline:
        dates.append(entry.get('date'))
        rel = entry.get('release')
        # make sure we have a list of releases, even if it is a single release
        # this is to make the code more extensible
        relvs = [rel] if type(rel) == str else rel
        if type(relvs) != list:
            logger.error(f"Unexpected release type: {type(relvs).__name__}")
            continue
        for k in results:
            if k not in kpi_argset:
                continue
            # expect keywords type, source, function
            kpi: dict = KPIS.get(k)
            source_name: str = kpi.get('source')
            source = ids = None
            if 'values' not in results[k]:
                results[k]['values'] = {
                    'sum': [],
                    'min': [],
                    'max': [],
                    'mean': [],
                    'std': [],
                }
            match source_name:
                case 'cve':
                    source = cves
                    ids = entry.get('cves')
                case 'entry':
                    source = entry
                case 'release':
                    source = releases
                    ids = relvs
                case _:
                    logger.error(f"Unexpected source name: {source_name}")
                    continue
            if ids is None:
                ids = source if type(source) == list else [source]
            scores = []
            for id in ids:
                elem = id if type(id) == dict else (
                    source.get(id) if type(id) == str else None
                )
                if elem is None:
                    logger.error(f"Could not find {source} for {id}")
                    continue
                key = kpi.get('key')
                if key is None:
                    logger.error(f"Could not find function for KPI '{k}'")
                    continue
                if type(key) == str:
                    # when given a string, the key is a dictionary key
                    val = elem.get(key)
                    if val:
                        scores.append(val)
                    else:
                        logger.info(f"Could not find key '{key}' for {id}")
                        scores.append(None)
                elif callable(key):
                    # when given a function, the key is a function with args (data, elem)
                    try:
                        value = key(data, elem)
                        scores.append(value)
                    except Exception as e:
                        logger.error(f"Could not compute KPI '{k}' for {id}: {e}")
                        continue
                else:
                    logger.error(f"Unexpected function type: {type(key).__name__}")
                    continue
            scores = [s for s in scores if s is not None]
            non_null = previous_non_null.get(k)
            vals = results[k]['values']
            if len(scores) > 0:
                # replace the previous values with the new ones
                previous_non_null[k] = {
                    'sum': sum(scores),
                    'min': min(scores),
                    'max': max(scores),
                    'mean': np.mean(scores),
                    'std': np.std(scores),
                }
            for k2 in vals:
                vals[k2].append(non_null[k2])
    # then we compute the KPIs for the CVEs
    results['dates'] = dates
    return results