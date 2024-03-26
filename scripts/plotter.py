import argparse, sys, time, pprint, json, datetime
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from pprint import pprint
from pathlib import Path
from src.middleware import Middleware
import src.schemas.nvd as nvd
from loguru import logger
from src.schemas.projects import *
# model_to_dict translates PeeWee models to dictionaries for JSON serialisation
# the purpose is to make the data that have produced the plots available to readers of the report
from playhouse.shortcuts import model_to_dict

# This is the main script to generate results from the database
# The script should plot, concerning CVEs:
# - Timeline, where each month counts the most recent release
# --- Number of vulnerabilities
# --- Max, median, mean, and standard deviation of the CVSS score
# --- Patch lag (time between the CVE being published and the release being fixed)
# - Number of vulnerabilities
# --- By CWE category
# --- By CWE weakness (specific weakness)
# --- By severity
# --- By impact (confidentiality, integrity, availability)

parser = argparse.ArgumentParser(description='Plot data from a file')
parser.add_argument('config', help='The configuration file')
parser.add_argument('--start', help='The start year', default=2020)
parser.add_argument('--platform', help='The default platform', default='pypi')
parser.add_argument('--step', help='The step size', default='m')
parser.add_argument('-p', '--projects', nargs='+', help='The projects to plot', required=True)
parser.add_argument('-o', '--output', help='The output directory', default='output')
parser.add_argument('--kpis', nargs='+', help='The key performance indicators to plot', default=['count', 'base', 'nloc'])
parser.add_argument('--debug', help='The debug level of the logger', default='INFO')
parser.add_argument('--show', help='Show the plots', action='store_true')

args = parser.parse_args()

def impact_to_int(score: str):
    """
    Translates a CVSS score to an integer
    """
    if score is None:
        return None
    elif type(score) in [int, float]:
        return score
    score = score.lower()
    match score:
        case 'none':
            return 0
        case 'low' | 'partial':
            return 1
        case 'high' | 'complete':
            return 2
    return None


# These are the key performance indicators for the releases

KPIS = {
    'base': {
        'default': 'mean',
        'key': 'cvss_base_score',
        'max': 10,
        'source': 'cve',
        'title': 'CVSS Base Score',
        'y_label': 'Score',
    },
    'files': {
        'default': 'sum', # all files for all releases (generalise for dependencies)
        'key': 'files',
        'source': 'releases',
        'title': 'Number of Files',
        'source': 'release',
        'y_label': 'Count',
    },
    'functions': {
        'default': 'sum',
        'key': 'functions',
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
        'key': lambda *args: len(args[2].get('cves', [])),
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

sns.set_theme(style='darkgrid')

def get_platform(project: str):
    """
    Returns the platforms for a project

    format: <platform>:<project>
    """
    platform = 'pypi' if args.platform is None else args.platform
    if ':' in project:
        parts = list(filter(bool, project.split(':')))
        if len(parts) != 2:
            logger.error(f"Invalid project format: {project}")
            exit(1)
        platform, project = parts[0], parts[1]
    return platform.lower(), project.lower()


def convert_datetime_to_str(data: dict):
    """
    Converts dictionaries with datetime objects to strings
    """
    if isinstance(data, Model):
        data = model_to_dict(data)
    if type(data) == list:
        return [ convert_datetime_to_str(entry) for entry in data ]
    elif type(data) != dict:
        return data
    for key, value in data.items():
        if isinstance(value, datetime.datetime):
            data[key] = value.strftime('%Y-%m-%d %H:%M:%S')
        else:
            data[key] = convert_datetime_to_str(value)
    return data

def try_json_dump(data: dict, path: Path):
    """
    Tries to dump a dictionary to a JSON file
    """
    if type(path) == str:
        path = Path(path)
        if not path.absolute().parent.exists():
            logger.error(f"Parent directory '{path.absolute().parent}' does not exist.")
            exit(1)
    data = convert_datetime_to_str(data)
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"Could not store data to path '{path.name}': {e}")
        exit(1)

# set the logger level
logger.remove()
logger.add(sink=sys.stdout, level=args.debug)

output_dir = Path(args.output)
if not output_dir.exists():
    logger.error(f"Output directory '{output_dir}' does not exist, create it.")
    exit(1)

# create the subdirectories
json_dir = output_dir / 'json'
plots_dir = output_dir / 'plots'
json_dir.mkdir(exist_ok=True)
plots_dir.mkdir(exist_ok=True)

def get_categories(timeline_entry: dict):
    pass

def get_scores(timeline_entry: dict):
    pass


def get_name_from_kpi(kpi: str):
    """
    Gets the name from a KPI
    """
    return kpi.replace('_', ' ').title().replace('Cvss', 'CVSS')

def get_timeline_kpis(data: dict, *kpi_args: str):
    """
    Gets the key performance indicators for a timeline
    """
    timeline = data.get('timeline')
    cves = data.get('cves')
    results = {}
    dates = []
    kpi_args = list(kpi_args)
    kpi_argset = set(kpi_args)
    # first, we compute release-related KPIs
    for entry in timeline:
        dates.append(entry.get('date'))
        rel = entry.get('release')
        # make sure we have a list of releases, even if it is a single release
        # this is to make the code more extensible
        relvs = [rel] if type(rel) == str else rel
        if type(relvs) != list:
            logger.error(f"Unexpected release type: {type(relvs).__name__}")
            continue
        for k in KPIS:
            if k not in kpi_argset:
                continue
            # expect keywords type, source, function
            kpi: dict = KPIS.get(k)
            source_name: str = kpi.get('source')
            source, ids = None, None
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
                        scores.append(0)
                elif type(key) == function:
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
            if k not in results:
                results[k] = []
            results[k] = {
                'sum': sum(scores),
                'min': min(scores),
                'max': max(scores),
                'mean': np.mean(scores),
                'std': np.std(scores),
            }
    # eliminate None values
    for kpi in results:
        prev_val = 0
        kpis = results[kpi]
        for i in range(kpis):
            if kpis[i] is None:
                kpis[i] = prev_val
            prev_val = kpis[i]
    # then we compute the KPIs for the CVEs
    return results

def plot_timelines(timelines: dict):
    """
    Expects a dictionary with the following structure:

    <project>: {
        'cves': { <cve-id>: {} },
        'releases': { <release-id>: {} }
        'timeline': [
            {
                'date': <date>,
                'release': <release-id>,
                'cves': [<cve-id>, <cve-id>, ...]
            }
        ]
    }
    """
    # the scores to plot
    figures = []
    for kpi in args.kpis:
        kpi = KPIS.get(kpi)
        if kpi is None:
            logger.error(f"Could not find KPI '{kpi}'")
            continue
        fig, ax = plt.subplots()
        figures.append((fig, ax, kpi))
        ax.set_title(kpi.get('title'))
        ax.set_ylabel(kpi.get('y_label'))
    kpi_keys = [ kpi.get('key') for _, _, kpi in figures ]
    max_values = {}
    for project, data in timelines.items():
        _, project = get_platform(project)
        results = get_timeline_kpis(data, *kpi_keys)
        for fig, ax, kpi in figures:
            ax: plt.Axes
            kpi_key = kpi.get('key')
            value = results.get(kpi_key)
            if value is None:
                logger.error(f"Could not find KPI '{kpi}' for {project}")
                continue
            suffix = ''
            lower = upper = None
            has_max = 'max' in kpi
            max_value = kpi.get('max', None)
            if type(value) == dict:
                lower = value.get('min')
                upper = value.get('max')
                value = value.get('mean')
                max_value = max(value) if not has_max else max_value
                suffix = f'{suffix} mean'
            else:
                max_value = max(value) if not has_max else max_value
            if not has_max:
                max_value = max_value * 1.1
            if max_values.get(kpi_key) is None:
                max_values[kpi_key] = max_value
            else:
                max_values[kpi_key] = max(max_values[kpi_key], max_value)
            ax.plot(results.get('dates'), value, label=f"{project.title()} {suffix}")
            if lower is not None and upper is not None:
                ax.fill_between(results.get('dates'), lower, upper, alpha=0.1, label=f"{project.title()} std")
    for fig, ax, kpi in figures:
        kpi_key = kpi.get('key')
        ax.set_ylim(ymin=0, ymax=max_values[kpi_key])
        ax.legend()
        fig.autofmt_xdate()
        filename = kpi.get('key', f"kpi-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
        fig.savefig(plots_dir / f"{filename}.png")

def plot_vulnerabilities(vulnerabilities: dict):
    """
    Expects a dictionary with the following structure:
    <project>: {
        <cve-id>: {}
    }
    """
    categories = {}
    cves = {}
    pass

def combine_timeline_data(data: dict):
    """
    Combines timeline data to a single dictionary
    """
    pass

mw = Middleware(args.config)
# load the projects, arguments are optional
mw.load_projects(*args.projects)

if __name__ == '__main__':

    # extract the files to present in the JSON
    # to be transparent about the data
    # usage of schema here, instead of middleware, as this is straight from the database
    files = nvd.NVDFile.select().order_by(nvd.NVDFile.created_at.desc())
    files = [ model_to_dict(file) for file in files ]
    files = convert_datetime_to_str(files)

    with open(json_dir / 'files.json', 'w') as f:
        json.dump(files, f, indent=4)
    
    # timeline plot section
    timelines = {}
    for project in args.projects:
        # get timeline for each project
        platform, project = get_platform(project)
        logger.info(f"Getting timeline for {project} on {platform}...")
        timeline = mw.get_vulnerabilities_timeline(project,
                                                   args.start,
                                                   step=args.step,
                                                   platform=platform)
        cves = timeline.get('cves', {})
        logger.info(f"Found {len(cves)} CVEs for {project}")
        timelines[f"{platform}:{project}"] = timeline

    plot_timelines(timelines)
    try_json_dump(timelines, json_dir / 'timelines.json')

    if args.show:
        plt.show()

    exit(0)

    dependency_timelines = {}
    # TODO: get the dependencies for each project and plot the timeline
    for project in args.projects:
        # get timeline for each project
        data = timelines.get(project)
        if data is None:
            logger.error(f"Could not find timeline for {project}")
            continue
        releases = data.get('releases')
        timeline = data.get('timeline')
        for entry in timeline:
            rel = releases.get(entry.get('release'))
            if rel is None:
                continue
            version = rel.get('version')
            dependencies = mw.get_dependencies(project, version, platform=platform)
            for dep in rel.get('dependencies', []):
                platform, project = get_platform(dep)
                if dependency_timelines.get(project) is None:
                    dependency_timelines[project] = {}
                if dependency_timelines[project].get('timeline') is None:
                    dependency_timelines[project]['timeline'] = []
                dependency_timelines[project]['timeline'].append(entry)

    # get all the vulnerabilities for the projects
    # and plot them
    # 1) by CWE category
    # 2) by CWE weakness
    # 3) by severity
    vulnerabilities = {}
    for project in args.projects:
        # get all the vulnerabilities for the project
        platform, project = get_platform(project)
        vulnerabilities[project] = mw.get_vulnerabilities(project,
                                                          platform=platform,
                                                          include_categories=True)
    plot_vulnerabilities(vulnerabilities)
    try_json_dump(vulnerabilities, json_dir / 'vulnerabilities.json')
        
    # TODO: do the same above but for each dependencies
    
    # TODO: create LaTeX tables with the data

    # TODO: store the data in a JSON directory
        
    # TODO: plot complexity of code
    # include TIMESTAMP OF NVD FILE
    if args.show:
        plt.show()