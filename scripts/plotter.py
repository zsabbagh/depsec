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

KPIS = {
    'base': {
        'key': 'cvss_base_score',
        'title': 'CVSS Base Score',
        'max': 10,
        'y_label': 'Score',
    },
    'impact': {
        'key': 'cvss_impact_score',
        'title': 'CVSS Impact Score',
        'max': 10,
        'y_label': 'Score',
    },
    'exploitability': {
        'key': 'cvss_exploitability_score',
        'title': 'CVSS Exploitability Score',
        'max': 10,
        'y_label': 'Score',
    },
    'confidentiality': {
        'key': 'cvss_confidentiality_impact',
        'title': 'CVSS Confidentiality Impact',
        'max': 2,
        'y_label': 'Impact',
    },
    'integrity': {
        'key': 'cvss_integrity_impact',
        'title': 'CVSS Integrity Impact',
        'max': 2,
        'y_label': 'Impact',
    },
    'availability': {
        'key': 'cvss_availability_impact',
        'title': 'CVSS Availability Impact',
        'max': 2,
        'y_label': 'Impact',
    },
    'cves': {
        'key': 'cves_count',
        'title': 'Number of CVEs',
        'y_label': 'Count',
    },
    'nloc': {
        'key': 'nlocs',
        'title': 'Number of Lines of Code',
        'y_label': 'NLOC',
    },
    'cves/nloc': {
        'key': 'cves_per_10k_nlocs',
        'title': 'CVEs per 10k NLOC',
        'y_label': 'CVEs per 10k NLOC',
    },
    'cc': {
        'key': 'ccs',
        'title': 'Cyclomatic Complexity (CC) average',
        'y_label': 'CC',
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

def get_name_from_kpi(kpi: str):
    """
    Gets the name from a KPI
    """
    return kpi.replace('_', ' ').title().replace('Cvss', 'CVSS')

def get_timeline_kpis(data: dict, *kws: str):
    """
    Gets the key performance indicators for a timeline
    """
    timeline = data.get('timeline')
    cves = data.get('cves')
    dates, cves_count, nlocs, ccs, cves_per_10k_nlocs = [], [], [], [], []
    for entry in timeline:
        rel = data.get('releases', {}).get(entry.get('release'))
        count = len(entry.get('cves', []))
        nloc = rel.get('nloc_total', 0) if rel is not None else 0
        nloc = 0 if nloc is None else nloc
        cc = rel.get('cc_average', 0) if rel is not None else 0
        date = entry.get('date')
        dates.append(date)
        cves_count.append(count)
        nlocs.append(nloc)
        ccs.append(cc)
        cves_per_10k_nlocs.append(count / (nloc / 10000) if nloc > 0 else 0)
    prev_cc, prev_nloc = 0, 0
    for cc in ccs:
        if cc is not None and cc > 0:
            prev_cc = cc
            break
    for nloc in nlocs:
        if nloc is not None and nloc > 0:
            prev_nloc = nloc
            break
    for i in range(len(dates)):
        cc = ccs[i]
        nloc = nlocs[i]
        if cc is None or cc == 0:
            ccs[i] = prev_cc
        else:
            prev_cc = cc
        if nloc is None or nloc == 0:
            nlocs[i] = prev_nloc
            cves_per_10k_nlocs[i] = cves_count[i] / (prev_nloc / 10000) if prev_nloc > 0 else 0
        else:
            prev_nloc = nloc
    results = {
        'dates': dates,
        'cves_count': cves_count,
        'nlocs': nlocs,
        'ccs': ccs,
        'cves_per_10k_nlocs': cves_per_10k_nlocs,
    }
    for kw in kws:
        if kw in results:
            continue
        max_scores = []
        min_scores = []
        std_scores = []
        mean_scores = []
        median_scores = []
        max_value = None
        for entry in timeline:
            scrs = []
            for cve in entry['cves']:
                if kw not in cves.get(cve, {}):
                    continue
                val = cves.get(cve, {}).get(kw)
                if max_value is None:
                    if type(val) == str:
                        max_value = 2
                    else:
                        max_value = 10
                value = impact_to_int(val)
                if type(value) not in [int, float]:
                    logger.warning(f"Unexpected value for {project}, keyword '{kw}' in {cve}: {value}")
                    continue
                scrs.append(value)
            if len(scrs) == 0:
                max_scores.append(0)
                std_scores.append(0)
                mean_scores.append(0)
                median_scores.append(0)
                min_scores.append(0)
                continue
            std_scores.append(np.std(scrs))
            max_scores.append(max(scrs))
            min_scores.append(min(scrs))
            mean_scores.append(np.mean(scrs))
            median_scores.append(np.std(scrs))
        results[kw] = {
            'max': max_scores,
            'min': min_scores,
            'mean': mean_scores,
            'median': median_scores,
            'std': std_scores,
        }
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
            if type(value) == dict:
                value = value.get('mean')
                suffix = f'{suffix} mean'
            ax.plot(results.get('dates'), value, label=f"{project.title()} {suffix}")
    for fig, ax, kpi in figures:
        ax.legend()
        fig.autofmt_xdate()
        filename = kpi.get('key', f"kpi-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
        fig.savefig(plots_dir / f"{kpi.get('key')}.png")

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
        timelines[f"{platform}:{project}"] = timeline

    plot_timelines(timelines)
    try_json_dump(timelines, json_dir / 'timelines.json')

    if args.show:
        plt.show()

    exit(0)

    dependency_timelines = {}
    for project in args.projects:
        # get timeline for each project
        platform, project = get_platform(project)
        logger.info(f"Getting dependencies for {project} on {platform}...")
        dependencies = mw.get_dependencies(project, platform=platform)
        dependency_timelines[f"{platform}:{project}"] = {
            'dependencies': dependencies,
        }
        logger.debug(f"Dependencies for {project}: {len(dependencies)}")
        for dependency in dependencies:
            timeline = mw.get_vulnerabilities_timeline(dependency.name,
                                                       args.start,
                                                       step=args.step,
                                                       platform=platform)
            dependency_timelines[f"{platform}:{project}"][dependency] = timeline

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