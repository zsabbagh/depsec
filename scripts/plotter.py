import argparse, sys, time, pprint, json, datetime
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import src.utils.compute as compute
from copy import deepcopy
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
parser.add_argument('--end', help='The end year', default=None)
parser.add_argument('--platform', help='The default platform', default='pypi')
parser.add_argument('--step', help='The step size', default='m')
parser.add_argument('-p', '--projects', nargs='+', help='The projects to plot', required=True)
parser.add_argument('-o', '--output', help='The output directory', default='output')
parser.add_argument('--kpis', nargs='+', help='The key performance indicators to plot', default=['count', 'base', 'nloc'])
parser.add_argument('--debug', help='The debug level of the logger', default='INFO')
parser.add_argument('--show', help='Show the plots', action='store_true')
parser.add_argument('--dependencies', help="Generate plots for each project's dependencies as well", action='store_true')
parser.add_argument('--force', help='Force reload of dependencies', action='store_true')
parser.add_argument('--kind', help='What kind of plots to plot, timeline or overall', nargs='+', default=['timeline', 'overall'])

# TODO: Add possibility to combine KPIs as left and right y-axis

args = parser.parse_args()



# These are the key performance indicators for the releases

kpiset = set(list(map(lambda x: x.lower(), args.kpis)))
valid_kpis = set(compute.KPIS_TIMELINE.keys())
if not kpiset.issubset(valid_kpis):
    invalid_kpis = list(kpiset - valid_kpis)
    logger.error(f"Invalid KPIs: {', '.join(invalid_kpis)}. Valid KPIs are: {', '.join(valid_kpis)}")
    exit(1)

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

def plot_timelines(timelines: dict, title_prefix: str = ''):
    """
    Expects a dictionary with the following structure:

    <project>: {
        'cves': { <cve-id>: {} },
        'releases': { <release-id>: {} }
        'timeline': [
            {
                'date': <date>,
                'release': <release-id> | [ <release-id>, <release-id>, ...],
                'cves': [<cve-id>, <cve-id>, ...]
            }
        ]
    }
    """
    # the scores to plot
    figures = {}
    title_prefix = f"{title_prefix.strip()} "
    for kpi in args.kpis:
        fig, ax = plt.subplots()
        title = compute.KPIS_TIMELINE.get(kpi).get('title')
        y_label = compute.KPIS_TIMELINE.get(kpi).get('y_label')
        ax.set_title(f"{title_prefix}{title}")
        ax.set_ylabel(y_label)
        figures[kpi] = (fig, ax)
    max_values = {}
    min_values = {}
    for project, data in timelines.items():
        _, project = get_platform(project)
        results = compute.timeline_kpis(data, *args.kpis)
        for kpi in args.kpis:
            fig, ax = figures.get(kpi, (None, None))
            logger.info(f"Processing kpi '{kpi}' for {project}")
            if fig is None or ax is None:
                logger.error(f"Could not find figure for KPI '{kpi}'")
                continue
            ax: plt.Axes
            kpi_dict = results.get(kpi)
            if kpi_dict is None:
                logger.error(f"Could not find KPI '{kpi}' for {project}")
                continue
            default_value_key = kpi_dict.get('default', 'sum')
            values = kpi_dict.get('values', [])
            if values is None:
                logger.error(f"Could not find KPI '{kpi}' for {project}")
                continue
            values = compute.values_to_stats(values)
            suffix = kpi_dict.get('suffix', default_value_key)
            prev = {
                k: 0 for k in values
            }
            for i in range(0, len(values.get(default_value_key))):
                if values.get(default_value_key)[i] is None:
                    for k in values:
                        values.get(k)[i] = prev.get(k)
                else:
                    prev = {
                        k: values.get(k)[i] for k in values
                    }
            lower = upper = None
            has_max = 'max' in kpi_dict
            max_value = kpi_dict.get('max', None)
            has_min = 'min' in kpi_dict
            min_value = kpi_dict.get('min', None)
            if type(values) == dict:
                lower = values.get('min')
                upper = values.get('max')
                values = values.get(default_value_key)
                max_value = max(values) if not has_max else max_value
                min_value = min(values) if not has_min else min_value
            else:
                max_value = max(values) if not has_max else max_value
                min_value = min(values) if not has_min else min_value
            if not has_max:
                max_value = max_value * 1.1
                min_value = min_value * 1.1
            if max_values.get(kpi) is None:
                max_values[kpi] = max_value
            else:
                max_values[kpi] = max(max_values[kpi], max_value)
            if min_values.get(kpi) is None:
                min_values[kpi] = min_value
            else:
                min_values[kpi] = min(min_values[kpi], min_value)
            ax.plot(results.get('dates'), values, label=f"{project.title()} {suffix}")
            fill = kpi_dict.get('fill', True)
            if fill and default_value_key in ['mean', 'median']:
                if lower is not None and upper is not None:
                    ax.fill_between(results.get('dates'), lower, upper, alpha=0.1)
    for kpi in args.kpis:
        fig, ax = figures.get(kpi, (None, None))
        min_val = min_values.get(kpi)
        if min_val is None or min_val > 0:
            min_val = 0
        ax.set_ylim(ymin=min_val, ymax=max_values[kpi])
        # Shrink current axis's height by 10% on the bottom
        # Put a legend below current axis
        ax.legend(loc='upper center', framealpha=0.5)
        fig.autofmt_xdate()
        filename = f"{kpi.replace('/', '-')}"
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
    
    if 'timeline' in args.kind:
    
        # timeline plot section
        timelines = {}
        for project in args.projects:
            # get timeline for each project
            platform, project = get_platform(project)
            logger.info(f"Getting timeline for {project} on {platform}...")
            timeline = mw.get_vulnerabilities_timeline(project,
                                                    start_date=args.start,
                                                    end_date=args.end,
                                                    step=args.step,
                                                    platform=platform)
            cves = timeline.get('cves', {})
            logger.info(f"Found {len(cves)} CVEs for {project}")
            timelines[f"{platform}:{project}"] = timeline

        plot_timelines(timelines)
        try_json_dump(timelines, json_dir / 'timelines.json')

        if args.dependencies:
            dependency_timelines = {}
            timeline_entries = {}
            for project in timelines:
                platform, project = get_platform(project)
                # get timeline for each project
                logger.info(f"Getting dependencies for {project} on {platform}...")
                indirect_timelines = mw.get_indirect_vulnerabilities_timeline(project,
                                                                            start_date=args.start,
                                                                            end_date=args.end,
                                                                            step=args.step,
                                                                            platform=platform)
                dependency_timelines[f"{platform}:{project}"] = indirect_timelines
            plot_timelines(dependency_timelines, "Dependency")
            try_json_dump(dependency_timelines, json_dir / 'dependency_timelines.json')

    if 'overall' in args.kind:
        # get all the vulnerabilities for the projects
        # and plot them
        # 1) by CWE category
        # 2) by CWE weakness
        # 3) by severity
        # 4) by impact
        # 5) issues
        vulnerabilities = {}
        for project in args.projects:
            # get all the vulnerabilities for the project
            platform, project = get_platform(project)
            project_id = f"{platform}:{project}"
            vulnerabilities[project_id] = mw.get_vulnerabilities(project,
                                                            platform=platform,
                                                            include_categories=False)
            project_instance = mw.get_project(project, platform=platform)
            project_dict = model_to_dict(project_instance, recurse=False)
            # complement the project with the releases
            vulnerabilities[project_id]['project'] = project_dict
            vulnerabilities[project_id]['releases'] = [ model_to_dict(release, recurse=False) for release in project_instance.releases ]
            pprint(vulnerabilities[project_id])
            time.sleep(1)
        plot_vulnerabilities(vulnerabilities)
        try_json_dump(vulnerabilities, json_dir / 'vulnerabilities.json')

    if args.show:
        plt.show()
        
    # TODO: do the same above but for each dependencies
    
    # TODO: create LaTeX tables with the data

    # TODO: store the data in a JSON directory
        
    # TODO: plot complexity of code
    # include TIMESTAMP OF NVD FILE
    if args.show:
        plt.show()