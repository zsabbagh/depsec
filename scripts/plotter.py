import argparse, sys, time, pprint, json, datetime
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import src.utils.compute as compute
from copy import deepcopy
from pprint import pprint
from pathlib import Path
from src.aggregator import Aggregator
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
# --- Patch lag (time between the CVE being published and the release being fixed) (differentiate patch lag and technical lag)
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
parser.add_argument('--output', help='The output directory', default='output')
parser.add_argument('-t', '--timeline', help='Plot the timeline', nargs='+', default=[])
parser.add_argument('-o', '--overall', help='Plot the overall data', nargs='+', default=[])
parser.add_argument('--debug', help='The debug level of the logger', default='INFO')
parser.add_argument('--show', help='Show the plots', action='store_true')
parser.add_argument('--dependencies', help="Generate plots for each project's dependencies as well", action='store_true')
parser.add_argument('--force', help='Force reload of dependencies', action='store_true')

# TODO: Add possibility to combine KPIs as left and right y-axis

args = parser.parse_args()

args.projects = sorted(list(map(str.lower, args.projects)))


args.timeline = sorted(list(map(str.lower, args.timeline)))
args.overall = sorted(list(map(str.lower, args.overall)))

if len(args.timeline) > 0 and args.timeline[0] in ['all', '*']:
    args.timeline = list(compute.KPIS_TIMELINE.keys())

# These are the key performance indicators for the releases
# convert to set for quick lookup
kpiset_timeline = set(args.timeline)
valid_kpis = set(compute.KPIS_TIMELINE.keys())
if not kpiset_timeline.issubset(valid_kpis):
    invalid_kpis = list(kpiset_timeline - valid_kpis)
    logger.error(f"Invalid KPIs: {', '.join(invalid_kpis)}. Valid KPIs are: {', '.join(valid_kpis)}")
    exit(1)

sns.set_theme(style='darkgrid')

class Global:
    colours = [
        "#0cad6f","#4582b1","#f4d06f","#c4603b","#c477bf"
    ]
    # source_palette = [
    #   "#2B9EC7",
    #   "#C66A50"
    # ]
    source_palette = {
        "Direct": "#2B9EC7",
        "Indirect": "#C66A50"
    }
    # #50ffb1, #3accc0, #2398ce, #145aa9, #041c83, #5b1878, #b1136d
    issues_palette = {
        "B1": "#50ffb1",
        "B2": "#3accc0",
        "B3": "#2398ce",
        "B4": "#145aa9",
        "B5": "#041c83",
        "B6": "#5b1878",
        "B7": "#b1136d"
    }
    dependency_palette = ["#30bbb9","#2badb1","#259faa","#2091a2","#1b849a","#157692","#10688b","#0a5a83","#054c7b"]

    class Colours:
        light_grey = "#c0c0c0"

def colour_to_rgb(colour: str):
    """
    Converts a colour to RGB
    """
    if colour.startswith('#'):
        colour = colour[1:]
    return tuple(int(colour[i:i+2], 16) for i in (0, 2, 4))

def rgb_to_colour(rgb: tuple):
    """
    Converts an RGB tuple to a colour
    """
    return "#{:02x}{:02x}{:02x}".format(*rgb)

def tone_colour(colour: str, factor: float):
    """
    Tone a colour by a factor
    """
    rgb = colour_to_rgb(colour)
    new_rgb = tuple(int(c * factor) for c in rgb)
    new_rgb = tuple(min(255, c) for c in new_rgb)
    return rgb_to_colour(new_rgb)

def plot_grouped_bar(*args):
    pass

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
    elif type(data) == set:
        if len(data) == 0:
            return []
        ls = list(data)
        if type(ls[0]) in [int, float, str]:
            return sorted(ls)
        return [ convert_datetime_to_str(entry) for entry in ls ]
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
    logger.info(f"Storing data to path '{path if type(path) == str else path.name}'...")
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

def get_version(release: str):
    """
    Gets the version numer from a release string <project>:<version>
    """
    try:
        parts = list(filter(bool, release.split(':')))
        return parts[1]
    except:
        return release

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
    for kpi in args.timeline:
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
        results = compute.timeline_kpis(data, *args.timeline)
        for kpi in args.timeline:
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
    for kpi in args.timeline:
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
        prefix = title_prefix.strip().lower().replace(' ', '-')
        prefix = f"timeline-{prefix}-" if prefix else "timeline-"
        fig.savefig(plots_dir / f"{prefix}{filename}.png")


def plot_overall_cve_distribution(overall: dict, *measurements: str):
    """
    Plots CVE distribution of an overall dictionary
    """
    # CVE distribution
    df: pd.DataFrame = pd.DataFrame()
    project_ids = sorted(list(overall.keys()))
    project_names = []
    for project_id in project_ids:
        platform, project_name = get_platform(project_id)
        project_names.append(project_name)
        data = overall[project_id]
        res = compute.cve_distribution(data, project_name)
        df = pd.concat([df, res], ignore_index=True)
    fig, axs = plt.subplots(1, len(project_ids), figsize=(10, 8))
    for i, project in enumerate(project_names):
        ax = axs[i]
        project_data = df[df['Project'] == project]
        sns.swarmplot(data=project_data,
                      x='Source',
                      y='CVSS Base Score',
                      ax=ax,
                      palette=Global.source_palette,
                      size=5)
        sns.violinplot(data=project_data,
                    x='Source',
                    y='CVSS Base Score',
                    ax=ax,
                    fill=False,
                    color=Global.Colours.light_grey,
                    cut=0)
        ax.set_title(project.title())
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        ax.set_ylim(0, 10.5)
        ax.set_yticks(np.arange(0, 11, 1))
    fig.suptitle("CVSS Base Score Distribution")
    fig.supxlabel("Project")
    fig.supylabel("CVSS Base Score")
    fig.savefig(plots_dir / 'overall-cve-distribution.png')

def plot_overall_cwe_distribution(overall: dict, *measurements: str):
    """
    Plots CWE distribution
    """
    df: pd.DataFrame = pd.DataFrame()
    cwe_count = {}
    project_ids = sorted(list(overall.keys()))
    project_names = []
    for project_id in  project_ids:
        platform, project_name = get_platform(project_id)
        project_names.append(project_name)
        data = overall[project_id]
        res: pd.DataFrame = compute.cwe_distribution(data, project_name)
        for cwe_id in res['CWE ID']:
            if cwe_id not in cwe_count:
                cwe_count[cwe_id] = 0
            cwe_count[cwe_id] += res[res['CWE ID'] == cwe_id]['CVE Count']
        df = pd.concat([df, res], ignore_index=True)
    fig, axs = plt.subplots(len(project_ids), 1, figsize=(10, 8))
    plt.subplots_adjust(hspace=0.5)
    for i, project in enumerate(project_names):
        ax: plt.Axes = axs[i]
        project_data = df[df['Project'] == project]
        project_data = project_data.sort_values(by='CVE Count', ascending=False)
        project_data = project_data.head(10)
        sns.barplot(data=project_data, x='CWE ID', y='CVE Count', ax=ax, color=Global.colours[i])
        max_count = max(project_data['CVE Count'])
        ylim = max_count + 1 if max_count > 10 else 5
        step = ylim // 5
        ax.set_ylim(0, ylim)
        ax.set_yticks(np.arange(0, ylim, step))
        ax.set_title(project.title())
        ax.set_xlabel(None)
        ax.set_ylabel(None)
    fig.suptitle("Top 10 CWEs by CVE Count")
    fig.supxlabel("CWE ID")
    fig.supylabel("CVE Count")
    fig.savefig(plots_dir / 'overall-cwe-distribution.png')

def plot_semver_cve_distribution(overall: dict, *measurements: str):
    """
    Plots the distribution of SemVer releases
    """
    project_ids = sorted(list(overall.keys()))
    project_names = []
    df: pd.DataFrame = pd.DataFrame()
    for project_id in project_ids:
        platform, project_name = get_platform(project_id)
        project_names.append(project_name)
        data = overall[project_id]
        res = compute.semver_cve_distribution(data, project_name)
        df = pd.concat([df, res], ignore_index=True)
    fig, axs = plt.subplots(len(project_ids), 1, figsize=(10, 8))
    fig.subplots_adjust(hspace=0.5)
    for i, project in enumerate(project_names):
        ax: plt.Axes = axs[i]
        project_data = df[df['Project'] == project]
        project_data = project_data.sort_values(by=['Major', 'Minor', 'Source'], ascending=True)
        max_version = project_data['Major'].max()
        project_unique: pd.DataFrame = project_data.copy()
        project_unique = project_unique.drop_duplicates(subset=['Major', 'CVE ID'])
        sns.swarmplot(data=project_unique, x='Major', y='CVSS Base Score', hue='Source', ax=ax, palette=Global.source_palette, zorder=2)
        sns.violinplot(data=project_unique, x='Major', y='CVSS Base Score', ax=ax, fill=False, color=Global.Colours.light_grey, cut=0, zorder=0)
        # ax2 = ax.twinx()
        # sns.countplot(data=project_unique, x='Major', ax=ax2, color=Global.Colours.light_grey, hue='Source', width=0.1, zorder=1)
        steps = 5
        ax.set_title(project.title())
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        ax.set_ylim(0, 10.5)
        ax.set_yticks(np.arange(0, 11, 11//steps))
        ax.set_xticks(np.arange(0, max_version+1, 1))
    fig.suptitle("Applicable CVEs by Major Semantic Version")
    fig.supxlabel("Major Semantic Version")
    fig.supylabel("CVSS Base Score")
    fig.savefig(plots_dir / 'semver-cve-distribution.png')
    # set right y-axis label

def plot_semver_bandit_distribution(overall: dict, *measurements: str):
    """
    Plots the distribution of Bandit issues
    """
    pass

def plot_overall(overall: dict, *measurements: str):
    """
    Expects a dictionary with the following structure:

    <project>: {
        'cves': { <cve-id>: {} },
        'cwes': { <cwe-id>: {} },
        'releases': { <release-id>: {} }
        'latest': {},
        'bandit': {
            'by_test'
            'by_cwe'
            'count'
        },
    }
    """
    # this will be more hard-coded plotting, given the wide variety of data

    logger.info(f"Plotting overall data for {len(overall)} projects...")
    # plotting the overall data
    plot_overall_cve_distribution(overall)
    plot_overall_cwe_distribution(overall)

    # TODO: overall time KPIs (time to fix, time to CVE publish)

    # TODO: scatter plot of CVEs, x-axis: exploitability, y-axis: impact
            

    # TODO: bar chart of CWE categories, sorted by number of vulnerabilities

    # TODO: KPIs per minor/major release (count, severity, impact, patch lag)
    plot_semver_cve_distribution(overall)

    # TODO: frequency plot of Bandit test ID issues

    # TODO: frequency plot of Bandit severity/confidence

    # TODO: bandit issues / nloc

    pass

def plot_bandit(bandit: dict):
    """
    Plots Bandit data.
    Expects a list of dictionaries of issues.

    {
        project: [ issues ]
    }
    """
    project_count = len(bandit)

    # plot the test category distribution
    fig_category, axs_category = plt.subplots(project_count, 1, figsize=(10, 8))
    fig_category.subplots_adjust(hspace=0.5)
    i = 0
    values = ['None', 'Low', 'Medium', 'High', 'Critical']
    for project_id, issues in bandit.items():
        ax: plt.Axes = axs_category[i]
        platform, project = get_platform(project_id)
        version = f":{issues[0]['project_version']}" if len(issues) > 0 and issues[0]['project'] == project else ''
        df = pd.DataFrame(issues)
        # sort the X-axis by the test category
        df = df.sort_values(by=['test_category', 'source'], ascending=True)
        df = df[ df['is_test'] == False ]
        sns.swarmplot(data=df, x='test_category', y='score', hue='source', ax=ax, palette=Global.source_palette)
        sns.violinplot(data=df, x='test_category', y='score', ax=ax, fill=False, color=Global.Colours.light_grey, cut=0)
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        ax.set_title(f"{project.title()}{version}")
        ax.set_yticks(range(len(values)), values)
        i += 1
    fig_category.suptitle("Bandit Test Category Distribution")
    fig_category.supxlabel("Test Category")
    fig_category.savefig(plots_dir / 'bandit-test-category-distribution.png')
    bandit_json = convert_datetime_to_str(bandit)

    fig_module, axs_module = plt.subplots(project_count, 1, figsize=(10, 8))
    fig_module.subplots_adjust(hspace=0.5)
    i = 0
    for project_id, issues in bandit.items():
        ax: plt.Axes = axs_module[i]
        platform, project = get_platform(project_id)
        version = f":{issues[0]['project_version']}" if len(issues) > 0 and issues[0]['project'] == project else ''
        df = pd.DataFrame(issues)
        # get unique filenames, test ids, and code snippets
        df = df[ df['is_test'] == False ]
        # count the number of issues per module
        total_count = df.groupby(['project_package']).size().reset_index(name='total_count')
        total_count = total_count.sort_values(by='total_count', ascending=False).head(10)
        # in df, drop the columns that are not in total_count
        df = df[df['project_package'].isin(total_count['project_package'])]
        unique_categories = df['test_category'].unique()
        unique_categories = sorted(unique_categories)
        df = df.groupby(['project_package', 'test_category']).size().reset_index(name='count')
        for project_package in total_count['project_package']:
            # add 0 counts for missing categories
            project_categories: pd.DataFrame = df[df['project_package'] == project_package]['test_category'].unique()
            for test_category in unique_categories:
                if test_category not in project_categories:
                    # add row
                    row = pd.DataFrame({
                        'project_package': [project_package],
                        'test_category': [test_category],
                        'count': [0]
                    })
                    df = pd.concat([df, row], ignore_index=True)
        df = df.merge(total_count, on='project_package', how='left')
        df = df.sort_values(by=['total_count', 'test_category'], ascending=[False, True])
        # top 10 packages
        sns.barplot(data=df, x='project_package', y='count', hue='test_category', ax=ax, palette=Global.issues_palette, width=0.5)
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        # set the legend title
        ax.legend(title='Test Category')
        # tilt the x-axis labels
        for tick in ax.get_xticklabels():
            tick.set_rotation(15)
            # set font size
            tick.set_fontsize(8)
        ax.set_title(f"{project.title()}{version}")
        i += 1
    fig_module.suptitle("Bandit Issues by Package")
    fig_module.supxlabel("Package")
    fig_module.supylabel("Issue Count")
    fig_module.savefig(plots_dir / 'bandit-module-distribution.png')

    try_json_dump(bandit_json, json_dir / 'bandit-distribution.json')

def combine_timeline_data(data: dict):
    """
    Combines timeline data to a single dictionary
    """
    pass

ag = Aggregator(args.config)
# load the projects, arguments are optional
ag.load_projects(*args.projects)

if __name__ == '__main__':

    # extract the files to present in the JSON
    # to be transparent about the data
    # usage of schema here, instead of Aggregator, as this is straight from the database
    files = nvd.NVDFile.select().order_by(nvd.NVDFile.created_at.desc())
    files = [ model_to_dict(file) for file in files ]
    files = convert_datetime_to_str(files)

    with open(json_dir / 'files.json', 'w') as f:
        json.dump(files, f, indent=4)
    
    if args.timeline:
    
        # timeline plot section
        timelines = {}
        for project in args.projects:
            # get timeline for each project
            platform, project = get_platform(project)
            logger.info(f"Getting timeline for {project} on {platform}...")
            timeline = ag.get_vulnerabilities_timeline(project,
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
                indirect_timelines = ag.get_indirect_vulnerabilities_timeline(project,
                                                                            start_date=args.start,
                                                                            end_date=args.end,
                                                                            step=args.step,
                                                                            platform=platform)
                dependency_timelines[f"{platform}:{project}"] = indirect_timelines
            plot_timelines(dependency_timelines, "Dependency")
            try_json_dump(dependency_timelines, json_dir / 'dependency_timelines.json')

    if args.overall:
        # get all the vulnerabilities for the projects
        # and plot them
        # 1) by CWE category
        # 2) by CWE weakness
        # 3) by severity
        # 4) by impact
        # 5) issues
        overall = {}
        bandit = {}
        for project in args.projects:
            # get all the vulnerabilities for the project
            platform, project = get_platform(project)
            bandit_issues = ag.get_bandit_issues(project, platform=platform, with_dependencies=True)
            project_id = f"{platform}:{project}"
            bandit[project_id] = bandit_issues
            logger.info(f"Getting overall data for {project} on {platform}...")
            data = ag.get_report(project, platform=platform, with_dependencies=True)
            overall[project_id] = data
            logger.info(f"Got {len(data.get('cves'))} CVEs for {project}")
            logger.info(f"Got {len(data.get('cwes'))} CWEs for {project}")
        plot_overall(overall)
        plot_bandit(bandit)
        try_json_dump(overall, json_dir / 'overall.json')

    if args.show:
        plt.show()
        
    # TODO: do the same above but for each dependencies
    
    # TODO: create LaTeX tables with the data

    # TODO: store the data in a JSON directory
        
    # TODO: plot complexity of code
    # include TIMESTAMP OF NVD FILE
    if args.show:
        plt.show()