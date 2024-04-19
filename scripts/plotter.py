import argparse, sys, time, pprint, json, datetime
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import src.utils.compute as compute
import src.utils.report as report
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
parser.add_argument('--debug', help='The debug level of the logger', action='store_true')
parser.add_argument('--show', help='Show the plots', action='store_true')
parser.add_argument('--dependencies', help="Generate plots for each project's dependencies as well", action='store_true')
parser.add_argument('--force', help='Force reload', action='store_true')

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

class Translate:
    test_category = {
        "B1": "B1: Miscellaneous",
        "B2": "B2: Miscofiguration",
        "B3": "B3: Blacklist calls",
        "B4": "B4: Blacklist imports",
        "B5": "B5: Cryptography",
        "B6": "B6: Injection",
        "B7": "B7: XSS",
    }

# TODO: Generate palette of releases that are not the project, but indirect ones, where the main project is "blue" and the indirect ones shades of "turquoise" or something

class Global:
    # #0BD095, #0B84E0, #2E099C
    LEGEND = {'fontsize': 'small', 'framealpha': 0.4, 'title_fontsize': 'small'}
    LEGEND_XS = {'fontsize': 'x-small', 'framealpha': 0.4, 'title_fontsize': 'x-small'}
    SUBPLOTS = {'hspace': 0.45, 'right': 0.95, 'left': 0.08}
    SUBPLOTS_2X = {'hspace': 0.45, 'wspace': 0.2, 'right': 0.95, 'left': 0.1}
    project_palette = {
        "total": "#9EBDC1",
        "Total": "#9EBDC1",
        "django": "#0BD095",
        "Django": "#0BD095",
        "flask": "#0B84E0",
        "Flask": "#0B84E0",
        "tornado": "#2E099C",
        "Tornado": "#2E099C"
    }
    release_palettes = {}
    colours_indirect = ["#00c48d","#00ced9","#0598f3","#865fe1","#b754d8"]
    source_palette = {
        "Direct": "#325B8B",
        False: "#325B8B",
        "Indirect": "#0BD095",
        True: "#0BD095"
    }
    # #50ffb1, #3accc0, #2398ce, #145aa9, #041c83, #5b1878, #b1136d
    test_category_palette = {
        "B1": "#50ffb1",
        "B2": "#3accc0",
        "B3": "#2398ce",
        "B4": "#145aa9",
        "B5": "#041c83",
        "B6": "#5b1878",
        "B7": "#b1136d"
    }

    class Colours:
        direct = "#165DA0"
        indirect = "#0BD095"
        light_grey = "#9EBDC1"

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

def release_colours(project_name: str, *releases: str):
    """
    Generates a palette of colours for releases
    """
    palette = {
        k: Global.Colours.light_grey for k in releases
    }
    palette['total'] = Global.Colours.light_grey
    for i, release in enumerate(releases):
        release = release.lower()
        if release == project_name.lower():
            palette[release] = Global.Colours.direct
        else:
            palette[release] = Global.colours_indirect[i % len(Global.colours_indirect)]
    return palette


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
            logger.info(f"Successfully stored data to path '{path.name}'")
    except Exception as e:
        logger.error(f"Could not store data to path '{path.name}': {e}")
        exit(1)

# set the logger level
logger.remove()
logger.add(sink=sys.stdout, level='INFO' if not args.debug else 'DEBUG')

output_dir = Path(args.output)
if not output_dir.exists():
    logger.error(f"Output directory '{output_dir}' does not exist, create it.")
    exit(1)

# create the subdirectories
json_dir = output_dir / 'json'
plots_dir = output_dir / 'plots'
csv_dir = output_dir / 'csv'
csv_dir.mkdir(exist_ok=True)
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

def set_transparency(ax: plt.Axes, alpha: float):
    """
    Sets the transparency of the plot
    """
    for art in ax.collections:
        art.set_alpha(alpha)


def plot_overall_cve_distribution(cves: pd.DataFrame):
    """
    Plots CVE distribution of an overall dictionary
    """
    project_names = sorted(list(cves['project'].unique()))
    project_count = len(project_names)

    fig, axs = plt.subplots(1, project_count, figsize=(10, 8))
    axs = [axs] if project_count == 1 else axs
    fig.subplots_adjust(**Global.SUBPLOTS)
    for i, project in enumerate(project_names):
        ax = axs[i]
        releases = sorted(list(cves[cves['project'] == project]['release'].unique()))
        if project not in Global.release_palettes:
            Global.release_palettes[project] = release_colours(project, *releases)
        palette = Global.release_palettes[project]
        project_df = cves[cves['project'] == project]
        project_df = project_df.drop_duplicates(subset=['release', 'cve_id'])
        sns.violinplot(project_df, y='cvss_base_score', ax=ax, color=Global.Colours.light_grey, cut=0, zorder=1)
        set_transparency(ax, 0.2)
        sns.swarmplot(project_df, y='cvss_base_score', hue="release", ax=ax, palette=palette, zorder=2)
        ax.set_title(project.title())
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        ax.set_ylim(0, 10.5)
        ax.set_yticks([0, 4, 7, 9, 10])
        # change legend title
        ax.legend(title='Source', **Global.LEGEND)
    fig.suptitle("Overall CVE Distribution")
    fig.supylabel("CVSS Base Score")
    fig.supxlabel("Project")
    fig.savefig(plots_dir / 'cve-overall.png')

    fig, axs = plt.subplots(project_count, 2, figsize=(10, 8))
    axs = [axs] if project_count == 1 else axs
    fig.subplots_adjust(**Global.SUBPLOTS_2X)
    for i, project in enumerate(project_names):
        axes = axs[i]
        ax = axes[0]
        ax2 = axes[1]
        palette = Global.release_palettes[project]
        project_df = cves[cves['project'] == project]
        project_df = project_df.drop_duplicates(subset=['source', 'cve_id'])
        sns.scatterplot(project_df, x='published_to_patched', y='cvss_base_score', hue="release", ax=ax, palette=palette)
        sns.kdeplot(project_df, x='published_to_patched', ax=ax2, color=Global.project_palette[project], fill=True)
        ax.set_title(project.title())
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        ax.set_ylim(0, 10.5)
        ax.set_yticks([0, 4, 7, 9, 10])
        # change legend title
        ax.legend(title='Source', **Global.LEGEND_XS)
        ax2.set_title(project.title())
        ax2.set_xlabel(None)
        ax2.set_ylabel(None)
        ax2.tick_params(axis='y', rotation=20, labelsize='x-small')
    fig.suptitle("CVE Patch Time and CVSS Base Score Distribution")
    fig.supxlabel("Days from Published to Patched")
    fig.supylabel("CVSS Base Score | Density")
    fig.savefig(plots_dir / 'cve-overall-lag-score.png')

def plot_overall_cwe_distribution(df: pd.DataFrame):
    """
    Plots CWE distribution
    """
    # guarantee uniqueness of the crucial columns
    df = df.drop_duplicates(subset=['project', 'release', 'cwe_id', 'cve_id']).copy()
    df = df[df['cwe_id'] != None]
    project_names = sorted(list(df['project'].unique()))
    project_count = len(project_names)
    fig, axs = plt.subplots(project_count, 1, figsize=(10, 8))
    plt.subplots_adjust(**Global.SUBPLOTS)
    for i, project in enumerate(project_names):
        ax: plt.Axes = axs[i]
        df_project = df[df['project'] == project]
        if project not in Global.release_palettes:
            releases = sorted(list(df_project['release'].unique()))
            Global.release_palettes[project] = release_colours(project, *releases)
        palette = Global.release_palettes[project]
        # cwe count distinct cve_id
        df_cwe_count = df_project.groupby(['cwe_id']).size().reset_index(name='count').copy()
        # sort by count descending
        df_cwe_count = df_cwe_count.sort_values(by='count', ascending=False)
        # take head
        df_cwe_count = df_cwe_count.head(10)
        df_unique = df_project[df_project['cwe_id'].isin(df_cwe_count['cwe_id'])]
        # drop the columns that are not in df_cwe_count
        df_unique = df_unique[df_unique['cwe_id'].isin(df_cwe_count['cwe_id'])]
        # add count
        df_unique = df_unique.groupby(['release', 'cwe_id']).size().reset_index(name='count')
        # add the 'total_count' column
        df_unique['total_count'] = df_unique['cwe_id'].map(df_cwe_count.set_index('cwe_id')['count'])
        # rename the 'release' to "total" for all rows in the cwe_count df
        df_unique = df_unique.sort_values(by=['total_count', 'release'], ascending=[False, True])
        # sort by count
        sns.barplot(data=df_unique, x='cwe_id', y='count', hue='release', ax=ax, palette=palette)
        sns.barplot(data=df_cwe_count, x='cwe_id', y='count', ax=ax, color=Global.Colours.light_grey, alpha=0.5, zorder=0)
        max_count = max(df_unique['total_count'])
        ylim = max_count + 1 if max_count > 10 else 5
        step = ylim // 5
        ax.set_ylim(0, ylim)
        ax.set_yticks(np.arange(0, ylim, step))
        ax.legend(title='Release', **Global.LEGEND)
        ax.set_title(project.title())
        ax.set_xlabel(None)
        ax.set_ylabel(None)
    fig.suptitle("Top 10 CWEs by CVE Count")
    fig.supxlabel("CWE ID")
    fig.supylabel("CVE Count")
    fig.savefig(plots_dir / 'overall-cwe-distribution.png')

def plot_semver_cve_distribution(cves: pd.DataFrame, *kpis: str):
    """
    Plots the distribution of SemVer releases
    """
    print(f"Attemping to plot {len(cves)} CVEs...")
    project_names = sorted(list(cves['project'].unique()))
    for kpi in ['cvss_base_score', 'published_to_patched']:
        # the first KPIs are CVE values
        kpi_filename = kpi.replace('_', '-')
        fig, axs = plt.subplots(len(project_names), 1, figsize=(10, 8))
        fig.subplots_adjust(**Global.SUBPLOTS)
        title = "Applicable CVEs by Major Semantic Version"
        ylabel = "CVSS Base Score"
        match kpi:
            case "published_to_patched":
                title = "CVEs Published to Patched by Major Semantic Version"
                ylabel = "Days"
        for i, project in enumerate(project_names):
            ax: plt.Axes = axs[i]
            project_data = cves[cves['project'] == project]
            project_data = project_data.sort_values(by=['major', 'source'], ascending=True)
            max_version = project_data['major'].max()
            project_unique: pd.DataFrame = project_data.copy()
            # ensure that the same CVE is not counted twice
            project_unique = project_unique.drop_duplicates(subset=['major', 'cve_id'])
            sns.violinplot(data=project_unique, x='major', y=kpi, ax=ax, fill=False, color=Global.Colours.light_grey, cut=0, zorder=0)
            sns.swarmplot(data=project_unique, x='major', y=kpi, hue='source', ax=ax, palette=Global.source_palette, zorder=1)
            steps = 5
            ax.set_title(project.title())
            ax.set_xlabel(None)
            ax.set_xticks(np.arange(0, max_version+1, 1))
            ax.set_ylabel(None)
            if kpi.startswith('cvss'):
                ax.set_ylim(0, 10.5)
                ax.set_yticks(np.arange(0, 11, 11//steps))
        fig.suptitle(title)
        fig.supxlabel("Major Semantic Version")
        fig.supylabel(ylabel)
        fig.savefig(plots_dir / f'semver-cve-distribution-{kpi_filename}.png')
    # set right y-axis label
    fig_lag, axs_lag = plt.subplots(len(project_names), 1, figsize=(10, 8))
    fig_lag.subplots_adjust(**Global.SUBPLOTS)
    for i, project in enumerate(project_names):
        ax: plt.Axes = axs_lag[i]
        project_data = cves[cves['project'] == project]
        project_data = project_data.sort_values(by=['major', 'source'], ascending=True)
        max_version = project_data['major'].max()
        project_unique: pd.DataFrame = project_data.copy()
        # ensure that the same CVE is not counted twice
        project_unique = project_unique.drop_duplicates(subset=['major', 'cve_id'])
        project_unique = project_unique[project_unique['technical_lag'] == True]
        project_unique = project_unique.groupby(['major']).size().reset_index(name='count')
        sns.barplot(data=project_unique, x='major', y='count', ax=ax, color=Global.project_palette[project], zorder=0)
        steps = 5
        ax.set_title(project.title())
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        ax.set_yticks(np.arange(0, 11, 11//steps))
        ax.set_xticks(np.arange(0, max_version+1, 1))
    fig_lag.suptitle("CVEs Introduced by Technical Lag")
    fig_lag.supxlabel("Major Semantic Version")
    fig_lag.supylabel("Count")

def plot_issues(issues: pd.DataFrame):
    """
    Expects an issue-centred DataFrame
    """
    projects = sorted(list(issues['project'].unique()))
    project_count = len(projects)

    issues = issues[issues['is_test'] == False]

    # plot the test category distribution
    fig_category, axs_category = plt.subplots(project_count, 1, figsize=(10, 8))
    fig_category.subplots_adjust(**Global.SUBPLOTS)
    i = 0
    values = ['None', 'Low', 'Medium', 'High', 'Critical']
    for project in projects:
        ax: plt.Axes = axs_category[i]
        df = issues[issues['project'] == project].copy()
        releases = sorted(list(df['release'].unique()))
        palette = release_colours(project, *releases)
        version = df['project_version'].unique()[0]
        order = [project]
        for release in releases:
            if release != project:
                order.append(release)
        # sort the X-axis by the test category
        df = df.sort_values(by=['test_category', 'release'], ascending=True)
        df = df[ df['is_test'] == False ]
        sns.swarmplot(data=df, x='test_category', y='score', hue='release', ax=ax, palette=palette, hue_order=order)
        sns.violinplot(data=df, x='test_category', y='score', ax=ax, fill=False, color=Global.Colours.light_grey, cut=0)
        unique_categories = df['test_category'].unique()
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        ax.set_title(f"{project.title()}:{version}")
        ax.set_yticks(range(len(values)), values)
        i += 1
    fig_category.suptitle("Bandit Test Category Distribution")
    fig_category.supxlabel("Test Category")
    fig_category.savefig(plots_dir / 'bandit-test-category-distribution.png')

    fig_module, axs_module = plt.subplots(project_count, 1, figsize=(10, 8))
    fig_module.subplots_adjust(**Global.SUBPLOTS)
    i = 0
    for project in projects:
        ax: plt.Axes = axs_module[i]
        df = issues[issues['project'] == project].copy()
        version = df['project_version'].unique()[0]
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
        # translate the test category
        df = df.merge(total_count, on='project_package', how='left')
        df = df.sort_values(by=['total_count', 'test_category'], ascending=[False, True])
        # top 10 packages
        sns.barplot(data=df, x='project_package', y='count', hue='test_category', ax=ax, palette=Global.test_category_palette, width=0.5)
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        # set the legend title
        ax.legend(title='Test Category', **Global.LEGEND)
        # tilt the x-axis labels
        for tick in ax.get_xticklabels():
            tick.set_rotation(15)
            # set font size
            tick.set_fontsize(8)
        ax.set_title(f"{project.title()}{version}")
        i += 1
    fig_module.suptitle("Top 10 Package Bandit Issue Distribution")
    fig_module.supxlabel("Package")
    fig_module.supylabel("Issue Count")
    fig_module.savefig(plots_dir / 'bandit-module-distribution.png')

def combine_timeline_data(data: dict):
    """
    Combines timeline data to a single dictionary
    """
    pass

ag = Aggregator(args.config)
# load the projects, arguments are optional
ag.load_projects(*args.projects)

def get_argument(arg: str):
    """
    Gets the argument from the command line
    """
    if ':' in arg:
        parts = list(filter(bool, arg.split(':')))
        return parts[0], parts[1] if len(parts) > 1 else None
    return arg, None

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
        # TODO: update with new dataframe functions
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
        cves_df = pd.DataFrame()
        cves_overall_df = pd.DataFrame()
        issues_df = pd.DataFrame()
        static_df = pd.DataFrame()
        cve_overall_path = csv_dir / 'cves_overall.csv'
        cve_path = csv_dir / 'cves.csv'
        static_path = csv_dir / 'static.csv'
        issues_path = csv_dir / 'issues.csv'
        if not args.force:
            if static_path.exists():
                try:
                    static_df = pd.read_csv(static_path)
                except:
                    pass
            if cve_overall_path.exists():
                try:
                    cves_overall_df = pd.read_csv(cve_overall_path)
                except:
                    pass
            if cve_path.exists():
                try:
                    cves_df = pd.read_csv(cve_path)
                except:
                    pass
            if issues_path.exists():
                try:
                    issues_df = pd.read_csv(issues_path)
                except:
                    pass
        project_names = []
        for project in args.projects:
            platform, project_name = get_platform(project)
            proj = ag.get_project(project, platform)
            project_names.append(project_name)
            if proj is None:
                logger.error(f"Could not find project '{project}' on platform '{platform}'")
                continue
            latest_analysed = ag.get_release(project, platform, analysed=True)
            if cves_overall_df.empty or project_name not in cves_overall_df['project'].unique():
                df = ag.df_cves_per_project(project, platform, by_cwe=True)
                # get published_to_patched
                cves_overall_df = pd.concat([cves_overall_df, df], ignore_index=True)
            if cves_df.empty or project_name not in cves_df['project'].unique():
                df = ag.df_cves(project, platform)
                cves_df = pd.concat([cves_df, df], ignore_index=True)
            project_id = f"{platform}:{project}"
            # df = ag.df_cves(project, platform, by_cwe=True)
            # cwes_df = pd.concat([cwes_df, df], ignore_index=True)
            # df = ag.df_static(project, platform)
            # get only the latest analysed version
            # df = df[df['project_version'] == latest_analysed.version]
            # static_df = pd.concat([static_df, df], ignore_index=True)
            if issues_df.empty or project_name not in issues_df['project'].unique():
                df = ag.df_static(project, platform, with_issues=True, only_latest=True)
                issues_df = pd.concat([issues_df, df], ignore_index=True)
        cves_df.to_csv(cve_path, index=False)
        issues_df.to_csv(issues_path, index=False)
        static_df.to_csv(static_path, index=False)
        cves_overall_df.to_csv(cve_overall_path, index=False)

        # generate reports of the overall findings to explain the plots
        rep = report.cve_report(cves_overall_df)
        try_json_dump(rep, json_dir / 'cve_report.json')

        # work-in-progress "report" generation (explanation of results)
        plot_semver_cve_distribution(cves_df)
        cves_without_cwes = cves_overall_df.drop_duplicates(subset=['project', 'release', 'cve_id']).copy()
        plot_overall_cve_distribution(cves_without_cwes)
        plot_overall_cwe_distribution(cves_overall_df)
        plot_issues(issues_df)

    if args.show:
        plt.show()
        
    if args.show:
        plt.show()