import argparse, sys, time, pprint, json, datetime, re
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import depsec.utils.compute as compute
import depsec.utils.tools as tools
from copy import deepcopy
from pprint import pprint
from pathlib import Path
from depsec.aggregator import Aggregator
import depsec.schemas.nvd as nvd
from loguru import logger
from depsec.schemas.projects import *
# model_to_dict translates PeeWee models to dictionaries for JSON serialisation
# the purpose is to make the data that have produced the plots available to readers of the report
from playhouse.shortcuts import model_to_dict

def titlize(df: pd.DataFrame):
    """
    Titlize the columns of a DataFrame
    """
    if type(df) in [list, dict]:
        df = pd.DataFrame(df)
    df = df.copy()
    cols = df.columns
    cols = {
        col: col.replace('_', ' ').title() for col in cols
    }
    df = df.rename(columns=cols)
    return df

def to_latex(df: pd.DataFrame, file: str | Path, *to_keep: str,  **columns):
    """
    To LaTeX
    """
    df = df.copy()
    if len(to_keep) > 0:
        df = df[to_keep]
    def apprange(x):
        x = x.replace('[', '$[')
        x = x.replace(']', ']$')
        x = x.replace('(', '$(')
        x = x.replace(')', ')$')
        return x
    perc = lambda x: x.replace('%', '\\%') if type(x) == str else x
    lambdas = {
        'verb': lambda x: f"\\texttt{{{x}}}",
        'bold': lambda x: f"\\textbf{{{x}}}",
        'math': lambda x: f"${perc(x)}$",
        'app': apprange
    }
    # only keep the columns that are in the columns
    if len(columns) > 0:
        for col in columns:
            lmbd = lambdas.get(columns[col], None)
            if lmbd:
                df[col] = df[col].apply(lmbd)
    cols = df.columns
    cols = {
        col: col.title() for col in cols
    }
    df = df.rename(columns=cols)
    with open(file, 'w') as f:
        f.write(df.to_latex(index=False))

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
overall_keys = set(args.overall)

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
    SUBPLOTS_3X = {'hspace': 0.45, 'wspace': 0.25, 'right': 0.95, 'left': 0.1}
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

for project in args.projects:
    if project not in Global.project_palette:
        Global.project_palette[project] = Global.Colours.light_grey

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

def barplot_labels(ax: plt.Axes, fontsize: str = 'small'):
    """
    Adds labels to a barplot
    """
    for i in ax.containers:
        # round the value to 2 decimal places
        ax.bar_label(i, label_type='edge', fontsize=fontsize)

def adjust_labels(ax: plt.Axes, axis: str = 'x', rotation: int = 45, fontsize: int = 8):
    """
    Rotates the labels of the x-axis
    """
    labels = ax.get_xticklabels() if axis == 'x' else ax.get_yticklabels()
    for tick in labels:
        tick.set_rotation(rotation)
        tick.set_fontsize(fontsize)

def add_stats(df: pd.DataFrame, groupby: list, *columns: str):
    """
    Adds the mean of a column to the DataFrame
    """
    df = df.copy()
    for column in columns:
        col = df.groupby(groupby)[column]
        mean = col.transform('mean')
        median = col.transform('median')
        mx = col.transform('max')
        mn = col.transform('min')
        sm = col.transform('sum')
        df[f"{column}_mean"] = mean
        df[f"{column}_median"] = median
        df[f"{column}_max"] = mx
        df[f"{column}_min"] = mn
        df[f"{column}_sum"] = sm
    return df

def add_count(df: pd.DataFrame, groupby: list, id: str = None, name='count'):
    """
    Adds a count column to the DataFrame based on a groupby, named 'count'
    """
    unique = groupby + [id] if id is not None else groupby
    df_copy = df.copy().drop_duplicates(subset=unique).groupby(groupby).size().reset_index(name=name)
    df = df.merge(df_copy, on=groupby, how='left')
    return df

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
tex_dir = output_dir / 'tex'
table_dir = output_dir / 'tables'
plots_dir = output_dir / 'plots'
csv_dir = output_dir / 'csv'
tex_dir.mkdir(exist_ok=True)
table_dir.mkdir(exist_ok=True)
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


def split_severity(df: pd.DataFrame):
    """
    Returns the critical, high, medium, and low severity CVEs
    """
    df = df.copy()
    critical = df[df['cvss_base_score'] >= 9]
    high = df[(df['cvss_base_score'] >= 7) & (df['cvss_base_score'] < 9)]
    medium = df[(df['cvss_base_score'] >= 4) & (df['cvss_base_score'] < 7)]
    low = df[(df['cvss_base_score'] >= 0) & (df['cvss_base_score'] < 4)]
    return critical, high, medium, low

def split_impact(df: pd.DataFrame):
    """
    Returns tuples of low and high impact for confidentiality, integrity, and availability,
    in that order
    """
    result = []
    for term in ['confidentiality', 'integrity', 'availability']:
        kpi = f"cvss_{term}_impact"
        df[kpi] = df[kpi].map(compute.impact_to_int)
        low = df[df[kpi] == 1]
        high = df[df[kpi] == 2]
        result.append((low, high))
    return tuple(result)

def percentage(x: int, *totals: int, suffix: str = ''):
    """
    Returns the percentage of x from total
    """
    if x is None:
        return ''
    elif x == 0:
        return f"$0$"
    percs = []
    for total in totals:
        percs.append(f"${(x / (total or 1)) * 100:.2f}\%$")
    percs = ', '.join(percs) if percs else ''
    percs = f" ({percs})" if percs else ''
    suffix = f" {suffix.strip()}" if suffix else ''
    return f"${x}${percs}{suffix}"

def verbatim(x: str):
    """
    Returns the verbatim of x
    """
    return f"\\texttt{{{x}}}"

def count_cves(df: pd.DataFrame):
    """
    Counts the number of CVEs
    """
    return df['cve_id'].nunique()

def count_severity(df: pd.DataFrame):
    """
    Counts the number of CVEs by severity
    """
    critical, high, medium, low = split_severity(df)
    return count_cves(critical), count_cves(high), count_cves(medium), count_cves(low)

def plot_cves(df: pd.DataFrame):
    """
    Plots CVE distribution of an overall dictionary
    """
    project_names = sorted(list(df['project'].unique()))
    project_count = len(project_names)

    for project in project_names:
        releases = sorted(list(df[df['project'] == project]['release'].unique()))
        if project not in Global.release_palettes:
            Global.release_palettes[project] = release_colours(project, *releases)

    cves: pd.DataFrame = df.copy().drop_duplicates(subset=['project', 'release', 'cve_id'])

    # Overall CVE Distribution
    fig, axs = plt.subplots(1, project_count, figsize=(10, 8))
    axs = [axs] if project_count == 1 else axs
    fig.subplots_adjust(**Global.SUBPLOTS)
    dfs = []
    df_cia = []
    for i, project in enumerate(project_names):
        ax = axs[i]
        releases = sorted(list(cves[cves['project'] == project]['release'].unique()))
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
        # table
        total_count = project_df['cve_id'].nunique()
        for release in releases:
            release_df = project_df.copy()[project_df['release'] == release]
            release_count = release_df['cve_id'].nunique()
            critical, high, medium, low = split_severity(release_df)
            critical_count = critical['cve_id'].nunique()
            high_count = high['cve_id'].nunique()
            medium_count = medium['cve_id'].nunique()
            low_count = low['cve_id'].nunique()
            confidentiality, integrity, availability = split_impact(release_df)
            conf_low, conf_high = confidentiality
            integrity_low, integrity_high = integrity
            availability_low, availability_high = availability
            cl_count = conf_low['cve_id'].nunique()
            ch_count = conf_high['cve_id'].nunique()
            il_count = integrity_low['cve_id'].nunique()
            ih_count = integrity_high['cve_id'].nunique()
            al_count = availability_low['cve_id'].nunique()
            ah_count = availability_high['cve_id'].nunique()
            dfs.append({
                'project': verbatim(project),
                'release': verbatim(release),
                'count': percentage(release_count, total_count),
                'critical': percentage(critical_count, total_count),
                'high': percentage(high_count, total_count),
                'medium': percentage(medium_count, total_count),
                'low': percentage(low_count, total_count)
            })
            confstr = [cl_count and percentage(cl_count, total_count, suffix='low'), ch_count and percentage(ch_count, total_count, suffix='high')]
            intstr = [il_count and percentage(il_count, total_count, suffix='low'), ih_count and percentage(ih_count, total_count, suffix='high')]
            avstr = [al_count and percentage(al_count, total_count, suffix='low'), ah_count and percentage(ah_count, total_count, suffix='high')]
            confstr = list(filter(bool, confstr))
            intstr = list(filter(bool, intstr))
            avstr = list(filter(bool, avstr))
            df_cia.append({
                'project': verbatim(project),
                'release': verbatim(release),
                'confidentiality': ', '.join(confstr) or '$0$',
                'integrity': ', '.join(intstr) or '$0$',
                'availability': ', '.join(avstr) or '$0$'
            })
    dfs = titlize(dfs)
    dfs.to_latex(table_dir / 'cve-distribution.tex', index=False, caption="CVE Distribution by Severity", label="tab:cve-distribution")
    df_cia = titlize(df_cia)
    df_cia.to_latex(table_dir / 'cve-cia-distribution.tex', index=False, caption="CVE Distribution by CIA Impact", label="tab:cve-cia-distribution")
    fig.suptitle("Overall CVE Distribution")
    fig.supylabel("CVSS Base Score")
    fig.supxlabel("Project")
    fig.savefig(plots_dir / 'cve.png')

    # Patch Time
    lag: pd.DataFrame = df.copy().drop_duplicates(subset=['project', 'release', 'cve_id', 'version_end'])
    fig, axs = plt.subplots(project_count, 2, figsize=(10, 8))
    axs = [axs] if project_count == 1 else axs
    fig.subplots_adjust(**Global.SUBPLOTS_2X)
    for i, project in enumerate(project_names):
        axes = axs[i]
        ax = axes[0]
        ax2 = axes[1]
        palette = Global.release_palettes[project]
        project_df = lag[lag['project'] == project]
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
    fig.savefig(plots_dir / 'cve-patch-time.png')

    return # end of plot_cves, the rest is work-in-progress
    # Confidentiality, Integrity, Availability
    cves: pd.DataFrame = df.copy().drop_duplicates(subset=['project', 'release', 'cve_id'])
    fig, axs = plt.subplots(project_count, 1, figsize=(10, 8))
    fig.subplots_adjust(**Global.SUBPLOTS)
    xlabels = {
        'confidentiality': 0,
        'integrity': 1,
        'availability': 2
    }
    for i, project in enumerate(project_names):
        ax = axs[i]
        project_df = cves[cves['project'] == project]
        dtmp = pd.DataFrame()
        for term in ['confidentiality', 'integrity', 'availability']:
            # map impact to value
            kpi = f"cvss_{term}_impact"
            project_df[kpi] = project_df[kpi].map(compute.impact_to_int)
            d = project_df.copy()
            d['kpi'] = term
            d['score'] = d[kpi]
            # keep only "kpi", "score", "project", and "release"
            dtmp = pd.concat([dtmp, d[['project', 'release', 'kpi', 'score']]], ignore_index=True)
        # sort x-axis by Confidentiality, Integrity, Availability
        dtmp = dtmp.sort_values(by='kpi', key=lambda x: x.map(xlabels))
        sns.swarmplot(data=dtmp, x='kpi', y='score', hue='release', ax=ax, palette=Global.release_palettes[project])
        sns.violinplot(data=dtmp, x='kpi', y='score', ax=ax, color=Global.Colours.light_grey, cut=0)
        ax.set_title(project.title())
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        ax.set_yticks([0, 1, 2], ['None', 'Low', 'High'])
    fig.suptitle("CVE CIA Impact Distribution")
    fig.supxlabel("Impact")
    fig.supylabel("CVSS Impact Score")
    fig.savefig(plots_dir / 'cve-cia.png')

def top_cwe(df: pd.DataFrame, n: int = 10):
    """
    Computes the top N CWEs
    """
    df_top_n = df.groupby(['cwe_id']).size().reset_index(name='count').copy()
    # sort by count descending
    df_top_n = df_top_n.sort_values(by='count', ascending=False)
    # take head
    df_top_n = df_top_n.head(n)
    df_unique = df[df['cwe_id'].isin(df_top_n['cwe_id'])]
    # drop the columns that are not in df_top_n
    df_unique = df_unique[df_unique['cwe_id'].isin(df_top_n['cwe_id'])]
    # add count
    df_unique = df_unique.groupby(['release', 'cwe_id']).size().reset_index(name='count')
    # add the 'total_count' column
    df_unique['total_count'] = df_unique['cwe_id'].map(df_top_n.set_index('cwe_id')['count'])
    # rename the 'release' to "total" for all rows in the cwe_count df
    df_unique = df_unique.sort_values(by=['total_count', 'release'], ascending=[False, True])
    return df_top_n, df_unique

def score_to_label(score: float):
    """
    Converts a score to a label
    """
    if score >= 9:
        return 'Critical'
    elif score >= 7:
        return 'High'
    elif score >= 4:
        return 'Medium'
    return 'Low'

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
    fig_sev, axs_sev = plt.subplots(project_count, 1, figsize=(10, 8))
    plt.subplots_adjust(**Global.SUBPLOTS)
    # for LaTeX
    df_tex = []
    columns = ['project', 'release', 'cve_id', 'cwe_id', 'part', 'cvss_base_score']
    n = 25
    df_sev = df.copy()
    df_sev = df_sev[(df_sev['cwe_id'].isna() == False)]
    df_sev = df_sev.sort_values(by='cvss_base_score', ascending=False)
    df_sev['cvss_base_score'] = df_sev['cvss_base_score'].map(lambda x : f"${x:.1f}$")
    df_sev['cwe_id'] = df_sev['cwe_id'].map(verbatim)
    df_sev['part'] = df_sev['part'].map(verbatim)
    df_sev['project'] = df_sev['project'].map(verbatim)
    df_sev['release'] = df_sev['release'].map(verbatim)
    df_sev = df_sev.drop_duplicates(subset=['cve_id'])
    df_sev = df_sev.head(n)
    df_sev = df_sev[columns]
    for i, project in enumerate(project_names):
        ax: plt.Axes = axs[i]
        ax_sev: plt.Axes = axs_sev[i]
        df_project = df[df['project'] == project]
        # get most severe
        # to get the total count of CVEs for reporting
        cves_total = df_project['cve_id'].nunique()
        if project not in Global.release_palettes:
            releases = sorted(list(df_project['release'].unique()))
            Global.release_palettes[project] = release_colours(project, *releases)
        palette = Global.release_palettes[project]
        # cwe count distinct cve_id
        df_top_10, df_unique = top_cwe(df_project, 10)
        # sort by count
        sns.barplot(data=df_unique, x='cwe_id', y='count', hue='release', ax=ax, palette=palette)
        sns.barplot(data=df_top_10, x='cwe_id', y='count', ax=ax, color=Global.Colours.light_grey, alpha=0.5, zorder=0)

        df_sev_top_10 = df_project[df_project['cwe_id'].isin(df_top_10['cwe_id'])].copy()
        # set total_count using loc
        df_sev_top_10['total_count'] = df_sev_top_10['cwe_id'].map(df_top_10.set_index('cwe_id')['count'])
        df_sev_top_10 = df_sev_top_10.sort_values(by=['total_count'], ascending=False)
        sns.violinplot(data=df_sev_top_10, x='cwe_id', y='cvss_base_score', ax=ax_sev, color=Global.Colours.light_grey, cut=0, zorder=1)
        set_transparency(ax_sev, 0.2)
        sns.swarmplot(data=df_sev_top_10, x='cwe_id', y='cvss_base_score', ax=ax_sev, color=Global.Colours.direct, zorder=2)

        ax_sev.set_yticks([0, 4, 7, 9, 10])
        ax_sev.set_title(project.title())
        ax_sev.set_xlabel(None)
        ax_sev.set_ylabel(None)

        max_count = max(df_unique['total_count'])
        ylim = max_count + 1 if max_count > 10 else 5
        step = ylim // 5
        ax.set_ylim(0, ylim)
        ax.set_yticks(np.arange(0, ylim, step))
        ax.legend(title='Release', **Global.LEGEND)
        ax.set_title(project.title())
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        # add the confidentiality, integrity, and availability scores
        # TODO: Show the TOP 10 CWEs by each CIA impact
        # create table to LaTeX
        cwe_ids = df_top_10['cwe_id'].unique()
        for cwe_id in cwe_ids:
            cwe_df = df_project[df_project['cwe_id'] == cwe_id].copy()
            count = cwe_df['cve_id'].nunique()
            critical, high, medium, low = count_severity(cwe_df)
            cwe_df['cvss_confidentiality_impact'] = cwe_df['cvss_confidentiality_impact'].map(compute.impact_to_int)
            cwe_df['cvss_integrity_impact'] = cwe_df['cvss_integrity_impact'].map(compute.impact_to_int)
            cwe_df['cvss_availability_impact'] = cwe_df['cvss_availability_impact'].map(compute.impact_to_int)
            # confidentiality_count = cwe_df[cwe_df['cvss_confidentiality_impact'] >= 1]['cve_id'].nunique()
            # integrity_count = cwe_df[cwe_df['cvss_integrity_impact'] >= 1]['cve_id'].nunique()
            # availability_count = cwe_df[cwe_df['cvss_availability_impact'] >= 1]['cve_id'].nunique()
            df_tex.append({
                'project': verbatim(project),
                'cwe_id': verbatim(cwe_id),
                'count': percentage(count, cves_total),
                'total_count': count,
                'low': percentage(low, cves_total, count),
                'medium': percentage(medium, cves_total, count),
                'high': percentage(high, cves_total, count),
                'critical': percentage(critical, cves_total, count),
            })
    df_tex = pd.DataFrame(df_tex)
    df_tex = df_tex.sort_values(by=['project', 'total_count'], ascending=[True, False])
    df_tex = df_tex.drop(columns=['total_count'])
    df_tex = titlize(df_tex)
    df_tex.to_latex(table_dir / 'cwe-distribution.tex', index=False, caption="Severity by Top 10 CWE", label="tab:cwe-distribution")
    # create 'source' column, where 'release' is the source if 'part' is None or '-'
    df_sev['source'] = df_sev['part']
    idx = df_sev[(df_sev['source'] == None) | (df_sev['source'] == '-')].index
    print(idx)
    # overwrite 'source' with 'release' on idx
    df_sev.loc[idx, 'source'] = df_sev.loc[idx, 'release']
    df_sev = df_sev.drop(columns=['release', 'part'])
    df_sev = titlize(df_sev)
    df_sev.to_latex(table_dir / 'most-severe-cwe.tex', index=False, caption=f"Top {n} Severe CVEs", label="tab:most-severe-cwe")
    fig.suptitle("Top 10 CWEs by CVE Count")
    fig.supxlabel("CWE ID")
    fig.supylabel("CVE Count")
    fig.savefig(plots_dir / 'overall-cwe-distribution.png')

    fig_sev.suptitle("Top 10 CWEs Severity")
    fig_sev.supxlabel("CWE ID")
    fig_sev.supylabel("CVSS Base Score")
    fig_sev.savefig(plots_dir / 'cwe-top-10-severity.png')

def plot_semver(df: pd.DataFrame, static_df: pd.DataFrame):
    """
    Plots the distribution of SemVer releases
    """
    print(f"Attemping to plot {len(df)} CVEs...")
    project_names = sorted(list(df['project'].unique()))
    cves = df.copy()
    fig, axs = plt.subplots(len(project_names), 3, figsize=(10, 8))
    fig.subplots_adjust(**Global.SUBPLOTS_3X)
    for i, project in enumerate(project_names):
        axss: plt.Axes = axs[i]
        ax_cves_per_nloc = axss[1]
        ax_cve_count = axss[0]
        ax_nloc = axss[2]
        axss[1].set_title(f"{project.title()}")
        sdf = static_df[static_df['project'] == project].drop_duplicates(subset=['project', 'release', 'major', 'release_version']).copy()
        sdf = sdf[sdf['nloc_total'] >= 0]
        idx = sdf.groupby(['project', 'release', 'major'])['nloc_total'].idxmax()
        # sdf is the static data for the project
        sdf = sdf.loc[idx]
        pdf = cves[cves['project'] == project]
        count_col = 'cve_count'
        pdf = add_count(pdf, ['project', 'major', 'release'], 'cve_id', count_col)
        # for each release not in the project, add a row with 0 CVEs
        max_version = max(pdf['major'])
        for i in range(1, max_version+1):
            releases = list(sdf[sdf['major'] == i]['release'].unique())
            rels = pdf[pdf['major'] == i]['release'].unique()
            for rel in releases:
                if rel not in rels:
                    srow = sdf[(sdf['major'] == i) & (sdf['release'] == rel)].copy()
                    srow[count_col] = 0
                    pdf = pd.concat([pdf, srow], ignore_index=True)
        
        for i, row in pdf[pdf['nloc_total'].isna()].iterrows():
            release = row['release']
            major = row['major']
            srow = sdf[(sdf['release'] == release) & (sdf['major'] == major)].copy()
            # upate the nloc_total
            pdf.loc[i, 'nloc_total'] = srow['nloc_total'].values[0]
        
        # get the CVE count per major version
        if project not in Global.release_palettes:
            releases = sorted(list(pdf['release'].unique()))
            rels = []
            for release in releases:
                if release in pdf[pdf['cve_count'] > 0]['release'].unique():
                    rels.append(release)
            Global.release_palettes[project] = release_colours(project, *rels)
        palette = Global.release_palettes[project]
        releases = sdf['release'].unique()
        for rel in releases:
            # make release colour in palette grey if it has 0 CVEs
            majors = pdf[pdf['release'] == rel]['major'].unique()
            dtmp = pdf[(pdf['release'] == rel) & (pdf['cve_count'] == 0)]
            if dtmp['major'].unique().size == majors.size:
                pdf.loc[pdf['release'] == rel, 'release'] = 'other'
                palette['other'] = Global.Colours.light_grey
        
        for major in pdf['major'].unique():
            # drop duplicates
            other_nloc_sum = pdf[(pdf['major'] == major) & (pdf['release'] == 'other')]['nloc_total'].sum()
            # overwrite value
            pdf.loc[(pdf['major'] == major) & (pdf['release'] == 'other'), 'nloc_total'] = other_nloc_sum

        pdf['cves_per_nloc'] = 10000 * pdf['cve_count'] / pdf['nloc_total']
        # round the cves_per_nloc to 2 decimal places
        idx = pdf.groupby(['project', 'major', 'release'])['cve_count'].idxmax()
        pdf = pdf.loc[idx]
        pdf['cves_per_nloc'] = pdf['cves_per_nloc'].round(1)

        # drop the 0 CVEs
        not_other = pdf[pdf['release'] != 'other']
        sns.barplot(data=not_other, x='major', y=count_col, hue='release', ax=ax_cve_count, palette=palette)
        barplot_labels(ax_cve_count)
        sns.barplot(data=not_other, x='major', y='cves_per_nloc', hue='release', ax=ax_cves_per_nloc, palette=palette)
        barplot_labels(ax_cves_per_nloc)
        sns.lineplot(data=pdf, x='major', y='nloc_total', hue='release', ax=ax_nloc, palette=palette)

        ax_cves_per_nloc.set_xticks(np.arange(0, max_version+1, 1))
        ax_cves_per_nloc.set_ylabel(None)
        ax_cves_per_nloc.legend(title='Release', **Global.LEGEND_XS)
        ax_cves_per_nloc.set_xlabel(None)
        ax_cve_count.legend(title='Release', **Global.LEGEND_XS)
        ax_cve_count.set_xticks(np.arange(0, max_version+1, 1))
        ax_cve_count.set_xlabel(None)
        ax_cve_count.set_ylabel(None)
        ax_nloc.legend(title='Release', **Global.LEGEND_XS)
        ax_nloc.set_xticks(np.arange(0, max_version+1, 1))
        ax_nloc.set_xlim(0.9, max_version+0.1)
        ax_nloc.set_xlabel(None)
        ax_nloc.set_ylabel(None)
        adjust_labels(ax_nloc, axis='y', rotation=20, fontsize=8)


    fig.suptitle("CVEs per 10,000 NLOC per Major Semantic Version")
    fig.supxlabel("Major Semantic Version")
    fig.supylabel("CVE Count | CVEs per 10,000 NLOC | NLOC")
    fig.savefig(plots_dir / f'cves-per-nloc-semver.png')

def split_issue_score(df: pd.DataFrame):
    """
    Returns the critical, high, medium, and low severity issues
    """
    df = df.copy()
    critical = df[df['score'] == 4]
    high = df[df['score'] == 3]
    medium = df[df['score'] == 2]
    low = df[df['score'] == 1]
    return critical, high, medium, low

def count_issues(df: pd.DataFrame):
    """
    Counts the number of issues
    """
    return df.drop_duplicates(subset=['filename', 'code', 'test_id']).shape[0]

def count_issue_severity(df: pd.DataFrame):
    """
    Counts the number of CVEs by severity
    """
    total = count_issues(df)
    critical, high, medium, low = split_issue_score(df)
    return total, count_issues(critical), count_issues(high), count_issues(medium), count_issues(low)

def plot_issues(df: pd.DataFrame):
    """
    Expects an issue-centred DataFrame
    """
    projects = sorted(list(df['project'].unique()))
    project_count = len(projects)

    issues = df[df['is_test'] == False]
    # count test_id 
    dftex = []
    dfcat = []
    dfrel = []

    # plot the test category distribution
    fig_category, axs_category = plt.subplots(project_count, 1, figsize=(10, 8))
    axs_category = [axs_category] if project_count == 1 else axs_category
    fig_category.subplots_adjust(**Global.SUBPLOTS)
    i = 0
    values = ['None', 'Low', 'Medium', 'High', 'Critical']
    for project in projects:
        ax: plt.Axes = axs_category[i]
        dftmp = issues[issues['project'] == project].copy()
        releases = sorted(list(dftmp['release'].unique()))
        palette = release_colours(project, *releases)
        version = dftmp['project_version'].unique()[0]
        order = [project]
        for release in releases:
            if release != project:
                order.append(release)
        # sort the X-axis by the test category
        dftmp = dftmp.sort_values(by=['test_category', 'release'], ascending=True)
        dftmp = dftmp[ dftmp['is_test'] == False ]
        # sns.swarmplot(data=dftmp, x='test_category', y='score', hue='release', ax=ax, palette=palette, hue_order=order)
        sns.violinplot(data=dftmp, x='test_category', y='score', ax=ax, fill=False, color=Global.Colours.light_grey, cut=0)
        unique_categories = dftmp['test_category'].unique()
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        ax.set_title(f"{project.title()}:{version}")
        ax.set_yticks(range(len(values)), values)
        i += 1
        total = count_issues(dftmp)
        for release in releases:
            dtmp = dftmp[dftmp['release'] == release]
            relcount = count_issue_severity(dtmp)
            nloc_max = dtmp['nloc_total'].max()
            issues_per_nloc = 10000 * relcount[0] / (nloc_max or 1)
            dfrel.append({
                'project': verbatim(project),
                'release': verbatim(release),
                'nloc': nloc_max,
                'issues/nloc': f"${issues_per_nloc:.1f}$",
                'count': percentage(relcount[0], total),
                'low': percentage(relcount[1], total),
                'medium': percentage(relcount[2], total),
                'high': percentage(relcount[3], total),
                'critical': percentage(relcount[4], total)
            })
            for test_id in dtmp['test_id'].unique():
                test_df = dtmp[dtmp['test_id'] == test_id]
                count = count_issue_severity(test_df)
                dftex.append({
                    'project': verbatim(project),
                    'release': verbatim(release),
                    'test_id': verbatim(test_id),
                    'count': percentage(count[0], total),
                    'low': percentage(count[1], total),
                    'medium': percentage(count[2], total),
                    'high': percentage(count[3], total),
                    'critical': percentage(count[4], total)
                })
            for test_category in unique_categories:
                test_df = dtmp[dtmp['test_category'] == test_category]
                count = count_issue_severity(test_df)
                if count == 0:
                    continue
                dfcat.append({
                    'project': verbatim(project),
                    'release': verbatim(release),
                    'test_category': verbatim(test_category),
                    'count': percentage(count[0], total),
                    'low': percentage(count[1], total),
                    'medium': percentage(count[2], total),
                    'high': percentage(count[3], total),
                    'critical': percentage(count[4], total)
                })
    dftex = pd.DataFrame(dftex)
    dftex = dftex.sort_values(by=['project', 'test_id', 'count'], ascending=[True, True, False])
    dftex = titlize(dftex)
    dftex.to_latex(table_dir / 'issue-distribution.tex', index=False, caption="Issue Distribution by Severity", label="tab:issue-distribution")
    dfcat = pd.DataFrame(dfcat)
    dfcat = dfcat.sort_values(by=['project', 'test_category', 'count'], ascending=[True, True, False])
    dfcat = titlize(dfcat)
    dfcat.to_latex(table_dir / 'issue-category-distribution.tex', index=False, caption="Issue Distribution by Category", label="tab:issue-category-distribution")
    dfrel = pd.DataFrame(dfrel)
    dfrel = dfrel.sort_values(by=['project', 'release', 'count'], ascending=[True, True, False])
    dfrel = titlize(dfrel)
    dfrel.to_latex(table_dir / 'issue-release-distribution.tex', index=False, caption="Issue Distribution by Release", label="tab:issue-release-distribution")
    fig_category.suptitle("Bandit Test Category Distribution")
    fig_category.supxlabel("Test Category")
    fig_category.savefig(plots_dir / 'bandit-test-category-distribution.png')

    fig_module, axs_module = plt.subplots(project_count, 1, figsize=(10, 8))
    axs_module = [axs_module] if project_count == 1 else axs_module
    fig_module.subplots_adjust(**Global.SUBPLOTS)
    i = 0
    for project in projects:
        ax: plt.Axes = axs_module[i]
        dftmp = issues[issues['project'] == project].copy()
        version = dftmp['project_version'].unique()[0]
        # count the number of issues per module
        total_count = dftmp.groupby(['project_package']).size().reset_index(name='total_count')
        total_count = total_count.sort_values(by='total_count', ascending=False).head(10)
        # in df, drop the columns that are not in total_count
        dftmp = dftmp[dftmp['project_package'].isin(total_count['project_package'])]
        unique_categories = dftmp['test_category'].unique()
        unique_categories = sorted(unique_categories)
        dftmp = dftmp.groupby(['project_package', 'test_category']).size().reset_index(name='count')
        for project_package in total_count['project_package']:
            # add 0 counts for missing categories
            project_categories: pd.DataFrame = dftmp[dftmp['project_package'] == project_package]['test_category'].unique()
            for test_category in unique_categories:
                if test_category not in project_categories:
                    # add row
                    row = pd.DataFrame({
                        'project_package': [project_package],
                        'test_category': [test_category],
                        'count': [0]
                    })
                    dftmp = pd.concat([dftmp, row], ignore_index=True)
        # translate the test category
        dftmp = dftmp.merge(total_count, on='project_package', how='left')
        dftmp = dftmp.sort_values(by=['total_count', 'test_category'], ascending=[False, True])
        # top 10 packages
        sns.barplot(data=dftmp, x='project_package', y='count', hue='test_category', ax=ax, palette=Global.test_category_palette, width=0.5)
        ax.set_xlabel(None)
        ax.set_ylabel(None)
        # set the legend title
        ax.legend(title='Test Category', **Global.LEGEND)
        # tilt the x-axis labels
        adjust_labels(ax, axis='x', rotation=15, fontsize=8)
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
        techlag_df = pd.DataFrame()
        cve_overall_path = csv_dir / 'cves_overall.csv'
        techlag_path = csv_dir / 'techlag.csv'
        cve_path = csv_dir / 'cves.csv'
        static_path = csv_dir / 'static.csv'
        issues_path = csv_dir / 'issues.csv'
        if not args.force:
            if static_path.exists():
                try:
                    static_df = pd.read_csv(static_path)
                except:
                    pass
            if techlag_path.exists():
                try:
                    techlag_df = pd.read_csv(techlag_path)
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
                df = ag.df_cves_per_project(project, platform, by_cwe=True, by_patch=True)
                # get published_to_patched
                cves_overall_df = pd.concat([cves_overall_df, df], ignore_index=True)
            if cves_df.empty or project_name not in cves_df['project'].unique():
                df = ag.df_cves(project, platform)
                cves_df = pd.concat([cves_df, df], ignore_index=True)
            project_id = f"{platform}:{project}"
            if issues_df.empty or project_name not in issues_df['project'].unique():
                df = ag.df_static(project, platform, with_issues=True, only_latest=True)
                issues_df = pd.concat([issues_df, df], ignore_index=True)
            if static_df.empty or project_name not in static_df['project'].unique():
                df = ag.df_static(project, platform, with_issues=False, only_latest=False)
                static_df = pd.concat([static_df, df], ignore_index=True)
            if techlag_df.empty or project_name not in techlag_df['project'].unique():
                print(f"Trying to get techlag for {project}")
                df = ag.df_tech_lag(project, platform)
                techlag_df = pd.concat([techlag_df, df], ignore_index=True)
        cves_df.to_csv(cve_path, index=False)
        issues_df.to_csv(issues_path, index=False)
        static_df.to_csv(static_path, index=False)
        cves_overall_df.to_csv(cve_overall_path, index=False)

        # drop the rows not in 'projects'
        cves_overall_df = cves_overall_df[cves_overall_df['project'].isin(project_names)]
        cves_df = cves_df[cves_df['project'].isin(project_names)]
        issues_df = issues_df[issues_df['project'].isin(project_names)]
        static_df = static_df[static_df['project'].isin(project_names)]

        # generate reports of the overall findings to explain the plots
        all_input = 'all' in args.overall
        if 'cwe' in overall_keys or all_input:
            cwe_df = cves_overall_df.copy()
            cwe_df = add_stats(cwe_df, ['project', 'release', 'cve_id', 'cwe_id'], 'published_to_patched')
            plot_overall_cwe_distribution(cves_overall_df)
        if 'issues' in overall_keys or all_input:
            pprint(issues_df)
            plot_issues(issues_df)
        if 'cve' in overall_keys or all_input:
            plot_cves(cves_overall_df)
            to_keep = ['project', 'release', 'cve_id', 'applicability']
            cves_unique = cves_overall_df.drop_duplicates(subset=to_keep)[to_keep].sort_values(by=to_keep)
            def repl(app):
                if not app:
                    return app
                app = app.replace('[', '$[')
                app = app.replace(']', ']$')
                app = app.replace('(', '$(')
                app = app.replace(')', ')$')
                return app
            cves_unique['applicability'] = cves_unique['applicability'].map(repl)
            to_latex(cves_unique, tex_dir / 'cves.tex')
        if 'semver' in overall_keys or all_input:
            plot_semver(cves_df, static_df)
        if 'techlag' in overall_keys or all_input:
            to_latex(techlag_df, tex_dir / 'techlag.tex',
                     project='Project',
                     version='Version',
                     dependency='Dependency',
                     requirements='Requirements',
                     next_version='Next Version')
            techlag_df.to_csv(techlag_path, index=False)

    if args.show:
        plt.show()
        
    if args.show:
        plt.show()