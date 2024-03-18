import argparse, sys, time, seaborn as sns, numpy as np, matplotlib.pyplot as plt, pprint, json
from pprint import pprint
from pathlib import Path
from src.middleware import Middleware
from loguru import logger
from src.schemas.projects import *
from pandas import DataFrame
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
parser.add_argument('-p', '--projects', nargs='+', help='The projects to plot', required=True)
parser.add_argument('-o', '--output', help='The output directory', default='output')
parser.add_argument('--debug', help='The debug level of the logger', default='INFO')

args = parser.parse_args()

def convert_datetime_to_str(data: dict):
    """
    Converts dictionaries with datetime objects to strings
    """
    if type(data) != dict:
        return data
    for key, value in data.items():
        if isinstance(value, datetime.datetime):
            data[key] = value.strftime('%Y-%m-%d %H:%M:%S')
        elif type(value) == dict:
            data[key] = convert_datetime_to_str(value)
        elif type(value) == list:
            data[key] = [ convert_datetime_to_str(entry) for entry in value ]
    return data

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
    fig_count, ax_count = plt.subplots()
    # the scores to plot
    scores = [
        ('CVSS base score', 'cvss_base_score'),
        ('CVSS impact score', 'cvss_impact_score'),
        ('CVSS exploitability score', 'cvss_exploitability_score'),
        ('CVSS confidentiality impact', 'cvss_confidentiality_impact'),
        ('CVSS integrity impact', 'cvss_integrity_impact'),
        ('CVSS availability impact', 'cvss_availability_impact'),
    ]
    figures_scores = []
    for title, kw in scores:
        fig, ax = plt.subplots()
        figures_scores.append((fig, ax, kw))
        ax.set_title(title)
        ax.set_ylabel('Score')
    pprint(timelines)
    for project, data in timelines.items():
        timeline = data.get('timeline')
        cves = data.get('cves')
        print(cves)
        dates = [ entry.get('date') for entry in timeline ]
        for fig, ax, kw in figures_scores:
            cves_count = [ len(entry.get('cves', [])) for entry in timeline ]
            max_scores = []
            mean_scores = []
            median_scores = []
            for entry in timeline:
                scrs = []
                for cve in entry['cves']:
                    val = cves.get(cve, {}).get(kw)
                    value = impact_to_int(val)
                    if type(value) not in [int, float]:
                        logger.warning(f"Unexpected value for {project}, keyword '{kw}' in {cve}: {value}")
                        continue
                    scrs.append(value)
                if len(scrs) == 0:
                    max_scores.append(0)
                    mean_scores.append(0)
                    median_scores.append(0)
                    continue
                max_scores.append(max(scrs))
                mean_scores.append(np.mean(scrs))
                median_scores.append(np.std(scrs))
            kw_name = kw.replace('cvss_', '').replace('_', ' ')
            ax.plot(dates, mean_scores, label=f"{project.title()} mean {kw_name}")
        ax_count.plot(dates, cves_count, label=f"{project.title()} # of CVEs")
    ax_count.set_ylabel('Number of CVEs')
    # add date points to each 5th entry
    ax_count.grid(color='gray', linestyle='-', linewidth=0.2, axis='y', zorder=0)
    fig_count.legend()
    fig_count.autofmt_xdate()
    fig_count.savefig(plots_dir / "cves.png")
    for fig, ax, kw in figures_scores:
        ax.set_ylabel('Score')
        ax.grid(color='gray', linestyle='-', linewidth=0.2, axis='y', zorder=0)
        fig.legend()
        fig.autofmt_xdate()
        fig.savefig(plots_dir / f"{kw}.png")


def plot_vulnerabilities(vulnerabilities: dict):
    """
    Expects a dictionary with the following structure:
    <project>: {
        <cve-id>: {}
    }
    """
    pass

mw = Middleware(args.config)
mw.load_projects(*args.projects)

if __name__ == '__main__':
    
    timelines = {}
    for project in args.projects:
        # get timeline for each project
        timeline = mw.get_vulnerabilities_timeline(project, 2014, step='m')
        timelines[project] = timeline
    plot_timelines(timelines)
    timelines = convert_datetime_to_str(timelines)
    with open(json_dir / 'timelines.json', 'w') as f:
        json.dump(timelines, f, indent=4)

    vulnerabilities = {}
    for project in args.projects:
        # get all the vulnerabilities for the project
        vulnerabilities[project] = mw.get_vulnerabilities(project)
    plot_vulnerabilities(vulnerabilities)
    vulnerabilities = convert_datetime_to_str(vulnerabilities)
    with open(json_dir / 'vulnerabilities.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)

    # TODO: store the data in a JSON directory
    # include TIMESTAMP OF NVD FILE