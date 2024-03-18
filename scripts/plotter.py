import argparse, sys, time, seaborn as sns, numpy as np, matplotlib.pyplot as plt, pprint
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
    fig, count_ax = plt.subplots()
    fig2, score_ax = plt.subplots()
    pprint(timelines)
    for project, data in timelines.items():
        timeline = data.get('timeline')
        cves = data.get('cves')
        print(cves)
        dates = [ entry.get('date') for entry in timeline ]
        cves_count = [ len(entry.get('cves', [])) for entry in timeline ]
        max_scores = []
        mean_scores = []
        median_scores = []
        for entry in timeline:
            scrs = []
            for cve in entry['cves']:
                scrs.append(cves.get(cve, {}).get('cvss_base_score'))
            if len(scrs) == 0:
                max_scores.append(0)
                mean_scores.append(0)
                median_scores.append(0)
                continue
            max_scores.append(max(scrs))
            mean_scores.append(np.mean(scrs))
            median_scores.append(np.std(scrs))
        count_ax.step(dates, cves_count, label=f"{project} # of CVEs")
        # score_ax.step(dates, max_scores, label=f"{project} max")
        score_ax.step(dates, mean_scores, label=f"{project} mean")
        # score_ax.step(dates, median_scores, label=f"{project} med")
    fig.legend()
    fig2.legend()
    plt.show()

mw = Middleware(args.config)
mw.load_projects(*args.projects)

if __name__ == '__main__':
    
    timelines = {}
    for project in args.projects:
        # get timeline for each project
        timeline = mw.get_vulnerabilities_timeline(project, 2014, step='m')
        timelines[project] = timeline
    plot_timelines(timelines)

    vulnerabilities = {}
    for project in args.projects:
        # get all the vulnerabilities for the project
        vulnerabilities[project] = mw.get_vulnerabilities(project)

    # TODO: store the data in a JSON directory
    # include TIMESTAMP OF NVD FILE