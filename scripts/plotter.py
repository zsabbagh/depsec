import argparse, sys
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
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

def plot_timelines(timelines: dict):
    """
    Expects a dictionary with the following structure:

    <project>: [
        {
            date: datetime,
            release: dict,
            cves: [dict]
        }
    ]
    """
    fig, count_ax = plt.subplots()
    fig2, score_ax = plt.subplots()
    pprint(timelines)
    for project, timeline in timelines.items():
        dates = [release['date'] for release in timeline]
        cves = [len(release['cves']) for release in timeline]
        max_scores = []
        mean_scores = []
        median_scores = []
        for entry in timeline:
            scrs = []
            for cve in entry['cves']:
                scrs.append(cve['cvss_base_score'])
            if len(scrs) == 0:
                max_scores.append(0)
                mean_scores.append(0)
                median_scores.append(0)
                continue
            max_scores.append(max(scrs))
            mean_scores.append(np.mean(scrs))
            median_scores.append(np.std(scrs))
        count_ax.step(dates, cves, label=project)
        # score_ax.step(dates, max_scores, label=f"{project} max")
        score_ax.step(dates, mean_scores, label=f"{project} mean")
        # score_ax.step(dates, median_scores, label=f"{project} med")
    plt.legend()
    plt.show()

mw = Middleware(args.config)

if __name__ == '__main__':
    
    timelines = {}
    for project in args.projects:
        timeline = mw.get_vulnerabilities_timeline(project, 2014, step='y')
        timelines[project] = timeline
    plot_timelines(timelines)