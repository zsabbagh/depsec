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

    <project>: {
        '<date>': {
            '<cve-id>', {
                'cve': CVE-DICT,
                'releases': [RELEASE-DICT, ...]
            }
        }
    }
    """
    fix, ax = plt.subplots()
    pprint(timelines)
    for project, timeline in timelines.items():
        dates_ordered = sorted(timeline.keys())
        y = [len(timeline[date_str]) for date_str in dates_ordered]
        ax.step(dates_ordered, y, label=project)
        df = DataFrame({'project': project, 'date': dates_ordered, 'count': y})
    plt.show()

mw = Middleware(args.config)

if __name__ == '__main__':
    
    timelines = {}
    for project in args.projects:
        timeline = mw.get_vulnerabilities_timeline(project, 2014, step='m')
        timelines[project] = timeline
    plot_timelines(timelines)