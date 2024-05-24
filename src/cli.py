import argparse
from depsec.aggregator import Aggregator

parser = argparse.ArgumentParser(
    description="Utilise DepSec to analyse dependencies of an open-source package/project (Python)."
)
parser.add_argument("do", type=str, help='What to do: "analyse", "plot", etc.')
parser.add_argument(
    "-c",
    "--config",
    type=str,
    help="Path to the configuration file.",
    default="config.yml",
)
parser.add_argument(
    "-p",
    "--projects",
    type=str,
    help="Path to the projects or a list of projects.",
    nargs="+",
    default="projects",
)
parser.add_argument(
    "-d",
    "--dependencies",
    type=str,
    help="Include dependencies in the analysis.",
    default=False,
)

args = parser.parse_args()


def main():
    ag = Aggregator(args.config)
    do = args.do.lower()
    ag.load_projects(*args.projects)
    match do:
        case "analyse":
            ag._analyse()
        case "plot":
            ag.plot(args.projects)
        case _:
            print("Unknown command.")


if __name__ == "__main__":
    main()
