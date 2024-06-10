import subprocess
import datetime
import os
import json
import lizard
import argparse
import re
from pathlib import Path
from pprint import pprint
from loguru import logger

# This file includes the running of other programmes or modules


def any_fulfils(ls: list, expr: callable) -> bool:
    """
    Check if any element in a list satisfies the expression.
    """
    for i in ls:
        if expr(i):
            return True
    return False


def paths_to_str(paths: list) -> str:
    """
    Convert a list of paths to a string.
    """
    return " ".join([str(p) for p in paths])


def autoskip_file(path: Path, dir: Path = ".") -> bool:
    """
    Automatically skip files that are in the test, examples, or docs directories.
    """
    path = Path(path).absolute() if type(path) == str else path.absolute()
    dir = Path(dir).absolute() if type(dir) == str else dir.absolute()
    stripped_path = Path(str(path).replace(str(dir), ""))
    if any_fulfils(
        list(stripped_path.parts),
        lambda x: bool(re.match(r"_{0,2}(test(?:ing)?|example|doc)s?", x)),
    ):
        return True
    elif path.stem.startswith("test_"):
        return True
    return False


def get_files(
    dir: str,
    includes: list = None,
    excludes: list = None,
    file_ext: str = ".py",
    autoskip: bool = True,
) -> list:
    """
    Get all files in a directory, optionally filtered by includes and excludes.
    """
    dir = Path(dir).absolute()
    if not dir.exists():
        logger.error(f"Directory '{dir}' does not exist!")
        return []
    files = []
    excs = (
        [
            Path(dir / e).absolute()
            for e in ([excludes] if type(excludes) == str else excludes)
        ]
        if excludes
        else []
    )
    incs = (
        [
            Path(dir / i).absolute()
            for i in ([includes] if type(includes) == str else includes)
        ]
        if includes
        else [dir]
    )
    for i in incs:
        skip = False
        for exc in excs:
            if str(i.absolute()).startswith(str(exc.absolute())):
                skip = True
                break
        if skip:
            print(f"Skipping '{i}' as it is in the exclude list.")
            continue
        if i.is_file():
            print(f"Adding file '{i}' to the list.")
            files.append(i)
            continue
        file_ext = [file_ext] if "|" not in file_ext else file_ext.split("|")
        globs = [f"**/*{ext}" for ext in file_ext]
        for g in globs:
            for f in i.glob(g):
                # check if is in directory test, examples, or docs
                if autoskip and autoskip_file(f, dir):
                    continue
                if f.is_file():
                    files.append(f)
    return files


def run_lizard(
    dir: str | Path, includes: list = None, excludes: list = None, file_ext: str = ".py"
) -> dict:
    """
    Runs Lizard on the codebase provided.

    dir: str | Path: The directory to run Lizard on.
    includes: list: The filepaths to include.
    excludes: list: The filepaths to exclude (starting with the directory provided).
    file_ext: str: The file extension(s) to include, separated by '|' or as a list.
    """
    if type(file_ext) == list:
        file_ext = "|".join(file_ext)
    files = get_files(dir, includes, excludes, file_ext=file_ext)
    nloc = 0
    ccn = 0
    functions = 0
    for file in files:
        # we check all files
        # do not remove test or __init__.py files unless stated in excludes
        file = Path(file)
        lizard_result = lizard.analyze_file(str(file))
        nloc += lizard_result.nloc
        for func in lizard_result.function_list:
            ccn += func.cyclomatic_complexity
            functions += 1
    ccn_avg = ccn / functions if functions > 0 else 0
    nloc_avg = nloc / functions if functions > 0 else 0
    return {
        "nloc": nloc,
        "nloc_average": nloc_avg,
        "ccn_average": ccn_avg,
        "files": len(files),
        "functions": functions,
    }


def run_bandit(
    dir: str | Path,
    includes: str | list = None,
    excludes: str | list = None,
    output: str | Path = None,
    skips: str = "",
    autoskip: bool = True,
) -> None:
    """
    Run Bandit on the codebase.

    dir: str | Path: The directory to run Bandit on.
    includes: str | list: The filepaths to include.
    excludes: str | list: The filepaths to exclude (starting with the directory provided).
    output: str | Path: The output directory for the Bandit results.

    returns:
    dict: The Bandit results for each directory.
    """
    # Run Bandit
    dir = Path(dir).absolute()
    includes = (
        [includes]
        if type(includes) == str
        else (includes if type(includes) == list else [])
    )
    includes = [Path(dir / i).absolute() for i in includes] if includes else [dir]
    excludes = (
        [excludes]
        if type(excludes) == str
        else (excludes if type(excludes) == list else [])
    )
    result = {}
    output_dir = Path(output).absolute() if output else Path(os.getcwd()) / "__temp__"
    if not output_dir.parent.exists():
        logger.error(f"Output directory '{output_dir.parent}' does not exist!")
        exit(1)
    if not output_dir.exists():
        output_dir.mkdir()
    processed_dirs = set()
    files_with_issues = set()
    loc = nosec = skipped_tests = 0
    total_issues = 0
    h_sev = m_sev = l_sev = u_sev = 0
    h_conf = m_conf = l_conf = u_conf = 0
    sev_conf = {}
    all_issues = []
    files_skipped = 0
    for incldir in includes:
        skipdir = False
        for procdir in processed_dirs:
            if str(incldir.absolute()).startswith(str(procdir)):
                logger.warning(
                    f"Skipping directory '{incldir.absolute()}' as it has already been counted."
                )
                skipdir = True
                break
        if skipdir:
            continue
        processed_dirs.add(str(incldir.absolute()))
        dirname = str(incldir).lstrip(str(dir.absolute()))
        if dirname == "":
            dirname = dir.absolute().name
        result[dirname] = {}
        dt = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        fn = output_dir / f"bandit-{dt}.json"
        if not incldir.exists():
            logger.debug(f"Skipping '{incldir}' as it does not exist.")
            continue
        logger.info("Running Bandit...")
        data = None
        try:
            command = ["bandit", "-r", str(incldir), "-f", "json", "-o", str(fn)]
            if bool(skips):
                command.extend(["-s", skips.upper()])
            subprocess.run(command)
            with open(fn, "r") as f:
                data = json.load(f)
                for err in data.get("errors", []):
                    if err.get("filename") is not None:
                        files_skipped += 1
                issues = data.get("results", [])
                for issue in issues:
                    filename = issue.get("filename")
                    if autoskip and autoskip_file(Path(filename), dir):
                        continue
                    # TODO: this is not the true measurement of files counted, this is for those that have issues
                    if filename is not None:
                        files_with_issues.add(filename)
                    # count issues
                    sev = issue.get("issue_severity", "undefined").lower()
                    conf = issue.get("issue_confidence", "undefined").lower()
                    if sev not in sev_conf:
                        sev_conf[sev] = {}
                    if conf not in sev_conf[sev]:
                        sev_conf[sev][conf] = 0
                    sev_conf[sev][conf] += 1
                    all_issues.append(issue)
                total_issues += len(issues)
                totalcount = data.get("metrics", {}).get("_totals", {})
                loc += totalcount.get("loc", 0)
                nosec += totalcount.get("nosec", 0)
                skipped_tests += totalcount.get("skipped_tests", 0)
                h_sev += totalcount.get("SEVERITY.HIGH", 0)
                m_sev += totalcount.get("SEVERITY.MEDIUM", 0)
                l_sev += totalcount.get("SEVERITY.LOW", 0)
                u_sev += totalcount.get("SEVERITY.UNDEFINED", 0)
                h_conf += totalcount.get("CONFIDENCE.HIGH", 0)
                m_conf += totalcount.get("CONFIDENCE.MEDIUM", 0)
                l_conf += totalcount.get("CONFIDENCE.LOW", 0)
                u_conf += totalcount.get("CONFIDENCE.UNDEFINED", 0)
                try:
                    fn.unlink()
                except Exception as e:
                    logger.error(f"Could not delete file '{fn}': {e}")
        except Exception as e:
            logger.error(f"Bandit found issues in the codebase: {e}")
            continue
    return {
        "issues": all_issues,
        "loc": loc,
        "nosec": nosec,
        "skipped_tests": skipped_tests,
        "issues_total": len(all_issues),
        "files_with_issues": len(files_with_issues),
        "files_skipped": files_skipped,
        "confidence_high_count": h_conf,
        "confidence_medium_count": m_conf,
        "confidence_low_count": l_conf,
        "confidence_undefined_count": u_conf,
        "severity_high_count": h_sev,
        "severity_medium_count": m_sev,
        "severity_low_count": l_sev,
        "severity_undefined_count": u_sev,
        "severity_confidence": sev_conf,
    }


if __name__ == "__main__":
    # Run Bandit
    parser = argparse.ArgumentParser(
        description="Run Bandit and Lizard on the codebase."
    )
    parser.add_argument(
        "dir", type=str, help="The directory to run Bandit and Lizard on."
    )
    parser.add_argument(
        "-i",
        "--includes",
        type=str,
        nargs="+",
        help="The filepaths to include.",
        default=None,
    )
    parser.add_argument(
        "-x",
        "--excludes",
        type=str,
        nargs="+",
        help="The filepaths to exclude (starting with the directory provided).",
        default=None,
    )
    args = parser.parse_args()
    report = run_bandit(
        dir=args.dir,
        includes=args.includes,
        excludes=args.excludes,
        output="depsec/__temp__",
    )
    pprint(report)
