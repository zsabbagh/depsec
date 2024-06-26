import argparse, re, sys
from loguru import logger
from pathlib import Path
from pprint import pprint
from depsec.schemas.projects import *
from depsec.aggregator import Aggregator
from depsec.utils.tools import bandit_value_score
from playhouse.shortcuts import model_to_dict

# A tiny script to help update Bandit issues in the database

parser = argparse.ArgumentParser(description="Update issues in the database")
parser.add_argument("config", help="Path to the configuration file")
parser.add_argument("-m", "--mark-issues", action="store_true", help="Mark issues as verified")
parser.add_argument("-u", "--update-modules", action="store_true", help="Update modules")
parser.add_argument("-r", "--repo-dir", help="Repository directory", default="./repositories/")
parser.add_argument("-d", "--dependencies", action="store_true", help="Include dependencies", default=True)
parser.add_argument("-p", "--projects", nargs='+', help="Projects to update")
parser.add_argument("--noskip", action="store_true", help="Skip verified issues", default=False)
parser.add_argument("--debug", action="store_true", help="Enable debug logging")
parser.add_argument("-min", "--minimum-confidence", help="Min confidence level of issues to update")
parser.add_argument("-max", "--maximum-confidence", help="Max confidence level of issues to update")
parser.add_argument("-a", "--accept-blank", action="store_true", help="Accept blank input of verification step to skip")
parser.add_argument("-s", "--score", action="store_true", help="Update scores")

args = parser.parse_args()

if not args.debug:
    logger.remove()
    logger.add(sys.stderr, level="INFO")

ag = Aggregator(args.config)

def pprint_issue(issue: BanditIssue) -> None:
    """
    Pretty print an issue
    """
    print()
    text = f"Verified as {'Probable True Positive' if issue.true_positive else 'Probable False Positive'}" if issue.verified else "Not verified"
    print(f"---- {text} ----")
    print(f"{issue.test_name} ({issue.test_id}) @ {issue.package}.{issue.module}")
    print(f"\t{issue.severity} | {issue.confidence} @ {issue.filename}")
    print()
    print(issue.code)
    print()
    print()

def update_modules(release: Release, repo_dir: str = None) -> None:
    """
    Updates 'module' field of a release
    """
    if repo_dir is None:
        logger.error("Repository directory not provided")
        return
    repo_dir = Path(repo_dir).absolute()
    report = release.bandit_report.first()
    release_name = release.project.name
    if report is not None:
        for issue in report.issues:
            module = issue.module
            path = Path(issue.filename)
            dirs = path.parts
            dir_str = None
            for i in range(len(dirs)-1, -1, -1):
                if dirs[i] == release_name:
                    dir_str = '/'.join(dirs[i+1:])
                    break
            module = Path(dir_str).stem
            package = '.'.join(Path(dir_str).parent.parts)
            issue.module = module
            issue.package = package
            issue.save()
            print(f"Updated module for {release.project.name} {release.version} {issue.test_id} to {package}.{module}")

def mark_issues(release: Release, with_dependencies: bool = True, mark_tests: bool = True) -> None:
    """
    Mark issues as verified
    """
    mx = args.maximum_confidence
    mn = args.minimum_confidence
    mx = bandit_value_score(mx) if mx is not None else None
    mn = bandit_value_score(mn) if mn is not None else None
    report = release.bandit_report.first()
    release_name = f"{release.project.name} {release.version}"
    if report is not None:
        for issue in report.issues:
            score = bandit_value_score(issue.confidence)
            if (mx is not None and score >= mx) or (mn is not None and score <= mn):
                print(f"Skip issue entered: Issue confidence '{issue.confidence}' does not match '< {args.maximum_confidence} | > {args.minimum_confidence}' for {release_name}")
                continue
            pprint_issue(issue)
            if not args.noskip and issue.verified:
                print(f"Skip issue entered: Issue already verified for {release_name}")
                continue
            if mark_tests:
                if (issue.package.startswith('test') or 'test' in issue.module) and input("Test detected. Skip OK? ").strip().lower() == '':
                    print(f"Skip issue entered: Issue in tests for {release_name}")
                    issue.verified = False
                    issue.true_positive = False
                    issue.save()
                    continue
            print(f"Processing issue for {release_name}")
            inp = None
            while inp is None:
                inp = input("Mark as verified? [y/n]: ")
                inp = inp.strip().lower()
                if inp == 'y':
                    issue.verified = True
                    issue.true_positive = True
                    issue.save()
                    print(f"Issue marked as verified for {release_name}")
                elif inp == 'n':
                    issue.verified = True
                    issue.true_positive = False
                    issue.save()
                    print(f"Issue marked as verified for {release_name} as undeclared")
                elif args.accept_blank and inp == '':
                    inp = True
                else:
                    inp = None
                    print(f"Invalid input, please try again")

for project in args.projects:
    version = None
    if ':' in project:
        try:
            project, version = tuple(project.split(':'))
        except:
            pass
    releases = []
    if version == 'all':
        releases = ag.get_releases(project, has_static_analysis=True)
    elif version is not None:
        if re.match(r"^\d+\.\d+\.\d+$", version) is None:
            version = f"=={version}"
        releases = ag.get_releases(project, requirements=version, has_static_analysis=True)
    else:
        rel = ag.get_release(project, has_static_analysis=True)
        if rel is None:
            logger.error(f"Release not found for {project}")
            continue
        releases.append(rel)
    for release in releases:
        process = [release]
        if args.dependencies:
            print("Including dependencies")
            for dependency in release.dependencies:
                dependency: ReleaseDependency
                print(f"Processing dependency {dependency.name} {dependency.version}")
                dep_release = ag.get_release(dependency.name, requirements=dependency.requirements, has_static_analysis=True)
                if dep_release is not None:
                    process.append(dep_release)
        for rel in process:
            print(f"Processing {rel.project.name} {rel.version}, commit: {rel.commit_hash} @ {rel.commit_at}")
            if args.update_modules:
                update_modules(rel, repo_dir=args.repo_dir)
            if args.mark_issues:
                input("Ready? [press enter] ")
                mark_issues(rel, with_dependencies=args.dependencies)
            if args.score:
                report: BanditReport = rel.bandit_report.first()
                sev_conf = {}
                sev = {}
                conf = {}
                if report is not None:
                    for issue in report.issues:
                        # add skip
                        s = issue.severity.lower()
                        c = issue.confidence.lower()
                        if s not in sev_conf:
                            sev_conf[s] = {}
                        sev[s] = sev.get(s, 0) + 1
                        conf[c] = conf.get(c, 0) + 1
                        sev_conf[s][c] = sev_conf[s].get(c, 0) + 1
                        severity_score = bandit_value_score(s)
                        confidence_score = bandit_value_score(c)
                        issue.score = severity_score + confidence_score
                        issue.save()
                        print(f"Updated score for {rel.project.name} {rel.version} {issue.test_id} to {issue.score}")
                    # add issue count
                    report.severity_high_count = sev.get('high', 0)
                    report.severity_medium_count = sev.get('medium', 0)
                    report.severity_low_count = sev.get('low', 0)
                    report.confidence_high_count = conf.get('high', 0)
                    report.confidence_medium_count = conf.get('medium', 0)
                    report.confidence_low_count = conf.get('low', 0)
                    report.severity_h_confidence_h_count = sev_conf.get('high', {}).get('high', 0)
                    report.severity_h_confidence_m_count = sev_conf.get('high', {}).get('medium', 0)
                    report.severity_h_confidence_l_count = sev_conf.get('high', {}).get('low', 0)
                    report.severity_m_confidence_h_count = sev_conf.get('medium', {}).get('high', 0)
                    report.severity_m_confidence_m_count = sev_conf.get('medium', {}).get('medium', 0)
                    report.severity_m_confidence_l_count = sev_conf.get('medium', {}).get('low', 0)
                    report.severity_l_confidence_h_count = sev_conf.get('low', {}).get('high', 0)
                    report.severity_l_confidence_m_count = sev_conf.get('low', {}).get('medium', 0)
                    report.severity_l_confidence_l_count = sev_conf.get('low', {}).get('low', 0)
                    report.save()
                    print(f"Updated issue count for {rel.project.name} {rel.version}")
