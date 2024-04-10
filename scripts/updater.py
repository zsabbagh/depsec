import argparse, re, sys
from loguru import logger
from pathlib import Path
from pprint import pprint
from src.schemas.projects import *
from src.aggregator import Aggregator
from playhouse.shortcuts import model_to_dict

# A tiny script to help update Bandit issues in the database

parser = argparse.ArgumentParser(description="Update issues in the database")
parser.add_argument("config", help="Path to the configuration file")
parser.add_argument("-m", "--mark-issues", action="store_true", help="Mark issues as verified")
parser.add_argument("-u", "--update-modules", action="store_true", help="Update modules")
parser.add_argument("-r", "--repo-dir", help="Repository directory", default="./repositories/")
parser.add_argument("-d", "--dependencies", action="store_true", help="Include dependencies", default=True)
parser.add_argument("-p", "--projects", nargs='+', help="Projects to update")
parser.add_argument("--debug", action="store_true", help="Enable debug logging")

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
    print(f"---- Issue ----")
    print(f"{issue.test_name} ({issue.test_id}) @ {issue.package}.{issue.module}")
    print(f"Severity: {issue.severity}")
    print(f"Confidence: {issue.confidence}")
    print(f"Filename: {issue.filename}")
    print(">> code start >>")
    print(issue.code)
    print("<< code end   <<")
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
            if module is None:
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

def mark_issues(project: str | Project, version: str = None, platform: str="pypi", with_dependencies: bool = True, skip_verified: bool = True, mark_tests: bool = True) -> None:
    """
    Mark issues as verified
    """
    releases = ag.get_analysed_releases(project, platform=platform, with_dependencies=with_dependencies)
    for release in releases:
        report = release.bandit_report.first()
        release_name = f"{release.project.name} {release.version}"
        if report is not None:
            for issue in report.issues:
                if skip_verified and issue.verified:
                    print(f"Skip issue entered: Issue already verified for {release_name}")
                    continue
                if mark_tests:
                    if issue.package.startswith('test'):
                        print(f"Skip issue entered: Issue in tests for {release_name}")
                        issue.verified = False
                        issue.save()
                        continue
                print(f"Processing issue for {release_name}")
                pprint_issue(issue)
                inp = None
                while inp is None:
                    inp = input("Mark as verified? [y/n]: ")
                    inp = inp.strip().lower()
                    if inp == 'y':
                        issue.verified = True
                        issue.save()
                        print(f"Issue marked as verified for {release_name}")
                    elif inp == 'n':
                        print(f"Issue not marked as verified for {release_name}")
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
            print(f"Processing {rel.project.name} {rel.version}")
            if args.update_modules:
                update_modules(release, repo_dir=args.repo_dir)
            if args.mark_issues:
                mark_issues(release, version, with_dependencies=args.dependencies)
