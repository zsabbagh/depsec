import argparse, re, lizard, glob, datetime, json, sys, subprocess, time
from pprint import pprint
from packaging import version as semver
from loguru import logger
from git import Repo
from pathlib import Path
from src.utils.proc import *
from src.middleware import Middleware
from src.schemas.projects import *
# This tool iterates git tags and runs a command for each tag

VERSION_TAG = r'^v?\d+\.\d+\.\d+$'

parser = argparse.ArgumentParser(description='Iterate git tags and run a command for each tag')
parser.add_argument('--projects', help='The projects file', default='projects.json')
parser.add_argument('--limit', help='The number of most recent releases to process', type=int, default=0)
parser.add_argument('--directory', help='The repositories directory', default='repositories')
parser.add_argument('--config', help='The configuration file to use', default='config.yml')
parser.add_argument('--level', help='The logging level to use', default='INFO')
parser.add_argument('--force', help='Force the operation', action='store_true')
parser.add_argument('--do', help='The operation to do', default=[], nargs='*')
parser.add_argument('--only', help='Only do the mentioned projects', default=[], nargs='*')


args = parser.parse_args()

logger.remove()
logger.add(sys.stdout, level=args.level.upper())

only = set(map(str.lower, args.only))

mw = Middleware(args.config)

directory = Path(args.directory)
if not directory.exists():
    logger.error(f"Directory {directory} does not exist")
    exit(1)

temp_dir = directory / '__temp__'
if not temp_dir.exists():
    temp_dir.mkdir()

data = None
with open(args.projects, 'r') as f:
    data = json.load(f)

def is_version_tag(tag: str):
    """
    Checks if a tag is a version tag
    """
    return bool(re.match(VERSION_TAG, tag))

for platform, projects in data.items():

    for project_name in projects:

        if only and project_name.lower() not in only:
            logger.info(f"Skipping {platform} project '{project_name}', only '{', '.join(list(only))}' provided")
            continue

        logger.info(f"Processing {platform} project {project_name}")

        repo = projects.get(project_name, {}).get('repo')
        if not repo:
            continue

        url = repo.get('url')
        includes = repo.get('includes')
        excludes = repo.get('excludes')
        url = re.sub(r'https?://|\.git$', '', url)
        repo_name = url.split('/')[-1]
        if '.' in repo_name:
            repo_name = repo_name.split('.')[0]
        url = f"https://github.com{url}.git"

        # TODO: Add creation of project if it does not exist

        # Get the project
        project = mw.get_project(project_name, platform)
        if not project:
            print(f"Project {project_name} not found")
            continue

        repo_path = directory / repo_name

        src_name = repo.get('src') or repo_name

        if not repo_path.exists():
            # TODO: Clone the repository
            logger.error(f"Repository {repo_name} does not exist. Cloning not implemented, do manually")
            continue

        logger.info(f"Checking out {repo_name} to {repo_path}")

        repo = Repo(repo_path)

        tags = repo.tags

        versions = {}

        for tag in tags:
            if not is_version_tag(tag.name):
                continue
            tag_version = tag.name.lstrip('v')
            versions[tag_version] = tag
        
        logger.info(f"Versions found for {repo_name}: {len(versions)}")

        processed = 0

        for version in sorted(versions.keys(), key=semver.parse, reverse=True):
            if bool(args.limit) and processed > args.limit:
                logger.info(f"Limit of {args.limit} reached, stopping")
                break
            release: Release = mw.get_release(repo_name, version, platform)
            if release is None:
                logger.warning(f"Release {project_name}:{version} not found by metadata, ignoring")
                continue
            processed += 1
            tag = versions[version]
            repo.git.checkout(tag.commit, force=True)
            date_time = datetime.datetime.fromtimestamp(tag.commit.committed_date)
            release.commit_at = date_time
            release.commit_hash = str(tag.commit)
            date_str = date_time.strftime('%Y-%m-%d %H:%M:%S')
            release = mw.get_release(repo_name, version, platform)
            if 'lizard' in args.do:
                res = run_lizard(repo_path, includes, excludes)
                nloc = res.get('nloc')
                avg_nloc = res.get('nloc_average')
                avg_ccn = res.get('ccn_average')
                files_counted = res.get('files')
                functions_counted = res.get('functions')
                release.counted_files = files_counted
                release.counted_functions = functions_counted
                release.nloc_total = round(nloc, 2) if nloc is not None else None
                release.nloc_average = round(avg_nloc, 2) if avg_nloc is not None else None
                release.ccn_average = round(avg_ccn, 2) if avg_ccn is not None else None
                logger.info(f"{project_name}:{version}, files: {files_counted}, NLOC {nloc}")
            if 'bandit' in args.do:
                res = run_bandit(repo_path, includes, excludes, temp_dir)
                if not res:
                    logger.error(f"Bandit failed for {project_name}:{version}")
                    continue
                previous_report = BanditReport.get_or_none(BanditReport.release == release)
                if previous_report:
                    previous_report.delete_instance()
                time.sleep(1)
                sevconf = res.get('severity_confidence', {})
                report = BanditReport.create(
                    release=release,
                    files_counted=res.get('files_counted'),
                    files_skipped=res.get('files_skipped'),
                    issues_total=res.get('total_issues'),
                    confidence_high_count=res.get('confidence_high_count'),
                    confidence_medium_count=res.get('confidence_medium_count'),
                    confidence_low_count=res.get('confidence_low_count'),
                    confidence_undefined_count=res.get('confidence_undefined_count'),
                    severity_high_count=res.get('severity_high_count'),
                    severity_medium_count=res.get('severity_medium_count'),
                    severity_low_count=res.get('severity_low_count'),
                    severity_undefined_count=res.get('severity_undefined_count'),
                    severity_h_confidence_h_count=sevconf.get('high', {}).get('high', 0),
                    severity_h_confidence_m_count=sevconf.get('high', {}).get('medium', 0),
                    severity_h_confidence_l_count=sevconf.get('high', {}).get('low', 0),
                    severity_m_confidence_h_count=sevconf.get('medium', {}).get('high', 0),
                    severity_m_confidence_m_count=sevconf.get('medium', {}).get('medium', 0),
                    severity_m_confidence_l_count=sevconf.get('medium', {}).get('low', 0),
                    severity_l_confidence_h_count=sevconf.get('low', {}).get('high', 0),
                    severity_l_confidence_m_count=sevconf.get('low', {}).get('medium', 0),
                    severity_l_confidence_l_count=sevconf.get('low', {}).get('low', 0),
                    loc=res.get('loc'),
                    nosec=res.get('nosec'),
                    skipped_tests=res.get('skipped_tests'),
                    updated_at=datetime.datetime.now(),
                )
                report.save()
                for issue in res.get('issues', []):
                    lines = issue.get('line_range', [])
                    if type(lines) == list:
                        lines = ', '.join(map(str, lines))
                    else:
                        lines = str(lines)
                    cwe = issue.get('issue_cwe', {})
                    cwe = f"CWE-{cwe.get('id')}" if cwe else None
                    issue_db = BanditIssue.create(
                        report=report,
                        description=issue.get('issue_text'),
                        filename=issue.get('filename'),
                        lines=lines,
                        code=issue.get('code'),
                        confidence=issue.get('issue_confidence', 'undefined').lower(),
                        severity=issue.get('issue_severity', 'undefined').lower(),
                        cwe_id=cwe,
                        test_id=issue.get('test_id'),
                        test_name=issue.get('test_name'),
                        more_info=issue.get('more_info'),
                    )
                    if issue_db:
                        issue_db.save()
            release.save()
