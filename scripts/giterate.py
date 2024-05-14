import argparse, re, lizard, glob, datetime, json, sys, subprocess, time
from pprint import pprint
from packaging import version as semver
from loguru import logger
from git import Repo
from pathlib import Path
from depsec.utils.proc import *
from depsec.aggregator import Aggregator
from depsec.schemas.projects import *
# This tool iterates git tags and runs a command for each tag

SEMVER_TAG = r'v?(\d+\.\d+(?:\.\d+)?)'
CALVER_TAG = r'(\d{4}[a-z]?(?:\.\d+){0,2})'

parser = argparse.ArgumentParser(description='Iterate git tags and run a command for each tag')
parser.add_argument('-p', '--projects', help='The projects file', default='projects.json')
parser.add_argument('-l', '--limit', help='The number of most recent releases to process', type=int, default=0)
parser.add_argument('-d', '--directory', help='The repositories directory', default='repositories')
parser.add_argument('--config', help='The configuration file to use', default='config.yml')
parser.add_argument('--level', help='The logging level to use', default='INFO')
parser.add_argument('--force', help='Force the operation', action='store_true')
parser.add_argument('--do', help='The operation to do', default=[], nargs='*')
parser.add_argument('-o', '--only', help='Only do the mentioned projects', default=[], nargs='*')
parser.add_argument('-c', '--clone', help='Clone if the repository does not exist', action='store_true', default=False)
parser.add_argument('-s', '--skips', help='Tests to skip, in Bandit test IDs (b?\d{3})', default='')
parser.add_argument('--tags', help='Show tags only', action='store_true')
parser.add_argument('--exclude-projects', help='Exclude the mentioned projects', default=[], nargs='*')

args = parser.parse_args()
excluded_projects = set(map(str.lower, args.exclude_projects))

skips = args.skips
if bool(skips):
    skips = skips.split(',')
    skips = list(map(lambda x: f"B{x}" if not x.upper().startswith('B') else x.upper(), skips))
args.skips = ','.join(skips)

logger.remove()
logger.add(sys.stdout, level=args.level.upper())

only = set(map(str.lower, args.only))

aggr = Aggregator(args.config)
aggr.load_projects()

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

def version_tag(tag: str, pattern: str = None):
    """
    Returns the version tag from the tag if it matches the pattern
    """
    if type(pattern) == str:
        if '@semver' in pattern:
            pattern = pattern.replace('@semver', SEMVER_TAG)
        if '@calver' in pattern:
            pattern = pattern.replace('@calver', CALVER_TAG)
    else:
        pattern = SEMVER_TAG
    pattern = rf"^{pattern}$"
    groups = re.match(pattern, tag)
    if groups:
        return groups.group(1)
    return None

for platform, projects in data.items():

    for project_name in projects:

        if project_name.lower() in excluded_projects:
            logger.debug(f"Excluding {platform} project '{project_name}'")
            continue

        if only and project_name.lower() not in only:
            logger.debug(f"Skipping {platform} project '{project_name}', only '{', '.join(list(only))}' provided")
            continue

        logger.info(f"Processing {platform} project {project_name}")
        repo = projects.get(project_name, {}).get('repo')
        if not repo:
            logger.warning(f"Repository not found for {project_name}, skipping...")
            continue

        url = repo.get('url')
        includes = repo.get('includes')
        excludes = repo.get('excludes')
        url = re.sub(r'https?://', '', url)
        url = re.sub(r'.git$', '', url)
        repo_name = url.split('/')[-1]
        if '.' in repo_name:
            repo_name = repo_name.split('.')[0]
        url = f"https://{url}.git"

        # Get the project
        project = aggr.get_project(project_name, platform)
        if not project:
            print(f"Project {project_name} not found")
            continue

        repo_path = directory / repo_name

        depsec_name = repo.get('depsec') or repo_name

        tag_pattern = repo.get('tags')

        if not repo_path.exists():
            # TODO: Clone the repository
            if args.clone:
                logger.info(f"Cloning {repo_name} to {repo_path}... (url: {url})")
                try:
                    repo = Repo.clone_from(url, repo_path)
                except Exception as e:
                    logger.error(f"Failed to clone {project_name} to '{repo_path}', error: {e}")
                    exit(1)
                logger.info(f"Cloned {project_name} to '{repo_path}'!")
            else:
                logger.error(f"Repository {repo_name} does not exist, skipping, clone with --clone")
                continue

        logger.info(f"Checking out {repo_name} to {repo_path}")
        repo = Repo(repo_path)
        tags = repo.tags
        versions = {}

        if args.tags:
            tags = [ tag.name for tag in tags ]
            tags = sorted(list(set(tags)))
            print(f"-- Tags for {repo_name} --")
            for tag in tags:
                v = version_tag(tag, tag_pattern)
                if v:
                    print(f"{v} <<-- '{tag}' matches")
                else:
                    print(tag)
            continue
        
        for tag in tags:
            tag_version = version_tag(tag.name, tag_pattern)
            if not tag_version:
                continue
            versions[tag_version] = tag
        
        logger.info(f"Versions found for {repo_name}: {len(versions)}")
        processed = 0
        rels = aggr.get_releases(project_name, platform)
        rels = [ rel.version for rel in rels]
        logger.info(f"Releases found for {repo_name}: {', '.join(rels)}")

        version_iter = []
        for v in versions.keys():
            try:
                semver.parse(v)
                version_iter.append(v)
            except:
                print(f"Invalid version: {v}")
                pass

        for version in sorted(version_iter, key=semver.parse, reverse=True):
            print(f"Processing {project_name}:{version}...")
            if bool(args.limit) and processed > args.limit:
                logger.info(f"Limit of {args.limit} reached, stopping")
                break
            release: Release = aggr.get_release(project_name, version, platform)
            if release is None:
                logger.warning(f"Release '{version}' for {project_name} not found by metadata, ignoring")
                continue
            if excludes:
                release.excludes = ', '.join(list(map(str, excludes)))
                release.save()
            if includes:
                release.includes = ', '.join(list(map(str, includes)))
                release.save()
            processed += 1
            tag = versions[version]
            repo.git.checkout(tag.commit, force=True)
            date_time = datetime.datetime.fromtimestamp(tag.commit.committed_date)
            release.commit_at = date_time
            release.commit_hash = str(tag.commit)
            date_str = date_time.strftime('%Y-%m-%d %H:%M:%S')
            if excludes:
                excl_str = ', '.join(list(map(str, excludes)))
                logger.info(f"Updating {project_name}:{version} excludes to '{excl_str}'")
                release.excludes = excl_str
            if includes:
                incl_str = ', '.join(list(map(str, includes)))
                logger.info(f"Updating {project_name}:{version} includes to '{incl_str}'")
                release.includes = incl_str
            release.save()
            if 'lizard' in args.do or 'all' in args.do:
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
            if 'bandit' in args.do or 'all' in args.do:
                res = run_bandit(repo_path, includes, excludes, temp_dir, skips=args.skips)
                if not res:
                    logger.error(f"Bandit failed for {project_name}:{version}")
                    continue
                previous_report = BanditReport.get_or_none(BanditReport.release == release)
                if previous_report:
                    previous_report.delete_instance()
                sevconf = res.get('severity_confidence', {})
                logger.info(f"{project_name}:{version}, files: {res.get('files_with_issues')}, issues: {res.get('issues_total')}")
                report = BanditReport.create(
                    release=release,
                    files_with_issues=res.get('files_with_issues'),
                    files_skipped=res.get('files_skipped'),
                    issues_total=res.get('issues_total'),
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
