import re, lizard, glob, datetime, json, sys, subprocess, time
from pprint import pprint
from packaging import version as semver
from loguru import logger
from git import Repo
from pathlib import Path
from src.utils.proc import *
from src.aggregator import Aggregator
from src.schemas.projects import *
# This tool iterates git tags and runs a command for each tag

SEMVER_TAG = r'v?(\d+\.\d+(?:\.\d+)?)'
CALVER_TAG = r'(\d{4}[a-z]?(?:\.\d+){0,2})'

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

def run_analysis(project: Project, directory: Path, temp_dir: Path = '/tmp', lizard: bool = True, bandit: bool = True):
    """
    Analyse a project with lizard and bandit
    """
    directory = Path(directory)
    project_name = project.name.lower()
    platform = project.platform.lower()
    repo_url = project.repository_url

    logger.info(f"Processing {platform} project {project_name}")
    if not repo_url:
        logger.warning(f"Repository not found for '{project_name}', skipping...")
        return None

    url = re.sub(r'https?://', '', repo_url)
    url = re.sub(r'.git$', '', url)
    repo_name = url.split('/')[-1]
    if '.' in repo_name:
        repo_name = repo_name.split('.')[0]
    url = f"https://{url}.git"

    repo_path = directory / repo_name
    tag_regex = project.tag_regex

    if not repo_path.exists():
        # clone the repository
        logger.info(f"Cloning {repo_name} to {repo_path}... (url: {url})")
        try:
            repo = Repo.clone_from(url, repo_path)
        except Exception as e:
            logger.error(f"Failed to clone {project_name} to '{repo_path}', error: {e}")
            return None
        logger.info(f"Cloned {project_name} to '{repo_path}'!")

    includes = project.includes
    if type(includes) == str:
        includes = [ incl.strip() for incl in includes.split(',') ]
    elif includes is None:
        includes = ['src/', f"{project_name}/"]
    excludes = project.excludes
    if type(excludes) == str:
        excludes = [ excl.strip() for excl in excludes.split(',') ]
    elif excludes is None:
        excludes = ['tests/', 'test/', 'docs/', 'doc/', 'examples/', 'example/']

    logger.info(f"Checking out {repo_name} to {repo_path}")
    repo = Repo(repo_path)
    tags = repo.tags
    versions = {}
    
    for tag in tags:
        tag_version = version_tag(tag.name, tag_regex)
        if not tag_version:
            continue
        versions[tag_version] = tag
    
    logger.info(f"Versions found for {repo_name}: {len(versions)}")
    processed = 0
    rels = project.releases
    rels = {rel.version: rel for rel in rels}
    logger.info(f"Releases found for {repo_name}: {', '.join(rels.keys())}")

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
        release: Release = rels.get(version)
        if release is None:
            logger.warning(f"Release '{version}' for {project_name} not found by metadata, ignoring")
            continue
        if excludes:
            release.excludes = ','.join(list(map(str, excludes)))
            release.save()
        if includes:
            release.includes = ','.join(list(map(str, includes)))
            release.save()
        processed += 1
        tag = versions[version]
        repo.git.checkout(tag.commit, force=True)
        date_time = datetime.datetime.fromtimestamp(tag.commit.committed_date)
        release.commit_at = date_time
        release.commit_hash = str(tag.commit)
        if excludes:
            excl_str = ', '.join(list(map(str, excludes)))
            logger.info(f"Updating {project_name}:{version} excludes to '{excl_str}'")
            release.excludes = excl_str
        if includes:
            incl_str = ', '.join(list(map(str, includes)))
            logger.info(f"Updating {project_name}:{version} includes to '{incl_str}'")
            release.includes = incl_str
        release.save()
        if lizard:
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
        if bandit:
            reports = BanditReport.select().where(BanditReport.release == release)
            for report in reports:
                report.delete_instance()
            res = run_bandit(repo_path, includes, excludes, temp_dir)
            if not res:
                logger.error(f"Bandit failed for {project_name}:{version}")
                continue
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
                test_id = issue.get('test_id')
                issue_db = BanditIssue.create(
                    report=report,
                    description=issue.get('issue_text'),
                    filename=issue.get('filename'),
                    lines=lines,
                    code=issue.get('code'),
                    confidence=issue.get('issue_confidence', 'undefined').lower(),
                    severity=issue.get('issue_severity', 'undefined').lower(),
                    cwe_id=cwe,
                    test_id=test_id,
                    test_category=test_id[:2] if test_id else None,
                    test_name=issue.get('test_name'),
                    more_info=issue.get('more_info'),
                )
                if issue_db:
                    issue_db.save()
        release.save()
