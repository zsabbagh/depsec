import re, lizard, glob, datetime, json, sys, subprocess, time, os
from pprint import pprint
from packaging import version as semver
from loguru import logger
from depsec.utils import tools
from git import Repo
from pathlib import Path
from depsec.utils.proc import *
from depsec.schemas.projects import *

# This tool iterates git tags and runs a command for each tag

# second group is pre/rc/alpha/beta
SEMVER_TAG = r"v?(\d+\.\d+(?:\.\d+)?)(?:[\-.]((?:pre|rc|a|b)(?:\d+)?))?"
CALVER_TAG = r"(\d{4}[a-z]?(?:\.\d+){0,2})"


def is_semver(tag: str):
    return bool(re.match(SEMVER_TAG, tag))


def is_calver(tag: str):
    return bool(re.match(CALVER_TAG, tag))


def version_tag(tag: str, pattern: str = None):
    """
    Returns the version tag from the tag if it matches the patter\item[\textbf{RQ}.] How can one enable the automated analysis of the security of \Gls{OSS} projects and provide an understanding of the impact that dependencies have on a project, with respect to codebase complexity and security, with a focus on the packages present in the Python ecosystem?n
    """
    if type(pattern) == str:
        if "@semver" in pattern:
            pattern = pattern.replace("@semver", SEMVER_TAG)
        if "@calver" in pattern:
            pattern = pattern.replace("@calver", CALVER_TAG)
    else:
        pattern = SEMVER_TAG
    groups = re.match(pattern, tag)
    if groups:
        pre = groups.group(2) if groups.group(2) else ""
        return f"{groups.group(1)}{pre}"
    return None


def get_owner_project(github_url: str):
    """
    Get the owner and project name from a GitHub URL
    """
    groups = re.match(r"(?:https?://)?github.com/([^/]+)/([^/]+)", github_url)
    if groups is None:
        logger.error(f"Invalid GitHub URL: {github_url}")
        return None, None
    owner = groups.group(1)
    project = groups.group(2)
    return owner, project


def clone_repo(project: Project, repos_dir: Path | str, prompt: bool = True):
    """
    Clone a repository
    """
    if type(repos_dir) == str:
        repos_dir = Path(repos_dir)
    project_name = project.name.lower()
    platform = project.platform.lower()
    repo_url = project.repository_url

    logger.info(f"Processing {platform} project {project_name}")
    if not repo_url:
        logger.warning(f"Repository not found for '{project_name}', skipping...")
        return None, None
    elif "github" not in repo_url:
        logger.error(
            f"Unsupported platform for '{project_name}', skipping '{repo_url}'..."
        )
        return None, None

    owner, repo_name = get_owner_project(repo_url)
    url = f"https://github.com/{owner}/{repo_name}.git"

    repo_path = repos_dir / owner / repo_name

    if not repo_path.exists():
        # clone the repository
        logger.info(f"Cloning {repo_name} to {repo_path}... (url: {url})")
        try:
            if prompt:
                prompt = input(f"Clone {project_name} to '{repo_path}'? (Y/n): ")
                if prompt.lower() == "n":
                    logger.warning(f"Skipping {project_name}")
                    return None, None
            repo = Repo.clone_from(url, repo_path)
        except Exception as e:
            logger.error(f"Failed to clone {project_name} to '{repo_path}', error: {e}")
            return None, None
        logger.info(f"Cloned {project_name} to '{repo_path}'!")
    else:
        repo = Repo(repo_path)
    return repo, repo_path


def identify_tags(repo: Repo):
    """
    Identify tags in the repository
    """
    semver_matches = []
    calver_matches = []
    tags = repo.tags
    total_tags = len(tags)
    for tag in tags:
        tagname = tag.name
        semver_tag = re.match(SEMVER_TAG, tag.name)
        if semver_tag:
            s = semver_tag.group(1)
            semver_matches.append(f"{tagname} ({s})")
        calver_tag = re.match(CALVER_TAG, tag.name)
        if calver_tag:
            s = calver_tag.group(1)
            calver_matches.append(f"{tagname} ({s})")
    print(
        f"Semver matches ({len(semver_matches)} / {total_tags}): {', '.join(semver_matches)}"
    )
    print(
        f"Calver matches ({len(calver_matches)} / {total_tags}): {', '.join(calver_matches)}"
    )
    print(f"If none of the above, please provide a regex pattern to match the tags")
    tag_regex = input("Enter the tag regex (@semver, @calver expands): ")
    return (
        f"{tag_regex}"
        if tag_regex
        else ("@semver" if len(semver_matches) > len(calver_matches) else "@calver")
    )


def find_main_package(project: Project, repo_path: str | Path):
    """
    Find the main package in a Python repository
    """
    if type(repo_path) == str:
        repo_path = Path(repo_path)
    max_count = 0
    main_package = None
    for root, dirs, files in os.walk(repo_path):
        if "__init__.py" in files:
            # Count Python files in the directory
            py_files_count = sum(1 for f in files if f.endswith(".py"))
            # Update main package if this directory has more Python files
            if py_files_count > max_count:
                max_count = py_files_count
                main_package = root
    if main_package is None and (repo_path / f"{project.name}.py").exists():
        main_package = repo_path / f"{project.name}.py"

    return main_package


def get_includes(project_name: str, repo_path: Path, in_python: bool = False):
    """
    Get the includes for a project
    """
    repo_path = Path(repo_path).absolute()
    includes = []
    if not includes:
        # check if 'python' directory exists
        python_dir = repo_path / "python"
        if python_dir.exists() and not in_python:
            # can only happen for the root directory
            includes = includes + get_includes(project_name, python_dir, in_python=True)
        src_dir = repo_path / "src"
        if src_dir.exists():
            includes.append("src/")
    # get files and directories in the repository
    fildirs = [f for f in glob.glob(f"{repo_path}/*", recursive=False)]
    for fildir in fildirs:
        fildir = Path(fildir)
        stem = fildir.stem
        if stem.lower() in project_name.lower():
            if fildir.is_file():
                includes.append(fildir.name)
            else:
                includes.append(f"{fildir.name}/")
    return includes


def get_package_and_module(project: Project | str, file_path: Path | str):
    """
    Get the package and module name from a file path
    """
    if type(file_path) == str:
        file_path = Path(file_path)
    file_path = Path(file_path)
    project_name = project.name.lower() if type(project) == Project else project.lower()
    parts = list(file_path.parts)
    filename = file_path.name
    module = file_path.stem
    package = []
    for i, part in enumerate(parts):
        if str(part).lower() == project_name and i < len(parts) - 1:
            package = parts[i + 1 : -1] if i + 1 < len(parts) else []
            break
    package = ".".join(package)
    return package if package != filename else ".", module


def run_analysis(
    project: Project,
    repos_dir: Path,
    *v_or_rel: str | Release,
    temp_dir: Path = "/tmp",
    lizard: bool = True,
    bandit: bool = True,
    limit: int = None,
    skip_pre: bool = True,
):
    """
    Analyse a project with lizard and bandit
    """
    repos_dir = Path(repos_dir)
    project_name = project.name.lower()
    tag_regex = project.tag_regex

    platform = project.platform.lower()

    # this should be done already, connect to the repo
    repo, repo_path = clone_repo(project, repos_dir)
    if repo is None:
        logger.error(f"Failed to clone {project_name}, skipping...")
        return

    includes = get_includes(project_name, repo_path)
    excludes = project.excludes
    if type(excludes) == str:
        excludes = [excl.strip() for excl in excludes.split(",")]

    follows_standard = False
    for incl in includes:
        if (repo_path / incl).exists():
            follows_standard = True
    if not follows_standard:
        print(
            f"Project {project_name} does not follow standard Python package structure"
        )
    tags = repo.tags
    versions = {}

    for tag in tags:
        tag_version = version_tag(tag.name, tag_regex)
        if not tag_version:
            continue
        versions[tag_version] = tag

    logger.info(f"Versions found for {project_name}'s repo: {len(versions)}")
    processed = 0
    rels = project.releases
    rels = {rel.version: rel for rel in rels}
    logger.info(f"Releases found for {project_name}: {len(rels)}")

    releases = (
        set([rel.version if type(rel) == Release else rel for rel in v_or_rel])
        if v_or_rel
        else set()
    )
    logger.debug(f"Releases '{sorted(list(releases))}' provided.")

    version_iter = []
    release_tags = 0
    for v in versions.keys():
        try:
            semver.parse(v)
            release_tags += 1
            if len(releases) > 0 and v not in releases:
                logger.debug(f"Releases provided, skipping '{v}'...")
                continue
            if skip_pre and tools.version_has_pre(v):
                logger.debug(f"Skipping pre-release '{v}'...")
                continue
            version_iter.append(v)
        except:
            logger.warning(f"Invalid version tag '{v}' found, skipping...")
            pass
    project.release_tags = release_tags
    project.save()
    if includes:
        project.includes = ",".join(list(map(str, includes)))
    if not project.excludes and excludes:
        project.excludes = ",".join(list(map(str, excludes)))
    project.save()
    processed_count = 0
    for version in sorted(version_iter, key=semver.parse, reverse=True):
        if limit and tools.version_has_pre(version):
            print(
                f"Skipping pre-release {version}, as limit is set to {limit} versions"
            )
            continue
        release: Release = rels.get(version)
        if release is None:
            logger.warning(
                f"Release '{version}' for {project_name} not found by metadata, ignoring"
            )
            continue
        processed_count += 1
        print(
            f"Processing {project_name}:{version} ({processed_count}/{len(version_iter) if limit is None else limit})..."
        )
        if (limit and limit > 0) and processed_count > limit:
            logger.debug(f"Limit reached, stopping at {limit} versions")
            break
        if excludes:
            release.excludes = ",".join(list(map(str, excludes)))
            release.save()
        processed += 1
        tag = versions[version]
        repo.git.checkout(tag.commit, force=True)
        # add includes to each release
        includes = get_includes(project_name, repo_path)
        if includes:
            release.includes = ",".join(list(map(str, includes)))
            release.save()
        date_time = datetime.datetime.fromtimestamp(tag.commit.committed_date)
        release.commit_at = date_time
        release.commit_hash = str(tag.commit)
        if excludes:
            excl_str = ", ".join(list(map(str, excludes)))
            logger.info(f"Updating {project_name}:{version} excludes to '{excl_str}'")
            release.excludes = excl_str
        if includes:
            incl_str = ", ".join(list(map(str, includes)))
            logger.info(f"Updating {project_name}:{version} includes to '{incl_str}'")
            release.includes = incl_str
        release.save()
        time_lizard = None
        time_bandit = None
        if lizard:
            file_ext = ".js|.ts" if project.platform == "npm" else ".py"
            time_before = time.time()
            res = run_lizard(repo_path, includes, excludes, file_ext=file_ext)
            time_lizard = time.time() - time_before
            nloc = res.get("nloc")
            avg_nloc = res.get("nloc_average")
            avg_ccn = res.get("ccn_average")
            files_counted = res.get("files")
            functions_counted = res.get("functions")
            release.time_to_analyse = time_lizard
            release.counted_files = files_counted
            release.counted_functions = functions_counted
            release.nloc_total = round(nloc, 2) if nloc is not None else None
            release.nloc_average = round(avg_nloc, 2) if avg_nloc is not None else None
            release.ccn_average = round(avg_ccn, 2) if avg_ccn is not None else None
            logger.info(
                f"{project_name}:{version}, files: {files_counted}, NLOC {nloc}"
            )
        if bandit:
            if platform != "pypi":
                logger.error(
                    f"Error: Bandit is only supported for PyPI projects, skipping {project_name}:{version}"
                )
                continue
            time_before = time.time()
            reports = BanditReport.select().where(BanditReport.release == release)
            time_bandit = time.time() - time_before
            for report in reports:
                report.delete_instance()
            res = run_bandit(repo_path, includes, excludes, temp_dir)
            if not res:
                logger.error(f"Bandit failed for {project_name}:{version}")
                continue
            sevconf = res.get("severity_confidence", {})
            logger.info(
                f"{project_name}:{version}, files: {res.get('files_with_issues')}, issues: {res.get('issues_total')}"
            )
            report = BanditReport.create(
                release=release,
                time_to_analyse=time_bandit,
                files_with_issues=res.get("files_with_issues"),
                files_skipped=res.get("files_skipped"),
                issues_total=res.get("issues_total"),
                confidence_high_count=res.get("confidence_high_count"),
                confidence_medium_count=res.get("confidence_medium_count"),
                confidence_low_count=res.get("confidence_low_count"),
                confidence_undefined_count=res.get("confidence_undefined_count"),
                severity_high_count=res.get("severity_high_count"),
                severity_medium_count=res.get("severity_medium_count"),
                severity_low_count=res.get("severity_low_count"),
                severity_undefined_count=res.get("severity_undefined_count"),
                severity_h_confidence_h_count=sevconf.get("high", {}).get("high", 0),
                severity_h_confidence_m_count=sevconf.get("high", {}).get("medium", 0),
                severity_h_confidence_l_count=sevconf.get("high", {}).get("low", 0),
                severity_m_confidence_h_count=sevconf.get("medium", {}).get("high", 0),
                severity_m_confidence_m_count=sevconf.get("medium", {}).get(
                    "medium", 0
                ),
                severity_m_confidence_l_count=sevconf.get("medium", {}).get("low", 0),
                severity_l_confidence_h_count=sevconf.get("low", {}).get("high", 0),
                severity_l_confidence_m_count=sevconf.get("low", {}).get("medium", 0),
                severity_l_confidence_l_count=sevconf.get("low", {}).get("low", 0),
                loc=res.get("loc"),
                nosec=res.get("nosec"),
                skipped_tests=res.get("skipped_tests"),
                updated_at=datetime.datetime.now(),
            )
            report.save()
            for issue in res.get("issues", []):
                lines = issue.get("line_range", [])
                if type(lines) == list:
                    lines = ", ".join(map(str, lines))
                else:
                    lines = str(lines)
                cwe = issue.get("issue_cwe", {})
                cwe = f"CWE-{cwe.get('id')}" if cwe else None
                test_id = issue.get("test_id")
                filename = issue.get("filename")
                filepath = Path(filename)
                filepath = str(filepath.absolute()).replace(
                    str(repo_path.absolute()), ""
                )
                package, module = get_package_and_module(project, filepath)
                issue_db = BanditIssue.create(
                    report=report,
                    description=issue.get("issue_text"),
                    filename=filepath,
                    lines=lines,
                    module=module,
                    package=package,
                    code=issue.get("code"),
                    confidence=issue.get("issue_confidence", "undefined").lower(),
                    severity=issue.get("issue_severity", "undefined").lower(),
                    cwe_id=cwe,
                    test_id=test_id,
                    test_category=test_id[:2] if test_id else None,
                    test_name=issue.get("test_name"),
                    more_info=issue.get("more_info"),
                )
                if issue_db:
                    issue_db.save()
        release.save()
