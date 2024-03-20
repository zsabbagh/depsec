import argparse, re, lizard, glob, datetime, json, sys
from packaging import version
from loguru import logger
from git import Repo
from pathlib import Path
from src.middleware import Middleware
# This tool iterates git tags and runs a command for each tag

VERSION_TAG = r'^v?\d+\.\d+\.\d+$'

def is_version_tag(tag: str):
    """
    Checks if a tag is a version tag
    """
    return bool(re.match(VERSION_TAG, tag))

def get_code_complexity(dir: str | Path, includes: str | list = '**/*.py', excludes: str | list = None):
    """
    Gets the code complexity of a directory using lizard
    """
    dir = Path(dir)
    if not dir.exists():
        return None, None, None
    total_nloc = 0
    cc = 0
    functions = 0
    files = []
    includes = [includes] if type(includes) == str else includes
    exclude_set = set(excludes) if excludes else set()
    if excludes:
        excludes = [excludes] if type(excludes) == str else excludes
        for exclude in excludes:
            for file in glob.glob(str(dir / exclude), recursive=True):
                exclude_set.add(str(file))
    for include in includes:
        for file in glob.glob(str(dir / include), recursive=True):
            if file in exclude_set:
                continue
            files.append(file)
    if not files:
        logger.warning(f"No files found in {dir} with includes {includes} and excludes {excludes}")
        # Files in the directory
        files = list(dir.glob('*'))
        if not files:
            logger.warning(f"No files found in {dir}")
        else:
            files = [str(file.name) for file in files]
            logger.warning(f"Files found in {dir}: {', '.join(files)}")
        return None, None, None
    for file in files:
        file = Path(file)
        if file.name == '__init__.py' or 'test' in file.name:
            continue
        lizard_result = lizard.analyze_file(str(file))
        total_nloc += lizard_result.nloc
        for func in lizard_result.function_list:
            cc += func.cyclomatic_complexity
            functions += 1
    avg_cc = cc / functions if functions > 0 else 0
    avg_nloc = total_nloc / functions if functions > 0 else 0
    return total_nloc, avg_nloc, avg_cc, len(files)

parser = argparse.ArgumentParser(description='Iterate git tags and run a command for each tag')
parser.add_argument('--projects', help='The projects file', default='projects.json')
parser.add_argument('--directory', help='The repositories directory', default='repositories')
parser.add_argument('--config', help='The configuration file to use', default='config.yml')
parser.add_argument('--level', help='The logging level to use', default='INFO')


args = parser.parse_args()

logger.remove()
logger.add(sys.stdout, level=args.level.upper())

mw = Middleware(args.config)

directory = Path(args.directory)
if not directory.exists():
    logger.error(f"Directory {directory} does not exist")
    exit(1)

data = None
with open(args.projects, 'r') as f:
    data = json.load(f)

for platform, projects in data.items():

    for project_name in projects:

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
            pass

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

        for ver in sorted(versions.keys(), key=lambda x : version.parse(x), reverse=True):
            release = mw.get_release(repo_name, ver, platform)
            if release is None:
                logger.warning(f"Release {project_name}:{ver} not found by metadata, ignoring")
                continue
            tag = versions[ver]
            repo.git.checkout(tag.commit, force=True)
            if release.total_nloc is not None and release.total_nloc > 0:
                logger.info(f"{project_name}:{ver} already exists with NLOC {release.total_nloc}, skipping")
                continue
            total_nloc, avg_nloc, avg_cc, files_counted = get_code_complexity(repo_path.absolute(), includes, excludes)
            date_time = datetime.datetime.fromtimestamp(tag.commit.committed_date)
            date_str = date_time.strftime('%Y-%m-%d %H:%M:%S')
            release = mw.get_release(repo_name, ver, platform)
            release.files_counted = files_counted
            release.total_nloc = round(total_nloc, 2) if total_nloc is not None else None
            release.avg_nloc = round(avg_nloc, 2) if avg_nloc is not None else None
            release.avg_cc = round(avg_cc, 2) if avg_cc is not None else None
            release.save()
            logger.info(f"{project_name}:{ver}, files: {files_counted}, NLOC {total_nloc}")