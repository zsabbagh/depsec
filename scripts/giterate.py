import argparse, re, lizard, glob, datetime
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

def get_code_complexity(dir: str | Path):
    """
    Gets the code complexity of a directory using lizard
    """
    dir = Path(dir)
    total_nloc = 0
    cc = 0
    functions = 0
    for file in glob.glob(str(dir / '**/*.py'), recursive=True):
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
    return total_nloc, avg_nloc, avg_cc

parser = argparse.ArgumentParser(description='Iterate git tags and run a command for each tag')
parser.add_argument('directories', help='The directories of the git repositories (dir:src, or platform:dir:src)', nargs='+')
parser.add_argument('--platform', help='The platform that is used', default='pypi')
parser.add_argument('--config', help='The configuration file to use', default='config.yml')

args = parser.parse_args()

mw = Middleware(args.config)

platform = args.platform

for directory in args.directories:

    if ':' in directory:
        parts = directory.split(':')
        if len(parts) == 3:
            platform, directory, src_name = tuple(parts)
        elif len(parts) == 2:
            directory, src_name = tuple(parts)
    else:
        src_name = None

    repo_path = Path(directory)
    repo_name = repo_path.name

    src_name = src_name or repo_name
    src_path = repo_path / src_name

    repo = Repo(repo_path)

    tags = repo.tags

    versions = {}

    for tag in tags:
        if not is_version_tag(tag.name):
            continue
        tag_version = tag.name.lstrip('v')
        versions[tag_version] = tag

    print(f"Found {len(versions)} versions")

    for version in sorted(versions.keys(), reverse=True):
        release = mw.get_release(repo_name, version, platform)
        tag = versions[version]
        repo.git.checkout(tag.commit)
        total_nloc, avg_nloc, avg_cc = get_code_complexity(src_path)
        date_time = datetime.datetime.fromtimestamp(tag.commit.committed_date)
        date_str = date_time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"{tag.name}: {total_nloc}")

        # repo.git.checkout(tag)
        # Run command here