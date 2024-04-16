import re, datetime
from loguru import logger
from packaging import version as semver
from pathlib import Path
from loguru import logger
from src.schemas.projects import Release, Project

def bandit_value_score(value: str) -> int:
    """
    Calculate the score of a Bandit issue severity or confidence value.
    """
    value = value.lower()
    match value:
        case 'low':
            return 0
        case 'medium':
            return 1
        case 'high':
            return 2
    return 0

def bandit_issue_score(severity: str, confidence: str) -> int:
    """
    Calculate the score of a Bandit issue.
    """
    return bandit_value_score(severity) + bandit_value_score(confidence)

def parse_requirement(requirement: str) -> dict:
    """
    
    """
    requirement = requirement.strip()
    regex = re.match(r'([<>=]+)(.*)', requirement)
    if not regex:
        logger.debug(f"Error parsing requirement '{requirement}'")
        return None
    try:
        operator, version = regex.groups()
    except Exception as e:
        logger.debug(f"Error parsing requirement '{requirement}'")
        return None
    return operator, version

def date_range(start_date: str | int | datetime.datetime, end_date: str | int | datetime.datetime, step: str = 'm'):
    """
    Generate a range of dates.

    start_date: The start date
    end_date: The end date
    step: The step size ('m' for months, 'y' for years)
    """
    start_date = strint_to_date(start_date)
    end_date = strint_to_date(end_date)
    if start_date is None:
        return
    end_date = datetime.datetime.now() if end_date is None else end_date
    current_date = start_date
    while current_date < end_date:
        yield current_date
        current_date = datetime_increment(current_date, step)

def parse_requirements(requirements: str) -> list:
    """
    Parse a list of requirements.
    """
    if requirements is None:
        return []
    if type(requirements) == str:
        requirements = requirements.strip().split(',')
    results = [parse_requirement(requirement) for requirement in requirements]
    return [result for result in results if result]

def get_max_version(requirements: str) -> str:
    """
    Get the maximum version from a list of requirements.

    requirements: The requirements to check

    Returns: The maximum version and whether it is inclusive
    """
    requirements = parse_requirements(requirements)
    max_version = include_end = None
    for requirement in requirements:
        operator, version = requirement
        include_end = operator.startswith('<=')
        if operator.startswith('<'):
            if max_version is None or semver.parse(version) > semver.parse(max_version):
                max_version = semver.parse(version)
    return max_version, include_end

def version_satisfies_requirements(v: str, requirements: str) -> bool:
    """
    Check if a version satisfies the requirements.

    v: The version to check
    requirements: The requirements to check
    """
    v = semver.parse(v.strip('.')) if type(v) == str else v
    requirements = requirements.split(',')
    for requirement in requirements:
        parsed = parse_requirement(requirement)
        if not parsed:
            return False
        operator, version = parsed
        version = semver.parse(version.strip('.'))
        match operator:
            # return False if the version does not satisfy the requirement
            case '>':
                if v <= version:
                    return False
            case '>=':
                if v < version:
                    return False
            case '<':
                if v >= version:
                    return False
            case '<=':
                if v > version:
                    return False
            case '==':
                if v != version:
                    return False
            case '!=':
                if v == version:
                    return False
            case _:
                raise ValueError(f"Unexpected operator '{operator}'")
    return True

def strint_to_date(date: str | int | datetime.datetime | None):
    """
    Convert a date to a datetime object.

    date: int implies a year, str implies a date, datetime implies a datetime object
    """
    if date is None:
        return None
    if type(date) == datetime.datetime:
        return date
    if type(date) == int:
        date = str(date)
    count_dash = date.count('-')
    fmt = '%Y-%m-%d' if count_dash == 2 else '%Y-%m' if count_dash == 1 else '%Y'
    if type(date) == str:
        return datetime.datetime.strptime(date, fmt)
    raise ValueError(f"Unexpected date type '{type(date).__name__}'")

def version_in_range(v: str, start: str = None, end: str = None, exclude_start: bool = False, exclude_end: bool = False) -> bool:
    """
    Compare two versions using semver.
    Defaults to inclusive start and inclusive end.
    """
    v = semver.parse(v) if type(v) == str else v
    start = semver.parse(start) if type(start) == str else start
    end = semver.parse(end) if type(end) == str else end
    is_after_start = start is None or (v > start if exclude_start else v >= start)
    is_before_end = end is None or (v < end if exclude_end else v <= end)
    return is_after_start and is_before_end

def version_is_stable(v: str) -> bool:
    """
    Check if a version is deprecated or not a stable release.
    """
    v = semver.parse(v) if type(v) == str else v
    return (v.major >= 1 and v.pre is None) if v else False

def datetime_increment(dt: datetime.datetime, step: str = 'm'):
    """
    Increment a datetime object by a given step.
    """
    year, month = dt.year, dt.month
    if step == 'y':
        year += 1
    elif step == 'm':
        month += 1
        if month > 12:
            month = 1
            year += 1
    else:
        raise ValueError(f"Unimplemented step '{step}'")
    return datetime.datetime(year, month, 1)

def get_database_dir_and_name(databases: dict, name: str):
    """
    Get the path and name of the database
    """
    data = databases.get(name, {})
    path = data.get('path', './data')
    path = Path(path).resolve()
    if not path.exists():
        raise ValueError(f"Path does not exist for '{name}', cannot create database to non-existent path '{path}'")
    elif not path.is_dir():
        raise ValueError(f"Path is not a directory for '{name}', cannot create database to non-directory path '{path}'")
    name = data.get('name', name)
    if not name.endswith('.db'):
        name = f"{name}.db"
    return path, name

def create_purl(type, namespace, name, version, qualifiers=None, subpath=None):
    """
    Create a PURL (Package URL) string, used by Snyk for example.

    type: The package type (e.g., 'pypi' for Python packages).
    namespace: The namespace of the package (often left blank for Python).
    name: The name of the package.
    version: The version of the package.
    qualifiers: A dictionary of qualifier keys and values.
    subpath: The subpath within the package.
    """
    purl = f"pkg:{type}/{namespace}/{name}@{version}"
    if qualifiers:
        # Convert qualifiers dictionary to a sorted, encoded string
        qualifier_str = '&'.join(f"{key}={value}" for key, value in sorted(qualifiers.items()))
        purl += f"?{qualifier_str}"
    if subpath:
        purl += f"#{subpath}"
    return purl

def homepage_to_vendor(homepage: str) -> str:
    """
    Get the vendor from the homepage URL.

    This is not a perfect solution, but it works for most cases.
    """
    if not homepage:
        return None
    homepage = re.sub(r'^https?://', '', homepage)
    parts = homepage.split('.')
    if len(parts) < 2:
        return None
    domain = parts[-2]
    if domain == 'github':
        result = parts[-1]
        if result is not None:
            result = result.split('/')
            result = result[1] if len(result) > 1 else None
    elif domain == 'readthedocs':
        return None
    else:
        result = parts[-2]
    return result

def datetime_in_range(dt: datetime.datetime,
                      start: datetime.datetime,
                      end: datetime.datetime,
                      exclude_start: bool = False,
                      exclude_end: bool = True):
    """
    Check if a datetime is within a range.

    dt: The datetime to check
    start: The start of the range
    end: The end of the range (exclusive)
    exclude_start: Whether to exclude the start of the range (default: False, inclusive)
    exclude_end: Whether to exclude the end of the range (default: True, exclusive)
    """
    exclude_start, exclude_end = bool(exclude_start), bool(exclude_end)
    def comp_start(dt, start):
        return dt > start if exclude_start else dt >= start
    def comp_end(dt, end):
        return dt < end if exclude_end else dt <= end
    if dt is None:
        logger.warning(f"Unexpected 'None' datetime!")
        return False
    if start is None and end is None:
        return True
    elif end is None:
        return comp_start(dt, start)
    elif start is None:
        return comp_end(dt, end)
    return comp_start(dt, start) and comp_end(dt, end)