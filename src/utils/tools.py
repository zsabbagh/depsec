import re, datetime
from packaging import version as semver
from pathlib import Path
from loguru import logger

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

def version_deprecated(v: str) -> bool:
    """
    Check if a version is deprecated.
    """
    v = semver.parse(v) if type(v) == str else v
    return v.major > 0 if v else False

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