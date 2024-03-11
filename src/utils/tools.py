import re, datetime
from pathlib import Path

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
    print(f"Homepage: {homepage}")
    homepage = re.sub(r'^https?://', '', homepage)
    print(f"Homepage: {homepage}")
    parts = homepage.split('.')
    print(f"Parts: {parts}")
    if len(parts) < 2:
        return None
    domain = parts[-2]
    if domain == 'github':
        result = parts[-1]
        if result is not None:
            result = result.split('/')[1]
    elif domain == 'readthedocs':
        return None
    else:
        result = parts[-2]
    return result