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
