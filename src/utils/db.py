import src.schemas.cwe as cwe
import src.schemas.nvd as nvd
from src.utils.tools import version_in_range, datetime_in_range
from packaging import version as semver
from playhouse.shortcuts import model_to_dict
from loguru import logger
from src.schemas.projects import *
from typing import List

def is_applicable(release: Release | str | dict, applicability: dict | list) -> bool:
    """
    Checks if a release is applicable to a specific version range.

    release: Release object | version string | dictionary with version and published_at, at least version
    applicability: The version range or the list of version ranges, or the CVE object containing 'applicability'
    """
    if 'applicability' in applicability:
        # got a cve
        applicability = applicability['applicability']
    apps = applicability if type(applicability) == list else [applicability]
    applies = False
    version = release.version if isinstance(release, Release) else (
        semver.parse(release) if isinstance(release, str) else semver.parse(release['version']) if 'version' in release else None
    )
    if version is None:
        logger.error(f"Could not parse version from release type: {type(release).__name__}")
        return False
    for app in apps:
        version_start = app.get('version_start')
        version_start = semver.parse(version_start.strip('.')) if version_start is not None else version_start
        version_end = app.get('version_end')
        version_end = semver.parse(version_end.strip('.')) if version_end is not None else version_end
        exclude_start = app.get('exclude_start', False)
        exclude_end = app.get('exclude_end', False)
        if version_start is not None or version_end is not None:
            if version_in_range(version, version_start, version_end, exclude_start, exclude_end):
                applies = True
                break
            # do not check datetime as it is not applicable
    return applies

# This file contains utility functions
# to translate data structures of PeeWee models
# to other data structures.
def compute_version_ranges(project: Project, apps: list):
    """
    Computes the specific version window for a CVE.
    That is, it will convert a list of versions to a list of ranges.

    project: The project object
    apps: The list of applications, with dictionaries of version applicabilities.
    Converts { 'version': ... } to { 'version_start': ..., 'version_end': ... }
    """
    versions = set()
    applicabilities = []
    for app in apps:
        if 'version' in app:
            versions.add(app['version'])
        else:
            applicabilities.append(app)
    if versions != set():
        # go through each minor version and create a range
        asc_versions = sorted(list(versions), key=semver.parse)
        previous_version = asc_versions[0]
        max_version = asc_versions[-1]
        relselect = Release.select().where(Release.project == project)
        relselect = sorted([rel for rel in relselect if version_in_range(rel.version, previous_version)], key=lambda x : semver.parse(x.version))
        for rel in relselect:
            # releases are sorted semantically
            if previous_version not in versions:
                if rel.version in versions:
                    previous_version = rel.version
                elif version_in_range(rel.version, max_version):
                    previous_version = rel.version
                    break
                continue
            elif rel.version in versions:
                continue
            start_rel = Release.get_or_none(
                Release.project == project,
                Release.version == previous_version
            )
            end_rel = Release.get_or_none(
                Release.project == project,
                Release.version == rel.version
            )
            applicabilities.append({
                'version_start': str(previous_version),
                'version_end': rel.version,
                'start_date': start_rel.published_at if start_rel else None,
                'exclude_start': False,
                'end_date': end_rel.published_at if end_rel else None,
                'exclude_end': True,
            })
            previous_version = rel.version
    return applicabilities

def _map_attrs_dict(objs: list) -> list:
    """
    Map the attributes of a list of objects to a list of dictionaries.

    objs: The list of objects
    attrs: The attributes to include in the dictionary
    """
    return [ model_to_dict(obj, recurse=False) for obj in objs ]

class CWE:

    def get(cwe_id: cwe.Entry | str | int,
            to_dict: bool = True) -> cwe.Entry | dict | None:
        """
        Get a CWE id (or CWE Entry) to a CWE entry.
        """
        cwe_db = None
        if type(cwe_id) in [str, int]:
            if type(cwe_id) == int:
                cwe_id = str(cwe_id)
            if not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"
            cwe_db = cwe.Entry.get_or_none(cwe.Entry.cwe_id == cwe_id)
            if cwe_db is None:
                logger.error(f"Could not find CWE with id {cwe_id}")
                return None
        elif not isinstance(cwe_id, cwe.Entry):
            raise ValueError(f"Invalid type for cwe_id: {type(cwe_id)}")
        return model_to_dict(cwe_db) if to_dict else cwe_db

    def relations(entry: cwe.Entry | str | int,
                  kind: str = None,
                  as_entry: bool = False,
                  to_dict: bool = True) -> cwe.Entry | dict | None:
        """
        Fetch the category of a CWE entry.

        entry: The CWE entry
        attrs: The attributes to include in the dictionary
        kind: The kind of relation to fetch
        as_entry: Whether to fetch the relations that are related to the relations
        """
        entry = CWE.get(entry, to_dict=False)
        if entry is None:
            return
        logger.debug(f"Fetching relations for {entry.cwe_id}")
        relations = [ r for r in entry.relations if r.kind == kind or kind is None ]
        for relation in relations:
            logger.debug(f"Found relation of kind '{relation.kind}', from {relation.main.cwe_id} to {relation.other_id}")
        logger.debug(f"Got {len(relations)} relations of kind '{kind}'")
        if as_entry:
            result = []
            for relation in relations:
                result.append(CWE.get(relation.other_id, to_dict=False))
            relations = result
        return _map_attrs_dict(relations) if to_dict else relations
    
    def categories(entry: cwe.Entry | str | int,
                   as_entry: bool = False,
                   to_dict: bool = True) -> cwe.Entry | dict | None:
        """
        Fetch the category of a CWE entry.

        entry: The CWE entry
        attrs: The attributes to include in the dictionary
        """
        return CWE.relations(entry, kind="IsMemberOf", as_entry=as_entry, to_dict=to_dict)

class NVD:

    def get(entry: nvd.CVE | str,
            to_dict: bool = True) -> nvd.CVE | dict | None:
        """
        Get a NVD CVE id (or NVD CVE Entry) to a NVD CVE entry.

        entry: The NVD CVE entry or the id of the NVD CVE entry (with or without the prefix "CVE-")
        to_dict: Whether to return the result as a dictionary (non-recursive)
        """
        cve_db = None
        if type(entry) == str:
            if not entry.startswith("CVE-"):
                entry = f"CVE-{entry}"
            cve_db = nvd.CVE.get_or_none(nvd.CVE.cve_id == entry)
            if cve_db is None:
                logger.error(f"Could not find CVE with id {entry}")
                return None
        elif not isinstance(entry, nvd.CVE):
            raise ValueError(f"Invalid type for entry: {type(entry)}")
        return model_to_dict(cve_db) if to_dict else cve_db

    def cwes(entry: nvd.CVE | str,
             categories: bool = 1,
             exclude_deprecated: bool = 1,
             to_dict: bool = True) -> List[cwe.Entry] | list[dict] | None:
        """
        This function translates a NVD CVE object to the corresponding CWE object.

        entry: The NVD CVE object or the id of the NVD CVE object
        categories: Whether to include the (unique) categories of the CWEs (default: truthy)
        to_dict: Whether to return the result as a dictionary (non-recursive)
        """
        categories = bool(categories)
        exclude_deprecated = bool(exclude_deprecated)
        entry = NVD.get(entry, to_dict=False)
        if entry is None:
            return None
        cwes = [ c for c in entry.cwes ]
        logger.debug(f"Found {len(cwes)} CWEs")
        results = [ CWE.get(c.cwe_id, to_dict=False) for c in cwes ]
        ids_added = set()
        for cw in cwes:
            if cw.cwe_id in ids_added:
                continue
            if categories:
                cws = CWE.categories(cw.cwe_id, as_entry=True, to_dict=False)
                cws = [ c for c in cws if c.cwe_id not in ids_added ]
                for c in cws:
                    logger.debug(f"Adding CWE {c.cwe_id} to the list, with status {c.status}")
                    ids_added.add(c.cwe_id)
                    results.append(c)
            else:
                cw = CWE.get(cw.cwe_id, to_dict=False)
                if cw is not None:
                    results.append(cw)
            ids_added.add(cw.cwe_id)
        results = [ res for res in results if not exclude_deprecated or res.status.lower() not in ('deprecated', 'obsolete') ]
        return _map_attrs_dict(results) if to_dict else results
