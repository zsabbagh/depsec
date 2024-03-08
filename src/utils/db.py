import src.schemas.cwe as cwe
import src.schemas.nvd as nvd
from playhouse.shortcuts import model_to_dict
from loguru import logger
from src.schemas.projects import *
from typing import List

# This file contains utility functions
# to translate data structures of PeeWee models
# to other data structures.

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
        relations = [ r for r in entry.relations ]
        if kind is not None:
            relations = [ r for r in relations if r.kind == kind ]
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
             to_dict: bool = True) -> List[cwe.Entry] | list[dict] | None:
        """
        This function translates a NVD CVE object to the corresponding CWE object.

        entry: The NVD CVE object or the id of the NVD CVE object
        categories: Whether to include the (unique) categories of the CWEs (default: truthy)
        to_dict: Whether to return the result as a dictionary (non-recursive)
        """
        categories = bool(categories)
        entry = NVD.get(entry, to_dict=False)
        cwes = [ c for c in entry.cwes ]
        logger.debug(f"Found {len(cwes)} CWEs")
        results = []
        ids_added = set()
        for cw in cwes:
            if cw.cwe_id in ids_added:
                continue
            ids_added.add(cw.cwe_id)
            if categories:
                cws = CWE.categories(cw.cwe_id, as_entry=True, to_dict=False)
                cws = [ c for c in cws if c.cwe_id not in ids_added ]
                for c in cws:
                    ids_added.add(c.cwe_id)
                    results.append(c)
            else:
                cw = CWE.get(cw.cwe_id, to_dict=False)
                if cw is not None:
                    results.append(cw)
        return _map_attrs_dict(results) if to_dict else results
