import src.schemas.cwe as cwe
import src.schemas.nvd as nvd
from loguru import logger
from src.schemas.projects import *

# This file contains utility functions
# to translate data structures of PeeWee models
# to other data structures.

def get_categories_from_cwe(entry: cwe.Entry | str):
    """
    
    """
    if type(entry) in [str, int]:
        if type(entry) == int:
            entry = str(entry)
        if not entry.startswith("CWE-"):
            entry = f"CWE-{entry}"
        cwe_db = cwe.Entry.get_or_none(cwe.Entry.cwe_id == cwe)
        if cwe_db is None:
            logger.error(f"Could not find CWE with id {entry}")
            return
    relations = [ r for r in entry.relations ]
    return relations