import src.schemas.cwe as cwe
import src.schemas.nvd as nvd
from loguru import logger

def to_cwes(vuln: nvd.CVE | str):
    """
    This function translates a NVD CVE object to the corresponding CWE object.

    vuln: The NVD CVE object or the id of the NVD CVE object
    """
    if type(vuln) in [str, int]:
        if type(vuln) == int:
            vuln = str(vuln)
        if not vuln.startswith("CVE-"):
            vuln = f"CVE-{vuln}"
        vuln = nvd.CVE.get_or_none(nvd.CVE.cve_id == vuln)
        if vuln is None:
            logger.error(f"Could not find CVE with id {vuln}")
            return
    logger.debug(f"Translating {vuln.cve_id} to CWE")
    cwes = [ c for c in vuln.cwes ]
    logger.debug(f"Found {len(cwes)} CWEs")
    results = []
    for cw in cwes:
        cw = cwe.Entry.get_or_none(cwe.Entry.cwe_id == cw.cwe_id)
        if cw is not None:
            results.append(cw)
        else:
            logger.warning(f"Could not find CWE with id {cw.cwe_id}")
    return results
        