import datetime, os
from peewee import *
from src.schemas.config import DatabaseConfig

CONFIG = DatabaseConfig()

class CVE(Model):
    """
    CVE models a Common Vulnerability and Exposures

    id: The CVE id
    cve The CVE id
    description: The description of the CVE
    published_at: The date the CVE was published
    last_modified_at: The date the CVE was last modified
    updated_at: The date the row in the database was updated
    cwe: The Common Weakness Enumeration
    cvss_version: The Common Vulnerability Scoring System version
    cvss_expliotability_score: The CVSS exploitability score
    cvss_impact_score: The CVSS impact score
    cvss_vector_string: The CVSS vector string
    cvss_attack_vector: The CVSS attack vector
    cvss_attack_complexity: The CVSS attack complexity
    cvss_privileges_required: The CVSS privileges required
    cvss_user_interaction: The CVSS user interaction
    cvss_scope: The CVSS scope
    cvss_confidentiality_impact: The CVSS confidentiality impact
    cvss_integrity_impact: The CVSS integrity impact
    cvss_availability_impact: The CVSS availability impact
    cvss_base_score: The CVSS base score
    cvss_base_severity: The CVSS base severity
    """
    id = AutoField()
    cve_id = CharField(null=False, unique=True)
    description = TextField(null=True)
    published_at = DateTimeField(null=True)
    last_modified_at = DateTimeField(null=True)
    updated_at = DateTimeField(default=datetime.datetime.now)
    cvss_version = CharField(null=True)
    cvss_expliotability_score = FloatField(null=True)
    cvss_impact_score = FloatField(null=True)
    cvss_vector_string = CharField(null=True)
    cvss_attack_vector = CharField(null=True)
    cvss_attack_complexity = CharField(null=True)
    cvss_privileges_required = CharField(null=True)
    cvss_user_interaction = CharField(null=True)
    cvss_scope = CharField(null=True)
    cvss_confidentiality_impact = CharField(null=True)
    cvss_integrity_impact = CharField(null=True)
    cvss_availability_impact = CharField(null=True)
    cvss_base_score = FloatField(null=True)
    cvss_base_severity = CharField(null=True)

    has_cwe = BooleanField(default=False)

    class Meta:
        database = CONFIG.get()
        table_name = 'cves'

class CWE(Model):
    """
    CWE models a Common Weakness Enumeration

    id: The CWE id
    cwe The CWE id
    name: The name of the CWE
    description: The description of the CWE
    updated_at: The date the row in the database was updated
    """
    cve = ForeignKeyField(CVE, backref='cwes')
    cwe_id = CharField(null=False)
    updated_at = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = CONFIG.get()
        table_name = 'cwes'

class NVDFile(Model):
    """
    NVDFile models a file from the National Vulnerability Database
    This is to keep track of the files that have been processed and speed up the process

    id: The NVDFile id
    file: The file name
    created_at: The date the file was created
    cves_total: The total number of CVEs in the file
    cves_processed: The number of CVEs processed
    cves_skipped: The number of CVEs skipped
    updated_at: The date the row in the database was updated
    """
    id = AutoField()
    file = CharField(null=False)
    created_at = DateTimeField(null=True)
    updated_at = DateTimeField(default=datetime.datetime.now)
    cves_processed = IntegerField(null=True)
    cves_skipped = IntegerField(null=True)

    class Meta:
        database = CONFIG.get()
        table_name = 'nvd_files'

class ConfigNode(Model):
    """
    ConfigNode models a configuration node,
    which is a node in the configurations of a CVE

    id: The configuration node id
    cpe: The Common Platform Enumeration
    operator: The operator of the node
    children: The children of the node
    """
    id = AutoField()
    cve = ForeignKeyField(CVE, backref='config_nodes')
    is_root = BooleanField(default=False)
    operator = CharField(null=True)

    class Meta:
        database = CONFIG.get()
        table_name = 'config_nodes'

class ConfigEdge(Model):
    """
    ConfigGraph models a configuration graph,

    id: The configuration children id
    root: The root id
    parent The parent id
    cpe: The Common Platform Enumeration
    """
    id = AutoField()
    root = ForeignKeyField(ConfigNode, backref='root')
    parent = ForeignKeyField(ConfigNode, backref='children')
    child = ForeignKeyField(ConfigNode, backref='parents')

    class Meta:
        database = CONFIG.get()
        table_name = 'config_edges'

class CPE(Model):
    """
    CPE models a Common Platform Enumeration
    which links a CVE to a project, in this case a Python package

    id: The CPE id
    node The configuration node id
    platform: The platform of the CPE
    vendor: The vendor of the CPE
    product: The product of the CPE
    version: The version of the CPE
    version_start: The start version of the CPE
    version_end: The end version of the CPE
    exclude_start_version: Whether to exclude the start version (default: False)
    exclude_end_version: Whether to exclude the end version (default: True)
    language: The language of the CPE
    updated_at: The date the row in the database was updated
    """
    id = AutoField()
    uri = CharField(null=False)
    node = ForeignKeyField(ConfigNode, backref='cpes')
    part = CharField(null=True)
    vendor = CharField(null=False)
    product = CharField(null=False)
    version = CharField(null=True)
    language = CharField(null=True)
    sw_edition = CharField(null=True)
    target_sw = CharField(null=True)
    target_hw = CharField(null=True)
    other = CharField(null=True)

    version_start = CharField(null=True)
    version_end = CharField(null=True)
    exclude_start_version = BooleanField(default=False)
    exclude_end_version = BooleanField(default=True)
    updated_at = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = CONFIG.get()
        table_name = 'cpes'

CONFIG.add_tables(
    CVE,
    CWE,
    NVDFile,
    ConfigNode,
    ConfigEdge,
    CPE
)
