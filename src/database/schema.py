import datetime, os
from peewee import *

class DatabaseConfig:
    """
    Configures the database, a static class
    that does not need to be instantiated

    get: Get the database
    set(path): Set the SQLite database by path
    """
    __database = DatabaseProxy()
    
    @staticmethod
    def get():
        """
        Gets the database
        """
        return DatabaseConfig.__database

    @staticmethod
    def is_set():
        """
        Checks if the database is set,
        that is, if it is not None or a DatabaseProxy
        """
        return type(DatabaseConfig.__database).__name__ not in ['NoneType', 'DatabaseProxy']
    
    @staticmethod
    def set(path: str):
        """
        Sets the database by path
        """
        database = SqliteDatabase(path)
        DatabaseConfig.__database.initialize(database)
        DatabaseConfig.__database.create_tables([Project,
             Release,
             ReleaseDependency,
             ReleaseRepo,
             CVE,
             CPE,
             ConfigNode,
             ConfigEdge,
             NVDFile])
        DatabaseConfig.__database.close()


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
    cwe = CharField(null=True)
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

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'cves'

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
        database = DatabaseConfig.get()
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
    cve = ForeignKeyField(CVE, backref='configurations')
    is_root = BooleanField(default=False)
    operator = CharField(null=True)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'config_nodes'

class ConfigEdge(Model):
    """
    ConfigGraph models a configuration graph,

    id: The configuration children id
    parent The parent id
    cpe: The Common Platform Enumeration
    """
    id = AutoField()
    root = ForeignKeyField(ConfigNode, backref='root')
    parent = ForeignKeyField(ConfigNode, backref='children')
    child = ForeignKeyField(ConfigNode, backref='parents')

    class Meta:
        database = DatabaseConfig.get()
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
    version_end: The end version of the CPE, exclusive
    language: The language of the CPE
    updated_at: The date the row in the database was updated
    """
    id = AutoField()

    node = ForeignKeyField(ConfigNode, backref='cpe')
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
    updated_at = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'cpes'

class Project(Model):
    """
    Project models a libraries.io project,
    that is, a Python package etc

    id: The project id
    name: The name of the project
    platform: The platform of the project
    language: The language of the project
    contributions: The number of contributions to the project
    homepage: The homepage of the project
    vendor: The vendor of the project (commonly deduced from the homepage domain)
    stars: The number of stars the project has
    forks: The number of forks the project has
    dependent_repos: The number of dependent repositories
    dependent_projects: The number of dependent projects
    updated_at: The date the row in the database was updated
    package_manager_url: The URL of the package manager
    repository_url: The URL of the repository
    """
    id = AutoField()
    name = CharField(null=False)
    platform = CharField(null=False)
    language = CharField(null=True)
    contributions = IntegerField(null=True)
    homepage = CharField(null=True)
    vendor = CharField(null=True)
    stars = IntegerField(null=True)
    forks = IntegerField(null=True)
    dependent_repos = IntegerField(null=True)
    dependent_projects = IntegerField(null=True)
    updated_at = DateTimeField(default=datetime.datetime.now)
    package_manager_url = CharField(null=True)
    repository_url = CharField(null=True)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'projects'

class Release(Model):
    """
    Release models a release of a project
    
    id: The release id
    project The project id
    published_at: The date the release was published
    version: The version number of the release
    updated_at: The date the row in the database was updated
    """
    id = AutoField()
    project = ForeignKeyField(Project, backref='releases')
    published_at = DateTimeField(null=True)
    version = CharField(null=False)
    updated_at = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'releases'

class ReleaseDependency(Model):
    """
    ReleaseDependency models a release's dependencies

    release The release id
    name: The name of the dependency
    project_name: The name of the project the dependency is on, usually the same as the name
    platform: The platform the dependency is on
    requirements: The version requirements of the dependency
    updated_at: The date the row in the database was updated
    """
    
    release = ForeignKeyField(Release, backref='dependencies')
    name = CharField(null=False)
    project_name = CharField(null=False)
    platform = CharField(null=True)
    requirements = CharField(null=True)
    updated_at = DateTimeField(default=datetime.datetime.now)
    optional = BooleanField(default=False)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'release_dependencies'

class ReleaseRepo(Model):
    """
    ReleaseRepo models a release's repository

    release The release id
    repo_url: The URL of the repository
    updated_at: The date the row in the database was updated
    """
    release = ForeignKeyField(Release, backref='repos')
    repo_url = CharField(null=False)
    updated_at = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'release_repos'