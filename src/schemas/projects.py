import datetime, os
from peewee import *
from src.schemas.config import DatabaseConfig

DB_PROJECTS = DatabaseConfig()

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
    release_dependency_count: The number of releases that has been counted
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
    product = CharField(null=True)
    stars = IntegerField(null=True)
    forks = IntegerField(null=True)
    latest_release = CharField(null=True)
    dependent_repos = IntegerField(null=True)
    dependent_projects = IntegerField(null=True)
    updated_at = DateTimeField(default=datetime.datetime.now)
    package_manager_url = CharField(null=True)
    repository_url = CharField(null=True)

    class Meta:
        database = DB_PROJECTS.get()
        table_name = 'projects'

class Release(Model):
    """
    Release models a release of a project. Note nloc and cc excludes test files
    
    id: The release id
    project The project id
    published_at: The date the release was published
    version: The version number of the release
    updated_at: The date the row in the database was updated
    counted_functions: The number of functions counted
    counted_files: The number of files counted
    nloc_total: The total NLOC
    nloc_average: The average NLOC
    ccn_average: The average cyclomatic complexity
    commit_at: The date the commit was made
    commit_hash: The hash of the commit
    includes: The files included in the release for analysis
    excludes: The files excluded from the release for analysis
    """
    id = AutoField()
    project = ForeignKeyField(Project, backref='releases', on_delete='CASCADE')
    published_at = DateTimeField(null=True)
    version = CharField(null=False)
    updated_at = DateTimeField(default=datetime.datetime.now)
    counted_functions = IntegerField(null=True)
    counted_files = IntegerField(null=True)
    nloc_total = IntegerField(null=True)
    nloc_average = FloatField(null=True)
    ccn_average = FloatField(null=True)
    commit_at = DateTimeField(null=True)
    commit_hash = CharField(null=True)
    includes = TextField(null=True)
    excludes = TextField(null=True)
    dependency_count = IntegerField(null=True)
    class Meta:
        database = DB_PROJECTS.get()
        table_name = 'releases'
    
class BanditReport(Model):
    """
    BanditReport models a bandit report

    id: The bandit result id
    release: The release id
    issue: The issue
    filename: The filename
    line: The line number
    code: The code
    updated_at: The date the row in the database was updated
    """
    id = AutoField()
    release = ForeignKeyField(Release, backref='bandit_report', on_delete='CASCADE', unique=True)
    updated_at = DateTimeField(default=datetime.datetime.now)
    issues_total = IntegerField(null=True)
    files_with_issues = IntegerField(null=True)
    files_skipped = IntegerField(null=True)
    confidence_high_count = IntegerField(null=True)
    confidence_medium_count = IntegerField(null=True)
    confidence_low_count = IntegerField(null=True)
    confidence_undefined_count = IntegerField(null=True)
    severity_high_count = IntegerField(null=True)
    severity_medium_count = IntegerField(null=True)
    severity_low_count = IntegerField(null=True)
    severity_undefined_count = IntegerField(null=True)
    severity_h_confidence_h_count = IntegerField(null=True)
    severity_h_confidence_m_count = IntegerField(null=True)
    severity_h_confidence_l_count = IntegerField(null=True)
    severity_m_confidence_h_count = IntegerField(null=True)
    severity_m_confidence_m_count = IntegerField(null=True)
    severity_m_confidence_l_count = IntegerField(null=True)
    severity_l_confidence_h_count = IntegerField(null=True)
    severity_l_confidence_m_count = IntegerField(null=True)
    severity_l_confidence_l_count = IntegerField(null=True)
    loc = IntegerField(null=True)
    nosec = IntegerField(null=True)
    skipped_tests = IntegerField(null=True)
    class Meta:
        database = DB_PROJECTS.get()
        table_name = 'bandit_reports'

class BanditIssue(Model):
    """
    Models a bandit issue, that is, an issue found in a Bandit report
    """
    id = AutoField()
    report = ForeignKeyField(BanditReport, backref='issues', on_delete='CASCADE')
    description = TextField(null=False)
    verified = BooleanField(default=False) # Whether the issue has been verified as true or false
    package = CharField(null=False)
    module = CharField(null=False)
    filename = CharField(null=False)
    score = IntegerField(null=True)
    confidence = CharField(null=True)
    severity = CharField(null=True)
    more_info = CharField(null=True)
    test_id = CharField(null=False)
    test_name = CharField(null=False)
    code = TextField(null=True)
    lines = CharField(null=True)
    cwe_id = CharField(null=True)
    class Meta:
        database = DB_PROJECTS.get()
        table_name = 'bandit_issues'

class ReleaseDependency(Model):
    """
    ReleaseDependency models a release's dependencies

    release The release id
    name: The name of the dependency
    project_name: The name of the project the dependency is on, usually the same as the name
    platform: The platform the dependency is on
    requirements: The version requirements of the dependency
    version: The version of the dependency (note, not strictly required)
    depth: The depth of the dependency, as in, how many steps of inheritance
    inherited_from: The project the dependency is inherited from
    updated_at: The date the row in the database was updated
    """
    
    release = ForeignKeyField(Release, backref='dependencies', on_delete='CASCADE')
    name = CharField(null=False)
    project_name = CharField(null=False) # Is this really necessary?
    platform = CharField(null=True)
    requirements = CharField(null=True)
    version = CharField(null=True) # Version from OSI
    depth = BooleanField(default=False, null=True)
    inherited_from = CharField(null=True)
    updated_at = DateTimeField(default=datetime.datetime.now)
    optional = BooleanField(default=False)

    class Meta:
        database = DB_PROJECTS.get()
        table_name = 'release_dependencies'

class ReleaseRepo(Model):
    """
    ReleaseRepo models a release's repository

    release The release id
    repo_url: The URL of the repository
    updated_at: The date the row in the database was updated
    """
    release = ForeignKeyField(Release, backref='repos', on_delete='CASCADE')
    repo_url = CharField(null=False)
    updated_at = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = DB_PROJECTS.get()
        table_name = 'release_repos'

# Add the tables to the database
DB_PROJECTS.add_tables(
    Project,
    Release,
    ReleaseDependency,
    ReleaseRepo,
    BanditReport,
    BanditIssue
)
