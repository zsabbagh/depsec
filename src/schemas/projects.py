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
    dependencies = IntegerField(null=True) # The number of dependencies
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
    total_nloc: The total number of lines of code
    avg_nloc: The average number of lines of code
    avg_cc: The average cyclomatic complexity
    commit_at: The date the commit was made
    commit_hash: The hash of the commit
    """
    id = AutoField()
    project = ForeignKeyField(Project, backref='releases', on_delete='CASCADE')
    published_at = DateTimeField(null=True)
    version = CharField(null=False)
    updated_at = DateTimeField(default=datetime.datetime.now)
    total_nloc = IntegerField(null=True)
    avg_nloc = FloatField(null=True)
    avg_cc = FloatField(null=True)
    commit_at = DateTimeField(null=True)
    commit_hash = CharField(null=True)

    class Meta:
        database = DB_PROJECTS.get()
        table_name = 'releases'

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
    ReleaseRepo
)
