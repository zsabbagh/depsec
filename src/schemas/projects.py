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


class Product(Model):
    """
    Model for products

    Meant to connect with CPEs
    """
    platform = CharField(null=False)
    name = CharField(null=False)
    vendor = CharField(null=False)
    product = CharField(null=False)
    created_at = DateTimeField(default=datetime.datetime.now)
    updated_at = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = DB_PROJECTS.get()
        table_name = 'products'

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
        database = DB_PROJECTS.get()
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
        database = DB_PROJECTS.get()
        table_name = 'release_repos'

# Add the tables to the database
DB_PROJECTS.add_tables(
    Project,
    Product,
    Release,
    ReleaseDependency,
    ReleaseRepo
)