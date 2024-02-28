import datetime, os
from peewee import *

class DatabaseConfig:
    __database = DatabaseProxy()
    
    @staticmethod
    def get():
        return DatabaseConfig.__database
    
    @staticmethod
    def set(name):
        database = SqliteDatabase(name)
        DatabaseConfig.__database.initialize(database)
        DatabaseConfig.__database.create_tables([Project,
             Release,
             ReleaseDependency,
             ReleaseRepo])
        DatabaseConfig.__database.close()


class Project(Model):

    id = AutoField()
    name = CharField(null=False)
    project_name = CharField(null=False)
    language = CharField(null=True)
    platform = CharField(null=True)
    updated_at = TimestampField(default=datetime.datetime.now)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'projects'

class Release(Model):

    id = AutoField()
    project_id = ForeignKeyField(Project, backref='releases')
    published_at = TimestampField(null=True)
    version_number = CharField(null=False)
    updated_at = TimestampField(default=datetime.datetime.now)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'releases'

class ReleaseDependency(Model):
    
    release_id = ForeignKeyField(Release, backref='dependencies')
    name = CharField(null=False)
    platform = CharField(null=True)
    requirements = CharField(null=True)
    updated_at = TimestampField(default=datetime.datetime.now)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'release_dependencies'

class ReleaseRepo(Model):
    
    release_id = ForeignKeyField(Release, backref='repos')
    repo_url = CharField(null=False)
    updated_at = TimestampField(default=datetime.datetime.now)

    class Meta:
        database = DatabaseConfig.get()
        table_name = 'release_repos'