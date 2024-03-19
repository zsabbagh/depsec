import datetime
from peewee import *
from src.schemas.config import DatabaseConfig

CONFIG = DatabaseConfig()

class View(Model):
    """
    View models a view of a Common Weakness Enumeration list

    Could this be skipped?
    """
    id = AutoField()
    name = CharField(null=False)
    kind = CharField(null=False)
    status = CharField(null=True)
    objective = TextField(null=True)
    
    class Meta:
        database = CONFIG.get()
        table_name = 'views'

class Entry(Model):
    """
    Entry models a weakness of a Common Weakness Enumeration list entry
    Not connected with a foreign key to CVE, as this is a separate entity
    and has its own migration script

    id: The CWE id (in the database)
    cwe_id: The CWE id, format CWE-n where n is a number
    name: The name of the CWE
    description: The description of the CWE
    updated_at: The date the row in the database was updated
    """
    id = AutoField()
    cwe_id = CharField(null=False, unique=True)
    kind = CharField(null=True)
    name = CharField(null=True)
    abstraction = CharField(null=True)
    structure = CharField(null=True)
    status = CharField(null=True)
    summary = TextField(null=True)

    background_details = TextField(null=True)
    likelihood_of_exploit = CharField(null=True)
    updated_at = DateTimeField(default=datetime.datetime.now)

    detection_methods = TextField(null=True)
    consequences = TextField(null=True)

    class Meta:
        database = CONFIG.get()
        table_name = 'entries'


class Consequence(Model):
    """
    Consequence models a consequence of a Common Weakness Enumeration

    id: The CWEConsequence id
    cwe_id: The CWE id
    consequence: The consequence of the CWE
    scope: The scope of the consequence
    updated_at: The date the row in the database was updated
    """
    id = AutoField()
    scope = CharField(null=True)
    impact = CharField(null=True)
    updated_at = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = CONFIG.get()
        table_name = 'consequences'

class Relation(Model):
    """
    Relation models a relation between a CVE and a CWE
    Is this really necessary?

    main_id: The main id
    other_id: The other id
    """
    main = ForeignKeyField(Entry, backref='relations')
    kind = CharField(null=False)
    ordinal = CharField(null=True)
    view_id = CharField(null=True) # The view table is not implemented yet
    other_id = CharField(null=False)

    class Meta:
        database = CONFIG.get()
        table_name = 'relations'


CONFIG.add_tables(View,
                  Entry,
                  Consequence,
                  Relation)