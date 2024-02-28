# It will be a class that will be used to interact with the database.
# The class will have methods to create, read, update, and delete (CRUD) records in the database
import sqlite3
from tools.parse import Config

class Core:
    """
    The Core class handling the database
    and communication with the APIs when necessary.
    """

    def __init__(self, config: str | Config):
        """
        Initialise the class
        database_path: The path to the database
        """
        self.__config: Config = None
        if type(config) == str:
            self.__config = Config(config)
        else:
            self.__config = config