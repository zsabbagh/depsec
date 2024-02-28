# It will be a class that will be used to interact with the database.
# The class will have methods to create, read, update, and delete (CRUD) records in the database
import sqlite3
from src.tools.config import Config
from database.schema import *

class Core:
    """
    The Core class handling the database
    and communication with the APIs when necessary.
    """

    def __init__(self, config: str | Config):
        """
        Initialise the class

        config: The path to the config file or the config object
        """
        self.__config: Config = None
        if type(config) in [str, dict]:
            self.__config = Config(config)
        elif type(config) == Config:
            self.__config = config
        # Set the database path
        DatabaseConfig.set(self.__config.get_database_path())
        