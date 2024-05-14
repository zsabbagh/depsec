from pathlib import Path
from peewee import SqliteDatabase, DatabaseProxy
from loguru import logger

class DatabaseConfig:
    """
    A class to configure the database path
    and create the tables
    """

    def __init__(self):
        """
        Sets the database by path
        """
        self.__database = DatabaseProxy()
        self.__tables = []
    
    def get(self):
        """
        Gets the database
        """
        return self.__database

    def is_set(self):
        """
        Checks if the database is set,
        that is, if it is not None or a DatabaseProxy
        """
        type_is_correct = type(self.__database).__name__ not in ['NoneType', 'DatabaseProxy']
        tables_exist = len(self.__tables) > 0
        if type_is_correct:
            logger.warning('Database is not set')
            return False
        elif not tables_exist:
            logger.warning('No tables have been added to the database')
            return False
        return True
    
    def set(self, path: str, name: str = None):
        """
        Sets the database by path
        """
        path = Path(path).resolve()
        logger.debug(f"Setting database to {path}")
        if not path.exists():
            raise ValueError('Path does not exist, cannot create database to non-existent path')
        if not name.endswith('.db'):
            name = f"{name}.db"
        if not str(path).endswith('.db') and path.is_dir():
            path = path.joinpath(name)
        database = SqliteDatabase(str(path))
        self.__database.initialize(database)
        self.__database.close()
        table_names = [type(table).__name__ for table in self.__tables]
        logger.debug(f"Database set to {path}, creating tables '{', '.join(table_names) if len(table_names) > 0 else 'None'}'")
        self.create_tables(*self.__tables)
    
    def add_tables(self, *tables):
        """
        Adds tables to the database
        """
        self.__tables = list(tables)
    
    def create_tables(self, *tables):
        """
        Creates the tables in the database, variadic
        """
        if not self.is_set():
            raise ValueError('Database is not set')
        self.__database.connect()
        self.__database.create_tables(list(tables))
        self.__database.close()
