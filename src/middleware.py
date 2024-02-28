from src.queriers.libraries import LibrariesQuerier
from src.database.schema import *
from src.tools.config import Config

class Middleware:
    """
    The middleware for querying the libraries.io API
    or database
    """

    def __print(self, *args, **kwargs):
        """
        Print if debug is enabled
        """
        if self.__debug:
            print(*args, **kwargs)
    
    def set_debug(self, debug: bool = None):
        """
        Set debug
        """
        if debug is not None:
            self.__debug = debug
        else:
            self.__debug = not self.__debug
    
    def __init__(self, config, debug=False) -> None:
        """
        Initialise the middleware
        """
        self.__debug = debug
        self.config = Config(config)
        self.libraries = LibrariesQuerier(self.config.api_keys.libraries)
        DatabaseConfig.set(config.get_database_path())
    
    def get_project(self,
                    package_name: str,
                    platform: str="pypi"):
        """
        Get project
        """
        package = Project.get_or_none(Project.name ** package_name and Project.platform ** platform)
        if package is not None:
            self.__print(f"Found {package_name} in database")
            return package
        self.__print(f"Querying libraries.io for {package_name}")
        result: dict = self.libraries.query_package(package_name, package_name)
        name = result.get('name', '').strip().lower()
        platform = result.get('platform', '').strip().lower()
        language = result.get('language', '').strip().lower()
        contributions = result.get('contributions_count', 0)
        dependent_repos = result.get('dependent_repos_count', 0)
        dependent_projects = result.get('dependent_projects_count', 0)
        project = Project.create(name=name,
                                 platform=platform,
                                 language=language,
                                 contributions=contributions,
                                 dependent_repos=dependent_repos,
                                 dependent_projects=dependent_projects)
        if project:
            project.save()
        return project


