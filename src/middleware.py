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
        DatabaseConfig.set(self.config.get_database_path())
    
    def get_project(self,
                    package_name: str,
                    platform: str="pypi"):
        """
        Get project, returns (Project, Releases)
        """
        # Force lowercase
        package_name = package_name.strip().lower()
        platform = platform.strip().lower()
        self.__print(f"Getting {package_name} from database with platform {platform}")
        # Query the database
        project = Project.get_or_none((
            (Project.name == package_name) & 
            (Project.platform == platform)
        ))
        if project is not None:
            # If the package is in the database, return it
            self.__print(f"Found {package_name} in database")
            releases = Release.get(Release.project_id == project.id)
            return project, releases
        self.__print(f"Querying libraries.io for {package_name}")
        # Query libraries.io if the package is not in the database
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
            releases = []
            for release in result.get('versions', []):
                number = release.get('number', '')
                if number == '':
                    continue
                self.__print(f"Creating release {number} for {name} with data: {release}")
                published_at = release.get('published_at', None)
                try:
                    # transform the date to a datetime object
                    published_at = datetime.datetime.strptime(published_at, '%Y-%m-%dT%H:%M:%S.%fZ')
                    # print the date in integer value
                    self.__print(f"Date parsed: {published_at}")
                except:
                    self.__print(f"Error parsing date {published_at}")
                    published_at = None
                release = Release.create(
                    project=project,
                    version_number=release.get('number', ''),
                    published_at=release.get('published_at', None),
                )
                releases.append(release)
                release.save()
        return project, releases


mw = Middleware("config.yml", debug=True)