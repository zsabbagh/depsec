import time
from src.queriers.libraries import LibrariesQuerier
from src.database.schema import *
from src.tools.config import Config

class Middleware:
    """
    The middleware for querying the libraries.io API
    or database
    """

    def __error(self, msg: str):
        """
        Print an error message
        """
        print(f"Error @{type(self).__name__}: {msg}")

    def __format_strings(self, *strings: str):
        """
        Format arbitrary amount of strings
        """

        def _fmt(string: str):
            if not string:
                return ''
            return string.strip().lower()

        strings = tuple(map(_fmt, strings))

        return strings

    def __print(self, *args, **kwargs):
        """
        Print if debug is enabled
        """
        if self.__debug:
            print(*args, **kwargs)
            if self.__debug_delay is not None:
                time.sleep(self.__debug_delay / 1000.0)
    
    def set_debug(self, debug: bool = None):
        """
        Set debug
        """
        if debug is not None:
            self.__debug = debug
        else:
            self.__debug = not self.__debug
    
    def __init__(self, config, debug: bool=False, debug_delay: int=None) -> None:
        """
        Initialise the middleware
        """
        self.__debug = debug
        self.__debug_delay = debug_delay
        self.__print(f"Initialising {type(self).__name__} with config {config}")
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
            return project
        self.__print(f"Querying libraries.io for {package_name}")

        # Query libraries.io if the package is not in the database
        result: dict = self.libraries.query_package(package_name, package_name)

        name = result.get('name', '')
        platform = result.get('platform', '')
        language = result.get('language', '')
        name, platform, language = self.__format_strings(name, platform, language)

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
            # Create releases
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
                self.__print(f"Type of published_at {type(published_at).__name__}")
                release = Release.create(
                    project_id=project.id,
                    version_number=number,
                    published_at=published_at,
                )
                release.save()

        return project
    
    def get_releases(self, project_name: str, version_number: str = '', platform: str="pypi"):
        """
        Gets all releases of a project 
        """
        project_name, platform = self.__format_strings(project_name, platform)
        project = self.get_project(project_name, platform)
        if project is None:
            self.__error(f"Project {project_name} not found")
            return None
        releases = [ release for release in Release.select().where(Release.project_id == project.id) ]
        releases = list(filter(lambda release: release.version_number.startswith(version_number), releases) if version_number else releases)
        return releases

    def get_dependencies(self, project_name: str, version_number: str, platform: str="pypi"):
        """
        Get dependencies of a project and a specific version number (release)
        """
        # Force lowercase
        project_name, version_number = self.__format_strings(project_name, version_number)

        # Get the project
        project = self.get_project(project_name)
        if project is None:
            self.__error(f"Project {project_name} not found")
            return None
        # Get the release
        release = Release.get_or_none((
            (Release.project_id == project.id) &
            (Release.version_number == version_number)
        ))
        if release is None:
            self.__error(f"Release {version_number} not found for {project_name}")
            return None
        dependencies = [ dep for dep in ReleaseDependency.select().where(ReleaseDependency.release_id == release.id) ]
        if len(dependencies) > 0:
            # Found dependencies in the database
            self.__print(f"Found {len(dependencies)} dependencies for {project_name} {version_number}")
            return dependencies
        # No dependencies in database, query the API
        self.__print(f"Querying libraries.io for dependencies of {project_name} {version_number}")
        result = self.libraries.query_dependencies(project_name, version_number, platform)
        if result is None or 'dependencies' not in result:
            self.__error(f"Dependencies not found for {project_name} {version_number}")
            return None
        dependencies = result['dependencies']
        deps = []
        for dependency in dependencies:
            name = dependency.get('name', '')
            project_name = dependency.get('project_name', '')
            if name == '':
                self.__error(f"Dependency name not found")
                continue
            ptfrm = dependency.get('platform', '')
            reqs = dependency.get('requirements', '')
            optional = dependency.get('optional', False)
            name, project_name, ptfrm = self.__format_strings(name, project_name, ptfrm)
            self.__print(f"Creating dependency {name} {project_name} {ptfrm} {reqs} {optional}")
            dep_instance = ReleaseDependency.create(
                release_id=release.id,
                name=name,
                project_name=project_name,
                platform=ptfrm,
                requirements=reqs,
                optional=optional
            )
            dep_instance.save()
            deps.append(dep_instance)
        return deps

if __name__ == "__main__":
    mw = Middleware("config.yml", debug=True)