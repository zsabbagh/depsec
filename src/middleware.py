import time, yaml, json, glob
from src.queriers.libraries import LibrariesQuerier
from src.queriers.snyk import SnykQuerier
from src.database.schema import *
from src.utils.tools import *
from loguru import logger

class Middleware:
    """
    The middleware for querying the libraries.io API
    or database
    """

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

    def config(self, config_path: str):
        """
        Set the config file
        """
        self.__config = None
        extension = config_path.split('.')[-1]
        # lambda for loading the file
        loader = lambda f : json.load(f) if extension == 'json' else yaml.safe_load(f)
        if os.path.exists(config_path):
            with open(config_path) as f:
                self.__config = loader(f)
        if self.__config is None:
            dir = os.path.dirname(os.path.abspath(__file__))
            for file_ext in ['json', 'yml', 'yaml']:
                for file in glob.glob(f"{dir}/*.{file_ext}"):
                    with open(file) as f:
                        self.__config = loader(f)
                    if self.__config is not None:
                        break
                if self.__config is not None:
                    break
        if self.__config is None:
            raise Exception(f"Config file not found at {config_path}")
        apis = self.__config.get('apis', {})
        self.libraries = LibrariesQuerier(apis)
        self.snyk = SnykQuerier(apis)
        DatabaseConfig.set(self.__config.get('database', {}).get('path', ''))
    
    def set_debug(self, debug: bool = None):
        """
        Set debug
        """
        if debug is not None:
            self.__debug = debug
        else:
            self.__debug = not self.__debug
    
    def __init__(self, config_path: str, debug: bool=False, debug_delay: int=None) -> None:
        """
        Initialise the middleware
        """
        self.__debug = debug
        self.__debug_delay = debug_delay
        logger.debug(f"Initalising middleware with config file {config_path}")
        self.config(config_path)
    
    def get_project(self,
                    package_name: str,
                    platform: str="pypi"):
        """
        Get project, returns (Project, Releases)
        """
        # Force lowercase
        package_name = package_name.strip().lower()
        platform = platform.strip().lower()
        logger.debug(f"Getting {package_name} from database with platform {platform}")
        # Query the database
        project = Project.get_or_none((
            (Project.name == package_name) & 
            (Project.platform == platform)
        ))
        if project is not None:
            # If the package is in the database, return it
            logger.debug(f"Found {package_name} in database")
            return project
        logger.debug(f"Querying libraries.io for {package_name}")

        # Query libraries.io if the package is not in the database
        result: dict = self.libraries.query_package(package_name, package_name)

        name = result.get('name', '')
        platform = result.get('platform', '')
        language = result.get('language', '')
        name, platform, language = self.__format_strings(name, platform, language)
        package_manager_url = result.get('package_manager_url')
        repository_url = result.get('repository_url')
        stars, forks = result.get('stars'), result.get('forks')
        contributions = result.get('contributions_count')
        dependent_repos = result.get('dependent_repos_count')
        dependent_projects = result.get('dependent_projects_count')
        homepage = result.get('homepage')
        vendor_name = homepage_to_vendor(homepage)
        logger.debug(f"Creating project {name}")
        project = Project.create(contributions=contributions,
                                dependent_projects=dependent_projects,
                                dependent_repos=dependent_repos,
                                homepage=homepage,
                                vendor=vendor_name,
                                forks=forks,
                                language=language,
                                name=name,
                                package_manager_url=package_manager_url,
                                platform=platform,
                                repository_url=repository_url,
                                stars=stars)
        if project:
            project.save()
            logger.debug(f"Created project {name} in database")
            # Create releases
            for release in result.get('versions', []):
                number = release.get('number', '')
                logger.debug(f"Creating release {number}")
                if number == '':
                    continue
                published_at = release.get('published_at', None)
                try:
                    # transform the date to a datetime object
                    published_at = datetime.datetime.strptime(published_at, '%Y-%m-%dT%H:%M:%S.%fZ')
                    # print the date in integer value
                except:
                    published_at = None
                release = Release.create(
                    project=project,
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
            logger.error(f"Project {project_name} not found")
            return None
        releases = [ release for release in Release.select().where(Release.project == project.id) ]
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
            logger.error(f"Project {project_name} not found")
            return None
        # Get the release
        release = Release.get_or_none((
            (Release.project == project) &
            (Release.version_number == version_number)
        ))
        if release is None:
            logger.error(f"Release '{version_number}' not found for {project_name}")
            return None
        dependencies = [ dep for dep in ReleaseDependency.select().where(ReleaseDependency.release == release) ]
        if len(dependencies) > 0:
            # Found dependencies in the database
            logger.debug(f"Found {len(dependencies)} dependencies for {project_name} {version_number}")
            return dependencies
        # No dependencies in database, query the API
        logger.debug(f"Querying libraries.io for dependencies of {project_name} {version_number}")
        result = self.libraries.query_dependencies(project_name, version_number, platform)
        if result is None or 'dependencies' not in result:
            logger.error(f"Dependencies not found for {project_name} {version_number}")
            return None
        dependencies = result['dependencies']
        deps = []
        for dependency in dependencies:
            name = dependency.get('name', '')
            project_name = dependency.get('project_name', '')
            if name == '':
                logger.error(f"Dependency name not found for {project_name} {version_number}")
                continue
            ptfrm = dependency.get('platform', '')
            reqs = dependency.get('requirements', '')
            optional = dependency.get('optional', False)
            name, project_name, ptfrm = self.__format_strings(name, project_name, ptfrm)
            logger.debug(f"Creating dependency {name} {project_name} {ptfrm} {reqs} {optional}")
            dep_instance = ReleaseDependency.create(
                release=release,
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