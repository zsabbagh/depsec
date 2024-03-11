import time, yaml, json, glob
import src.schemas.nvd as nvd
import src.schemas.cwe as cwe
import src.utils.db as db
from playhouse.shortcuts import model_to_dict
from pprint import pprint
from src.queriers.libraries import LibrariesQuerier
from src.queriers.snyk import SnykQuerier
from src.schemas.projects import *
from src.utils.tools import *
from loguru import logger
from pathlib import Path
from typing import List, Dict

class Middleware:
    """
    The middleware to communicate with the databases and the APIs
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

        databases = self.__config.get('databases', {})
        if not databases:
            logger.warning("No databases found in config file")
            raise Exception("No databases found in config file")

        # Configure the databases
        projects_path, projects_name = get_database_dir_and_name(databases, 'projects')
        vulns_path, vulns_name = get_database_dir_and_name(databases, 'vulnerabilities')
        weaks_path, weaks_name = get_database_dir_and_name(databases, 'weaknesses')
        DB_PROJECTS.set(projects_path, projects_name)
        nvd.CONFIG.set(vulns_path, vulns_name)
        cwe.CONFIG.set(weaks_path, weaks_name)
    
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
    
    def set_project_vendor(self,
                           project_name: str,
                           vendor: str,
                           platform: str="pypi") -> Project:
        """
        Set the vendor of a project
        """
        project_name, platform = self.__format_strings(project_name, platform)
        project = self.get_project(project_name, platform)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        project.vendor = vendor
        project.save()
        return project
    
    def get_project(self,
                    project_name: str,
                    platform: str="pypi") -> Project:
        """
        Get project, returns (Project, Releases)
        """
        # Force lowercase
        project_name = project_name.strip().lower()
        platform = platform.strip().lower()
        logger.debug(f"Getting {project_name} from database with platform {platform}")
        # Query the database
        project = Project.get_or_none((
            (Project.name == project_name) & 
            (Project.platform == platform)
        ))
        if project is not None:
            # If the package is in the database, return it
            logger.debug(f"Found {project_name} in database")
            return project
        logger.debug(f"Querying libraries.io for {project_name}")

        # Query libraries.io if the package is not in the database
        result: dict = self.libraries.query_package(project_name)

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
                    version=number,
                    published_at=published_at,
                )
                release.save()

        return project
    
    def get_releases(self,
                     project_name: str,
                     version: str = '',
                     platform: str="pypi") -> List[Release]:
        """
        Gets all releases of a project 
        """
        project_name, platform = self.__format_strings(project_name, platform)
        project = self.get_project(project_name, platform)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        releases = [ release for release in Release.select().where(Release.project == project.id) ]
        releases = list(filter(lambda release: release.version.startswith(version), releases) if version else releases)
        return releases
    
    def get_vulnerabilities(self,
                            project_name: str,
                            version: str = None,
                            platform: str="pypi") -> List[nvd.CVE]:
        """
        Get vulnerabilities of a project and a specific version number (release)
        """
        # Force lowercase
        project_name, version, platform = self.__format_strings(project_name, version, platform)
        # Get the project
        project = self.get_project(project_name, platform)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        # Get the release
        release = None
        if version:
            release = Release.get_or_none((
                (Release.project == project) &
                (Release.version == version)
            ))
            if release is None:
                logger.error(f"Release '{version}' not found for {project_name}")
                return None
        logger.debug(f"Querying databases for vulnerabilities of {project_name} {version}")
        cpes = nvd.CPE.select().where((nvd.CPE.vendor == project.vendor) & (nvd.CPE.product == project.name))
        logger.debug(f"Found {len(cpes)} CPEs for {project.vendor} {project.name}")
        # We need to find the CPEs that match the version
        vulns = []
        vulnset = set()
        release_published_at = release.published_at if release else None
        for cpe in cpes:
            # Get release of versions since some contain letters
            cve = cpe.node.cve
            if cve.id in vulnset:
                logger.debug(f"Vulnerability {cve.id} already in set")
                continue
            logger.debug(f"Getting release for {cpe.vendor} {cpe.product} {cpe.version_start} - {cpe.version_end}")
            start_release = Release.get_or_none((
                (Release.project == project) &
                (Release.version == cpe.version_start)
            ))
            end_release = Release.get_or_none((
                (Release.project == project) &
                (Release.version == cpe.version_end)
            ))
            start_date: datetime = start_release.published_at if start_release else None
            end_date: datetime = end_release.published_at if end_release else None
            logger.debug(f"Getting vulnerabilities for {cpe.vendor} {cpe.product} {cpe.version_start} ({start_date}) - {cpe.version_end}({end_date})")
            node = cpe.node
            if node.operator != 'OR':
                logger.warning(f"Operator '{node.operator}' is not OR")
            if not node.is_root:
                logger.warning(f"Node {node.id} is not root")
            if release_published_at is not None:
                if start_date is not None and end_date is not None:
                    if start_date <= release_published_at < end_date:
                        logger.debug(f"Release {release.version} is in range {cpe.version_start} - {cpe.version_end}")
                        vulnset.add(cve.id)
                        vulns.append(cve)
                elif start_date is not None and release_published_at >= start_date:
                    logger.debug(f"Release {release.version} is in range {cpe.version_start} - {cpe.version_end}")
                    vulnset.add(cve.id)
                    vulns.append(cve)
                elif end_date is not None and release_published_at < end_date:
                    logger.debug(f"Release {release.version} is in range {cpe.version_start} - {cpe.version_end}")
                    vulnset.add(cve.id)
                    vulns.append(cve)
            else:
                vulnset.add(cve.id)
                vulns.append(cve)
        return vulns
    
    def get_vulnerabilities_timeline(self,
                                     project_name: str,
                                     start_date: str,
                                     end_date: str = None,
                                     step: str = 'y',
                                     platform: str="pypi") -> List[dict]:
        """
        Returns a list of vulnerabilities for a project in a specific time range.
        For each date, the most recent release is used to check for vulnerabilities.

        project_name: str
        start_date: str, format: YYYY[-MM]
        end_date: str, format: YYYY[-MM] or falsy value
        step: str, format: y(ear) / m(month), needs to match the format of the dates' lowest precision
        platform: str, default: pypi

        Returns:
        [
            {
                'date': datetime.datetime,
                'release': dict,
                'cves': [dict, ...]
            }
        ]
        """
        start_date = str(start_date)
        if end_date:
            end_date = str(end_date)
        step = step.strip().lower()
        project = self.get_project(project_name, platform)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        start_date: datetime.datetime = datetime.datetime.strptime(start_date, '%Y-%m' if '-' in start_date else '%Y')
        if end_date:
            end_date = datetime.datetime.strptime(end_date, '%Y-%m' if '-' in end_date else '%Y')
        else:
            end_date = datetime.datetime.now()
        # for each date in the range, get the most recent releases and check for vulnerabilities
        def non_recursive_model_to_dict(model):
            return model_to_dict(model, recurse=False)
        results: list = []
        while start_date <= end_date:
            rel_mr = project.releases.where(Release.published_at <= start_date).order_by(Release.published_at.desc()).first()
            if rel_mr is None:
                logger.warning(f"No release found for {project.name} at {start_date}")
                start_date = datetime_increment(start_date, step)
                continue
            logger.info(f"Got most recent release {rel_mr.version} for {project.name} at {start_date}")
            vulns = self.get_vulnerabilities(project.name, rel_mr.version, platform)
            results.append({
                'date': start_date,
                'release': non_recursive_model_to_dict(rel_mr),
                'cves': [ non_recursive_model_to_dict(cve) for cve in vulns if cve is not None ]
            })
            start_date = datetime_increment(start_date, step)
        return results
    
    def get_dependencies(self,
                         project_name: str,
                         version: str,
                         platform: str="pypi") -> List[ReleaseDependency]:
        """
        Get dependencies of a project and a specific version number (release)
        """
        # Force lowercase
        project_name, version = self.__format_strings(project_name, version)

        # Get the project
        project = self.get_project(project_name)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        # Get the release
        release = Release.get_or_none((
            (Release.project == project) &
            (Release.version == version)
        ))
        if release is None:
            logger.error(f"Release '{version}' not found for {project_name}")
            return None
        dependencies = [ dep for dep in ReleaseDependency.select().where(ReleaseDependency.release == release) ]
        if len(dependencies) > 0:
            # Found dependencies in the database
            logger.debug(f"Found {len(dependencies)} dependencies for {project_name} {version}")
            return dependencies
        # No dependencies in database, query the API
        logger.debug(f"Querying libraries.io for dependencies of {project_name} {version}")
        result = self.libraries.query_dependencies(project_name, version, platform)
        if result is None or 'dependencies' not in result:
            logger.error(f"Dependencies not found for {project_name} {version}")
            return None
        dependencies = result['dependencies']
        deps = []
        for dependency in dependencies:
            name = dependency.get('name', '')
            project_name = dependency.get('project_name', '')
            if name == '':
                logger.error(f"Dependency name not found for {project_name} {version}")
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
    # For the purpose of loading in interactive shell
    # e.g., py -i src/middleware.py
    mw = Middleware("config.yml", debug=True)