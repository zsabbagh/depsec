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
    
    def load_projects(self, file: str = 'projects.json') -> Project:
        """
        Update the projects
        """
        if not file.endswith('.json'):
            file = f"{file}.json"
        logger.info(f"Loading projects from '{file}'")
        path = Path(file)
        result = []
        with open(path) as f:
            data = json.load(f)
            for platform in data:
                logger.debug(f"Loading platform {platform}")
                projects = data[platform]
                for proj in projects:
                    logger.debug("Loading project {proj}")
                    info = projects[proj]
                    project = self.get_project(proj, platform)
                    vendor = info.get('vendor')
                    product = info.get('product')
                    if vendor is not None:
                        project.vendor = vendor
                    if product is not None:
                        project.product = product
                    project.save()
                    result.append(project)
        logger.info(f"Loaded {len(result)} projects")
        return result
    
    def get_project(self,
                    project_name: str,
                    platform: str="pypi") -> Project:
        """
        When you get a project, it does the following:

        1) If the project is in the database, it returns it
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
        if project is not None and project.releases.count() > 0:
            # If the package is in the database, return it
            logger.debug(f"Found {project_name} in database")
            return project
        elif project is not None:
            logger.debug(f"Project {project_name} in database but no releases found")
            project.delete_instance()
        logger.debug(f"Querying libraries.io for {project_name}")

        # Query libraries.io if the package is not in the database
        logger.debug(f"Querying libraries.io for {project_name}")
        time.sleep(1)
        result: dict = self.libraries.query_package(project_name)
        if result is None:
            logger.error(f"Project {project_name} not found in libraries.io")
            return None

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
                except:
                    published_at = None
                release = Release.create(
                    project=project,
                    version=number,
                    published_at=published_at,
                )
                release.save()
            # get the latest release
            latest_release = Release.select().where(Release.project == project).order_by(Release.published_at.desc()).first()
            project.latest_release = latest_release.version
            project.save()
        return project

    def get_dependency_graph(self,
                                project_name: str,
                                platform: str="pypi",
                                max_depth: int = 2) -> List[Project]:
        """
        Get all dependencies of a project

        project_name: str
        platform: str, default: pypi
        max_depth: int, default: 2 (max depth of the dependency graph)

        Results:
        {
            'platform': str,
            'projects': [ <project_name> ],
            'graph': {
                <project_name>: {
                    <project_name>: {
                        ...
                    }
                }
        }
        """
        # Force lowercase
        logger.info(f"Getting dependency graph for {project_name} {platform}, max depth {max_depth}")
        project_name, platform = self.__format_strings(project_name, platform)
        project = self.get_project(project_name, platform)
        processed = {}
        # results per platform
        total = set()
        graph = {
            project.name: {}
        }
        queue = [(project, [project.name])]
        count = 0
        while len(queue) > 0:
            p, ks = queue.pop(0)
            logger.info(f"Getting dependencies for {p.name} {p.platform}, depth {len(ks)}")
            if max_depth > 0 and len(ks) > max_depth:
                logger.warning(f"Max depth reached, skipping {p.name}")
                continue
            logger.info(f"Currently processed {len(processed)} projects")
            r = graph
            for i in range(len(ks)):
                k = ks[i]
                r = r.get(k, {})
            if p.name in processed:
                logger.warning(f"Project {p.name} already processed, skipping")
                r[p.name] = processed[p.name]
                continue
            processed[p.name] = r
            deps = self.get_dependencies(p.name, platform=p.platform)
            for dep in deps:
                count += 1
                total.add(dep.project_name)
                logger.info(f"Processing dependency {dep.name} {dep.platform}, nr {count}")
                if dep.name.startswith('pytest') or '[' in dep.name:
                    logger.warning(f"Skipping dependency {dep.name}")
                    continue
                logger.debug(f"Getting project {dep.project_name} {dep.platform}")
                dep_project = self.get_project(dep.project_name, dep.platform)
                if dep_project is None:
                    logger.error(f"Project {dep.project_name} not found")
                    continue
                if dep_project.dependencies is None or dep_project.dependencies > 0:
                    r[dep_project.name] = {}
                    queue.append((dep_project, ks + [dep_project.name]))
                else:
                    r[dep_project.name] = {}
                    logger.warning(f"No dependencies found for {dep_project.name}: {dep_project.dependencies}")
        return { 'platform': platform, 'projects': sorted(list(total)), 'graph': graph }
    
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
        product_name = project.name if project.product is None else project.product
        logger.debug(f"Getting CPEs for {project.vendor} {product_name}")
        cpes = nvd.CPE.select().where((nvd.CPE.vendor == project.vendor) & (nvd.CPE.product == product_name))
        logger.debug(f"Found {len(cpes)} CPEs for {project.vendor} {project.name}")
        # We need to find the CPEs that match the version
        vulns = []
        vulnset = set()
        release_published_at = release.published_at if release else None
        for cpe in cpes:
            logger.debug(f"Processing CPE {cpe.vendor} {cpe.product} {cpe.version_start} - {cpe.version_end}")
            # Get release of versions since some contain letters
            cve = cpe.node.cve
            if cve.id in vulnset:
                logger.debug(f"Vulnerability {cve.id} already in set")
                continue
            logger.debug(f"Getting release for {cpe.vendor} {cpe.product} {cpe.version_start} - {cpe.version_end}")
            start_release = Release.get_or_none(
                Release.project == project,
                Release.version == cpe.version_start
            )
            end_release = Release.get_or_none(
                Release.project == project,
                Release.version == cpe.version_end
            )
            start_date: datetime = start_release.published_at if start_release else None
            end_date: datetime = end_release.published_at if end_release else None
            logger.debug(f"Getting vulnerabilities for {cpe.vendor} {cpe.product} {cpe.version_start} ({start_date}) - {cpe.version_end}({end_date})")
            node = cpe.node
            if node.operator != 'OR':
                logger.warning(f"Operator '{node.operator}' is not OR")
            if not node.is_root:
                logger.warning(f"Node {node.id} is not root, getting root")
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
        {
            'cves': { <cve_id>: <cve> },
            'releases': { <version>: <release> },
            'timeline': [
                {
                    'date': <date>,
                    'release': <version>,
                    'cves': [ <cve_id> ]
                }
            ]
        }
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
        results: list = {
            'cves': {},
            'releases': {},
            'timeline': []
        }
        cves = results.get('cves')
        releases = results.get('releases')
        timeline = results.get('timeline')
        while start_date <= end_date:
            rel_mr = project.releases.where(Release.published_at <= start_date).order_by(Release.published_at.desc()).first()
            if rel_mr is None:
                logger.warning(f"No release found for {project.name} at {start_date}")
                start_date = datetime_increment(start_date, step)
                continue
            logger.info(f"Got most recent release {rel_mr.version} for {project.name} at {start_date}")
            vulns = self.get_vulnerabilities(project.name, rel_mr.version, platform)
            timeline.append({
                'date': start_date,
                'release': rel_mr.version,
                'cves': [ cve.cve_id for cve in vulns if cve is not None ]
            })
            for cve in vulns:
                cves[cve.cve_id] = non_recursive_model_to_dict(cve)
            releases[rel_mr.version] = non_recursive_model_to_dict(rel_mr)
            start_date = datetime_increment(start_date, step)
        return results
    
    def get_dependencies(self,
                         project_name: str,
                         version: str = None,
                         platform: str="pypi") -> List[ReleaseDependency]:
        """
        Get dependencies of a project and a specific version number (release)

        project_name: str
        version: str, if None, the latest release is used
        platform: str, default: pypi
        """
        # Force lowercase
        project_name = self.__format_strings(project_name)[0]
        # Get the project
        project = self.get_project(project_name)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        elif project.dependencies == 0:
            logger.error(f"No dependencies found for {project_name}")
            return None
        # Get the release
        version = version if version else project.latest_release
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
        # Save the dependencies
        project.dependencies = len(dependencies)
        project.save()
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