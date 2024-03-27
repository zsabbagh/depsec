import time, yaml, json, glob, sys
import src.schemas.nvd as nvd
import src.schemas.cwe as cwe
import src.utils.db as db
import argparse
from packaging import version as semver
from playhouse.shortcuts import model_to_dict
from pprint import pprint
from src.queriers.libraries import LibrariesQuerier
from src.queriers.snyk import SnykQuerier
from src.queriers.osi import OSIQuerier
from src.schemas.projects import *
from src.utils.tools import *
from loguru import logger
from pathlib import Path
from typing import List, Dict

def pm(model: List[Model] | Model, recurse=False):
    """
    Pretty print a model
    """
    def fn(m):
        if isinstance(m, Model):
            return model_to_dict(m, recurse=recurse)
        return m
    if isinstance(model, list):
        model = list(map(fn, model))
    else:
        model = fn(model)
    pprint(model)

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
        self.osi = OSIQuerier(apis)

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
    
    def load_projects(self, *projects: str, file: str = 'projects.json') -> Project:
        """
        Update the projects
        """
        if not file.endswith('.json'):
            file = f"{file}.json"
        logger.info(f"Loading projects from '{file}'")
        path = Path(file)
        result = []
        if len(projects) > 0:
            for project in projects:
                logger.debug(f"Loading project {project}")
                project = self.get_project(project)
                result.append(project)
            return result
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
        2) Query API for the project
        3) Create the project and its releases in the database
        """
        if isinstance(project_name, Project):
            return project_name
        # Force lowercase
        project_name = project_name.strip().lower()
        platform = platform.strip().lower()
        logger.debug(f"Getting {project_name} from database with platform {platform}")
        # Query the database
        project = Project.get_or_none(
            Project.name == project_name,
            Project.platform == platform
        )
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

    def get_releases(self,
                     project: str | Project,
                     platform: str="pypi",
                     descending: bool = True,
                     exclude_deprecated: bool = True,
                     sort_semantically: bool = True,
                     before: str | int | datetime.datetime = None,
                     requirements: str = None) -> List[Release]:
        """
        Gets all releases of a project 
        Returns a sorted list of releases, based on the semantic versioning

        project: str | Project, the project name or the project object
        platform: str, default: pypi
        descending: bool, default: True
        exclude_deprecated: bool, default: True
        sort_semantically: bool, default: True, this will sort the releases based on the semantic versioning
        requirements: str, default: None, if provided (a comma separated list of requirements), only the releases that satisfy the requirements are returned
        """
        project = self.get_project(project, platform)
        if project is None:
            return None
        project_name = project.name
        releases = []
        before_date = strint_to_date(before)
        for release in project.releases:
            version = semver.parse(release.version)
            if before_date is not None and release.published_at > before_date:
                continue
            if version is None:
                logger.error(f"Invalid version {release.version} for {project_name}")
                continue
            if exclude_deprecated and version_deprecated(version):
                logger.warning(f"Skipping deprecated version {release.version} for {project_name}")
                continue
            if requirements is not None:
                # check if the version satisfies the requirements
                if not version_satisfies_requirements(version, requirements):
                    logger.debug(f"Version {release.version} does not satisfy requirements {requirements} for {project_name}")
                    continue
            releases.append(release)
        if sort_semantically:
            releases = sorted(releases, key=lambda x : semver.parse(x.version), reverse=descending)
        else:
            releases = sorted(releases, key=lambda x : x.published_at, reverse=descending)
        return releases
    
    def get_release(self,
                    project: str | Project,
                    version: str = None,
                    platform: str="pypi") -> Release:
        """
        Get a specific release of a project, uses latest release if version is None

        project: str | Project, the project name or the project object
        version: str, the version number, if None, the latest release is used
        """
        project = self.get_project(project, platform)
        if project is None:
            return None
        version = version if version else project.latest_release
        release = Release.get_or_none(
            Release.project == project.id,
            Release.version == version
        )
        return release

    def get_most_recent_release(self,
                                project: str | Project,
                                date: datetime.datetime = None,
                                platform: str="pypi",
                                exclude_deprecated: bool = False,
                                sort_semantically: bool = True) -> Release:
        """
        Get the most recent release of a project at a specific date
        """
        project = self.get_project(project, platform)
        rels = Release.select().where(Release.project == project,
                                      Release.published_at <= date)
        if exclude_deprecated:
            rels = [ rel for rel in rels if not version_deprecated(semver.parse(rel.version)) ]
        
        if sort_semantically:
            rels = sorted(rels, key=lambda x : semver.parse(x.version), reverse=True)
        else:
            rels = sorted(rels, key=lambda x : x.published_at, reverse=True)
        
        return rels[-1] if len(rels) > 0 else None

    def get_release_timeline(self,
                                project_name: str,
                                start_date: str | int | datetime.datetime = 2019,
                                end_date: str = None,
                                step: str = 'y',
                                platform: str="pypi",
                                exclude_deprecated: bool = False,
                                sort_semantically: bool = True) -> List[tuple]:
        """
        Computes the release timeline of a project in a specific time range

        returns: list of tuples (datetime, Release)
        """
        start_date = strint_to_date(start_date)
        end_date = strint_to_date(end_date)
        step = step.strip().lower()
        project = self.get_project(project_name, platform)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        if not end_date:
            end_date = datetime.datetime.now()
        # for each date in the range, get the most recent releases and check for vulnerabilities
        results: list = []
        # releases are sorted in descending order
        releases = self.get_releases(project.name, platform=platform, descending=True, exclude_deprecated=exclude_deprecated, sort_semantically=sort_semantically)
        while start_date <= end_date:
            release_most_recent = None
            # naive quadratic time complexity, could be improved
            for rel in releases:
                if rel.published_at <= start_date:
                    release_most_recent = rel
                    break
            results.append((start_date, release_most_recent))
            start_date = datetime_increment(start_date, step)
        return results
    
    def get_vulnerabilities(self,
                            project: str | Project,
                            version: str = None,
                            platform: str="pypi",
                            include_categories: bool = False) -> List[nvd.CVE]:
        """
        Get vulnerabilities of a project and a specific version number (release)

        returns: 
        {
            'cves': {
                <cve_id>: {
                    'applicability': [
                        { 'version_start': <version>, 'version_end': <version>, 'start_date': <date>, 'end_date': <date> },
                        ...
                    ],
                    <key>: <value>,
                }
                ...
            },
            'cwes': {
                <cwe_id>: {
                    <key>: <value>,
                    ...
                    'cves': [ <cve_id>, ... ]
                }
                ...
            }
        }
        """
        # Force lowercase
        version = version if version else ''
        # Get the project
        project = self.get_project(project, platform)
        if project is None:
            return None
        project_name = project.name
        # Get the release
        release = None
        if version:
            release = Release.get_or_none(
                Release.project == project,
                Release.version == version
            )
            if release is None:
                logger.error(f"Release '{version}' not found for {project_name}")
                return None
        logger.debug(f"Querying databases for vulnerabilities of {project_name} {version}")
        product_name = project.product or project_name
        logger.debug(f"Getting CPEs for {project.vendor} {product_name}")
        cpes = nvd.CPE.select().where((nvd.CPE.vendor == project.vendor) & (nvd.CPE.product == product_name))
        logger.debug(f"Found {len(cpes)} CPEs for {project.vendor} {project.name}")
        # We need to find the CPEs that match the version
        vulnset = set()
        release_published_at = release.published_at if release else None
        results = {
            'cves': {},
            'cwes': {},
        }
        cves, cwes = results['cves'], results['cwes']
        processed_versions = {}
        logger.debug(f"Got {len(cpes)} CPEs for {project.vendor} {project.name} {version}")
        for cpe in cpes:
            logger.debug(f"Processing CPE {cpe.vendor} {cpe.product} {cpe.version_start} - {cpe.version_end}")
            # Get release of versions since some contain letters
            node = cpe.node
            # extract cve from node
            cve = node.cve if node else None
            logger.debug(f"Getting release for {cpe.vendor} {cpe.product} {cpe.version_start} - {cpe.version_end}")
            start_release = Release.get_or_none(
                Release.project == project,
                Release.version == cpe.version_start
            )
            end_release = Release.get_or_none(
                Release.project == project,
                Release.version == cpe.version_end
            )
            exclude_end = cpe.exclude_end_version
            exclude_start = cpe.exclude_start_version
            vuln_cpe_id = f"{cve.cve_id}:{cpe.version}:{cpe.version_start}:{cpe.version_end}"
            has_exact_version = cpe.version is not None and cpe.version not in ['', '*']
            if has_exact_version:
                if cve.cve_id not in processed_versions:
                    processed_versions[cve.cve_id] = set()
                elif cpe.version in processed_versions[cve.cve_id]:
                    logger.debug(f"Vulnerability {vuln_cpe_id} already in set")
                    continue
                processed_versions[cve.cve_id].add(cpe.version)
            if vuln_cpe_id in vulnset and not has_exact_version:
                logger.debug(f"Vulnerability {vuln_cpe_id} already in set")
                continue
            start_date: datetime = start_release.published_at if start_release else None
            end_date: datetime = end_release.published_at if end_release else None
            logger.debug(f"Getting vulnerabilities for {cpe.vendor}:{cpe.product}:{cpe.version} {cpe.version_start} ({start_date}) - {cpe.version_end}({end_date})")
            add = False
            if has_exact_version:
                applicability = {
                    'version': cpe.version,
                }
                add = cpe.version == release.version if release is not None else True
            else:
                applicability = {
                    'version_start': cpe.version_start if bool(cpe.version_start) else None,
                    'exclude_start': exclude_start,
                    'version_end': cpe.version_end if bool(cpe.version_end) else None,
                    'exclude_end': exclude_end,
                    'start_date': start_date,
                    'end_date': end_date,
                }
                add = datetime_in_range(release_published_at, start_date, end_date, exclude_start, exclude_end) if release_published_at is not None else True
            if add:
                vulnset.add(cve.id)
                if cve.cve_id not in cves:
                    weaknesses = db.NVD.cwes(cve.cve_id, categories=include_categories, to_dict=False)
                    # TODO: verify categories
                    cwe_ids = set()
                    for cwe in weaknesses:
                        logger.debug(f"Processing CWE {cwe.cwe_id}")
                        cwe_id = cwe.cwe_id
                        cwe_ids.add(cwe_id)
                        if cwe_id not in cwes:
                            cwes[cwe_id] = model_to_dict(cwe, recurse=False)
                            cwes[cwe_id]['cves'] = [cve.cve_id]
                        else:
                            cwes[cwe_id]['cves'].append(cve.cve_id)
                    cve_data = model_to_dict(cve)
                    cve_data['cwes'] = sorted(list(cwe_ids))
                    cve_data['applicability'] = [applicability]
                    cves[cve.cve_id] = cve_data
                else:
                    cves[cve.cve_id]['applicability'].append(applicability)
        # translate 'version' applicability to 'version_start' and 'version_end'
        for _, cve in cves.items():
            apps = cve.get('applicability', [])
            apps = db.compute_version_ranges(project, apps)
            for app in apps:
                v_end = app.get('version_end')
                if app.get('exclude_end', False):
                    if v_end is not None:
                        rels = self.get_releases(project.name, platform=platform, descending=False, sort_semantically=True, requirements=f">{v_end}")
                        if len(rels) > 0:
                            pub_at = rels[0].published_at
                            app['patched_at'] = pub_at
                            app['patched_version'] = rels[0].version
                    if app.get('patched_at') is None:
                        app['patched_at'] = None
                        app['patched_version'] = None
                else:
                    app['patched_at'] = app.get('end_date')
                    app['patched_version'] = app.get('version_end')
            cve['applicability'] = apps
        return results
    
    
    def get_indirect_vulnerabilities(self,
                                     project_name: str,
                                     version: str = None,
                                     platform: str="pypi",
                                     exclude_deprecated: bool = True,
                                     include_categories: bool = False,
                                     most_recent_version: bool = True,
                                     before: str | int | datetime.datetime = None,
                                     sort_semantically: bool = True,) -> List[nvd.CVE]:
        """
        Get indirect vulnerabilities of a project and a specific version number (release)
        This is done by getting the dependencies of the project and checking for vulnerabilities in them
        Each release is formatted as project:version

        project_name: str, the project name
        version: str, the version number, if None, the latest release is used
        platform: str, default: pypi
        include_categories: bool, default: False, include CWE categories in the results
        most_recent_version: bool, default: True, if True, the most recent release is used

        returns:
        {
            'cves':
            'cwes':
            'releases'
        }
        """
        release = self.get_release(project_name, version, platform)
        if release is None:
            logger.error(f"Release {version} not found for {project_name}")
            return None
        version = release.version
        results = {
            'cves': {},
            'cwes': {},
            'releases': {},
        }
        cves, cwes, releases = results['cves'], results['cwes'], results['releases']
        dependencies = self.get_dependencies(project_name, version, platform)
        for dep in dependencies:
            depname = dep.name
            requirements = dep.requirements
            rels = self.get_releases(depname, platform=dep.platform, exclude_deprecated=exclude_deprecated, sort_semantically=sort_semantically, requirements=requirements, before=before)
            if most_recent_version:
                rels = [rels.pop(0)] if len(rels) > 0 else []
            for rel in rels:
                vulnerabilities = self.get_vulnerabilities(depname, rel.version, platform=dep.platform)
                rel_id = f"{depname}:{rel.version}"
                for cve_id in vulnerabilities.get('cves', {}):
                    # add project name to applicability
                    cve = vulnerabilities['cves'][cve_id]
                    for app in cve.get('applicability', []):
                        app['project'] = depname
                    if cve_id in cves:
                        cves[cve_id]['applicability'].extend(cve.get('applicability', []))
                    else:
                        cves[cve_id] = cve
                for cwe_id in vulnerabilities.get('cwes', {}):
                    weak = vulnerabilities['cwes'][cwe_id]
                    if cwe_id not in cwes:
                        cwes[cwe_id] = weak
                    else:
                        weakset = set(cwes[cwe_id].get('cves', []))
                        weakset.update(weak.get('cves', []))
                        cwes[cwe_id]['cves'] = list(weakset)
                if rel_id not in releases:
                    releases[rel_id] = model_to_dict(rel, recurse=False)
                    bandit_report = rel.bandit_report.first()
                    if bandit_report:
                        releases[rel_id]['bandit_report'] = model_to_dict(bandit_report, recurse=False)
        return results
    
    
    def get_vulnerabilities_timeline(self,
                                     project_name: str | list,
                                     start_date: str = 2019,
                                     end_date: str = None,
                                     step: str = 'y',
                                     platform: str="pypi",
                                     exclude_deprecated: bool = False) -> List[tuple]:
        """
        Returns a list of vulnerabilities for a project in a specific time range.
        For each date, the most recent release is used to check for vulnerabilities.

        project_name: str, or list of str
        start_date: str, format: YYYY[-MM]
        end_date: str, format: YYYY[-MM] or falsy value
        step: str, format: y(ear) / m(month), needs to match the format of the dates' lowest precision
        platform: str, default: pypi

        Returns: tuple of (date, release, cves)
        """
        project = self.get_project(project_name, platform)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        # for each date in the range, get the most recent releases and check for vulnerabilities
        results: list = {
            'cwes': {},
            'cves': {},
            'releases': model_to_dict(project, recurse=False),
            'timeline': []
        }
        results['releases'] = {}
        cves, releases, timeline = results['cves'], results['releases'], results['timeline']
        cwes = results['cwes']
        vulnerabilities = self.get_vulnerabilities(project.name, platform=platform)
        rels = self.get_releases(project.name, platform=platform, exclude_deprecated=exclude_deprecated)
        logger.info(f"Generating timeline with {len(rels)} releases for {project.name}, got: {len(vulnerabilities.get('cves', {}))} vulnerabilities")
        rel_timeline = self.get_release_timeline(project.name, start_date=start_date, end_date=end_date, step=step, platform=platform, exclude_deprecated=exclude_deprecated)
        for date, rel in rel_timeline:
            if rel is None:
                logger.warning(f"No release found for {project.name} at {start_date}")
                start_date = datetime_increment(start_date, step)
                results['timeline'].append({
                    'date': date,
                    'release': None,
                    'cves': []
                })
                continue
            logger.info(f"Got most recent release {rel.version} for {project.name} at {date}")
            vulns = []
            for vuln in vulnerabilities.get('cves', {}).values():
                applicabilities = vuln.get('applicability', [])
                is_applicable = db.is_applicable(rel, applicabilities)
                if is_applicable:
                    vulns.append(vuln)
                    for cwe_id in vuln.get('cwes', []):
                        if cwe_id not in cwes:
                            cwes[cwe_id] = vulnerabilities.get('cwes', {}).get(cwe_id, {})
            timeline.append({
                'date': date,
                'release': rel.version,
                'cves': [ cve['cve_id'] for cve in vulns if cve is not None ]
            })
            for cve in vulns:
                cve_id = cve.get('cve_id')
                if cve_id:
                    cves[cve_id] = cve
            releases[rel.version] = model_to_dict(rel, recurse=False)
            bandit_report = rel.bandit_report.first()
            if bandit_report:
                results['releases'][rel.version]['bandit_report'] = model_to_dict(bandit_report, recurse=False)
            date = datetime_increment(date, step)
        return results
    
    def get_indirect_vulnerabilities_timeline(self,
                                                project_name: str | list,
                                                start_date: str = 2019,
                                                end_date: str = None,
                                                step: str = 'y',
                                                platform: str="pypi",
                                                exclude_deprecated: bool = False) -> List[tuple]:
            """
            Returns a list of vulnerabilities for a project in a specific time range.
            For each date, the most recent release is used to check for vulnerabilities.
    
            project_name: str, or list of str
            start_date: str, format: YYYY[-MM]
            end_date: str, format: YYYY[-MM] or falsy value
            step: str, format: y(ear) / m(month), needs to match the format of the dates' lowest precision
            platform: str, default: pypi
    
            Returns: tuple of (date, release, cves)
            """
            project = self.get_project(project_name, platform)
            if project is None:
                logger.error(f"Project {project_name} not found")
                return None
            # for each date in the range, get the most recent releases and check for vulnerabilities
            results: list = {
                'cwes': {},
                'cves': {},
                'releases': model_to_dict(project, recurse=False),
                'timeline': []
            }
            results['releases'] = {}
            dependencies = {}
            cves, releases, timeline = results['cves'], results['releases'], results['timeline']
            cwes = results['cwes']
            vulnerabilities = self.get_indirect_vulnerabilities(project.name, platform=platform)
            rels = self.get_releases(project.name, platform=platform, exclude_deprecated=exclude_deprecated)
            logger.info(f"Generating timeline with {len(rels)} releases for {project.name}, got: {len(vulnerabilities.get('cves', {}))} vulnerabilities")
            rel_timeline = self.get_release_timeline(project.name, start_date=start_date, end_date=end_date, step=step, platform=platform, exclude_deprecated=exclude_deprecated)
            previous_deps = []
            for date, rel in rel_timeline:
                if rel is None:
                    logger.warning(f"No release found for {project.name} at {start_date}")
                    start_date = datetime_increment(start_date, step)
                    results['timeline'].append({
                        'date': date,
                        'release': None,
                        'cves': []
                    })
                    continue
                logger.info(f"Got most recent release {rel.version} for {project.name} at {date}")
                deps = self.get_dependencies(project.name, rel.version, platform)
                if len(previous_deps) > 0 and deps is None:
                    # some versions do not have dependencies as they are unsupported releases
                    # assume the dependencies are the same as the previous release
                    deps = previous_deps
                elif deps is not None:
                    previous_deps = deps
                else:
                    logger.warning(f"No dependencies found for {project.name} {rel.version}")
                    deps = []
                for dep in deps:
                    depname = dep.name
                    if depname not in dependencies:
                        dependencies[depname] = self.get_vulnerabilities(depname, platform=dep.platform)
                vulns = []
                for vuln in vulnerabilities.get('cves', {}).values():
                    applicabilities = vuln.get('applicability', [])
                    is_applicable = db.is_applicable(rel, applicabilities)
                    if is_applicable:
                        vulns.append(vuln)
                        for cwe_id in vuln.get('cwes', []):
                            if cwe_id not in cwes:
                                cwes[cwe_id] = vulnerabilities.get('cwes', {}).get(cwe_id, {})
                timeline.append({
                    'date': date,
                    'release': rel.version,
                    'cves': [ cve['cve_id'] for cve in vulns if cve is not None ]
                })
                for cve in vulns:
                    cve_id = cve.get('cve_id')
                    if cve_id:
                        cves[cve_id] = cve
                releases[rel.version] = model_to_dict(rel, recurse=False)
                bandit_report = rel.bandit_report.first()
                if bandit_report:
                    results['releases'][rel.version]['bandit_report'] = model_to_dict(bandit_report, recurse=False)
                date = datetime_increment(date, step)
    
    def get_dependencies(self,
                         project: str | Project,
                         version: str = None,
                         platform: str="pypi",
                         force: bool = False) -> List[ReleaseDependency]:
        """
        Get dependencies of a project and a specific version number (release).
        Includes indirect dependencies.

        project_name: str
        version: str, if None, the latest release is used
        platform: str, default: pypi
        """
        # Force lowercase
        # Get the project
        project_name = project.name if isinstance(project, Project) else project
        project = self.get_project(project_name)
        if project is None:
            return None
        elif project.dependencies == 0 and not force:
            logger.info(f"No dependencies found for {project_name}")
            return None
        project_name = project.name
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
        dependencies = [ dep for dep in release.dependencies ]
        if len(dependencies) > 0 and not force:
            # Found dependencies in the database
            logger.debug(f"Found {len(dependencies)} dependencies for {project_name} {version}")
            return dependencies
        # No dependencies in database, query the API
        logger.debug(f"Querying libraries.io for dependencies of {project_name} {version}")
        result = self.osi.query_dependencies(project_name, version, platform)
        if result is None or 'nodes' not in result:
            logger.error(f"Dependencies not found for {project_name} {version}")
            return None
        nodes = result.get('nodes', [])
        if nodes[0].get('versionKey', {}).get('name', '') != project_name:
            # OSI should always return the first node as the project itself
            logger.error(f"First node is not {project_name}! Solve this")
            return None
        edges = result.get('edges', [])
        metadata = {}
        # process the graph
        for edge in edges:
            req = edge.get('requirement', '')
            nfr = edge.get('fromNode', None)
            nto = edge.get('toNode', None)
            if nto is None:
                continue
            node = nodes[nto]
            node_from = nodes[nfr] if nfr is not None else None
            node_to_name = node.get('versionKey', {}).get('name', '')
            if node_from is not None:
                node_from_name = node_from.get('versionKey', {}).get('name', '')
            metadata[node_to_name] = {
                'requirements': req,
                'inherited_from': node_from_name,
                'depth': None,
            }
        for nname in metadata:
            depth = 0
            inherited_from = metadata[nname].get('inherited_from', None)
            while inherited_from is not None:
                depth += 1
                inherited_from = metadata.get(inherited_from, {}).get('inherited_from', None)
            metadata[nname]['depth'] = depth
        results = []
        # Save the dependencies
        project.dependencies = len(dependencies)
        project.save()
        for node in nodes:
            relation = node.get('relation', '')
            if relation == 'SELF':
                logger.warning(f"Skipping self-relation for {project_name} {version}")
                continue
            version_key = node.get('versionKey', {})
            name = version_key.get('name', '').lower()
            if name == project_name or not name:
                logger.warning(f"Skipping dependency '{name}' for {project_name} {version}")
                continue
            ptfrm = version_key.get('system', '').lower()
            requirements = metadata.get(name, {}).get('requirements', '')
            depth = metadata.get(name, {}).get('depth', 0)
            name, project_name, ptfrm = self.__format_strings(name, project_name, ptfrm)
            version = version_key.get('version', '')
            logger.debug(f"Creating dependency {name} {project_name} {ptfrm} {requirements}")
            inherited_from = metadata.get(name, {}).get('inherited_from', None)
            dep_instance = ReleaseDependency.create(
                release=release,
                name=name,
                project_name=project_name,
                platform=ptfrm,
                version=version,
                is_direct=relation=='DIRECT',
                inherited_from=inherited_from if inherited_from != project_name else None,
                depth=depth,
                requirements=requirements,
            )
            dep_instance.save()
            results.append(dep_instance)
        project.dependencies = len(results)
        project.save()
        return results

if __name__ == "__main__":
    # For the purpose of loading in interactive shell and debugging
    # e.g., py -i src/middleware.py
    parser = argparse.ArgumentParser()
    parser.add_argument('project', type=str, help='The project name', default='jinja2')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    logger.remove()
    args = parser.parse_args()
    logger.add(sys.stdout, colorize=True, backtrace=True, diagnose=True, level='DEBUG' if args.debug else 'INFO')
    mw = Middleware("config.yml", debug=True)
    mw.load_projects()
    p = mw.get_project(args.project)
    rels = mw.get_releases(args.project)
    relvs = sorted(list(map(lambda x : x.version, rels)))
    deps = mw.get_dependencies(args.project, force=True)
    depnames = list(map(lambda x : x.name, deps)) if deps is not None else []
    rel: Release = mw.get_release(args.project, p.latest_release)
    reltl = mw.get_release_timeline(args.project)
    bandit_report = rel.bandit_report.first()
    vulns = mw.get_vulnerabilities(args.project)
    depvuln = mw.get_indirect_vulnerabilities(args.project)
    vulnstl = mw.get_vulnerabilities_timeline(args.project)
    vers = sorted(rels, key=lambda x : semver.parse(x.version), reverse=True)
    cwes = [ (c, vulns.get('cwes').get(c, {}).get('status')) for c in vulns.get('cwes', {}) ]
    cves = [ c for c in vulns.get('cves', {}) ]