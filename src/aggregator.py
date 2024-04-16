import time, yaml, json, glob, sys, pandas as pd, datetime as dt
import src.schemas.nvd as nvd
import src.schemas.cwe as cwe
import src.utils.db as db
import argparse
from copy import deepcopy
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

class Aggregator:
    """
    The Aggregator to communicate with the databases and the APIs
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
        Initialise the Aggregator
        """
        self.__debug = debug
        self.__debug_delay = debug_delay
        logger.debug(f"Initalising Aggregator with config file {config_path}")
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
                    published_at = dt.datetime.strptime(published_at, '%Y-%m-%dT%H:%M:%S.%fZ')
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
                     before: str | int | dt.datetime = None,
                     after: str | int | dt.datetime = None,
                     analysed: bool = False,
                     requirements: str = None) -> List[Release]:
        """
        Gets all releases of a project 
        Returns a sorted list of releases, based on the semantic versioning

        project: str | Project, the project name or the project object
        platform: str, default: pypi
        descending: bool, default: True
        exclude_deprecated: bool, default: True
        sort_semantically: bool, default: True, this will sort the releases based on the semantic versioning
        before: str | int | dt.datetime, default: None, if provided, only the releases before the date are returned
        after: str | int | dt.datetime, default: None, if provided, only the releases after the date are returned
        requirements: str, default: None, if provided (a comma separated list of requirements), only the releases that satisfy the requirements are returned
        """
        project = self.get_project(project, platform)
        if project is None:
            return None
        project_name = project.name
        releases = []
        before_date = strint_to_date(before)
        after_date = strint_to_date(after)
        for release in project.releases:
            try:
                version = semver.parse(release.version)
            except Exception as e:
                logger.debug(f"Error parsing version {release.version} for {project_name}: {e}")
                continue
            if before_date is not None and release.published_at > before_date:
                continue
            if after_date is not None and release.published_at < after_date:
                continue
            if version is None:
                logger.error(f"Invalid version {release.version} for {project_name}")
                continue
            if exclude_deprecated and not version_is_stable(version):
                logger.debug(f"Skipping deprecated version {release.version} for {project_name}")
                continue
            if requirements is not None:
                # check if the version satisfies the requirements
                if not version_satisfies_requirements(version, requirements):
                    logger.debug(f"Version {release.version} does not satisfy requirements {requirements} for {project_name}")
                    continue
            if analysed and release.nloc_total is None:
                logger.debug(f"Skipping release {release.version} without static analysis for {project_name}")
                continue
            releases.append(release)
        if sort_semantically:
            releases = sorted(releases, key=lambda x : semver.parse(x.version), reverse=descending)
        else:
            releases = sorted(releases, key=lambda x : x.published_at, reverse=descending)
        return releases
    
    def get_release(self,
                    project_or_release: str | Project | Release,
                    version: str = None,
                    platform: str="pypi",
                    before: str | int | dt.datetime = None,
                    requirements: str = None,
                    analysed: bool = False,
                    after: str | int | dt.datetime = None) -> Release:
        """
        Get a specific release of a project, uses latest release if version is None

        project: str | Project, the project name or the project object
        version: str, the version number, if None, the latest release is used
        platform: str, default: pypi
        before: str | int | dt.datetime, default: None, if provided, only the releases before the date are returned
        after: str | int | dt.datetime, default: None, if provided, only the releases after the date are returned
        requirements: str, default: None, if provided (a comma separated list of requirements), only the releases that satisfy the requirements are returned
        analysed: bool, default: False, if True, a release with static analysis is returned if available
        """
        if isinstance(project_or_release, Release):
            return project_or_release
        project = self.get_project(project_or_release, platform)
        if project is None:
            return None
        version = version if version else project.latest_release
        before_date = strint_to_date(before)
        after_date = strint_to_date(after)
        if before_date is not None or after_date is not None or requirements is not None or analysed:
            releases = self.get_releases(project.name, platform=platform, before=before_date, after=after, sort_semantically=True, requirements=requirements)
            if analysed:
                for rel in releases:
                    if rel.nloc_total is not None:
                        return rel
            return releases[0] if len(releases) > 0 else None
        release = Release.get_or_none(
            Release.project == project.id,
            Release.version == version
        )
        return release

    def get_most_recent_release(self,
                                project: str | Project,
                                date: dt.datetime = None,
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
            rels = [ rel for rel in rels if version_is_stable(semver.parse(rel.version)) ]
        
        if sort_semantically:
            rels = sorted(rels, key=lambda x : semver.parse(x.version), reverse=True)
        else:
            rels = sorted(rels, key=lambda x : x.published_at, reverse=True)
        
        return rels[-1] if len(rels) > 0 else None

    def get_release_timeline(self,
                                project_name: str,
                                start_date: str | int | dt.datetime = 2019,
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
            end_date = dt.datetime.now()
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
                            include_categories: bool = False) -> dict:
        """
        Get vulnerabilities of a project and a specific version number (release).
        If a version is not provided, the all vulnerabilities are returned.

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
        # we do not skip deprecated versions here as the "first" release might be deprecated
        releases = self.get_releases(project.name, platform=platform, descending=False, sort_semantically=False, requirements=f">0.9", exclude_deprecated=False)
        releases = sorted(releases, key=lambda x : x.published_at, reverse=False) if releases is not None else []
        first_release = releases[0] if len(releases) > 0 else None
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
            cpe: nvd.CPE
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
                    'version_start': cpe.version_start if bool(cpe.version_start) else (
                        first_release.version if first_release is not None else None
                    ),
                    'exclude_start': exclude_start,
                    'version_end': cpe.version_end if bool(cpe.version_end) else None,
                    'exclude_end': exclude_end,
                    'start_date': start_date if start_date is not None else (
                        first_release.published_at if first_release is not None else None
                    ),
                    'end_date': end_date,
                }
                # check applicability on release version instead of release date, since the date might be in range, but the version not
                add = version_in_range(version, cpe.version_start, cpe.version_end, exclude_start, exclude_end) if bool(version) else True
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
                # add project name to clarify the applicability
                app['project'] = project_name
                v_end = app.get('version_end')
                if app.get('exclude_end', False) is False:
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
        for _, cw in cwes.items():
            cw['cves'] = sorted(list(set(cw['cves'])))
        return results
    
    def get_indirect_vulnerabilities(self,
                                     project_name: str,
                                     version: str = None,
                                     platform: str="pypi",
                                     exclude_deprecated: bool = True,
                                     include_categories: bool = False,
                                     most_recent_version: bool = True,
                                     before: str | int | dt.datetime = None,
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
        if dependencies is None:
            logger.error(f"Dependencies not found for {project_name}")
            return results
        for dep in dependencies:
            logger.info(f"Getting vulnerabilities for {dep.name}")
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
                    bandit_report = release.bandit_report.first()
                    if bandit_report:
                        releases[rel_id]['bandit_report'] = model_to_dict(bandit_report, recurse=False)
        return results
    
    
    def get_vulnerabilities_timeline(self,
                                     project_name: str | list,
                                     start_date: str = 2019,
                                     end_date: str = None,
                                     step: str = 'y',
                                     platform: str="pypi",
                                     exclude_deprecated: bool = False) -> dict:
        """
        Returns a list of vulnerabilities for a project in a specific time range.
        For each date, the most recent release is used to check for vulnerabilities.

        project_name: str, or list of str
        start_date: str, format: YYYY[-MM]
        end_date: str, format: YYYY[-MM] or falsy value
        step: str, format: y(ear) / m(month), needs to match the format of the dates' lowest precision
        platform: str, default: pypi

        Returns:
        {
            'cves': {},
            'cwes': {},
            'releases': {},
            'timeline': [ { 'date': datetime, 'release': str, 'cves': [str] }, ... ]
        }
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
                logger.debug(f"No release found for {project.name} at {start_date}")
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
                                                exclude_deprecated: bool = False,
                                                force: bool = False) -> dict:
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
        dep_vulns = {}
        cves, releases, timeline = results['cves'], results['releases'], results['timeline']
        cwes = results['cwes']
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
            deps = self.get_dependencies(project.name, rel.version, platform, force=force)
            if len(previous_deps) > 0 and deps is None:
                # some versions do not have dependencies as they are unsupported releases
                # assume the dependencies are the same as the previous release
                deps = previous_deps
            elif deps is not None:
                previous_deps = deps
            else:
                logger.warning(f"No dependencies found for {project.name} {rel.version}")
                deps = []
            # all vulns for all dependencies
            all_vulns = set()
            all_releases = set()
            for dep in deps:
                # process each dependency
                depname = dep.name
                if depname not in dep_vulns:
                    # here we get all the vulnerabilities, so that we quickly can look them up
                    vulns = self.get_vulnerabilities(depname, platform=dep.platform)
                    dep_vulns[depname] = vulns if vulns is not None else {}
                # process each existing vulnerability
                requirements = dep.requirements
                dep_release = self.get_release(depname, platform=dep.platform, before=date, requirements=requirements)
                if dep_release is None:
                    logger.warning(f"No release found for {depname} at {date}")
                    continue
                rel_id = f"{depname}:{dep_release.version}"
                all_releases.add(rel_id)
                if rel_id not in releases:
                    releases[rel_id] = model_to_dict(dep_release, recurse=False)
                    bandit_report = dep_release.bandit_report.first()
                    if bandit_report:
                        releases[rel_id]['bandit_report'] = model_to_dict(bandit_report, recurse=False)
                for vuln in dep_vulns.get(depname, {}).get('cves', {}).values():
                    # process each vulnerability
                    applicabilities = vuln.get('applicability', [])
                    is_applicable = db.is_applicable(dep_release, applicabilities)
                    if is_applicable:
                        # we have found an applicable vulnerability
                        cve_id = vuln.get('cve_id')
                        if cve_id not in cves:
                            cves[cve_id] = vuln
                        all_vulns.add(cve_id)
                        for cwe_id in vuln.get('cwes', []):
                            if cwe_id not in cwes:
                                cwes[cwe_id] = dep_vulns.get('cwes', {}).get(cwe_id, {})
            timeline.append({
                'date': date,
                'release': sorted(list(all_releases)),
                'cves': sorted(list(all_vulns))
            })
            date = datetime_increment(date, step)
        return results
    
    def get_dependencies(self,
                         project_or_release: str | Project | Release,
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
        release = self.get_release(project_or_release, version, platform)
        if release is None:
            logger.error(f"Release '{version}' not found for {project_name}")
            return None
        project_name = project_or_release if type(project_or_release) == str else (
            project_or_release.project.name if type(project_or_release) == Release else project_or_release.name
        )
        if not force:
            if release.dependency_count == 0:
                logger.debug(f"No dependencies found for {project_name} {version}")
                return None
            elif release.dependency_count is not None:
                dependencies = [ dep for dep in release.dependencies ]
                # Found dependencies in the database
                logger.debug(f"Found {len(dependencies)} dependencies for {project_name} {version}")
                return dependencies
        else:
            # Delete the dependencies
            for dep in release.dependencies:
                dep.delete_instance()
        # No dependencies in database, query the API
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
        for node in nodes:
            relation = node.get('relation', '')
            if relation == 'SELF':
                logger.debug(f"Skipping self-relation for {project_name} {version}")
                continue
            version_key = node.get('versionKey', {})
            name = version_key.get('name', '').lower()
            if name == project_name or not name:
                logger.debug(f"Skipping dependency '{name}' for {project_name} {version}")
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
        release.dependency_count = len(results)
        release.save()
        return results
    
    
    def get_bandit_report(self,
                          project_or_release: str | Project,
                          version: str = None,
                          force: bool = True,
                          platform: str="pypi") -> BanditReport:
        """
        Gets the bandit report of a project or a specific release
        If no version is provided, the latest release with a bandit report is used

        project_or_release: str | Project | Release
        version: str, the version number, if None, the latest release is used
        platform: str, default: pypi
        """
        project = release = None
        if isinstance(project_or_release, Project):
            version = version if version else project_or_release.latest_release
            project = project_or_release
        elif isinstance(project_or_release, Release):
            version = project_or_release.version
            project = project_or_release.project
        else:
            project = self.get_project(project_or_release, platform)
            version = version if version else project.latest_release
        if project is None:
            logger.error(f"Project {project_or_release} not found")
            return None
        if release is None:
            release = self.get_release(project, version, platform)
            if release is None:
                logger.error(f"Release {version} not found for {project.name}")
                return None
        bandit_report = release.bandit_report.first()
        if bandit_report is None and force:
            logger.info(f"No bandit report found for {project.name} {version}")
            releases = self.get_releases(project.name, platform=platform, sort_semantically=True)
            for rel in releases:
                bandit_report = rel.bandit_report.first()
                if bandit_report is not None:
                    logger.info(f"Found bandit report for {project.name} {rel.version}")
                    break
        if bandit_report is None:
            logger.error(f"No bandit report found for {project.name} {version}")
            return None
        return bandit_report
    
    def get_analysed_releases(self,
                          project: str | Project,
                          platform: str="pypi",
                          with_dependencies: bool = True) -> List[Release]:
        """
        Gets all releases of a project with static analysis.
        First is the project, then the dependencies, when with_dependencies is True

        project: str | Project
        platform: str, default: pypi
        with_dependencies: bool, default: True, if True, dependencies are included in the list
        """
        release = self.get_release(project, platform=platform, analysed=True)
        results = []
        if release is None:
            logger.error(f"No release found for {project}")
            return results
        results.append(release)
        for dependency in release.dependencies:
            dep_name = dependency.name
            dep_release = self.get_release(dep_name, platform=dependency.platform, analysed=True)
            if dep_release is not None:
                results.append(dep_release)
        return results
    
    def get_bandit_issues(self,
                          project: str | Project,
                          platform: str="pypi",
                          with_dependencies: bool = True) -> List[dict]:
        """
        Gets all Bandit issues with / without dependencies
        """
        project_name = project if isinstance(project, str) else project.name
        results = []
        releases = self.get_analysed_releases(project, platform=platform, with_dependencies=with_dependencies)
        for release in releases:
            report = release.bandit_report.first()
            source = 'Direct' if release.project.name == project_name else 'Indirect'
            release_name = f"{release.project.name}"
            if report is not None:
                for issue in report.issues:
                    module = issue.module if issue.module else ''
                    package = issue.package if issue.package else ''
                    is_test = package.startswith('test') or 'test' in module
                    if is_test:
                        logger.debug(f"Detected test file {issue.filename} for {project_name} {release.version}, test ID {issue.test_id}")
                    severity = issue.severity
                    confidence = issue.confidence
                    score = bandit_issue_score(severity, confidence)
                    issue = model_to_dict(issue, recurse=False)
                    issue['project'] = release.project.name
                    issue['source'] = source
                    issue['score'] = score
                    issue['package_module'] = f"{package}.{module}" if package and module else package or module
                    issue['project_package'] = f"{release_name}.{package}" if package else release_name
                    issue['project_version'] = release.version
                    issue['is_test'] = is_test
                    test_id = issue.get('test_id')
                    issue['test_category'] = test_id[:2] if test_id and len(test_id) > 2 else None
                    results.append(issue)
        return results
    
    def get_report(self,
                    *projects: str | Project,
                    platform: str="pypi",
                    exclude_deprecated: bool = True,
                    only_latest: bool = False,
                    with_dependencies: bool = False) -> dict:
        """
        Gets an "overall" report of a project.
        These are designed to be generalised for dependencies as well

        *projects: str | Project, the project name or the project object, which could be dependencies
        platform: str, default: pypi
        exclude_deprecated: bool, default: True, if True, deprecated releases are excluded (non-stable)
        only_latest: bool, default: False, if True, only the latest release is used for CVEs
        with_dependencies: bool, default: False, if True, dependencies are included in the report


        returns a vulnerability report complemented with releases and the latest release's bandit report:
        {
            'cves': {}
            'cwes': {} 
            'releases': {
                'project:version': {
                    'version': str,
                    'published_at': datetime,
                    'bandit_report': {} ... bandit report for the release without issues
                },
            }
            'latest': {
                'project': {
                    'version': str,
                    'published_at': datetime,
                    'bandit_report': {
                        'issues': [ {} ... bandit issue, ... ]
                    }
                },
            }
        }
        """
        results = {
            'cves': {},
            'cwes': {},
            'releases': {},
            'latest': {},
            'bandit': {},
        }
        bandit = results['bandit']
        dep_vulns = {}
        dep_rels = {}
        for project in projects:
            project_name = project
            project = self.get_project(project, platform)
            if project is None:
                logger.error(f"Project {project} not found")
                return None
            result = self.get_vulnerabilities(project,
                                              project.latest_release if only_latest else None,
                                              platform=platform)
            result = result if result is not None else {}
            rels = self.get_releases(project, platform=platform, exclude_deprecated=exclude_deprecated)
            releases = {}
            latest_release = project.latest_release
            bandit_report = self.get_bandit_report(project)
            latest_rel_id = f"{project_name}:{latest_release}"
            for rel in rels:
                # this is to provide information of all releases, although not necessarily used
                # added for transparency
                rel_id = f"{project_name}:{rel.version}"
                rel_dict = model_to_dict(rel, recurse=False)
                rel_dict['dependencies'] = {}
                if with_dependencies:
                    deps = self.get_dependencies(project_name, rel.version, platform)
                    if deps is not None:
                        for dep in deps:
                            dep_name = dep.name
                            if dep_name not in dep_rels:
                                rels = self.get_releases(dep_name, platform=dep.platform)
                                vulns = self.get_vulnerabilities(dep_name, platform=dep.platform)
                                dep_rels[dep_name] = rels if rels is not None else []
                                dep_vulns[dep_name] = vulns if vulns is not None else {}
                            else:
                                vulns = dep_vulns[dep_name]
                                rels = dep_rels[dep_name]
                            for cve in vulns.get('cves', {}):
                                if cve not in result['cves']:
                                    result['cves'][cve] = vulns['cves'][cve]
                            for cwe in vulns.get('cwes', {}):
                                if cwe not in result['cwes']:
                                    result['cwes'][cwe] = vulns['cwes'][cwe]
                            dep_version = dep.version
                            dep_platform = dep.platform
                            dep_req = dep.requirements
                            dep_id = f"{dep_name}:{dep_version}"
                            # gets the release of the dependency that fulfills the requirements
                            satisfies = []
                            not_satisfies = []
                            for rel in rels:
                                if rel.version == dep_version:
                                    satisfies.append(rel)
                                else:
                                    not_satisfies.append(rel)
                            if len(satisfies) == 0:
                                logger.debug(f"No release found for {dep_name} {dep_version} {dep_req}")
                                continue
                            dep_rel = satisfies[0]
                            dep_cve = set()
                            dep_patch_lag = set()
                            for cve_id in vulns.get('cves', {}):
                                cve = vulns['cves'][cve_id]
                                if cve_id not in result['cves']:
                                    result['cves'][cve_id] = cve
                                for app in cve.get('applicability', []):
                                    if db.is_applicable(dep_rel, app):
                                        dep_cve.add(cve_id)
                                        v_end = app.get('version_end')
                                        v_excl = app.get('exclude_end', False)
                                        if v_end is not None and v_excl is False:
                                            rels = self.get_releases(dep_name, platform=dep_platform, requirements=f">{v_end}")
                                            if len(rels) > 0:
                                                v_end = rels[0].version
                                        if v_end is not None and '<' in dep_req and not version_satisfies_requirements(v_end, dep_req):
                                            # if there is a limiting version and the v_end does not satisfy the requirements
                                            logger.info(f"Patch lag for {rel_id} dependency {dep_name} {dep_version} ({cve_id}). Version end {v_end} '{dep_req}'")
                                            dep_patch_lag.add(cve_id)
                            # count the amount of vulnerabilities introduced by requirements
                            rel_dict['dependencies'][dep_id] = {
                                'name': dep_name,
                                'version': dep_version,
                                'platform': dep_platform,
                                'requirements': dep.requirements,
                                'cves': dep_cve,
                                'patch_lag': dep_patch_lag,
                            }
                rel_dict['cves'] = set()
                rel_dict['cwes'] = set()
                releases[rel_id] = rel_dict
                for cve in result.get('cves', {}).values():
                    cve_id = cve.get('cve_id')
                    if db.is_applicable(rel, cve.get('applicability', [])):
                        rel_dict['cves'].add(cve_id)
                        rel_dict['cwes'].update(cve.get('cwes', []))
                if rel_id == latest_rel_id:
                    if 'latest' not in result:
                        result['latest'] = {}
                    result['latest'][rel_id] = deepcopy(releases[rel_id])
            if bandit_report:
                # if there is a bandit report, add it to the latest release
                bandit_release = bandit_report.release
                brel_id = f"{project_name}:{bandit_report.release.version}"
                issues = bandit_report.issues
                bandit_report = model_to_dict(bandit_report, recurse=False)
                bandit_report['issues'] = [ model_to_dict(issue, recurse=False) for issue in issues ]
                bandit_report['release'] = brel_id
                result['latest'][latest_rel_id]['bandit_report'] = bandit_report
                result['latest'][latest_rel_id]['analysed_release'] = brel_id
                brel = model_to_dict(bandit_release, recurse=False)
                latest_rel = result['latest'][latest_rel_id]
                for key in brel:
                    # if the key is not in the latest release, add it
                    # this is to avoid overwriting the latest release's data, yet adding static code analysis data
                    if type(brel[key]) in [str, int, float, dt.datetime] and latest_rel.get(key) is None:
                        latest_rel[key] = brel[key]
            else:
                logger.error(f"No bandit report found for {project_name}")
            for cve_id in result.get('cves', {}):
                if cve_id not in results['cves']:
                    results['cves'][cve_id] = result['cves'][cve_id]
                else:
                    app = result['cves'][cve_id].get('applicability', [])
                    results['cves'][cve_id]['applicability'].extend(app)
            for cwe_id in result.get('cwes', {}):
                if cwe_id not in results['cwes']:
                    results['cwes'][cwe_id] = result['cwes'][cwe_id]
                else:
                    cves = result['cwes'][cwe_id].get('cves', [])
                    prev_cves = results['cwes'][cwe_id].get('cves', [])
                    new_cves = set(cves + prev_cves)
                    results['cwes'][cwe_id]['cves'] = sorted(list(new_cves))
            for rel_id in releases:
                if rel_id not in results['releases']:
                    results['releases'][rel_id] = releases[rel_id]
            for latest in result.get('latest', {}):
                if latest not in results['latest']:
                    results['latest'][latest] = result['latest'][latest]
        bandit['count'] = {}
        bandit['by_test'] = {}
        bandit['by_cwe'] = {}
        for lrel in results['latest']:
            for dep in results['latest'][lrel].get('dependencies', {}).values():
                depname = dep['name']
                dproj = self.get_release(depname, dep['version'], platform=dep['platform'], requirements=dep['requirements'], analysed=True)
                if dproj is None:
                    logger.error(f"Dependency {depname} {dep['version']} not found")
                    continue
                bandit_report = dproj.bandit_report.first()
                dproj_dict = model_to_dict(dproj, recurse=False)
                dproj_dict['bandit_report'] = model_to_dict(bandit_report, recurse=False) if bandit_report else None
                for key in dproj_dict:
                    if type(dproj_dict[key]) in [str, int, float, dt.datetime, dict] and dep.get(key) is None:
                        dep[key] = dproj_dict[key]
            bandit_report = results['latest'][lrel].get('bandit_report', {})
            if 'issues' in bandit_report:
                issues = bandit_report['issues']
                for issue in issues:
                    test_id = issue.get('test_id')
                    cwe_id = issue.get('cwe_id', 'unknown')
                    by_test = bandit['by_test']
                    by_cwe = bandit['by_cwe']
                    if test_id not in by_test:
                        by_test[test_id] = {
                            'release': set([lrel])
                        }
                    else:
                        if lrel not in by_test[test_id]['release']:
                            by_test[test_id]['release'].add(lrel)
                    if cwe_id not in by_cwe:
                        by_cwe[cwe_id] = {
                            'release': set([lrel])
                        }
                    else:
                        if lrel not in by_cwe[cwe_id]['release']:
                            by_cwe[cwe_id]['release'].add(lrel)
                    severity = issue.get('severity', '').lower()
                    confidence = issue.get('confidence', '').lower()
                    sev = f"severity_{severity[0]}"
                    conf = f"confidence_{confidence[0]}"
                    sevconf = f"{sev}_{conf}"
                    by_test[test_id][sev] = by_test[test_id].get(sev, 0) + 1
                    by_test[test_id][conf] = by_test[test_id].get(conf, 0) + 1
                    by_test[test_id][sevconf] = by_test[test_id].get(sevconf, 0) + 1
                    by_cwe[cwe_id][sev] = by_cwe[cwe_id].get(sev, 0) + 1
                    by_cwe[cwe_id][conf] = by_cwe[cwe_id].get(conf, 0) + 1
                    by_cwe[cwe_id][sevconf] = by_cwe[cwe_id].get(sevconf, 0) + 1
            for test in bandit['by_test'].values():
                for key in test:
                    if type(test[key]) not in [int, float]:
                        continue
                    bandit['count'][key] = test.get(key, 0) + test[key]
                sev_h_conf_h = test.get('severity_h_confidence_h', 0)
                sev_h_conf_m = test.get('severity_h_confidence_m', 0)
                sev_h_conf_l = test.get('severity_h_confidence_l', 0)
                sev_m_conf_h = test.get('severity_m_confidence_h', 0)
                sev_m_conf_m = test.get('severity_m_confidence_m', 0)
                sev_m_conf_l = test.get('severity_m_confidence_l', 0)
                sev_l_conf_h = test.get('severity_l_confidence_h', 0)
                sev_l_conf_m = test.get('severity_l_confidence_m', 0)
                sev_l_conf_l = test.get('severity_l_confidence_l', 0)
                critical = sev_h_conf_h
                high = sev_h_conf_m + sev_m_conf_h
                medium = sev_h_conf_l + sev_m_conf_m + sev_l_conf_h
                low = sev_m_conf_l + sev_l_conf_m
                none = sev_l_conf_l
                bandit['count']['issues_critical'] = bandit['count'].get('critical', 0) + critical
                bandit['count']['issues_high'] = bandit['count'].get('high', 0) + high
                bandit['count']['issues_medium'] = bandit['count'].get('medium', 0) + medium
                bandit['count']['issues_low'] = bandit['count'].get('low', 0) + low
        return results
    
    # we need these dataframes, where "release" includes dependencies by "source"
    # structure: Project | Version | Source | 
    # 1) CVEs per release
    # 2) CWEs per release
    # 4) Bandit Issues per release
    # 5) Static Analysis Summary per release

    def get_releases_with_dependencies(self, project: str | Project, platform: str="pypi", analysed: bool = True, before_release: bool = True, sort_semantically: bool = True, only_latest: bool = False) -> List[list]:
        """
        Gets a list of tuples where each tuple contains a release and its dependencies

        returns:
        [[(release, None), (deprel, dep), ...], ...], list of lists where each list contains all releases with the dependency object it is derived from
        """
        results = []
        releases = self.get_releases(project, platform=platform, analysed=analysed, exclude_deprecated=True, sort_semantically=sort_semantically)
        if releases is None:
            return results
        for release in releases:
            dependencies = self.get_dependencies(project, release.version, platform)
            dependencies = dependencies if dependencies is not None else []
            result = [(release, None)]
            for dep in dependencies:
                # get the latest release of each dependency before the main project's release
                before_date = release.published_at if before_release else None
                deprel = self.get_release(dep.name, dep.version, platform=dep.platform, requirements=dep.requirements, before=before_date)
                if deprel is not None:
                    result.append((deprel, dep))
            results.append(result)
            if only_latest:
                break
        return results
    
    def __patch_lag(self, cve: dict, release: Release) -> dict:
        """
        Returns a dictionary of patch lag KPIs for a CVE
        """
        if release is None:
            logger.error(f"Release cannot be None")
            return {}
        project_name = release.project.name
        apps = cve.get('applicability', [])
        releases = self.get_releases(project_name, platform=release.project.platform)
        releases = sorted(releases, key=lambda x: x.published_at)
        first_release = releases[0] if len(releases) > 0 else None
        cve_published = cve.get('published_at')
        for app in apps:
            if db.is_applicable(release, app):
                start_date = app.get('start_date') if app.get('start_date') is not None else first_release.published_at
                not_patched = app.get('version_end') is None
                patched_date = app.get('patched_at')
                # the first "applicability" targets the release, as the apps are disjoint ranges
                return {
                    'start_to_patched': (patched_date - start_date).days if patched_date is not None else None,
                    'start_to_published': (cve_published - start_date).days,
                    'published_to_patched': (patched_date - cve_published).days if patched_date is not None else None,
                    'release_to_patched': (patched_date - release.published_at).days if patched_date is not None else None,
                    'release_to_published': (cve_published - release.published_at).days,
                    'not_patched': not_patched,
                }
        return {}
    
    def __compute_tech_lag(self, cve: dict, release: Release, constraints: str) -> bool:
        """
        Computes whether a release has "technical lag" for a CVE.
        A technical lag is when a dependency constraint disallows a patch for a CVE.
        """
        if constraints is None:
            # if there are no constraints, there cannot be a technical lag
            return False
        max_version, include_end = get_max_version(constraints)
        if include_end:
            patch = max_version.release[2] if len(max_version.release) > 2 else 0
            patch += 1
            max_version = semver.parse(f"{max_version.major}.{max_version.minor}.{patch}")
        if max_version is None:
            return False
        for app in cve.get('applicability', []):
            if db.is_applicable(release, app):
                version_start = app.get('version_start')
                version_end = app.get('version_end')
                excl_start = app.get('exclude_start', False)
                excl_end = app.get('exclude_end', False)
                if version_in_range(max_version, version_start, version_end, excl_start, excl_end):
                    return True
                return False
        return False

    def __model_with_release_data(self, model: Model, main_release: Release, release: Release, dependency: ReleaseDependency) -> dict:
        """
        Adds release data to a dictionary
        """
        constraints = dependency.requirements if dependency is not None else None
        if type(model) != dict and not isinstance(model, Model):
            logger.error(f"Incorrect typing logic. Expected 'dict' or 'Model'")
            exit(1)
        result = model_to_dict(model, recurse=False) if isinstance(model, Model) else model
        major = minor = None
        project_name = main_release.project.name
        project_version = main_release.version
        try:
            version = semver.parse(project_version)
            major = version.major
            minor = version.minor
        except:
            pass
        result['major'] = major
        result['minor'] = minor
        result['project'] = project_name
        result['project_version'] = project_version
        result['source'] = 'Direct' if release.project.name == project_name else 'Indirect'
        result['release'] = release.project.name
        result['release_version'] = release.version
        result['release_requirements'] = constraints
        result['inherited_from'] = dependency.inherited_from if dependency is not None else None
        return { k: v for k, v in result.items() if type(v) not in [dict, list] }

    def df_cves(self, project: str | Project, platform: str="pypi", by_cwe: bool = False) -> pd.DataFrame:
        """
        Returns a DataFrame of CVEs per release, where a "release" refers to a project's release including each dependency's releases.
        Gets the latest release of each dependency before the main project's release's release date.
        """
        project = self.get_project(project, platform)
        project_name = project.name
        release_deps = self.get_releases_with_dependencies(project, platform=platform, analysed=False)
        df_cves = []
        vulnerabilities = {}
        vulnerabilities[project_name] = self.get_vulnerabilities(project, platform=platform)
        for releases in release_deps:
            if len(releases) == 0:
                logger.warning(f"Unexpected empty list of releases")
                continue
            # releases are lists of tuples, where each tuple is a release and its dependency
            main_release = releases[0][0] # the first release is the main project's release
            for release, dependency in releases:
                # again, the releases are tuples of the release and whether it is derived from a dependency
                constraints = dependency.requirements if dependency is not None else None
                release_name = release.project.name
                if release_name not in vulnerabilities:
                    vulnerabilities[release_name] = self.get_vulnerabilities(release.project, platform=platform)
                cves = vulnerabilities.get(release_name, {}).get('cves', None)
                for cve_id in cves:
                    cve = cves[cve_id]
                    if db.is_applicable(release, cve):
                        # add whether the release has "technical lag"
                        model_dict = self.__model_with_release_data(cve, main_release, release, dependency)
                        model_dict['technical_lag'] = self.__compute_tech_lag(cve, release, constraints)
                        patch_lag = self.__patch_lag(cve, release)
                        model_dict.update(patch_lag)
                        if by_cwe:
                            for cwe_id in cve.get('cwes', []):
                                model_dict['cwe_id'] = cwe_id
                                df_cves.append(model_dict)
                        else:
                            df_cves.append(model_dict)
        # ensure uniqueness of crucial columns
        columns = ['release', 'release_version', 'cve_id']
        if by_cwe:
            columns.append('cwe_id')
        return pd.DataFrame(df_cves).drop_duplicates(columns)

    def df_static(self, project: str | Project, platform: str="pypi", with_issues: bool = False, only_latest: bool = True) -> pd.DataFrame:
        release_deps = self.get_releases_with_dependencies(project, platform=platform, analysed=True, only_latest=only_latest)
        df = []
        for releases in release_deps:
            if len(releases) == 0:
                logger.warning(f"Unexpected empty list of releases")
                continue
            main_release = releases[0][0]
            for release, dependency in releases:
                bandit_report = self.get_bandit_report(release)
                if bandit_report is None:
                    continue
                if with_issues:
                    for issue in bandit_report.issues:
                        severity = issue.severity
                        confidence = issue.confidence
                        issue_dict = self.__model_with_release_data(issue, main_release, release, dependency)
                        issue_dict['severity_score'] = bandit_value_score(severity)
                        issue_dict['test_category'] = issue.test_id[:2] if issue.test_id and len(issue.test_id) > 2 else None
                        package = issue.package or ''
                        module = issue.module or ''
                        issue_dict['is_test'] = package.startswith('test') or 'test' in module
                        issue_dict['project_package'] = f"{release.project.name}.{package}"
                        issue_dict['confidence_score'] = bandit_value_score(confidence)
                        issue_dict['score'] = bandit_issue_score(severity, confidence)
                        df.append(issue_dict)
                else:
                    bandit_report = model_to_dict(bandit_report, recurse=False)
                    rel_dict = self.__model_with_release_data(release, main_release, release, dependency)
                    for k in bandit_report:
                        if k not in rel_dict:
                            rel_dict[k] = bandit_report[k]
                    df.append(rel_dict)
        return pd.DataFrame(df)
    
    def df_timeline(self, project: str | Project, platform: str="pypi",
                        start_date: int | str | dt.datetime = 2019,
                        end_date: int | str | dt.datetime = None,
                        step: str = 'm',
                        analysed: bool = False,
                        with_issues: bool = False) -> pd.DataFrame:
        """
        Returns a DataFrame of the timeline of a project's releases
        """
        project = self.get_project(project, platform)
        releases = self.get_releases_with_dependencies(project, platform=platform, analysed=analysed)
        df = pd.DataFrame()
        source_df = self.df_cves(project, platform, by_cwe=False) if not analysed else self.df_static(project, platform, with_issues=with_issues, only_latest=False)
        for date in date_range(start_date, end_date, step):
            date_releases = None
            print(f"Processing date {date}")
            for rels in releases:
                if len(rels) == 0:
                    logger.warning(f"Unexpected empty list of releases")
                    continue
                main_release = rels[0][0]
                if main_release.published_at.date() <= date.date():
                    date_releases = rels
                    break
            for release, _ in date_releases:
                # for each release in the timeline map the values to these
                rel_df = source_df[(source_df['release'] == release.project.name) & (source_df['release_version'] == release.version)].copy()
                rel_df['date'] = date
            df = pd.concat([df, rel_df])
        return df
                
    
if __name__ == "__main__":
    # For the purpose of loading in interactive shell and debugging
    # e.g., py -i src/Aggregator.py
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--project', type=str, help='The project name')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    logger.remove()
    args = parser.parse_args()
    logger.add(sys.stdout, colorize=True, backtrace=True, diagnose=True, level='DEBUG' if args.debug else 'INFO')
    ag = Aggregator("config.yml", debug=True)
    ag.load_projects()
    project = ag.get_project(args.project) if args.project else None